const dns = require('dns').promises;
const net = require('net');
const validator = require('validator');
const punycode = require('punycode/');
const logger = require('../utils/logger');
const SyntaxValidator = require('./syntaxValidator');
const DNSValidator = require('./dnsValidator');
const ExternalSMTPService = require('./externalSMTPService');
const DisposableEmailDetector = require('./disposableEmailDetector');
const RoleAccountDetector = require('./roleAccountDetector');
const FreeEmailDetector = require('./freeEmailDetector');
const SpamTrapDetector = require('./spamTrapDetector');

class EmailVerificationService {
  constructor() {
    this.syntaxValidator = new SyntaxValidator();
    this.dnsValidator = new DNSValidator();
    this.externalSMTPService = new ExternalSMTPService();
    this.disposableEmailDetector = new DisposableEmailDetector();
    this.roleAccountDetector = new RoleAccountDetector();
    this.freeEmailDetector = new FreeEmailDetector();
    this.spamTrapDetector = new SpamTrapDetector();
  }

  /**
   * Comprehensive email verification with external SMTP service
   * @param {string} email - Email address to verify
   * @param {Object} options - Verification options
   * @returns {Object} Verification result
   */
  async verifyEmail(email, options = {}) {
    const startTime = Date.now();
    
    try {
      // Normalize email
      const normalizedEmail = this.normalizeEmail(email);
      
      if (!normalizedEmail) {
        return this.createErrorResult('Invalid email format', email);
      }

      const result = {
        email: normalizedEmail,
        originalEmail: email,
        isValid: false,
        quality: 'unknown',
        checks: {},
        details: {},
        timestamp: new Date().toISOString(),
        processingTime: 0
      };

      // Extract domain
      const domain = normalizedEmail.split('@')[1];
      const localPart = normalizedEmail.split('@')[0];

      // Level 1: Advanced Syntax Verification
      logger.info(`Starting syntax verification for: ${email}`);
      result.checks.syntax = await this.syntaxValidator.validate(normalizedEmail);

      if (!result.checks.syntax.isValid) {
        result.processingTime = Date.now() - startTime;
        return result;
      }

      // Level 2: International Domain Support
      result.checks.international = this.checkInternationalSupport(domain);

      // Level 3: Domain and DNS Check
      if (options.checkDNS !== false) {
        logger.info(`Starting DNS verification for domain: ${domain}`);
        result.checks.dns = await this.dnsValidator.validateDomain(domain);
      }

      // Level 4: MX Record Check
      if (options.checkMX !== false && result.checks.dns?.isValid) {
        logger.info(`Starting MX verification for domain: ${domain}`);
        result.checks.mx = await this.dnsValidator.validateMX(domain);
      }

      // Level 4: Disposable Email Detection
      result.checks.disposable = await this.disposableEmailDetector.isDisposable(domain);

      // Level 4: Role Account Detection
      result.checks.role = this.roleAccountDetector.isRoleAccount(localPart);

      // Level 4: Free Email Detection
      result.checks.free = this.freeEmailDetector.isFreeEmail(domain);

      // Level 4: Spam Trap Detection
      result.checks.spamTrap = await this.spamTrapDetector.isSpamTrap(normalizedEmail);

      // Level 5: External SMTP Mailbox Verification
      if (options.checkSMTP !== false && result.checks.mx?.isValid && !result.checks.disposable.isDisposable) {
        logger.info(`Starting external SMTP verification for: ${email}`);
        try {
          result.checks.smtp = await this.externalSMTPService.validateEmail(
            normalizedEmail, 
            result.checks.mx.mxRecords,
            options
          );
        } catch (error) {
          logger.error(`External SMTP verification failed for ${email}:`, error);
          result.checks.smtp = {
            isValid: false,
            isDeliverable: false,
            smtpResponse: '',
            responseCode: null,
            errors: [`External SMTP service error: ${error.message}`],
            warnings: ['SMTP validation could not be completed'],
            testedMX: null,
            connectionStatus: 'external_service_failed'
          };
        }
      }

      // Level 5: Catch-all Detection (via external service)
      if (result.checks.smtp && options.checkCatchAll !== false) {
        try {
          result.checks.catchAll = await this.externalSMTPService.detectCatchAll(
            domain, 
            result.checks.mx.mxRecords,
            options
          );
        } catch (error) {
          logger.error(`External catch-all detection failed for ${domain}:`, error);
          result.checks.catchAll = {
            isCatchAll: false,
            confidence: 0,
            testResults: [],
            errors: [`External SMTP service error: ${error.message}`],
            warnings: ['Catch-all detection could not be completed']
          };
        }
      }

      // Special handling for Yahoo domains (Level 4)
      if (this.isYahooDomain(domain)) {
        result.checks.yahoo = await this.verifyYahooEmail(normalizedEmail);
      }

      // Calculate overall validity and quality
      this.calculateOverallResult(result);

      result.processingTime = Date.now() - startTime;
      logger.info(`Email verification completed for ${email} in ${result.processingTime}ms`);

      return result;

    } catch (error) {
      logger.error(`Email verification failed for ${email}:`, error);
      
      return {
        email: email,
        isValid: false,
        quality: 'error',
        error: error.message,
        processingTime: Date.now() - startTime,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Batch email verification with external SMTP service
   * @param {Array} emails - Array of email addresses
   * @param {Object} options - Verification options
   * @returns {Array} Array of verification results
   */
  async verifyEmailBatch(emails, options = {}) {
    const maxConcurrent = options.maxConcurrent || 10;
    const results = [];
    const smtpBatchVerifications = []; // For emails that pass levels 1-4
    
    logger.info(`Starting batch verification for ${emails.length} emails`);

    // Process emails in batches for levels 1-4
    for (let i = 0; i < emails.length; i += maxConcurrent) {
      const batch = emails.slice(i, i + maxConcurrent);
      const batchPromises = batch.map(async (email) => {
        try {
          // Run levels 1-4 verification
          const partialResult = await this.verifyEmail(email, { 
            ...options, 
            checkSMTP: false, // Skip SMTP for now
            checkCatchAll: false 
          });
          
          // If email passes levels 1-4 and SMTP check is enabled, prepare for external SMTP
          if (partialResult.checks.mx?.isValid && 
              !partialResult.checks.disposable?.isDisposable && 
              options.checkSMTP !== false) {
            smtpBatchVerifications.push({
              email: partialResult.email,
              mxRecords: partialResult.checks.mx.mxRecords,
              result: partialResult
            });
          }
          
          return partialResult;
        } catch (error) {
          logger.error('Batch verification error:', error);
          return this.createErrorResult('Batch processing failed', email);
        }
      });
      
      try {
        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
      } catch (error) {
        logger.error('Batch verification error:', error);
        // Add error results for failed batch
        batch.forEach(email => {
          results.push(this.createErrorResult('Batch processing failed', email));
        });
      }
    }

    // Now process SMTP verification in batch via external service
    if (smtpBatchVerifications.length > 0 && options.checkSMTP !== false) {
      try {
        logger.info(`Sending batch SMTP verification for ${smtpBatchVerifications.length} emails to external server`);
        
        const smtpBatchResult = await this.externalSMTPService.validateEmailBatch(
          smtpBatchVerifications.map(v => ({
            email: v.email,
            mxRecords: v.mxRecords
          })),
          options
        );

        // Merge SMTP results back into main results
        if (smtpBatchResult.results) {
          const smtpResultsMap = new Map();
          smtpBatchResult.results.forEach(smtpResult => {
            smtpResultsMap.set(smtpResult.email, smtpResult.smtp);
          });

          // Update results with SMTP data
          results.forEach(result => {
            const smtpData = smtpResultsMap.get(result.email);
            if (smtpData) {
              result.checks.smtp = smtpData;
              
              // Recalculate overall result with SMTP data
              this.calculateOverallResult(result);
            }
          });
        }

      } catch (error) {
        logger.error('Batch SMTP verification failed:', error);
        // Add error SMTP results for all pending verifications
        smtpBatchVerifications.forEach(verification => {
          const result = results.find(r => r.email === verification.email);
          if (result) {
            result.checks.smtp = {
              isValid: false,
              isDeliverable: false,
              errors: [`External SMTP service error: ${error.message}`],
              connectionStatus: 'external_service_failed'
            };
            this.calculateOverallResult(result);
          }
        });
      }
    }

    logger.info(`Batch verification completed for ${emails.length} emails`);
    return results;
  }

  /**
   * Normalize email address
   * @param {string} email - Email to normalize
   * @returns {string} Normalized email
   */
  normalizeEmail(email) {
    if (!email || typeof email !== 'string') {
      return null;
    }

    try {
      // Basic cleanup
      email = email.trim().toLowerCase();
      
      // Check basic format
      if (!email.includes('@') || email.split('@').length !== 2) {
        return null;
      }

      const [localPart, domain] = email.split('@');
      
      if (!localPart || !domain) {
        return null;
      }

      // Handle internationalized domains
      let normalizedDomain = domain;
      try {
        if (domain.includes('xn--') || /[^\x00-\x7F]/.test(domain)) {
          normalizedDomain = punycode.toASCII(domain);
        }
      } catch (error) {
        logger.warn(`Punycode conversion failed for domain: ${domain}`, error);
      }

      return `${localPart}@${normalizedDomain}`;
    } catch (error) {
      logger.error('Email normalization failed:', error);
      return null;
    }
  }

  /**
   * Check international domain support
   * @param {string} domain - Domain to check
   * @returns {Object} International support result
   */
  checkInternationalSupport(domain) {
    const result = {
      isInternational: false,
      hasUnicode: false,
      hasPunycode: false,
      originalDomain: domain,
      asciiDomain: domain
    };

    try {
      // Check for Unicode characters
      result.hasUnicode = /[^\x00-\x7F]/.test(domain);
      
      // Check for Punycode
      result.hasPunycode = domain.includes('xn--');
      
      result.isInternational = result.hasUnicode || result.hasPunycode;

      if (result.isInternational) {
        try {
          result.asciiDomain = punycode.toASCII(domain);
        } catch (error) {
          logger.warn(`Failed to convert domain to ASCII: ${domain}`, error);
        }
      }

      return result;
    } catch (error) {
      logger.error('International domain check failed:', error);
      return result;
    }
  }

  /**
   * Check if domain is Yahoo
   * @param {string} domain - Domain to check
   * @returns {boolean} True if Yahoo domain
   */
  isYahooDomain(domain) {
    const yahooDomains = [
      'yahoo.com', 'yahoo.co.uk', 'yahoo.de', 'yahoo.es', 'yahoo.it',
      'yahoo.fr', 'yahoo.com.au', 'yahoo.ca', 'yahoo.co.jp', 'yahoo.co.in',
      'ymail.com', 'rocketmail.com'
    ];
    
    return yahooDomains.includes(domain.toLowerCase());
  }

  /**
   * Yahoo-specific verification
   * @param {string} email - Email to verify
   * @returns {Object} Yahoo verification result
   */
  async verifyYahooEmail(email) {
    // Yahoo has specific requirements and behaviors
    return {
      isYahoo: true,
      verificationMethod: 'yahoo-specific',
      recommendation: 'Use standard SMTP verification with caution',
      note: 'Yahoo domains may require special handling'
    };
  }

  /**
   * Calculate overall result
   * @param {Object} result - Verification result object
   */
  calculateOverallResult(result) {
    const checks = result.checks;
    
    // Count failed checks
    let failedChecks = 0;
    let totalChecks = 0;
    let riskFactors = 0;

    // Critical checks
    if (checks.syntax && !checks.syntax.isValid) failedChecks++;
    if (checks.dns && !checks.dns.isValid) failedChecks++;
    if (checks.mx && !checks.mx.isValid) failedChecks++;
    
    totalChecks += 3;

    // SMTP check (if performed)
    if (checks.smtp) {
      totalChecks++;
      if (!checks.smtp.isValid) failedChecks++;
    }

    // Risk factors
    if (checks.disposable?.isDisposable) riskFactors++;
    if (checks.role?.isRole) riskFactors++;
    if (checks.spamTrap?.isSpamTrap) riskFactors++;
    if (checks.catchAll?.isCatchAll) riskFactors++;

    // Determine validity
    result.isValid = failedChecks === 0 && !checks.spamTrap?.isSpamTrap;

    // Determine quality
    if (!result.isValid) {
      result.quality = 'invalid';
    } else if (riskFactors >= 2) {
      result.quality = 'risky';
    } else if (riskFactors === 1) {
      result.quality = 'medium';
    } else {
      result.quality = 'high';
    }

    // Additional details
    result.details = {
      failedChecks,
      totalChecks,
      riskFactors,
      score: Math.max(0, ((totalChecks - failedChecks) / totalChecks) * 100 - (riskFactors * 10))
    };
  }

  /**
   * Create error result
   * @param {string} message - Error message
   * @param {string} email - Email address
   * @returns {Object} Error result
   */
  createErrorResult(message, email) {
    return {
      email: email,
      isValid: false,
      quality: 'invalid',
      error: message,
      timestamp: new Date().toISOString(),
      processingTime: 0
    };
  }
}

module.exports = EmailVerificationService; 