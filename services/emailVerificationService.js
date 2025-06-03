const dns = require('dns').promises;
const net = require('net');
const validator = require('validator');
const punycode = require('punycode/');
const logger = require('../utils/logger');
const SyntaxValidator = require('./syntaxValidator');
const DNSValidator = require('./dnsValidator');
const SMTPValidator = require('./smtpValidator');
const DisposableEmailDetector = require('./disposableEmailDetector');
const RoleAccountDetector = require('./roleAccountDetector');
const FreeEmailDetector = require('./freeEmailDetector');
const SpamTrapDetector = require('./spamTrapDetector');

class EmailVerificationService {
  constructor() {
    this.syntaxValidator = new SyntaxValidator();
    this.dnsValidator = new DNSValidator();
    this.smtpValidator = new SMTPValidator();
    this.disposableEmailDetector = new DisposableEmailDetector();
    this.roleAccountDetector = new RoleAccountDetector();
    this.freeEmailDetector = new FreeEmailDetector();
    this.spamTrapDetector = new SpamTrapDetector();
  }

  /**
   * Comprehensive email verification
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

      // 1. Advanced Syntax Verification
      logger.info(`Starting syntax verification for: ${email}`);
      result.checks.syntax = await this.syntaxValidator.validate(normalizedEmail);

      if (!result.checks.syntax.isValid) {
        result.processingTime = Date.now() - startTime;
        return result;
      }

      // 2. International Domain Support
      result.checks.international = this.checkInternationalSupport(domain);

      // 3. Domain and DNS Check
      if (options.checkDNS !== false) {
        logger.info(`Starting DNS verification for domain: ${domain}`);
        result.checks.dns = await this.dnsValidator.validateDomain(domain);
      }

      // 4. MX Record Check
      if (options.checkMX !== false && result.checks.dns?.isValid) {
        logger.info(`Starting MX verification for domain: ${domain}`);
        result.checks.mx = await this.dnsValidator.validateMX(domain);
      }

      // 5. Disposable Email Detection
      result.checks.disposable = await this.disposableEmailDetector.isDisposable(domain);

      // 6. Role Account Detection
      result.checks.role = this.roleAccountDetector.isRoleAccount(localPart);

      // 7. Free Email Detection
      result.checks.free = this.freeEmailDetector.isFreeEmail(domain);

      // 8. Spam Trap Detection
      result.checks.spamTrap = await this.spamTrapDetector.isSpamTrap(normalizedEmail);

      // 9. SMTP Mailbox Verification
      if (options.checkSMTP !== false && result.checks.mx?.isValid && !result.checks.disposable.isDisposable) {
        logger.info(`Starting SMTP verification for: ${email}`);
        result.checks.smtp = await this.smtpValidator.validateMailbox(normalizedEmail, result.checks.mx.mxRecords);
      }

      // 10. Catch-all Detection
      if (result.checks.smtp && options.checkCatchAll !== false) {
        result.checks.catchAll = await this.smtpValidator.detectCatchAll(domain, result.checks.mx.mxRecords);
      }

      // 11. Yahoo Specific Verification
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
   * Batch email verification
   * @param {Array} emails - Array of email addresses
   * @param {Object} options - Verification options
   * @returns {Array} Array of verification results
   */
  async verifyEmailBatch(emails, options = {}) {
    const maxConcurrent = options.maxConcurrent || 10;
    const results = [];
    
    // Process emails in batches
    for (let i = 0; i < emails.length; i += maxConcurrent) {
      const batch = emails.slice(i, i + maxConcurrent);
      const batchPromises = batch.map(email => this.verifyEmail(email, options));
      
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