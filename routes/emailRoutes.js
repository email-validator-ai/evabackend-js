const express = require('express');
const router = express.Router();
const Joi = require('joi');
const EmailVerificationService = require('../services/emailVerificationService');
const logger = require('../utils/logger');

// Initialize email verification service
const emailVerificationService = new EmailVerificationService();

// Validation schemas
const emailValidationSchema = Joi.object({
  email: Joi.string().email().required(),
  checkDNS: Joi.boolean().default(true),
  checkMX: Joi.boolean().default(true),
  checkSMTP: Joi.boolean().default(true),
  checkCatchAll: Joi.boolean().default(true)
});

const batchValidationSchema = Joi.object({
  emails: Joi.array().items(Joi.string()).min(1).max(1000).required(),
  checkDNS: Joi.boolean().default(true),
  checkMX: Joi.boolean().default(true),
  checkSMTP: Joi.boolean().default(false), // Default false for batch to avoid overwhelming
  checkCatchAll: Joi.boolean().default(false),
  maxConcurrent: Joi.number().integer().min(1).max(50).default(10)
});

// Middleware for input validation
const validateInput = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid input',
        details: error.details.map(detail => detail.message)
      });
    }
    req.validatedData = value;
    next();
  };
};

/**
 * @route POST /api/email/verify
 * @desc Verify a single email address
 * @access Public
 */
router.post('/verify', validateInput(emailValidationSchema), async (req, res) => {
  try {
    const { email, ...options } = req.validatedData;
    
    logger.info(`Email verification request for: ${email}`);
    
    const result = await emailVerificationService.verifyEmail(email, options);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Email verification failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route POST /api/email/verify/batch
 * @desc Verify multiple email addresses
 * @access Public
 */
router.post('/verify/batch', validateInput(batchValidationSchema), async (req, res) => {
  try {
    const { emails, ...options } = req.validatedData;
    
    logger.info(`Batch email verification request for ${emails.length} emails`);
    
    const results = await emailVerificationService.verifyEmailBatch(emails, options);
    
    // Generate summary statistics
    const summary = {
      total: results.length,
      valid: results.filter(r => r.isValid).length,
      invalid: results.filter(r => !r.isValid).length,
      quality: {
        high: results.filter(r => r.quality === 'high').length,
        medium: results.filter(r => r.quality === 'medium').length,
        risky: results.filter(r => r.quality === 'risky').length,
        invalid: results.filter(r => r.quality === 'invalid').length
      },
      avgProcessingTime: results.reduce((sum, r) => sum + (r.processingTime || 0), 0) / results.length
    };
    
    res.json({
      success: true,
      data: {
        summary,
        results
      }
    });
    
  } catch (error) {
    logger.error('Batch email verification failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/syntax/:email
 * @desc Check email syntax only
 * @access Public
 */
router.get('/syntax/:email', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email parameter is required'
      });
    }
    
    const result = await emailVerificationService.syntaxValidator.validate(email);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Syntax validation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/dns/:domain
 * @desc Check DNS records for domain
 * @access Public
 */
router.get('/dns/:domain', async (req, res) => {
  try {
    const domain = req.params.domain;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const dnsResult = await emailVerificationService.dnsValidator.validateDomain(domain);
    const mxResult = await emailVerificationService.dnsValidator.validateMX(domain);
    
    res.json({
      success: true,
      data: {
        domain: domain,
        dns: dnsResult,
        mx: mxResult
      }
    });
    
  } catch (error) {
    logger.error('DNS validation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/disposable/:domain
 * @desc Check if domain is disposable
 * @access Public
 */
router.get('/disposable/:domain', async (req, res) => {
  try {
    const domain = req.params.domain;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const result = await emailVerificationService.disposableEmailDetector.isDisposable(domain);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Disposable email check failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/role/:localpart
 * @desc Check if local part is a role account
 * @access Public
 */
router.get('/role/:localpart', async (req, res) => {
  try {
    const localPart = req.params.localpart;
    
    if (!localPart) {
      return res.status(400).json({
        success: false,
        error: 'Local part parameter is required'
      });
    }
    
    const result = emailVerificationService.roleAccountDetector.getRoleAccountDetails(localPart);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Role account check failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/free/:domain
 * @desc Check if domain is a free email provider
 * @access Public
 */
router.get('/free/:domain', async (req, res) => {
  try {
    const domain = req.params.domain;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }
    
    const result = emailVerificationService.freeEmailDetector.getProviderDetails(domain);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Free email check failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/spamtrap/:email
 * @desc Check if email is a spam trap
 * @access Public
 */
router.get('/spamtrap/:email', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email parameter is required'
      });
    }
    
    const result = await emailVerificationService.spamTrapDetector.getSpamTrapRiskAssessment(email);
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    logger.error('Spam trap check failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route POST /api/email/report
 * @desc Generate comprehensive email list report
 * @access Public
 */
router.post('/report', async (req, res) => {
  try {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails) || emails.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Emails array is required'
      });
    }
    
    if (emails.length > 5000) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 5000 emails allowed for report generation'
      });
    }
    
    logger.info(`Generating report for ${emails.length} emails`);
    
    // Generate verification results
    const verificationResults = await emailVerificationService.verifyEmailBatch(emails, {
      checkSMTP: false, // Skip SMTP for reports to avoid overwhelming servers
      maxConcurrent: 20
    });
    
    // Generate spam trap report
    const spamTrapReport = await emailVerificationService.spamTrapDetector.generateDetectionReport(emails);
    
    // Compile comprehensive report
    const report = {
      metadata: {
        totalEmails: emails.length,
        generatedAt: new Date().toISOString(),
        processingTime: verificationResults.reduce((sum, r) => sum + (r.processingTime || 0), 0)
      },
      summary: {
        valid: verificationResults.filter(r => r.isValid).length,
        invalid: verificationResults.filter(r => !r.isValid).length,
        quality: {
          high: verificationResults.filter(r => r.quality === 'high').length,
          medium: verificationResults.filter(r => r.quality === 'medium').length,
          risky: verificationResults.filter(r => r.quality === 'risky').length,
          invalid: verificationResults.filter(r => r.quality === 'invalid').length
        },
        risks: {
          disposable: verificationResults.filter(r => r.checks?.disposable?.isDisposable).length,
          role: verificationResults.filter(r => r.checks?.role?.isRole).length,
          free: verificationResults.filter(r => r.checks?.free?.isFree).length,
          spamTraps: spamTrapReport.spamTrapsFound
        }
      },
      recommendations: [],
      details: {
        verificationResults: verificationResults,
        spamTrapAnalysis: spamTrapReport
      }
    };
    
    // Generate recommendations
    if (report.summary.risks.spamTraps > 0) {
      report.recommendations.push('CRITICAL: Spam traps detected - immediate list cleanup required');
    }
    
    if (report.summary.risks.disposable > emails.length * 0.1) {
      report.recommendations.push('High number of disposable emails detected - review acquisition sources');
    }
    
    if (report.summary.quality.risky > emails.length * 0.2) {
      report.recommendations.push('High percentage of risky emails - consider list hygiene practices');
    }
    
    if (report.summary.quality.high < emails.length * 0.5) {
      report.recommendations.push('Low percentage of high-quality emails - review targeting strategies');
    }
    
    res.json({
      success: true,
      data: report
    });
    
  } catch (error) {
    logger.error('Report generation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/docs
 * @desc API documentation
 * @access Public
 */
router.get('/docs', (req, res) => {
  res.json({
    title: 'SMTP EVA - Email Verification API',
    version: '1.0.0',
    description: 'Advanced email verification system with comprehensive validation features',
    endpoints: {
      'POST /api/email/verify': {
        description: 'Verify a single email address',
        parameters: {
          email: 'string (required) - Email address to verify',
          checkDNS: 'boolean (optional) - Enable DNS validation',
          checkMX: 'boolean (optional) - Enable MX record validation',
          checkSMTP: 'boolean (optional) - Enable SMTP validation',
          checkCatchAll: 'boolean (optional) - Enable catch-all detection'
        }
      },
      'POST /api/email/verify/batch': {
        description: 'Verify multiple email addresses',
        parameters: {
          emails: 'array (required) - Array of email addresses (max 1000)',
          checkDNS: 'boolean (optional) - Enable DNS validation',
          checkMX: 'boolean (optional) - Enable MX record validation',
          checkSMTP: 'boolean (optional) - Enable SMTP validation',
          checkCatchAll: 'boolean (optional) - Enable catch-all detection',
          maxConcurrent: 'number (optional) - Max concurrent validations (1-50)'
        }
      },
      'GET /api/email/syntax/:email': {
        description: 'Check email syntax according to RFC standards'
      },
      'GET /api/email/dns/:domain': {
        description: 'Check DNS and MX records for domain'
      },
      'GET /api/email/disposable/:domain': {
        description: 'Check if domain is a disposable email provider'
      },
      'GET /api/email/role/:localpart': {
        description: 'Check if local part is a role account'
      },
      'GET /api/email/free/:domain': {
        description: 'Check if domain is a free email provider'
      },
      'GET /api/email/spamtrap/:email': {
        description: 'Check if email is a potential spam trap'
      },
      'POST /api/email/report': {
        description: 'Generate comprehensive email list analysis report',
        parameters: {
          emails: 'array (required) - Array of email addresses (max 5000)'
        }
      }
    },
    features: [
      'RFC-compliant syntax validation (RFC 1123, 2821, 2822, 3490, 3696, 4291, 5321, 5322, 5336)',
      'DNS and MX record validation',
      'SMTP mailbox verification',
      'International domain support (Unicode/Punycode)',
      'Disposable email detection',
      'Role account detection', 
      'Free email provider detection',
      'Spam trap detection',
      'Catch-all detection',
      'Yahoo-specific verification',
      'Comprehensive reporting'
    ],
    rateLimit: {
      window: '15 minutes',
      maxRequests: 100
    }
  });
});

/**
 * @route GET /api/email/stats
 * @desc Get system statistics
 * @access Public
 */
router.get('/stats', (req, res) => {
  try {
    const stats = {
      disposableProviders: emailVerificationService.disposableEmailDetector.getAllDisposableDomains().length,
      freeProviders: emailVerificationService.freeEmailDetector.getAllProviders().length,
      roleAccounts: emailVerificationService.roleAccountDetector.getAllRoleAccounts().length,
      spamTrapDomains: emailVerificationService.spamTrapDetector.getAllSpamTrapDomains().length,
      systemInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      }
    };
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Stats retrieval failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

module.exports = router; 