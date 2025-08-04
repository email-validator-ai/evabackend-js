const express = require('express');
const router = express.Router();
const Joi = require('joi');
const EmailVerificationService = require('../services/emailVerificationService');
const logger = require('../utils/logger');
const multer = require('multer');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Worker } = require('worker_threads');
const stream = require('stream');

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

/**
 * @route POST /api/email/validate-csv
 * @desc Upload and validate CSV file with parallel processing
 * @access Public
 */

// Configure multer for CSV file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 200 * 1024 * 1024 // 200MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV files are allowed'));
    }
  }
});

router.post('/validate-csv', upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No CSV file uploaded'
      });
    }

    logger.info(`Processing CSV file: ${req.file.originalname}, Size: ${req.file.size} bytes`);

    // Parse CSV from buffer
    const csvData = [];
    const csvStream = new stream.Readable();
    csvStream.push(req.file.buffer);
    csvStream.push(null);

    await new Promise((resolve, reject) => {
      csvStream
        .pipe(csv())
        .on('data', (row) => {
          csvData.push(row);
        })
        .on('end', resolve)
        .on('error', reject);
    });

    if (csvData.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'CSV file is empty or invalid'
      });
    }

    logger.info(`Parsed ${csvData.length} rows from CSV`);

    // Check if Email column exists
    const firstRow = csvData[0];
    if (!firstRow.hasOwnProperty('Email')) {
      return res.status(400).json({
        success: false,
        error: 'CSV must contain an "Email" column'
      });
    }

    // Create temporary directory for output files
    const tempDir = path.join(os.tmpdir(), 'email-validation-' + Date.now());
    fs.mkdirSync(tempDir, { recursive: true });

    // Get original columns from the first row
    const originalColumns = Object.keys(firstRow);
    
    // Create CSV file paths
    const validCsvPath = path.join(tempDir, 'valid_emails.csv');
    const invalidCsvPath = path.join(tempDir, 'invalid_emails.csv');
    const progressPath = path.join(tempDir, 'progress.json');

    // Initialize CSV writers with headers
    const validCsvWriter = createCsvWriter({
      path: validCsvPath,
      header: originalColumns.map(col => ({ id: col, title: col }))
    });

    const invalidColumns = [...originalColumns, 'Rejection_Reasons'];
    const invalidCsvWriter = createCsvWriter({
      path: invalidCsvPath,
      header: invalidColumns.map(col => ({ id: col, title: col }))
    });

    // Write headers immediately
    await validCsvWriter.writeRecords([]);
    await invalidCsvWriter.writeRecords([]);

    // Initialize counters and progress tracking
    let validCount = 0;
    let invalidCount = 0;
    let processedCount = 0;
    const totalCount = csvData.length;
    const batchSize = 50; // Save progress every 50 emails
    const startTime = Date.now();

    logger.info(`Starting sequential processing of ${totalCount} emails`);

    // Send immediate response with tempId so user can monitor progress
    res.json({
      success: true,
      message: 'CSV validation started',
      summary: {
        totalToProcess: totalCount,
        status: 'processing'
      },
      downloadLinks: {
        validEmails: `/api/email/download/${path.basename(tempDir)}/valid_emails.csv`,
        invalidEmails: `/api/email/download/${path.basename(tempDir)}/invalid_emails.csv`,
        progress: `/api/email/download/${path.basename(tempDir)}/progress.json`
      },
      progressEndpoint: `/api/email/progress/${path.basename(tempDir)}`,
      tempId: path.basename(tempDir)
    });

    // Process emails asynchronously after sending response
    setImmediate(async () => {
      try {
        // Process emails sequentially
        for (let i = 0; i < csvData.length; i++) {
          try {
            const emailData = csvData[i];
            const email = emailData.Email;
            
            if (!email || typeof email !== 'string') {
              // Invalid email format - add to invalid file immediately
              const invalidRecord = {};
              originalColumns.forEach(col => {
                invalidRecord[col] = emailData[col] || '';
              });
              invalidRecord.Rejection_Reasons = 'Missing or invalid email format';
              
              await invalidCsvWriter.writeRecords([invalidRecord]);
              invalidCount++;
            } else {
              // Perform validation (excluding SMTP)
              const validationResult = await emailVerificationService.verifyEmail(email, {
                checkDNS: true,
                checkMX: true,
                checkSMTP: false, // Exclude SMTP as requested
                checkCatchAll: true
              });

              // Extract validation reasons from the result
              const reasons = [];
              if (!validationResult.isValid) {
                if (validationResult.errors && validationResult.errors.length > 0) {
                  reasons.push(...validationResult.errors);
                }
                if (validationResult.checks) {
                  // Check syntax validation
                  if (validationResult.checks.syntax && !validationResult.checks.syntax.isValid) {
                    reasons.push('Invalid email syntax');
                  }
                  // Check DNS validation
                  if (validationResult.checks.dns && !validationResult.checks.dns.isValid) {
                    reasons.push('Domain does not exist');
                  }
                  // Check MX validation
                  if (validationResult.checks.mx && !validationResult.checks.mx.isValid) {
                    reasons.push('No mail servers found for domain');
                  }
                  // Check disposable email
                  if (validationResult.checks.disposable && validationResult.checks.disposable.isDisposable) {
                    reasons.push('Disposable/temporary email address');
                  }
                  // Check role account
                  if (validationResult.checks.role && validationResult.checks.role.isRole) {
                    reasons.push('Role-based email address');
                  }
                }
                if (reasons.length === 0) {
                  reasons.push('Email validation failed');
                }
              }

              // Prepare record with original columns
              const record = {};
              originalColumns.forEach(col => {
                record[col] = emailData[col] || '';
              });

              if (validationResult.isValid) {
                // Write to valid file immediately
                await validCsvWriter.writeRecords([record]);
                validCount++;
              } else {
                // Write to invalid file with reasons immediately
                record.Rejection_Reasons = reasons.join('; ');
                await invalidCsvWriter.writeRecords([record]);
                invalidCount++;
              }
            }

            processedCount++;

            // Log progress and save progress file every batch
            if (processedCount % batchSize === 0 || processedCount === totalCount) {
              const progress = {
                processedCount,
                totalCount,
                validCount,
                invalidCount,
                percentage: ((processedCount / totalCount) * 100).toFixed(2),
                elapsedTime: Date.now() - startTime,
                estimatedTimeRemaining: processedCount > 0 ? 
                  Math.round(((Date.now() - startTime) / processedCount) * (totalCount - processedCount)) : 0,
                lastUpdated: new Date().toISOString()
              };

              // Save progress to file
              fs.writeFileSync(progressPath, JSON.stringify(progress, null, 2));
              
              logger.info(`Progress: ${processedCount}/${totalCount} (${progress.percentage}%) - Valid: ${validCount}, Invalid: ${invalidCount}`);
            }

          } catch (error) {
            // Handle individual email processing errors
            logger.error(`Error processing email ${i + 1}:`, error);
            
            const emailData = csvData[i];
            const invalidRecord = {};
            originalColumns.forEach(col => {
              invalidRecord[col] = emailData[col] || '';
            });
            invalidRecord.Rejection_Reasons = `Processing error: ${error.message}`;
            
            await invalidCsvWriter.writeRecords([invalidRecord]);
            invalidCount++;
            processedCount++;
          }
        }

        logger.info(`Sequential processing complete: ${validCount} valid, ${invalidCount} invalid`);

        // Final progress update
        const finalProgress = {
          processedCount: totalCount,
          totalCount,
          validCount,
          invalidCount,
          percentage: 100,
          elapsedTime: Date.now() - startTime,
          completed: true,
          completedAt: new Date().toISOString()
        };
        fs.writeFileSync(progressPath, JSON.stringify(finalProgress, null, 2));
        
        logger.info(`CSV validation completed: ${validCount} valid, ${invalidCount} invalid emails`);
        
      } catch (error) {
        logger.error('Background processing failed:', error);
        
        // Update progress with error status
        const errorProgress = {
          processedCount,
          totalCount,
          validCount,
          invalidCount,
          percentage: ((processedCount / totalCount) * 100).toFixed(2),
          elapsedTime: Date.now() - startTime,
          error: true,
          errorMessage: error.message,
          lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(progressPath, JSON.stringify(errorProgress, null, 2));
      }
    });

    // Clean up temp files after 1 hour
    setTimeout(() => {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
        logger.info(`Cleaned up temporary files: ${tempDir}`);
      } catch (error) {
        logger.error('Error cleaning up temp files:', error);
      }
    }, 60 * 60 * 1000); // 1 hour

  } catch (error) {
    logger.error('CSV validation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/download/:tempId/:filename
 * @desc Download processed CSV files
 * @access Public
 */
router.get('/download/:tempId/:filename', (req, res) => {
  try {
    const { tempId, filename } = req.params;
    const filePath = path.join(os.tmpdir(), tempId, filename);

    // Validate file exists and is safe
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found or expired'
      });
    }

    // Validate filename to prevent directory traversal
    if (!['valid_emails.csv', 'invalid_emails.csv', 'progress.json'].includes(filename)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename'
      });
    }

    // Set appropriate headers based on file type
    if (filename.endsWith('.json')) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    } else {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    }
    
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

    fileStream.on('error', (error) => {
      logger.error('Error streaming file:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          error: 'Error downloading file'
        });
      }
    });

  } catch (error) {
    logger.error('Download failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route GET /api/email/progress/:tempId
 * @desc Get real-time progress of CSV processing
 * @access Public
 */
router.get('/progress/:tempId', (req, res) => {
  try {
    const { tempId } = req.params;
    const progressPath = path.join(os.tmpdir(), tempId, 'progress.json');

    // Check if progress file exists
    if (!fs.existsSync(progressPath)) {
      return res.status(404).json({
        success: false,
        error: 'Progress file not found or processing not started'
      });
    }

    // Read and return progress data
    const progressData = JSON.parse(fs.readFileSync(progressPath, 'utf8'));
    
    res.json({
      success: true,
      data: progressData
    });

  } catch (error) {
    logger.error('Error reading progress:', error);
    res.status(500).json({
      success: false,
      error: 'Error reading progress data',
      message: error.message
    });
  }
});

module.exports = router; 