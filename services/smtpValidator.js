const net = require('net');
const logger = require('../utils/logger');

class SMTPValidator {
  constructor() {
    this.timeout = parseInt(process.env.SMTP_TIMEOUT) || 10000;
    this.connectionTimeout = parseInt(process.env.SMTP_CONNECTION_TIMEOUT) || 5000;
  }

  /**
   * Validate mailbox existence via SMTP
   * @param {string} email - Email to validate
   * @param {Array} mxRecords - MX records for the domain
   * @returns {Object} SMTP validation result
   */
  async validateMailbox(email, mxRecords) {
    const result = {
      isValid: false,
      isDeliverable: false,
      smtpResponse: '',
      responseCode: null,
      errors: [],
      warnings: [],
      testedMX: null,
      connectionStatus: 'failed'
    };

    if (!mxRecords || mxRecords.length === 0) {
      result.errors.push('No MX records provided');
      return result;
    }

    // Try each MX record in priority order
    for (const mx of mxRecords) {
      try {
        logger.info(`Testing SMTP connection to ${mx.exchange} for ${email}`);
        const testResult = await this.testSMTPConnection(email, mx.exchange);
        
        if (testResult.success) {
          result.isValid = testResult.isValid;
          result.isDeliverable = testResult.isDeliverable;
          result.smtpResponse = testResult.response;
          result.responseCode = testResult.responseCode;
          result.testedMX = mx.exchange;
          result.connectionStatus = 'success';
          
          if (testResult.warnings) {
            result.warnings.push(...testResult.warnings);
          }
          
          return result;
        } else {
          result.warnings.push(`Failed to connect to ${mx.exchange}: ${testResult.error}`);
        }
      } catch (error) {
        result.warnings.push(`Error testing ${mx.exchange}: ${error.message}`);
        logger.warn(`SMTP test failed for ${mx.exchange}:`, error);
      }
    }

    result.errors.push('Could not establish SMTP connection to any MX server');
    return result;
  }

  /**
   * Test SMTP connection to specific server
   * @param {string} email - Email to test
   * @param {string} mxHost - MX server hostname
   * @returns {Object} Connection test result
   */
  async testSMTPConnection(email, mxHost) {
    return new Promise((resolve) => {
      const result = {
        success: false,
        isValid: false,
        isDeliverable: false,
        response: '',
        responseCode: null,
        error: null,
        warnings: []
      };

      const socket = new net.Socket();
      let step = 'connecting';
      let responseBuffer = '';

      // Set timeouts
      socket.setTimeout(this.timeout);
      
      const cleanup = () => {
        try {
          if (!socket.destroyed) {
            socket.destroy();
          }
        } catch (error) {
          // Ignore cleanup errors
        }
      };

      const handleResponse = (data) => {
        responseBuffer += data.toString();
        const lines = responseBuffer.split('\r\n');
        
        for (let i = 0; i < lines.length - 1; i++) {
          const line = lines[i];
          if (!line) continue;

          const code = parseInt(line.substring(0, 3));
          const message = line.substring(4);

          logger.debug(`SMTP ${step}: ${code} ${message}`);

          switch (step) {
            case 'connecting':
              if (code === 220) {
                step = 'helo';
                socket.write('HELO smtp-eva.local\r\n');
              } else {
                result.error = `Unexpected greeting: ${line}`;
                cleanup();
                resolve(result);
                return;
              }
              break;

            case 'helo':
              if (code === 250) {
                step = 'mail_from';
                socket.write('MAIL FROM:<test@smtp-eva.local>\r\n');
              } else {
                result.error = `HELO failed: ${line}`;
                cleanup();
                resolve(result);
                return;
              }
              break;

            case 'mail_from':
              if (code === 250) {
                step = 'rcpt_to';
                socket.write(`RCPT TO:<${email}>\r\n`);
              } else {
                result.error = `MAIL FROM failed: ${line}`;
                cleanup();
                resolve(result);
                return;
              }
              break;

            case 'rcpt_to':
              result.success = true;
              result.response = line;
              result.responseCode = code;

              if (code === 250) {
                result.isValid = true;
                result.isDeliverable = true;
              } else if (code === 251 || code === 252) {
                result.isValid = true;
                result.isDeliverable = false;
                result.warnings.push('Mailbox validation uncertain (forwarding or verification disabled)');
              } else if (code >= 400 && code < 500) {
                result.isValid = false;
                result.isDeliverable = false;
                if (code === 450 || code === 451 || code === 452) {
                  result.warnings.push('Temporary failure - mailbox might be valid');
                }
              } else if (code >= 500) {
                result.isValid = false;
                result.isDeliverable = false;
              }

              // Send QUIT to be polite
              socket.write('QUIT\r\n');
              step = 'quit';
              break;

            case 'quit':
              cleanup();
              resolve(result);
              return;
          }
        }

        // Keep the last incomplete line
        responseBuffer = lines[lines.length - 1];
      };

      socket.on('connect', () => {
        logger.debug(`Connected to ${mxHost}:25`);
      });

      socket.on('data', handleResponse);

      socket.on('error', (error) => {
        result.error = error.message;
        cleanup();
        resolve(result);
      });

      socket.on('timeout', () => {
        result.error = 'Connection timeout';
        cleanup();
        resolve(result);
      });

      socket.on('close', () => {
        if (step !== 'quit' && !result.success) {
          result.error = 'Connection closed unexpectedly';
        }
        resolve(result);
      });

      // Connect to MX server on port 25
      try {
        socket.connect(25, mxHost);
      } catch (error) {
        result.error = `Connection failed: ${error.message}`;
        resolve(result);
      }
    });
  }

  /**
   * Detect catch-all configuration
   * @param {string} domain - Domain to test
   * @param {Array} mxRecords - MX records for the domain
   * @returns {Object} Catch-all detection result
   */
  async detectCatchAll(domain, mxRecords) {
    const result = {
      isCatchAll: false,
      confidence: 0,
      testResults: [],
      errors: [],
      warnings: []
    };

    if (!mxRecords || mxRecords.length === 0) {
      result.errors.push('No MX records provided');
      return result;
    }

    // Generate random test emails
    const testEmails = [
      `test-${this.generateRandomString(8)}@${domain}`,
      `nonexistent-${this.generateRandomString(10)}@${domain}`,
      `fake-${this.generateRandomString(6)}@${domain}`,
      `random-${Date.now()}@${domain}`
    ];

    let acceptedCount = 0;
    
    for (const testEmail of testEmails) {
      try {
        const testResult = await this.validateMailbox(testEmail, mxRecords);
        result.testResults.push({
          email: testEmail,
          accepted: testResult.isValid,
          response: testResult.smtpResponse
        });

        if (testResult.isValid) {
          acceptedCount++;
        }
      } catch (error) {
        result.warnings.push(`Failed to test ${testEmail}: ${error.message}`);
      }

      // Add delay between tests to be respectful
      await this.delay(1000);
    }

    // Calculate confidence
    const acceptanceRate = acceptedCount / testEmails.length;
    
    if (acceptanceRate >= 0.75) {
      result.isCatchAll = true;
      result.confidence = Math.min(100, acceptanceRate * 100);
    } else if (acceptanceRate >= 0.5) {
      result.isCatchAll = true;
      result.confidence = acceptanceRate * 80;
      result.warnings.push('Possible catch-all configuration detected');
    } else {
      result.confidence = acceptanceRate * 30;
    }

    return result;
  }

  /**
   * Advanced SMTP validation with retry logic
   * @param {string} email - Email to validate
   * @param {Array} mxRecords - MX records
   * @param {Object} options - Validation options
   * @returns {Object} Enhanced validation result
   */
  async validateMailboxAdvanced(email, mxRecords, options = {}) {
    const maxRetries = options.maxRetries || 3;
    const retryDelay = options.retryDelay || 2000;
    
    let lastResult = null;
    let attempts = 0;

    while (attempts < maxRetries) {
      attempts++;
      
      try {
        const result = await this.validateMailbox(email, mxRecords);
        
        // If successful or definitively failed, return result
        if (result.isValid || result.responseCode >= 500) {
          return result;
        }
        
        // If temporary failure, retry
        if (result.responseCode >= 400 && result.responseCode < 500) {
          lastResult = result;
          if (attempts < maxRetries) {
            logger.info(`Retrying SMTP validation for ${email} (attempt ${attempts + 1}/${maxRetries})`);
            await this.delay(retryDelay);
            continue;
          }
        }
        
        return result;
        
      } catch (error) {
        logger.warn(`SMTP validation attempt ${attempts} failed for ${email}:`, error);
        
        if (attempts < maxRetries) {
          await this.delay(retryDelay);
          continue;
        }
        
        return {
          isValid: false,
          isDeliverable: false,
          error: `All ${maxRetries} attempts failed: ${error.message}`,
          attempts: attempts
        };
      }
    }

    return lastResult || {
      isValid: false,
      isDeliverable: false,
      error: `Maximum retries (${maxRetries}) exceeded`,
      attempts: attempts
    };
  }

  /**
   * Check for graylisting
   * @param {string} email - Email to test
   * @param {Array} mxRecords - MX records
   * @returns {Object} Graylisting detection result
   */
  async detectGraylisting(email, mxRecords) {
    const result = {
      isGraylisted: false,
      confidence: 0,
      indicators: [],
      recommendRetry: false
    };

    try {
      const testResult = await this.validateMailbox(email, mxRecords);
      
      // Common graylisting response codes and messages
      const graylistingIndicators = [
        { code: 450, message: 'greylisted' },
        { code: 451, message: 'please try again later' },
        { code: 452, message: 'try again' },
        { code: 421, message: 'service not available' }
      ];

      for (const indicator of graylistingIndicators) {
        if (testResult.responseCode === indicator.code && 
            testResult.smtpResponse.toLowerCase().includes(indicator.message)) {
          result.isGraylisted = true;
          result.confidence += 30;
          result.indicators.push(`Response code ${indicator.code} with message containing "${indicator.message}"`);
        }
      }

      // Check for temporary delays
      if (testResult.responseCode >= 400 && testResult.responseCode < 500) {
        result.confidence += 20;
        result.recommendRetry = true;
        result.indicators.push('Temporary failure response code');
      }

      result.isGraylisted = result.confidence >= 50;
      
      return result;

    } catch (error) {
      logger.error('Graylisting detection failed:', error);
      return result;
    }
  }

  /**
   * Generate random string
   * @param {number} length - String length
   * @returns {string} Random string
   */
  generateRandomString(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Delay function
   * @param {number} ms - Milliseconds to delay
   * @returns {Promise} Delay promise
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = SMTPValidator; 