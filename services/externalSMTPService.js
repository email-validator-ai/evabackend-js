const axios = require('axios');
const logger = require('../utils/logger');

class ExternalSMTPService {
  constructor() {
    this.smtpServerUrl = process.env.SMTP_SERVER_URL || 'http://localhost:3001';
    this.apiKey = process.env.SMTP_API_KEY || process.env.API_KEY;
    this.timeout = parseInt(process.env.EXTERNAL_SMTP_TIMEOUT) || 30000;
    this.retryAttempts = parseInt(process.env.EXTERNAL_SMTP_RETRIES) || 2;
    
    // Configure axios instance
    this.axiosInstance = axios.create({
      baseURL: this.smtpServerUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
        'User-Agent': 'SMTP-EVA-AWS-Client/1.0.0'
      }
    });

    // Request/Response interceptors for logging
    this.axiosInstance.interceptors.request.use(
      (config) => {
        logger.debug(`Making request to SMTP server: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        logger.error('Request interceptor error:', error);
        return Promise.reject(error);
      }
    );

    this.axiosInstance.interceptors.response.use(
      (response) => {
        logger.debug(`SMTP server response: ${response.status} for ${response.config.url}`);
        return response;
      },
      (error) => {
        logger.error(`SMTP server error: ${error.response?.status} ${error.response?.statusText}`, {
          url: error.config?.url,
          method: error.config?.method,
          data: error.response?.data
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Validate single email via external SMTP server
   * @param {string} email - Email to validate
   * @param {Array} mxRecords - MX records for the domain
   * @param {Object} options - Validation options
   * @returns {Object} SMTP validation result
   */
  async validateEmail(email, mxRecords, options = {}) {
    if (!this.apiKey) {
      throw new Error('SMTP_API_KEY not configured for external SMTP server communication');
    }

    const payload = {
      email,
      mxRecords,
      options
    };

    let lastError;
    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        logger.info(`Sending SMTP verification request for ${email} to external server (attempt ${attempt + 1})`);
        
        const response = await this.axiosInstance.post('/api/smtp/verify', payload);
        
        if (response.data && response.data.success) {
          logger.info(`SMTP verification successful for ${email}`);
          return response.data.data.smtp;
        } else {
          throw new Error(`Invalid response format from SMTP server: ${JSON.stringify(response.data)}`);
        }

      } catch (error) {
        lastError = error;
        
        if (this.isRetryableError(error) && attempt < this.retryAttempts) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 5000);
          logger.warn(`SMTP server request failed, retrying in ${delay}ms:`, error.message);
          await this.delay(delay);
          continue;
        } else {
          logger.error(`SMTP verification failed for ${email} after ${attempt + 1} attempts:`, error.message);
          break;
        }
      }
    }

    // Return error result if all attempts failed
    return this.createErrorResult(email, lastError);
  }

  /**
   * Validate multiple emails via external SMTP server
   * @param {Array} verifications - Array of {email, mxRecords} objects
   * @param {Object} options - Validation options
   * @returns {Object} Batch validation result
   */
  async validateEmailBatch(verifications, options = {}) {
    if (!this.apiKey) {
      throw new Error('SMTP_API_KEY not configured for external SMTP server communication');
    }

    if (!verifications || verifications.length === 0) {
      return {
        summary: { total: 0, valid: 0, deliverable: 0 },
        results: []
      };
    }

    const payload = {
      verifications,
      options
    };

    let lastError;
    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        logger.info(`Sending batch SMTP verification request for ${verifications.length} emails to external server (attempt ${attempt + 1})`);
        
        const response = await this.axiosInstance.post('/api/smtp/verify/batch', payload);
        
        if (response.data && response.data.success) {
          logger.info(`Batch SMTP verification successful for ${verifications.length} emails`);
          return response.data.data;
        } else {
          throw new Error(`Invalid response format from SMTP server: ${JSON.stringify(response.data)}`);
        }

      } catch (error) {
        lastError = error;
        
        if (this.isRetryableError(error) && attempt < this.retryAttempts) {
          const delay = Math.min(2000 * Math.pow(2, attempt), 10000);
          logger.warn(`SMTP server batch request failed, retrying in ${delay}ms:`, error.message);
          await this.delay(delay);
          continue;
        } else {
          logger.error(`Batch SMTP verification failed after ${attempt + 1} attempts:`, error.message);
          break;
        }
      }
    }

    // Return error results for all emails if batch failed
    const errorResults = verifications.map(v => ({
      email: v.email,
      smtp: this.createErrorResult(v.email, lastError)
    }));

    return {
      summary: {
        total: verifications.length,
        valid: 0,
        deliverable: 0,
        errors: verifications.length
      },
      results: errorResults
    };
  }

  /**
   * Detect catch-all configuration via external SMTP server
   * @param {string} domain - Domain to test
   * @param {Array} mxRecords - MX records for the domain
   * @param {Object} options - Detection options
   * @returns {Object} Catch-all detection result
   */
  async detectCatchAll(domain, mxRecords, options = {}) {
    if (!this.apiKey) {
      throw new Error('SMTP_API_KEY not configured for external SMTP server communication');
    }

    const payload = {
      domain,
      mxRecords,
      options
    };

    let lastError;
    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        logger.info(`Sending catch-all detection request for ${domain} to external server (attempt ${attempt + 1})`);
        
        const response = await this.axiosInstance.post('/api/smtp/catchall', payload);
        
        if (response.data && response.data.success) {
          logger.info(`Catch-all detection successful for ${domain}`);
          return response.data.data.catchAll;
        } else {
          throw new Error(`Invalid response format from SMTP server: ${JSON.stringify(response.data)}`);
        }

      } catch (error) {
        lastError = error;
        
        if (this.isRetryableError(error) && attempt < this.retryAttempts) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 5000);
          logger.warn(`SMTP server catch-all request failed, retrying in ${delay}ms:`, error.message);
          await this.delay(delay);
          continue;
        } else {
          logger.error(`Catch-all detection failed for ${domain} after ${attempt + 1} attempts:`, error.message);
          break;
        }
      }
    }

    // Return error result if all attempts failed
    return {
      isCatchAll: false,
      confidence: 0,
      testResults: [],
      errors: [`External SMTP server communication failed: ${lastError?.message || 'Unknown error'}`],
      warnings: []
    };
  }

  /**
   * Check external SMTP server status
   * @returns {Object} Server status
   */
  async checkServerStatus() {
    try {
      const response = await this.axiosInstance.get('/api/smtp/status');
      
      if (response.data && response.data.success) {
        return {
          available: true,
          status: response.data.data,
          responseTime: response.headers['x-response-time'] || 'unknown'
        };
      } else {
        return {
          available: false,
          error: 'Invalid response format',
          response: response.data
        };
      }

    } catch (error) {
      logger.error('Failed to check SMTP server status:', error.message);
      return {
        available: false,
        error: error.message,
        details: error.response?.data || null
      };
    }
  }

  /**
   * Check if error is retryable
   * @param {Error} error - Error to check
   * @returns {boolean} Whether error is retryable
   */
  isRetryableError(error) {
    if (!error) return false;

    // Network errors
    if (error.code === 'ECONNABORTED' || error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
      return true;
    }

    // HTTP status codes that should be retried
    if (error.response) {
      const status = error.response.status;
      return status === 408 || status === 429 || status >= 500;
    }

    return false;
  }

  /**
   * Create error result for failed SMTP validation
   * @param {string} email - Email that failed
   * @param {Error} error - Error that occurred
   * @returns {Object} Error result
   */
  createErrorResult(email, error) {
    return {
      isValid: false,
      isDeliverable: false,
      smtpResponse: '',
      responseCode: null,
      errors: [`External SMTP server error: ${error?.message || 'Unknown error'}`],
      warnings: ['SMTP validation could not be completed due to server communication issues'],
      testedMX: null,
      connectionStatus: 'external_server_failed',
      retryCount: this.retryAttempts,
      graylisted: false
    };
  }

  /**
   * Delay execution for specified milliseconds
   * @param {number} ms - Milliseconds to delay
   * @returns {Promise} Promise that resolves after delay
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get configuration info
   * @returns {Object} Configuration details
   */
  getConfig() {
    return {
      smtpServerUrl: this.smtpServerUrl,
      hasApiKey: !!this.apiKey,
      timeout: this.timeout,
      retryAttempts: this.retryAttempts
    };
  }
}

module.exports = ExternalSMTPService; 