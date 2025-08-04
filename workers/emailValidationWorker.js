const { parentPort, workerData } = require('worker_threads');
const EmailVerificationService = require('../services/emailVerificationService');

// Initialize email verification service
const emailVerificationService = new EmailVerificationService();

async function validateEmailBatch(emails) {
  const results = [];
  
  for (const emailData of emails) {
    try {
      const email = emailData.Email;
      
      if (!email || typeof email !== 'string') {
        results.push({
          ...emailData,
          isValid: false,
          reasons: ['Missing or invalid email format']
        });
        continue;
      }

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

      results.push({
        ...emailData,
        isValid: validationResult.isValid,
        reasons: reasons
      });

    } catch (error) {
      results.push({
        ...emailData,
        isValid: false,
        reasons: [`Validation error: ${error.message}`]
      });
    }
  }
  
  return results;
}

// Process the batch when worker receives data
if (workerData && workerData.emails) {
  validateEmailBatch(workerData.emails)
    .then(results => {
      parentPort.postMessage({ success: true, results });
    })
    .catch(error => {
      parentPort.postMessage({ success: false, error: error.message });
    });
}
