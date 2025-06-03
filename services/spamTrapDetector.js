const logger = require('../utils/logger');

class SpamTrapDetector {
  constructor() {
    // Known spam trap domains and patterns
    this.spamTrapDomains = new Set([
      // Known spam trap providers
      'spamtrap.com', 'spamtrap.net', 'spamtrap.org',
      'honeypot.com', 'honeypot.net', 'honeypot.org',
      'trap.com', 'trap.net', 'spamcop.net',
      'knujon.com', 'abuseat.org',
      
      // Common spam trap patterns
      'invalid.com', 'invalid.net', 'invalid.org',
      'blackhole.com', 'blackhole.net', 'devnull.com',
      'bitbucket.com', 'example.com', 'example.net', 'example.org',
      'test.com', 'test.net', 'test.org',
      
      // ISP spam traps (be very careful with these)
      'spamtrap.abuseat.org', 'spamtrap.cesmail.net'
    ]);

    // Patterns that might indicate spam traps
    this.spamTrapPatterns = [
      /^spam.*trap.*$/i,
      /^honey.*pot.*$/i,
      /^black.*hole.*$/i,
      /^dev.*null.*$/i,
      /^invalid.*$/i,
      /^fake.*$/i,
      /^test.*email.*$/i,
      /^no.*reply.*trap.*$/i,
      /^abuse.*trap.*$/i,
      /^compliance.*trap.*$/i
    ];

    // Suspicious email patterns that might indicate traps
    this.suspiciousPatterns = [
      /^[a-z]{20,}@/i,           // Very long random strings
      /^[0-9]{10,}@/i,           // Long numeric strings
      /^test[0-9]+@/i,           // test + numbers
      /^spam[0-9]+@/i,           // spam + numbers
      /^fake[0-9]+@/i,           // fake + numbers
      /^invalid[0-9]*@/i,        // invalid + optional numbers
      /^[a-f0-9]{32}@/i,         // MD5-like strings
      /^[a-f0-9]{40}@/i,         // SHA1-like strings
      /^[a-f0-9]{64}@/i,         // SHA256-like strings
      /^abuse.*@/i,              // abuse addresses
      /^postmaster.*@/i,         // postmaster variations
      /^.*noreply.*@/i,          // noreply variations
      /^.*no-reply.*@/i,         // no-reply variations
      /^.*donotreply.*@/i,       // donotreply variations
      /^.*unsubscribe.*@/i,      // unsubscribe traps
      /^.*compliance.*@/i,       // compliance traps
      /^.*legal.*@/i,            // legal traps
      /^.*security.*@/i          // security traps
    ];

    // AI-based indicators (for future ML implementation)
    this.aiFeatures = {
      commonWords: ['spam', 'trap', 'honey', 'pot', 'fake', 'test', 'invalid', 'abuse'],
      suspiciousPatterns: ['random-looking-strings', 'unusual-lengths', 'numeric-only'],
      behavioralIndicators: ['never-engaged', 'instant-complaints', 'impossible-signup-speed']
    };
  }

  /**
   * Check if email is a spam trap
   * @param {string} email - Email to check
   * @returns {Object} Spam trap detection result
   */
  async isSpamTrap(email) {
    const result = {
      isSpamTrap: false,
      confidence: 0,
      riskLevel: 'low',
      category: null,
      indicators: [],
      warnings: []
    };

    if (!email || typeof email !== 'string') {
      return result;
    }

    try {
      const normalizedEmail = email.toLowerCase().trim();
      const [localPart, domain] = normalizedEmail.split('@');

      if (!localPart || !domain) {
        return result;
      }

      // 1. Check against known spam trap domains
      const domainCheck = this.checkKnownSpamTrapDomains(domain);
      if (domainCheck.isSpamTrap) {
        result.isSpamTrap = true;
        result.confidence = domainCheck.confidence;
        result.riskLevel = 'high';
        result.category = 'known_domain';
        result.indicators = domainCheck.indicators;
        return result;
      }

      // 2. Check domain patterns
      const domainPatternCheck = this.checkDomainPatterns(domain);
      if (domainPatternCheck.suspicious) {
        result.confidence += domainPatternCheck.confidence;
        result.indicators.push(...domainPatternCheck.indicators);
      }

      // 3. Check email patterns
      const emailPatternCheck = this.checkEmailPatterns(normalizedEmail, localPart);
      if (emailPatternCheck.suspicious) {
        result.confidence += emailPatternCheck.confidence;
        result.indicators.push(...emailPatternCheck.indicators);
      }

      // 4. Check for suspicious characteristics
      const characteristicsCheck = this.checkSuspiciousCharacteristics(localPart, domain);
      if (characteristicsCheck.suspicious) {
        result.confidence += characteristicsCheck.confidence;
        result.indicators.push(...characteristicsCheck.indicators);
      }

      // 5. Check external sources (if available)
      if (process.env.SPAM_DETECTION_API_KEY) {
        try {
          const externalCheck = await this.checkExternalSources(normalizedEmail);
          if (externalCheck.isSpamTrap) {
            result.confidence = Math.max(result.confidence, externalCheck.confidence);
            result.indicators.push(...externalCheck.indicators);
          }
        } catch (error) {
          logger.warn('External spam trap check failed:', error);
        }
      }

      // 6. AI-based detection (placeholder for future implementation)
      const aiCheck = await this.aiBasedDetection(normalizedEmail, localPart, domain);
      if (aiCheck.suspicious) {
        result.confidence += aiCheck.confidence;
        result.indicators.push(...aiCheck.indicators);
      }

      // Determine final result
      result.confidence = Math.min(100, result.confidence);
      
      if (result.confidence >= 80) {
        result.isSpamTrap = true;
        result.riskLevel = 'high';
        result.category = 'high_confidence';
      } else if (result.confidence >= 60) {
        result.isSpamTrap = true;
        result.riskLevel = 'medium';
        result.category = 'medium_confidence';
      } else if (result.confidence >= 40) {
        result.riskLevel = 'medium';
        result.category = 'suspicious';
        result.warnings.push('Email shows suspicious characteristics');
      }

      return result;

    } catch (error) {
      logger.error('Spam trap detection failed:', error);
      result.warnings.push('Detection process failed');
      return result;
    }
  }

  /**
   * Check against known spam trap domains
   * @param {string} domain - Domain to check
   * @returns {Object} Domain check result
   */
  checkKnownSpamTrapDomains(domain) {
    const result = {
      isSpamTrap: false,
      confidence: 0,
      indicators: []
    };

    if (this.spamTrapDomains.has(domain)) {
      result.isSpamTrap = true;
      result.confidence = 100;
      result.indicators.push(`Known spam trap domain: ${domain}`);
    }

    return result;
  }

  /**
   * Check domain patterns for spam trap indicators
   * @param {string} domain - Domain to check
   * @returns {Object} Pattern check result
   */
  checkDomainPatterns(domain) {
    const result = {
      suspicious: false,
      confidence: 0,
      indicators: []
    };

    for (const pattern of this.spamTrapPatterns) {
      if (pattern.test(domain)) {
        result.suspicious = true;
        result.confidence += 40;
        result.indicators.push(`Domain matches spam trap pattern: ${pattern.source}`);
      }
    }

    // Check for suspicious domain characteristics
    if (domain.includes('spamtrap') || domain.includes('honeypot')) {
      result.suspicious = true;
      result.confidence += 50;
      result.indicators.push('Domain contains spam trap keywords');
    }

    if (domain.includes('blackhole') || domain.includes('devnull')) {
      result.suspicious = true;
      result.confidence += 45;
      result.indicators.push('Domain contains blackhole keywords');
    }

    if (domain === 'example.com' || domain === 'example.org' || domain === 'example.net') {
      result.suspicious = true;
      result.confidence += 60;
      result.indicators.push('Domain is RFC example domain');
    }

    return result;
  }

  /**
   * Check email patterns for spam trap indicators
   * @param {string} email - Full email address
   * @param {string} localPart - Local part of email
   * @returns {Object} Pattern check result
   */
  checkEmailPatterns(email, localPart) {
    const result = {
      suspicious: false,
      confidence: 0,
      indicators: []
    };

    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(email)) {
        result.suspicious = true;
        result.confidence += 25;
        result.indicators.push(`Email matches suspicious pattern: ${pattern.source}`);
      }
    }

    // Check for specific spam trap email formats
    if (localPart === 'spamtrap' || localPart === 'honeypot') {
      result.suspicious = true;
      result.confidence += 70;
      result.indicators.push('Local part is explicit spam trap');
    }

    if (localPart.startsWith('abuse') && localPart.includes('trap')) {
      result.suspicious = true;
      result.confidence += 60;
      result.indicators.push('Local part indicates abuse trap');
    }

    return result;
  }

  /**
   * Check for suspicious characteristics
   * @param {string} localPart - Local part of email
   * @param {string} domain - Domain part
   * @returns {Object} Characteristics check result
   */
  checkSuspiciousCharacteristics(localPart, domain) {
    const result = {
      suspicious: false,
      confidence: 0,
      indicators: []
    };

    // Check local part length (very long might be generated)
    if (localPart.length > 30) {
      result.suspicious = true;
      result.confidence += 15;
      result.indicators.push('Unusually long local part');
    }

    // Check for all lowercase or all numbers
    if (/^[a-z]+$/.test(localPart) && localPart.length > 15) {
      result.suspicious = true;
      result.confidence += 20;
      result.indicators.push('Long all-lowercase local part');
    }

    if (/^[0-9]+$/.test(localPart) && localPart.length > 8) {
      result.suspicious = true;
      result.confidence += 25;
      result.indicators.push('Long all-numeric local part');
    }

    // Check for random-looking strings (high entropy)
    const entropy = this.calculateEntropy(localPart);
    if (entropy > 3.5 && localPart.length > 10) {
      result.suspicious = true;
      result.confidence += 30;
      result.indicators.push('High entropy (random-looking) local part');
    }

    // Check for common spam trap keywords
    const spamKeywords = ['spam', 'trap', 'honey', 'pot', 'fake', 'test', 'invalid'];
    for (const keyword of spamKeywords) {
      if (localPart.includes(keyword)) {
        result.suspicious = true;
        result.confidence += 35;
        result.indicators.push(`Contains spam trap keyword: ${keyword}`);
      }
    }

    // Check for MD5/SHA hash-like patterns
    if (/^[a-f0-9]{32}$/.test(localPart)) {
      result.suspicious = true;
      result.confidence += 40;
      result.indicators.push('Looks like MD5 hash');
    }

    if (/^[a-f0-9]{40}$/.test(localPart)) {
      result.suspicious = true;
      result.confidence += 40;
      result.indicators.push('Looks like SHA1 hash');
    }

    // Check for common role accounts that might be traps
    const suspiciousRoles = ['abuse', 'postmaster', 'security', 'compliance', 'legal'];
    for (const role of suspiciousRoles) {
      if (localPart === role || localPart.startsWith(role)) {
        result.suspicious = true;
        result.confidence += 20;
        result.indicators.push(`Suspicious role account: ${role}`);
      }
    }

    return result;
  }

  /**
   * Calculate entropy of a string (measure of randomness)
   * @param {string} str - String to analyze
   * @returns {number} Entropy value
   */
  calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Check external sources for spam trap information
   * @param {string} email - Email to check
   * @returns {Object} External check result
   */
  async checkExternalSources(email) {
    const result = {
      isSpamTrap: false,
      confidence: 0,
      indicators: []
    };

    try {
      // Placeholder for external API integration
      // You could integrate with services like:
      // - SpamCop
      // - SURBL
      // - Custom blacklists
      // - Threat intelligence feeds

      // Example implementation:
      // const response = await axios.get(`https://api.spamdetection.com/check?email=${email}`, {
      //   headers: { 'Authorization': `Bearer ${process.env.SPAM_DETECTION_API_KEY}` }
      // });
      // 
      // if (response.data.isSpamTrap) {
      //   result.isSpamTrap = true;
      //   result.confidence = response.data.confidence || 80;
      //   result.indicators.push('External API confirmed spam trap');
      // }

      return result;
    } catch (error) {
      throw new Error(`External spam trap check failed: ${error.message}`);
    }
  }

  /**
   * AI-based spam trap detection (placeholder for ML implementation)
   * @param {string} email - Full email
   * @param {string} localPart - Local part
   * @param {string} domain - Domain part
   * @returns {Object} AI detection result
   */
  async aiBasedDetection(email, localPart, domain) {
    const result = {
      suspicious: false,
      confidence: 0,
      indicators: []
    };

    try {
      // Placeholder for AI/ML-based detection
      // This could include:
      // - Neural network analysis of email patterns
      // - Behavioral analysis based on historical data
      // - Natural language processing of email content
      // - Graph analysis of email relationships

      // Simple heuristic implementation as placeholder
      let suspicionScore = 0;

      // Check against common word patterns
      for (const word of this.aiFeatures.commonWords) {
        if (email.includes(word)) {
          suspicionScore += 10;
        }
      }

      // Check pattern complexity
      if (this.isComplexPattern(localPart)) {
        suspicionScore += 15;
      }

      if (suspicionScore > 20) {
        result.suspicious = true;
        result.confidence = Math.min(30, suspicionScore);
        result.indicators.push('AI heuristics indicate potential spam trap');
      }

      return result;
    } catch (error) {
      logger.error('AI spam trap detection failed:', error);
      return result;
    }
  }

  /**
   * Check if local part has complex/suspicious patterns
   * @param {string} localPart - Local part to analyze
   * @returns {boolean} True if complex pattern detected
   */
  isComplexPattern(localPart) {
    // Check for alternating character patterns
    const alternatingPattern = /^([a-z][0-9]){3,}$|^([0-9][a-z]){3,}$/i.test(localPart);
    
    // Check for repeated character sequences
    const repeatedSequence = /(.{2,})\1{2,}/.test(localPart);
    
    // Check for keyboard patterns
    const keyboardPatterns = ['qwerty', 'asdf', 'zxcv', '1234', 'abcd'];
    const hasKeyboardPattern = keyboardPatterns.some(pattern => 
      localPart.includes(pattern) || localPart.includes(pattern.split('').reverse().join(''))
    );

    return alternatingPattern || repeatedSequence || hasKeyboardPattern;
  }

  /**
   * Get spam trap risk assessment
   * @param {string} email - Email to assess
   * @returns {Object} Risk assessment
   */
  async getSpamTrapRiskAssessment(email) {
    const detection = await this.isSpamTrap(email);
    
    return {
      ...detection,
      recommendations: this.getRecommendations(detection),
      impact: this.getImpactAssessment(detection),
      mitigationStrategies: this.getMitigationStrategies(detection)
    };
  }

  /**
   * Get recommendations based on detection result
   * @param {Object} detection - Detection result
   * @returns {Array} Array of recommendations
   */
  getRecommendations(detection) {
    const recommendations = [];

    if (detection.isSpamTrap) {
      recommendations.push('IMMEDIATELY remove this email from all lists');
      recommendations.push('Do NOT send any emails to this address');
      recommendations.push('Investigate how this email was acquired');
      recommendations.push('Review your email acquisition processes');
    }

    if (detection.riskLevel === 'medium') {
      recommendations.push('Proceed with extreme caution');
      recommendations.push('Consider additional verification');
      recommendations.push('Monitor sending reputation closely');
    }

    if (detection.category === 'suspicious') {
      recommendations.push('Investigate email source and acquisition method');
      recommendations.push('Consider manual review before sending');
    }

    return recommendations;
  }

  /**
   * Get impact assessment
   * @param {Object} detection - Detection result
   * @returns {Object} Impact assessment
   */
  getImpactAssessment(detection) {
    const impact = {
      senderReputationRisk: 'low',
      deliverabilityImpact: 'minimal',
      legalRisk: 'low',
      listQualityImpact: 'minimal'
    };

    if (detection.isSpamTrap) {
      impact.senderReputationRisk = 'critical';
      impact.deliverabilityImpact = 'severe';
      impact.legalRisk = 'high';
      impact.listQualityImpact = 'severe';
    } else if (detection.riskLevel === 'medium') {
      impact.senderReputationRisk = 'high';
      impact.deliverabilityImpact = 'significant';
      impact.legalRisk = 'medium';
      impact.listQualityImpact = 'significant';
    }

    return impact;
  }

  /**
   * Get mitigation strategies
   * @param {Object} detection - Detection result
   * @returns {Array} Array of mitigation strategies
   */
  getMitigationStrategies(detection) {
    const strategies = [];

    if (detection.isSpamTrap || detection.riskLevel === 'high') {
      strategies.push('Implement double opt-in for all subscriptions');
      strategies.push('Regular list hygiene and validation');
      strategies.push('Source tracking for all email acquisitions');
      strategies.push('Real-time spam trap detection during signup');
      strategies.push('Regular audits of email acquisition partners');
    }

    strategies.push('Monitor sender reputation metrics');
    strategies.push('Implement email validation at point of entry');
    strategies.push('Use engagement-based list segmentation');

    return strategies;
  }

  /**
   * Check multiple emails for spam traps
   * @param {Array} emails - Array of emails to check
   * @returns {Array} Array of detection results
   */
  async checkMultipleEmails(emails) {
    const results = [];
    
    for (const email of emails) {
      try {
        const result = await this.isSpamTrap(email);
        results.push({
          email: email,
          ...result
        });
      } catch (error) {
        results.push({
          email: email,
          isSpamTrap: false,
          confidence: 0,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Add custom spam trap
   * @param {string} email - Email to add as spam trap
   * @param {string} source - Source of the information
   */
  addCustomSpamTrap(email, source = 'manual') {
    const domain = email.split('@')[1];
    if (domain) {
      this.spamTrapDomains.add(domain.toLowerCase().trim());
      logger.info(`Added custom spam trap domain: ${domain} (source: ${source})`);
    }
  }

  /**
   * Remove spam trap from detection
   * @param {string} domain - Domain to remove
   */
  removeSpamTrap(domain) {
    this.spamTrapDomains.delete(domain.toLowerCase().trim());
    logger.info(`Removed spam trap domain: ${domain}`);
  }

  /**
   * Get all known spam trap domains
   * @returns {Array} Array of spam trap domains
   */
  getAllSpamTrapDomains() {
    return Array.from(this.spamTrapDomains);
  }

  /**
   * Generate spam trap detection report
   * @param {Array} emails - Array of emails to analyze
   * @returns {Object} Detection report
   */
  async generateDetectionReport(emails) {
    const results = await this.checkMultipleEmails(emails);
    
    const report = {
      totalEmails: emails.length,
      spamTrapsFound: results.filter(r => r.isSpamTrap).length,
      suspiciousEmails: results.filter(r => r.riskLevel === 'medium').length,
      cleanEmails: results.filter(r => !r.isSpamTrap && r.riskLevel === 'low').length,
      riskDistribution: {
        high: results.filter(r => r.riskLevel === 'high').length,
        medium: results.filter(r => r.riskLevel === 'medium').length,
        low: results.filter(r => r.riskLevel === 'low').length
      },
      recommendations: [],
      detectionResults: results
    };

    // Generate overall recommendations
    if (report.spamTrapsFound > 0) {
      report.recommendations.push('CRITICAL: Spam traps detected - immediate action required');
      report.recommendations.push('Review and improve email acquisition processes');
    }

    if (report.suspiciousEmails > report.totalEmails * 0.1) {
      report.recommendations.push('High number of suspicious emails - audit email sources');
    }

    return report;
  }
}

module.exports = SpamTrapDetector; 