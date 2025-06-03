const validator = require('validator');
const logger = require('../utils/logger');

class SyntaxValidator {
  constructor() {
    // RFC-compliant regex patterns
    this.patterns = {
      // Basic email pattern
      basic: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      
      // RFC 5322 compliant pattern (simplified)
      rfc5322: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
      
      // Local part patterns
      localPart: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/,
      
      // Domain patterns
      domain: /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
      
      // Quoted string pattern for local part
      quotedString: /^"[^"\\]*(?:\\.[^"\\]*)*"$/,
      
      // Domain literal pattern
      domainLiteral: /^\[[0-9a-fA-F:.]+\]$/
    };
  }

  /**
   * Validate email syntax according to RFC standards
   * @param {string} email - Email to validate
   * @returns {Object} Validation result
   */
  async validate(email) {
    const result = {
      isValid: false,
      errors: [],
      warnings: [],
      compliance: {
        rfc1123: false,
        rfc2821: false,
        rfc2822: false,
        rfc3490: false,
        rfc3696: false,
        rfc4291: false,
        rfc5321: false,
        rfc5322: false,
        rfc5336: false
      },
      features: {
        hasQuotedStrings: false,
        hasQuotedPairs: false,
        hasComments: false,
        hasDomainLiterals: false,
        hasUnicode: false
      }
    };

    try {
      if (!email || typeof email !== 'string') {
        result.errors.push('Email must be a non-empty string');
        return result;
      }

      // Basic length check (RFC 5321)
      if (email.length > 320) {
        result.errors.push('Email exceeds maximum length of 320 characters (RFC 5321)');
        return result;
      }

      // Split email into local and domain parts
      const atIndex = email.lastIndexOf('@');
      if (atIndex === -1) {
        result.errors.push('Email must contain exactly one @ symbol');
        return result;
      }

      const localPart = email.substring(0, atIndex);
      const domain = email.substring(atIndex + 1);

      // Validate local part
      const localValidation = this.validateLocalPart(localPart);
      if (!localValidation.isValid) {
        result.errors.push(...localValidation.errors);
        result.warnings.push(...localValidation.warnings);
      }

      // Validate domain part
      const domainValidation = this.validateDomain(domain);
      if (!domainValidation.isValid) {
        result.errors.push(...domainValidation.errors);
        result.warnings.push(...domainValidation.warnings);
      }

      // Update features
      result.features = {
        ...localValidation.features,
        ...domainValidation.features
      };

      // Check overall validity
      result.isValid = localValidation.isValid && domainValidation.isValid;

      // Check RFC compliance
      this.checkRFCCompliance(email, localPart, domain, result);

      // Additional validations using validator library
      const validatorResult = validator.isEmail(email, {
        allow_utf8_local_part: true,
        require_tld: true,
        allow_ip_domain: true
      });

      if (!validatorResult && result.isValid) {
        result.warnings.push('Failed additional validation checks');
      }

      return result;

    } catch (error) {
      logger.error('Syntax validation error:', error);
      result.errors.push('Internal validation error');
      return result;
    }
  }

  /**
   * Validate local part (before @)
   * @param {string} localPart - Local part to validate
   * @returns {Object} Validation result
   */
  validateLocalPart(localPart) {
    const result = {
      isValid: false,
      errors: [],
      warnings: [],
      features: {
        hasQuotedStrings: false,
        hasQuotedPairs: false,
        hasComments: false
      }
    };

    if (!localPart) {
      result.errors.push('Local part cannot be empty');
      return result;
    }

    // RFC 5321: Local part maximum 64 characters
    if (localPart.length > 64) {
      result.errors.push('Local part exceeds maximum length of 64 characters (RFC 5321)');
      return result;
    }

    // Check for quoted strings
    if (localPart.startsWith('"') && localPart.endsWith('"')) {
      result.features.hasQuotedStrings = true;
      return this.validateQuotedLocalPart(localPart, result);
    }

    // Check for comments (simplified - basic support)
    if (localPart.includes('(') || localPart.includes(')')) {
      result.features.hasComments = true;
      result.warnings.push('Comments in local part detected - limited support');
    }

    // Validate unquoted local part
    return this.validateUnquotedLocalPart(localPart, result);
  }

  /**
   * Validate quoted local part
   * @param {string} localPart - Quoted local part
   * @param {Object} result - Result object to update
   * @returns {Object} Updated result
   */
  validateQuotedLocalPart(localPart, result) {
    // Check quoted string pattern
    if (!this.patterns.quotedString.test(localPart)) {
      result.errors.push('Invalid quoted string format in local part');
      return result;
    }

    // Check for quoted pairs
    if (localPart.includes('\\')) {
      result.features.hasQuotedPairs = true;
      
      // Validate quoted pairs
      const content = localPart.slice(1, -1); // Remove quotes
      const quotedPairPattern = /\\./g;
      const matches = content.match(quotedPairPattern);
      
      if (matches) {
        for (const match of matches) {
          if (match.length !== 2 || match[0] !== '\\') {
            result.errors.push('Invalid quoted pair in local part');
            return result;
          }
        }
      }
    }

    result.isValid = true;
    return result;
  }

  /**
   * Validate unquoted local part
   * @param {string} localPart - Unquoted local part
   * @param {Object} result - Result object to update
   * @returns {Object} Updated result
   */
  validateUnquotedLocalPart(localPart, result) {
    // Cannot start or end with dot
    if (localPart.startsWith('.') || localPart.endsWith('.')) {
      result.errors.push('Local part cannot start or end with a dot');
      return result;
    }

    // Cannot have consecutive dots
    if (localPart.includes('..')) {
      result.errors.push('Local part cannot contain consecutive dots');
      return result;
    }

    // Check allowed characters
    const allowedChars = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
    if (!allowedChars.test(localPart)) {
      result.errors.push('Local part contains invalid characters');
      return result;
    }

    result.isValid = true;
    return result;
  }

  /**
   * Validate domain part
   * @param {string} domain - Domain to validate
   * @returns {Object} Validation result
   */
  validateDomain(domain) {
    const result = {
      isValid: false,
      errors: [],
      warnings: [],
      features: {
        hasDomainLiterals: false,
        hasUnicode: false
      }
    };

    if (!domain) {
      result.errors.push('Domain cannot be empty');
      return result;
    }

    // RFC 5321: Domain maximum 253 characters
    if (domain.length > 253) {
      result.errors.push('Domain exceeds maximum length of 253 characters (RFC 5321)');
      return result;
    }

    // Check for domain literals [IP]
    if (domain.startsWith('[') && domain.endsWith(']')) {
      result.features.hasDomainLiterals = true;
      return this.validateDomainLiteral(domain, result);
    }

    // Check for Unicode characters
    if (/[^\x00-\x7F]/.test(domain)) {
      result.features.hasUnicode = true;
    }

    // Validate regular domain
    return this.validateRegularDomain(domain, result);
  }

  /**
   * Validate domain literal
   * @param {string} domain - Domain literal
   * @param {Object} result - Result object to update
   * @returns {Object} Updated result
   */
  validateDomainLiteral(domain, result) {
    const literal = domain.slice(1, -1); // Remove brackets
    
    // Check for IPv4
    if (validator.isIP(literal, 4)) {
      result.isValid = true;
      return result;
    }

    // Check for IPv6
    if (validator.isIP(literal, 6)) {
      result.isValid = true;
      return result;
    }

    // Check for IPv6 with prefix
    if (literal.startsWith('IPv6:') && validator.isIP(literal.substring(5), 6)) {
      result.isValid = true;
      return result;
    }

    result.errors.push('Invalid domain literal format');
    return result;
  }

  /**
   * Validate regular domain
   * @param {string} domain - Regular domain
   * @param {Object} result - Result object to update
   * @returns {Object} Updated result
   */
  validateRegularDomain(domain, result) {
    // Check basic domain pattern
    if (!this.patterns.domain.test(domain)) {
      result.errors.push('Invalid domain format');
      return result;
    }

    // Split into labels
    const labels = domain.split('.');
    
    // Must have at least 2 labels (domain.tld)
    if (labels.length < 2) {
      result.errors.push('Domain must have at least 2 labels (domain.tld)');
      return result;
    }

    // Validate each label
    for (let i = 0; i < labels.length; i++) {
      const label = labels[i];
      
      if (!label) {
        result.errors.push('Domain contains empty label');
        return result;
      }

      // RFC 1035: Label maximum 63 characters
      if (label.length > 63) {
        result.errors.push(`Domain label "${label}" exceeds maximum length of 63 characters`);
        return result;
      }

      // Labels cannot start or end with hyphen
      if (label.startsWith('-') || label.endsWith('-')) {
        result.errors.push(`Domain label "${label}" cannot start or end with hyphen`);
        return result;
      }

      // Check label characters
      if (!/^[a-zA-Z0-9-]+$/.test(label)) {
        // Allow punycode (xn--) and unicode for internationalized domains
        if (!label.startsWith('xn--') && !/[^\x00-\x7F]/.test(label)) {
          result.errors.push(`Domain label "${label}" contains invalid characters`);
          return result;
        }
      }
    }

    // Check TLD (last label)
    const tld = labels[labels.length - 1];
    if (!/^[a-zA-Z]{2,}$/.test(tld) && !tld.startsWith('xn--')) {
      result.warnings.push('TLD should contain only letters');
    }

    result.isValid = true;
    return result;
  }

  /**
   * Check RFC compliance
   * @param {string} email - Full email
   * @param {string} localPart - Local part
   * @param {string} domain - Domain part
   * @param {Object} result - Result object to update
   */
  checkRFCCompliance(email, localPart, domain, result) {
    // RFC 5322 - Internet Message Format
    if (this.patterns.rfc5322.test(email)) {
      result.compliance.rfc5322 = true;
    }

    // RFC 5321 - Simple Mail Transfer Protocol
    if (email.length <= 320 && localPart.length <= 64 && domain.length <= 253) {
      result.compliance.rfc5321 = true;
    }

    // RFC 3696 - Application Techniques for Checking and Transformation of Names
    if (result.compliance.rfc5322 && !email.includes('..')) {
      result.compliance.rfc3696 = true;
    }

    // RFC 1123 - Requirements for Internet Hosts
    if (domain.match(/^[a-zA-Z0-9.-]+$/)) {
      result.compliance.rfc1123 = true;
    }

    // RFC 2821 - Simple Mail Transfer Protocol (obsoleted by RFC 5321)
    result.compliance.rfc2821 = result.compliance.rfc5321;

    // RFC 2822 - Internet Message Format (obsoleted by RFC 5322)
    result.compliance.rfc2822 = result.compliance.rfc5322;

    // RFC 3490 - Internationalizing Domain Names in Applications (IDNA)
    if (result.features.hasUnicode || domain.includes('xn--')) {
      result.compliance.rfc3490 = true;
    }

    // RFC 4291 - IP Version 6 Addressing Architecture
    if (result.features.hasDomainLiterals) {
      const literal = domain.slice(1, -1);
      if (validator.isIP(literal, 6) || literal.startsWith('IPv6:')) {
        result.compliance.rfc4291 = true;
      }
    }

    // RFC 5336 - SMTP Extension for Internationalized Email Addresses
    if (result.features.hasUnicode) {
      result.compliance.rfc5336 = true;
    }
  }
}

module.exports = SyntaxValidator; 