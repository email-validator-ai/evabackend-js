const logger = require('../utils/logger');

class DisposableEmailDetector {
  constructor() {
    // Common disposable email domains
    this.disposableDomains = new Set([
      // Popular temporary email services
      '10minutemail.com', '10minutemail.net', '10minutemail.org',
      '20minutemail.com', '30minutemail.com',
      'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
      'mailinator.com', 'mailinator.net', 'mailinator.org',
      'yopmail.com', 'yopmail.net', 'yopmail.org',
      'tempmail.org', 'temp-mail.org', 'temp-mail.io',
      'throwaway.email', 'throwawaymail.com',
      'maildrop.cc', 'mailcatch.com', 'mailnesia.com',
      'sharklasers.com', 'grr.la', 'guerrillamailblock.com',
      'pokemail.net', 'spambox.us', 'spamcero.com',
      'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org',
      'spamhole.com', 'spamspot.com', 'spamthis.co.uk',
      'tempinbox.com', 'tempomail.fr', 'temporaryemail.net',
      'trashmail.com', 'trashmail.net', 'trashmail.org',
      'spamfree24.org', 'spamfree24.de', 'spamfree24.com',
      'emailondeck.com', 'emailondeck.de',
      'fakemail.net', 'fakeinbox.com', 'fake-mail.ml',
      'dispostable.com', 'disposeamail.com', 'disposableemailaddresses.com',
      'disposablemail.com', 'disposable.com',
      'getonemail.com', 'getonemail.net',
      'incognitomail.org', 'incognitomail.com',
      'jetable.org', 'jetable.com', 'jetable.net',
      'mailexpire.com', 'mail-temporaire.fr',
      'mohmal.com', 'mytemp.email', 'mytempmail.com',
      'neverbox.com', 'nowmymail.com',
      'objectmail.com', 'one-time.email', 'oneoffmail.com',
      'proxymail.eu', 'rcpt.at', 'receivemail.org',
      'super-auswahl.de', 'superrito.com',
      'thankyou2010.com', 'thisisnotmyrealemail.com',
      'tmailinator.com', 'trbvm.com', 'trialmail.de',
      'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org',
      'x.ip6.li', 'zoemail.org',
      // Additional patterns
      'getnada.com', 'harakirimail.com', 'mailforspam.com',
      'safetymail.info', 'spamherald.com', 'spamkill.info',
      'spamthisplease.com', 'temail.info', 'tempymail.com',
      'yopmail.fr', 'yopmail.gq', 'cool.fr.nf',
      'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx',
      'mega.zik.dj', 'speed.1s.fr', 'courriel.fr.nf',
      'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
      'guerrillamail.de', 'guerrillamail.biz', 'guerrillamail.info',
      'spam4.me', 'grr.la', 'guerrillamailblock.com',
      'sharklasers.com', 'guerrilla.com',
      'deadaddress.com', 'deadspam.com', 'dontreg.com',
      'dumpyemail.com', 'emailias.com', 'emailinfive.com',
      'emailmiser.com', 'emailto.de', 'emailwarden.com',
      'enterto.com', 'ephemail.net', 'explodemail.com',
      'filzmail.com', 'fleckens.hu', 'freemail.ms',
      'gishpuppy.com', 'gmai.com', 'haltospam.com',
      'hatespam.org', 'hidemail.de', 'hochsitze.com',
      'hotpop.com', 'inboxalias.com', 'inboxclean.com',
      'inboxclean.org', 'keepmymail.com', 'klzlk.com',
      'kurzepost.de', 'lifebyfood.com', 'lookugly.com',
      'lortemail.dk', 'lovemeleaveme.com', 'mailbidon.com',
      'maileater.com', 'mailme.lv', 'mailnull.com',
      'mailzilla.org', 'mbx.cc', 'mintemail.com',
      'mt2009.com', 'mx0.wwwnew.eu', 'mypartyclip.de',
      'myphantomemail.com', 'nospamfor.us', 'nowmymail.com',
      'nullbox.info', 'objectmail.com', 'obobbo.com',
      'oneoffemail.com', 'onlinedeals411.info', 'ordinaryamerican.net',
      'owlpic.com', 'pooae.com', 'pookmail.com',
      'privacy.net', 'proxymail.eu', 'punkass.com',
      'putthisinyourspamdatabase.com', 'quickinbox.com', 'rcpt.at',
      'rejectmail.com', 'rppkn.com', 'rtrtr.com',
      's0ny.net', 'safe-mail.net', 'shiftmail.com',
      'smellfear.com', 'snakemail.com', 'sneakemail.com',
      'sogetthis.com', 'soodonims.com', 'spam.la',
      'spamavert.com', 'spambob.net', 'spambob.org',
      'spamherelots.com', 'spamhereplease.com', 'spamthis.co.uk',
      'spamtroll.net', 'stuffmail.de', 'super-auswahl.de',
      'supergreatmail.com', 'superrito.com', 'tempinbox.co.uk',
      'tempinbox.com', 'tempmail.it', 'tempmail2.com',
      'tempomail.fr', 'temporaryforwarding.com', 'temporaryinbox.com',
      'thanksnospam.info', 'thankyou2010.com', 'thisisnotmyrealemail.com',
      'throwawayemailaddresses.com', 'tilien.com', 'tmailinator.com',
      'toiea.com', 'tradermail.info', 'trash2009.com',
      'trashemail.de', 'trashymail.com', 'tyldd.com',
      'uggsrock.com', 'wegwerfmail.de', 'wegwerfmail.net',
      'wegwerfmail.org', 'wh4f.org', 'whyspam.me',
      'willselfdestruct.com', 'winemaven.info', 'wronghead.com',
      'wuzupmail.net', 'xoxy.net', 'yogamaven.com',
      'yuurok.com', 'zippymail.info', 'zoemail.org'
    ]);

    // Common patterns for disposable email domains
    this.disposablePatterns = [
      /^temp.*\.com$/i,
      /^temp.*\.org$/i,
      /^temp.*\.net$/i,
      /^.*temp.*mail.*$/i,
      /^.*disposable.*$/i,
      /^.*throwaway.*$/i,
      /^.*temporary.*$/i,
      /^.*fake.*mail.*$/i,
      /^.*spam.*$/i,
      /^.*trash.*mail.*$/i,
      /^.*guerrilla.*$/i,
      /^.*mailinator.*$/i,
      /^.*10minute.*$/i,
      /^.*20minute.*$/i,
      /^.*30minute.*$/i,
      /.*\.tk$/i,
      /.*\.ml$/i,
      /.*\.ga$/i,
      /.*\.cf$/i
    ];

    // Load additional domains from external sources
    this.loadAdditionalDomains();
  }

  /**
   * Check if domain is disposable
   * @param {string} domain - Domain to check
   * @returns {Object} Disposable check result
   */
  async isDisposable(domain) {
    const result = {
      isDisposable: false,
      confidence: 0,
      source: null,
      category: null,
      risk: 'low'
    };

    try {
      const normalizedDomain = domain.toLowerCase().trim();

      // Check against known disposable domains
      if (this.disposableDomains.has(normalizedDomain)) {
        result.isDisposable = true;
        result.confidence = 100;
        result.source = 'known_list';
        result.category = 'confirmed_disposable';
        result.risk = 'high';
        return result;
      }

      // Check against patterns
      for (const pattern of this.disposablePatterns) {
        if (pattern.test(normalizedDomain)) {
          result.isDisposable = true;
          result.confidence = 85;
          result.source = 'pattern_match';
          result.category = 'likely_disposable';
          result.risk = 'high';
          return result;
        }
      }

      // Check for suspicious characteristics
      const suspiciousCheck = this.checkSuspiciousCharacteristics(normalizedDomain);
      if (suspiciousCheck.suspicious) {
        result.isDisposable = suspiciousCheck.confidence >= 70;
        result.confidence = suspiciousCheck.confidence;
        result.source = 'heuristic';
        result.category = 'suspicious';
        result.risk = suspiciousCheck.confidence >= 70 ? 'medium' : 'low';
        
        // Add details about why it's suspicious
        result.details = suspiciousCheck.reasons;
      }

      // Try to check against external API if available
      if (process.env.DISPOSABLE_EMAIL_API_KEY) {
        try {
          const apiResult = await this.checkExternalAPI(normalizedDomain);
          if (apiResult.isDisposable) {
            result.isDisposable = true;
            result.confidence = Math.max(result.confidence, apiResult.confidence);
            result.source = 'external_api';
            result.category = apiResult.category;
            result.risk = 'high';
          }
        } catch (error) {
          logger.warn('External disposable email API check failed:', error);
        }
      }

      return result;

    } catch (error) {
      logger.error('Disposable email detection failed:', error);
      return result;
    }
  }

  /**
   * Check for suspicious domain characteristics
   * @param {string} domain - Domain to analyze
   * @returns {Object} Suspicious characteristics result
   */
  checkSuspiciousCharacteristics(domain) {
    const result = {
      suspicious: false,
      confidence: 0,
      reasons: []
    };

    // Check domain length (very short or very long domains can be suspicious)
    if (domain.length < 4) {
      result.confidence += 20;
      result.reasons.push('Very short domain name');
    } else if (domain.length > 30) {
      result.confidence += 15;
      result.reasons.push('Very long domain name');
    }

    // Check for numbers in domain (common in disposable services)
    if (/\d/.test(domain)) {
      result.confidence += 10;
      result.reasons.push('Contains numbers');
    }

    // Check for multiple hyphens
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      result.confidence += 15;
      result.reasons.push('Multiple hyphens');
    }

    // Check for suspicious keywords
    const suspiciousKeywords = [
      'temp', 'fake', 'test', 'demo', 'trial', 'sample',
      'spam', 'trash', 'junk', 'mail', 'inbox', 'email',
      'drop', 'catch', 'throw', 'away', 'dispos', 'tempor',
      'minute', 'hour', 'day', 'short', 'quick', 'fast',
      'anon', 'hidden', 'secure', 'safe', 'protect'
    ];

    let keywordMatches = 0;
    for (const keyword of suspiciousKeywords) {
      if (domain.includes(keyword)) {
        keywordMatches++;
      }
    }

    if (keywordMatches > 0) {
      result.confidence += keywordMatches * 15;
      result.reasons.push(`Contains ${keywordMatches} suspicious keyword(s)`);
    }

    // Check TLD patterns
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'men'];
    const tld = domain.split('.').pop();
    if (suspiciousTLDs.includes(tld)) {
      result.confidence += 25;
      result.reasons.push('Suspicious TLD');
    }

    // Check for common disposable patterns
    if (domain.includes('mail') && domain.includes('temp')) {
      result.confidence += 30;
      result.reasons.push('Contains both "mail" and "temp"');
    }

    if (domain.includes('guerrilla') || domain.includes('10min') || domain.includes('20min')) {
      result.confidence += 40;
      result.reasons.push('Contains known disposable service patterns');
    }

    result.suspicious = result.confidence >= 50;
    result.confidence = Math.min(100, result.confidence);

    return result;
  }

  /**
   * Check external API for disposable email detection
   * @param {string} domain - Domain to check
   * @returns {Object} API check result
   */
  async checkExternalAPI(domain) {
    // This is a placeholder for external API integration
    // You can integrate with services like:
    // - DisposableEmailDetector.com
    // - Block-disposable-email.com
    // - Email validation services

    const result = {
      isDisposable: false,
      confidence: 0,
      category: 'unknown'
    };

    // Example API integration (you would implement this based on your chosen service)
    try {
      // const response = await axios.get(`https://api.example.com/check?domain=${domain}`, {
      //   headers: { 'Authorization': `Bearer ${process.env.DISPOSABLE_EMAIL_API_KEY}` }
      // });
      // 
      // result.isDisposable = response.data.disposable;
      // result.confidence = response.data.confidence || 80;
      // result.category = response.data.category || 'external_confirmed';

      return result;
    } catch (error) {
      throw new Error(`External API check failed: ${error.message}`);
    }
  }

  /**
   * Load additional disposable domains from external sources
   */
  async loadAdditionalDomains() {
    try {
      // You can load additional domains from:
      // - GitHub repositories with disposable email lists
      // - Your own database
      // - External APIs
      
      // Example: Load from a common GitHub repository
      // const response = await axios.get('https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json');
      // const additionalDomains = response.data;
      // for (const domain of additionalDomains) {
      //   this.disposableDomains.add(domain.toLowerCase());
      // }

      logger.info(`Loaded ${this.disposableDomains.size} disposable email domains`);
    } catch (error) {
      logger.warn('Failed to load additional disposable domains:', error);
    }
  }

  /**
   * Add domain to disposable list
   * @param {string} domain - Domain to add
   */
  addDisposableDomain(domain) {
    this.disposableDomains.add(domain.toLowerCase().trim());
  }

  /**
   * Remove domain from disposable list
   * @param {string} domain - Domain to remove
   */
  removeDisposableDomain(domain) {
    this.disposableDomains.delete(domain.toLowerCase().trim());
  }

  /**
   * Get all disposable domains
   * @returns {Array} Array of disposable domains
   */
  getAllDisposableDomains() {
    return Array.from(this.disposableDomains);
  }

  /**
   * Check multiple domains at once
   * @param {Array} domains - Array of domains to check
   * @returns {Array} Array of check results
   */
  async checkMultipleDomains(domains) {
    const results = [];
    
    for (const domain of domains) {
      try {
        const result = await this.isDisposable(domain);
        results.push({
          domain: domain,
          ...result
        });
      } catch (error) {
        results.push({
          domain: domain,
          isDisposable: false,
          confidence: 0,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Neural network-based detection (placeholder for advanced detection)
   * @param {string} domain - Domain to analyze
   * @returns {Object} Neural network analysis result
   */
  async neuralNetworkDetection(domain) {
    // This is a placeholder for implementing more advanced
    // machine learning-based disposable email detection
    // You could use services like TensorFlow.js or external ML APIs

    const result = {
      isDisposable: false,
      confidence: 0,
      method: 'neural_network'
    };

    try {
      // Implement neural network logic here
      // This could analyze:
      // - Domain name patterns
      // - Registration patterns
      // - Historical data
      // - Behavioral patterns

      return result;
    } catch (error) {
      logger.error('Neural network detection failed:', error);
      return result;
    }
  }
}

module.exports = DisposableEmailDetector; 