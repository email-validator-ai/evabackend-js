class FreeEmailDetector {
  constructor() {
    // Popular free email providers
    this.freeProviders = new Set([
      // Google
      'gmail.com', 'googlemail.com',
      
      // Microsoft
      'hotmail.com', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'hotmail.it',
      'hotmail.es', 'hotmail.ca', 'hotmail.com.au', 'hotmail.co.jp',
      'outlook.com', 'outlook.co.uk', 'outlook.fr', 'outlook.de', 'outlook.it',
      'outlook.es', 'outlook.ca', 'outlook.com.au', 'outlook.co.jp',
      'live.com', 'live.co.uk', 'live.fr', 'live.de', 'live.it',
      'live.ca', 'live.com.au', 'live.co.jp',
      'msn.com', 'windowslive.com',
      
      // Yahoo
      'yahoo.com', 'yahoo.co.uk', 'yahoo.ca', 'yahoo.com.au',
      'yahoo.de', 'yahoo.fr', 'yahoo.it', 'yahoo.es',
      'yahoo.co.jp', 'yahoo.co.in', 'yahoo.com.br',
      'ymail.com', 'rocketmail.com',
      
      // AOL
      'aol.com', 'aol.co.uk', 'aol.de', 'aol.fr', 'aol.it',
      'aim.com', 'netscape.net',
      
      // Apple
      'icloud.com', 'me.com', 'mac.com',
      
      // Other major providers
      'mail.com', 'email.com', 'gmx.com', 'gmx.de', 'gmx.net',
      'web.de', 'freenet.de', 't-online.de',
      'protonmail.com', 'protonmail.ch', 'pm.me',
      'tutanota.com', 'tutanota.de', 'tutamail.com', 'keemail.me',
      'zoho.com', 'zohomail.com',
      'yandex.com', 'yandex.ru', 'ya.ru',
      'mail.ru', 'inbox.ru', 'list.ru', 'bk.ru',
      'rambler.ru', 'lenta.ru',
      
      // Regional providers
      // China
      '163.com', '126.com', 'qq.com', 'sina.com', 'sohu.com',
      'yeah.net', 'tom.com', 'foxmail.com',
      
      // India
      'rediffmail.com', 'sify.com', 'in.com',
      
      // Europe
      'libero.it', 'virgilio.it', 'tiscali.it', 'alice.it',
      'orange.fr', 'laposte.net', 'free.fr', 'wanadoo.fr',
      'voila.fr', 'club-internet.fr',
      'terra.es', 'telefonica.net', 'latinmail.com',
      'correios.pt', 'sapo.pt', 'clix.pt',
      'wp.pl', 'onet.pl', 'interia.pl', 'gazeta.pl',
      'freemail.hu', 'citromail.hu', 'indamail.hu',
      'email.cz', 'seznam.cz', 'centrum.cz', 'atlas.cz',
      'abv.bg', 'mail.bg', 'dir.bg',
      'inbox.lv', 'apollo.lv', 'one.lv',
      
      // Latin America
      'bol.com.br', 'uol.com.br', 'ig.com.br', 'globo.com',
      'r7.com', 'terra.com.br', 'zipmail.com.br',
      'hotmail.com.ar', 'ciudad.com.ar', 'arnet.com.ar',
      'live.com.mx', 'hotmail.com.mx', 'yahoo.com.mx',
      
      // Other regions
      'rogers.com', 'sympatico.ca', 'shaw.ca', 'telus.net',
      'bigpond.com', 'bigpond.net.au', 'optusnet.com.au',
      'internode.on.net', 'westnet.com.au',
      'naver.com', 'hanmail.net', 'daum.net', 'korea.com',
      
      // Alternative/Privacy providers
      'cock.li', 'airmail.cc', 'guerrillamail.com',
      'secure-mail.biz', 'fastmail.com', 'fastmail.fm',
      'lavabit.com', 'hushmail.com', 'safe-mail.net',
      'countermail.com', 'neomailbox.com',
      
      // Mobile/SMS based
      'txt.att.net', 'vtext.com', 'tmomail.net',
      'messaging.sprintpcs.com', 'pm.sprint.com',
      
      // Educational (some free variants)
      'student.com', 'alumni.com', 'schools.com'
    ]);

    // Patterns for free email providers
    this.freePatterns = [
      /^mail\d*\.com$/i,
      /^email\d*\.com$/i,
      /^freemail\d*\.(com|org|net)$/i,
      /^webmail\d*\.(com|org|net)$/i,
      /^.*free.*mail.*$/i,
      /^.*student.*$/i,
      /^.*alumni.*$/i
    ];

    // Provider categories
    this.providerCategories = {
      'gmail.com': { category: 'major', provider: 'Google', popularity: 'very_high' },
      'googlemail.com': { category: 'major', provider: 'Google', popularity: 'high' },
      'hotmail.com': { category: 'major', provider: 'Microsoft', popularity: 'very_high' },
      'outlook.com': { category: 'major', provider: 'Microsoft', popularity: 'very_high' },
      'yahoo.com': { category: 'major', provider: 'Yahoo', popularity: 'high' },
      'aol.com': { category: 'major', provider: 'AOL', popularity: 'medium' },
      'icloud.com': { category: 'major', provider: 'Apple', popularity: 'medium' },
      'protonmail.com': { category: 'privacy', provider: 'ProtonMail', popularity: 'medium' },
      'tutanota.com': { category: 'privacy', provider: 'Tutanota', popularity: 'low' },
      'zoho.com': { category: 'business', provider: 'Zoho', popularity: 'medium' },
      'fastmail.com': { category: 'premium', provider: 'FastMail', popularity: 'low' }
    };
  }

  /**
   * Check if domain is a free email provider
   * @param {string} domain - Domain to check
   * @returns {Object} Free email detection result
   */
  isFreeEmail(domain) {
    const result = {
      isFree: false,
      confidence: 0,
      provider: null,
      category: null,
      popularity: null,
      risk: 'low'
    };

    if (!domain || typeof domain !== 'string') {
      return result;
    }

    const normalizedDomain = domain.toLowerCase().trim();

    // Check against known free providers
    if (this.freeProviders.has(normalizedDomain)) {
      result.isFree = true;
      result.confidence = 100;
      
      // Get provider details if available
      const providerInfo = this.providerCategories[normalizedDomain];
      if (providerInfo) {
        result.provider = providerInfo.provider;
        result.category = providerInfo.category;
        result.popularity = providerInfo.popularity;
        result.risk = this.assessRisk(providerInfo);
      } else {
        result.category = 'free';
        result.popularity = 'unknown';
      }
      
      return result;
    }

    // Check against patterns
    for (const pattern of this.freePatterns) {
      if (pattern.test(normalizedDomain)) {
        result.isFree = true;
        result.confidence = 75;
        result.category = 'pattern_match';
        result.risk = 'medium';
        return result;
      }
    }

    // Check for suspicious free email characteristics
    const suspiciousCheck = this.checkSuspiciousCharacteristics(normalizedDomain);
    if (suspiciousCheck.suspicious) {
      result.isFree = suspiciousCheck.confidence >= 60;
      result.confidence = suspiciousCheck.confidence;
      result.category = 'suspicious';
      result.risk = suspiciousCheck.confidence >= 60 ? 'low' : 'very_low';
      result.details = suspiciousCheck.reasons;
    }

    return result;
  }

  /**
   * Assess risk level based on provider info
   * @param {Object} providerInfo - Provider information
   * @returns {string} Risk level
   */
  assessRisk(providerInfo) {
    // Lower risk for major, well-established providers
    if (providerInfo.category === 'major' && providerInfo.popularity === 'very_high') {
      return 'very_low';
    }
    
    if (providerInfo.category === 'major') {
      return 'low';
    }

    // Medium risk for business/premium providers
    if (providerInfo.category === 'business' || providerInfo.category === 'premium') {
      return 'low';
    }

    // Higher risk for privacy providers (might be used for anonymity)
    if (providerInfo.category === 'privacy') {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Check for suspicious characteristics of potential free email providers
   * @param {string} domain - Domain to analyze
   * @returns {Object} Suspicious characteristics result
   */
  checkSuspiciousCharacteristics(domain) {
    const result = {
      suspicious: false,
      confidence: 0,
      reasons: []
    };

    // Check for common free email keywords
    const freeKeywords = [
      'free', 'mail', 'email', 'webmail', 'inbox', 'message',
      'post', 'send', 'secure', 'safe', 'private', 'anon',
      'temp', 'quick', 'fast', 'easy', 'simple', 'student',
      'alumni', 'school', 'edu'
    ];

    let keywordCount = 0;
    for (const keyword of freeKeywords) {
      if (domain.includes(keyword)) {
        keywordCount++;
      }
    }

    if (keywordCount > 0) {
      result.confidence += keywordCount * 15;
      result.reasons.push(`Contains ${keywordCount} free email keyword(s)`);
    }

    // Check for numeric patterns (common in free services)
    if (/\d+/.test(domain)) {
      result.confidence += 10;
      result.reasons.push('Contains numbers');
    }

    // Check for common free email TLDs
    const freeTLDs = ['com', 'org', 'net', 'info', 'me'];
    const tld = domain.split('.').pop();
    if (freeTLDs.includes(tld) && keywordCount > 0) {
      result.confidence += 10;
      result.reasons.push('Common TLD with free email keywords');
    }

    // Check for very short domains (often free services)
    if (domain.length <= 8 && keywordCount > 0) {
      result.confidence += 15;
      result.reasons.push('Short domain with email keywords');
    }

    // Check for common patterns
    if (/^(mail|email|webmail|inbox)\d*\.(com|org|net)$/i.test(domain)) {
      result.confidence += 25;
      result.reasons.push('Matches common free email pattern');
    }

    result.suspicious = result.confidence >= 40;
    result.confidence = Math.min(100, result.confidence);

    return result;
  }

  /**
   * Get detailed provider information
   * @param {string} domain - Domain to analyze
   * @returns {Object} Detailed provider information
   */
  getProviderDetails(domain) {
    const result = this.isFreeEmail(domain);

    if (result.isFree) {
      return {
        ...result,
        description: this.getProviderDescription(domain, result),
        recommendations: this.getRecommendations(result),
        marketingImpact: this.getMarketingImpact(result),
        deliverabilityNotes: this.getDeliverabilityNotes(result)
      };
    }

    return result;
  }

  /**
   * Get provider description
   * @param {string} domain - Domain
   * @param {Object} result - Detection result
   * @returns {string} Description
   */
  getProviderDescription(domain, result) {
    const descriptions = {
      major: 'Major free email provider with high user base',
      privacy: 'Privacy-focused email provider',
      business: 'Business-oriented email service with free tier',
      premium: 'Premium email service with free options',
      pattern_match: 'Likely free email provider based on naming patterns',
      suspicious: 'Possible free email provider'
    };

    if (result.provider) {
      return `${result.provider} - ${descriptions[result.category] || descriptions.major}`;
    }

    return descriptions[result.category] || 'Free email provider';
  }

  /**
   * Get recommendations for handling free email addresses
   * @param {Object} result - Detection result
   * @returns {Array} Array of recommendations
   */
  getRecommendations(result) {
    const recommendations = [];

    if (result.category === 'major' && result.popularity === 'very_high') {
      recommendations.push('Generally acceptable for most use cases');
      recommendations.push('High deliverability expected');
    }

    if (result.category === 'privacy') {
      recommendations.push('User may prioritize privacy and anonymity');
      recommendations.push('May have lower engagement rates');
    }

    if (result.risk === 'medium') {
      recommendations.push('Consider additional verification steps');
      recommendations.push('Monitor for engagement patterns');
    }

    if (result.category === 'pattern_match' || result.category === 'suspicious') {
      recommendations.push('Verify provider legitimacy');
      recommendations.push('May require additional validation');
    }

    return recommendations;
  }

  /**
   * Get marketing impact assessment
   * @param {Object} result - Detection result
   * @returns {Object} Marketing impact
   */
  getMarketingImpact(result) {
    const impact = {
      segmentation: 'personal',
      engagementExpectation: 'medium',
      deliverabilityRisk: 'low',
      recommendedApproach: 'standard'
    };

    if (result.category === 'major') {
      impact.engagementExpectation = 'high';
      impact.recommendedApproach = 'standard_marketing';
    }

    if (result.category === 'privacy') {
      impact.engagementExpectation = 'low';
      impact.recommendedApproach = 'privacy_conscious';
    }

    if (result.risk === 'medium') {
      impact.deliverabilityRisk = 'medium';
      impact.recommendedApproach = 'cautious';
    }

    return impact;
  }

  /**
   * Get deliverability notes
   * @param {Object} result - Detection result
   * @returns {Array} Array of deliverability notes
   */
  getDeliverabilityNotes(result) {
    const notes = [];

    if (result.category === 'major') {
      notes.push('Major providers have robust spam filtering');
      notes.push('Follow sender best practices for optimal delivery');
    }

    if (result.provider === 'Google') {
      notes.push('Gmail has sophisticated filtering algorithms');
      notes.push('Sender reputation is crucial');
    }

    if (result.provider === 'Microsoft') {
      notes.push('Outlook.com uses Microsoft Defender');
      notes.push('IP and domain reputation important');
    }

    if (result.provider === 'Yahoo') {
      notes.push('Yahoo has strict authentication requirements');
      notes.push('DMARC alignment strongly recommended');
    }

    return notes;
  }

  /**
   * Check multiple domains
   * @param {Array} domains - Array of domains to check
   * @returns {Array} Array of check results
   */
  checkMultipleDomains(domains) {
    return domains.map(domain => ({
      domain: domain,
      ...this.getProviderDetails(domain)
    }));
  }

  /**
   * Get domains by category
   * @param {string} category - Category to filter by
   * @returns {Array} Array of domains in category
   */
  getDomainsByCategory(category) {
    const domains = [];
    
    for (const domain of this.freeProviders) {
      const result = this.isFreeEmail(domain);
      if (result.category === category) {
        domains.push(domain);
      }
    }

    return domains;
  }

  /**
   * Get major free email providers
   * @returns {Array} Array of major providers
   */
  getMajorProviders() {
    return this.getDomainsByCategory('major');
  }

  /**
   * Get privacy-focused providers
   * @returns {Array} Array of privacy providers
   */
  getPrivacyProviders() {
    return this.getDomainsByCategory('privacy');
  }

  /**
   * Add custom free email provider
   * @param {string} domain - Domain to add
   * @param {Object} providerInfo - Provider information
   */
  addCustomProvider(domain, providerInfo = {}) {
    this.freeProviders.add(domain.toLowerCase().trim());
    
    if (providerInfo.provider || providerInfo.category) {
      this.providerCategories[domain.toLowerCase().trim()] = {
        category: providerInfo.category || 'custom',
        provider: providerInfo.provider || 'Unknown',
        popularity: providerInfo.popularity || 'unknown'
      };
    }
  }

  /**
   * Remove provider from detection
   * @param {string} domain - Domain to remove
   */
  removeProvider(domain) {
    this.freeProviders.delete(domain.toLowerCase().trim());
    delete this.providerCategories[domain.toLowerCase().trim()];
  }

  /**
   * Get all free email providers
   * @returns {Array} Array of all free email providers
   */
  getAllProviders() {
    return Array.from(this.freeProviders);
  }

  /**
   * Get provider statistics
   * @returns {Object} Provider statistics
   */
  getProviderStatistics() {
    const stats = {
      totalProviders: this.freeProviders.size,
      categories: {},
      popularityDistribution: {}
    };

    for (const [domain, info] of Object.entries(this.providerCategories)) {
      stats.categories[info.category] = (stats.categories[info.category] || 0) + 1;
      stats.popularityDistribution[info.popularity] = (stats.popularityDistribution[info.popularity] || 0) + 1;
    }

    return stats;
  }
}

module.exports = FreeEmailDetector; 