class RoleAccountDetector {
  constructor() {
    // Common role accounts
    this.roleAccounts = new Set([
      // Administrative roles
      'admin', 'administrator', 'root', 'sysadmin', 'webmaster',
      'postmaster', 'hostmaster', 'mailer-daemon', 'mailerdaemon',
      
      // Customer service
      'support', 'help', 'helpdesk', 'service', 'customer', 'customerservice',
      'tech', 'technical', 'techsupport', 'it', 'itsupport',
      
      // Sales and marketing
      'sales', 'marketing', 'info', 'information', 'contact', 'hello',
      'business', 'commercial', 'team', 'office', 'company',
      
      // Communication
      'noreply', 'no-reply', 'donotreply', 'do-not-reply',
      'automated', 'auto', 'system', 'daemon', 'robot', 'bot',
      
      // Legal and compliance
      'legal', 'compliance', 'privacy', 'gdpr', 'dpo', 'abuse',
      'security', 'dmca', 'copyright', 'takedown',
      
      // HR and careers
      'hr', 'human-resources', 'humanresources', 'careers', 'jobs',
      'recruiting', 'recruitment', 'talent', 'hiring',
      
      // Finance and billing
      'billing', 'finance', 'accounting', 'accounts', 'invoices',
      'payments', 'orders', 'purchase', 'purchasing',
      
      // Operations
      'operations', 'ops', 'devops', 'monitoring', 'alerts',
      'notifications', 'reports', 'backup', 'backups',
      
      // Generic functional roles
      'mail', 'email', 'newsletter', 'news', 'updates', 'alerts',
      'api', 'dev', 'test', 'testing', 'demo', 'sandbox',
      'staging', 'production', 'prod',
      
      // Social media
      'social', 'socialmedia', 'twitter', 'facebook', 'linkedin',
      'instagram', 'youtube', 'press', 'media', 'pr',
      
      // Departments
      'department', 'dept', 'division', 'group', 'unit',
      'board', 'directors', 'management', 'executive',
      
      // Events and partnerships
      'events', 'partnerships', 'partners', 'affiliates',
      'vendors', 'suppliers', 'contractors',
      
      // Quality and feedback
      'feedback', 'suggestions', 'quality', 'qa', 'qc',
      'testing', 'review', 'reviews', 'ratings'
    ]);

    // Patterns for role accounts
    this.rolePatterns = [
      /^no-?reply/i,
      /^do-?not-?reply/i,
      /^auto-?/i,
      /^system-?/i,
      /^admin-?/i,
      /^support-?/i,
      /^help-?/i,
      /^info-?/i,
      /^contact-?/i,
      /^team-?/i,
      /^dept-?/i,
      /^department-?/i,
      /-?admin$/i,
      /-?support$/i,
      /-?help$/i,
      /-?info$/i,
      /-?team$/i,
      /-?dept$/i,
      /-?department$/i,
      /^.+@.+-?(admin|support|help|info|team|dept)$/i
    ];
  }

  /**
   * Check if email local part is a role account
   * @param {string} localPart - Local part of email (before @)
   * @returns {Object} Role account detection result
   */
  isRoleAccount(localPart) {
    const result = {
      isRole: false,
      confidence: 0,
      category: null,
      type: null,
      risk: 'low'
    };

    if (!localPart || typeof localPart !== 'string') {
      return result;
    }

    const normalizedLocalPart = localPart.toLowerCase().trim();

    // Check against known role accounts
    if (this.roleAccounts.has(normalizedLocalPart)) {
      result.isRole = true;
      result.confidence = 100;
      result.category = this.categorizeRoleAccount(normalizedLocalPart);
      result.type = 'exact_match';
      result.risk = this.assessRisk(normalizedLocalPart);
      return result;
    }

    // Check against patterns
    for (const pattern of this.rolePatterns) {
      if (pattern.test(normalizedLocalPart)) {
        result.isRole = true;
        result.confidence = 85;
        result.category = this.categorizeByPattern(normalizedLocalPart, pattern);
        result.type = 'pattern_match';
        result.risk = this.assessRisk(normalizedLocalPart);
        return result;
      }
    }

    // Check for suspicious characteristics
    const suspiciousCheck = this.checkSuspiciousCharacteristics(normalizedLocalPart);
    if (suspiciousCheck.suspicious) {
      result.isRole = suspiciousCheck.confidence >= 70;
      result.confidence = suspiciousCheck.confidence;
      result.category = 'possible_role';
      result.type = 'heuristic';
      result.risk = suspiciousCheck.confidence >= 70 ? 'medium' : 'low';
      result.details = suspiciousCheck.reasons;
    }

    return result;
  }

  /**
   * Categorize role account by exact match
   * @param {string} localPart - Local part to categorize
   * @returns {string} Category name
   */
  categorizeRoleAccount(localPart) {
    const categories = {
      administrative: [
        'admin', 'administrator', 'root', 'sysadmin', 'webmaster',
        'postmaster', 'hostmaster', 'mailer-daemon', 'mailerdaemon'
      ],
      support: [
        'support', 'help', 'helpdesk', 'service', 'customer', 'customerservice',
        'tech', 'technical', 'techsupport', 'it', 'itsupport'
      ],
      sales_marketing: [
        'sales', 'marketing', 'info', 'information', 'contact', 'hello',
        'business', 'commercial', 'team', 'office', 'company'
      ],
      automated: [
        'noreply', 'no-reply', 'donotreply', 'do-not-reply',
        'automated', 'auto', 'system', 'daemon', 'robot', 'bot'
      ],
      legal: [
        'legal', 'compliance', 'privacy', 'gdpr', 'dpo', 'abuse',
        'security', 'dmca', 'copyright', 'takedown'
      ],
      hr: [
        'hr', 'human-resources', 'humanresources', 'careers', 'jobs',
        'recruiting', 'recruitment', 'talent', 'hiring'
      ],
      finance: [
        'billing', 'finance', 'accounting', 'accounts', 'invoices',
        'payments', 'orders', 'purchase', 'purchasing'
      ]
    };

    for (const [category, accounts] of Object.entries(categories)) {
      if (accounts.includes(localPart)) {
        return category;
      }
    }

    return 'generic';
  }

  /**
   * Categorize role account by pattern match
   * @param {string} localPart - Local part to categorize
   * @param {RegExp} pattern - Matched pattern
   * @returns {string} Category name
   */
  categorizeByPattern(localPart, pattern) {
    if (/no-?reply|do-?not-?reply|auto/i.test(pattern.source)) {
      return 'automated';
    }
    if (/admin/i.test(pattern.source)) {
      return 'administrative';
    }
    if (/support|help/i.test(pattern.source)) {
      return 'support';
    }
    if (/info|contact|team/i.test(pattern.source)) {
      return 'sales_marketing';
    }
    if (/dept|department/i.test(pattern.source)) {
      return 'departmental';
    }

    return 'generic';
  }

  /**
   * Assess risk level of role account
   * @param {string} localPart - Local part to assess
   * @returns {string} Risk level
   */
  assessRisk(localPart) {
    // High risk: automated accounts, noreply, system accounts
    const highRisk = [
      'noreply', 'no-reply', 'donotreply', 'do-not-reply',
      'automated', 'auto', 'system', 'daemon', 'robot', 'bot',
      'mailer-daemon', 'mailerdaemon'
    ];

    // Medium risk: admin, root, generic business accounts
    const mediumRisk = [
      'admin', 'administrator', 'root', 'webmaster',
      'info', 'contact', 'hello', 'team'
    ];

    if (highRisk.includes(localPart)) {
      return 'high';
    }
    if (mediumRisk.includes(localPart)) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Check for suspicious characteristics that might indicate a role account
   * @param {string} localPart - Local part to analyze
   * @returns {Object} Suspicious characteristics result
   */
  checkSuspiciousCharacteristics(localPart) {
    const result = {
      suspicious: false,
      confidence: 0,
      reasons: []
    };

    // Check for common role keywords
    const roleKeywords = [
      'admin', 'support', 'help', 'info', 'contact', 'team', 'service',
      'business', 'office', 'company', 'sales', 'marketing', 'tech',
      'system', 'auto', 'no', 'reply', 'mail', 'post', 'web', 'host'
    ];

    let keywordCount = 0;
    for (const keyword of roleKeywords) {
      if (localPart.includes(keyword)) {
        keywordCount++;
      }
    }

    if (keywordCount > 0) {
      result.confidence += keywordCount * 20;
      result.reasons.push(`Contains ${keywordCount} role-related keyword(s)`);
    }

    // Check for numeric suffixes (common in role accounts)
    if (/\d+$/.test(localPart)) {
      result.confidence += 15;
      result.reasons.push('Ends with numbers');
    }

    // Check for common separators in role accounts
    const separatorCount = (localPart.match(/[-_.]/g) || []).length;
    if (separatorCount > 1) {
      result.confidence += 10;
      result.reasons.push('Multiple separators');
    }

    // Check for very short local parts (often role accounts)
    if (localPart.length <= 3 && keywordCount > 0) {
      result.confidence += 25;
      result.reasons.push('Very short with role keywords');
    }

    // Check for common role account patterns
    if (/^(info|help|support|admin|contact|team|office|business)[\d_-]*$/i.test(localPart)) {
      result.confidence += 30;
      result.reasons.push('Matches common role account pattern');
    }

    // Check for department-like naming
    if (/^(hr|it|pr|qa|ops|dev|legal|sales|finance|billing)[\d_-]*$/i.test(localPart)) {
      result.confidence += 35;
      result.reasons.push('Matches department naming pattern');
    }

    result.suspicious = result.confidence >= 50;
    result.confidence = Math.min(100, result.confidence);

    return result;
  }

  /**
   * Get role account details
   * @param {string} localPart - Local part to analyze
   * @returns {Object} Detailed role account information
   */
  getRoleAccountDetails(localPart) {
    const result = this.isRoleAccount(localPart);

    if (result.isRole) {
      return {
        ...result,
        description: this.getDescription(localPart, result.category),
        recommendations: this.getRecommendations(result.category, result.risk),
        impact: this.getDeliverabilityImpact(result.category, result.risk)
      };
    }

    return result;
  }

  /**
   * Get description for role account
   * @param {string} localPart - Local part
   * @param {string} category - Role category
   * @returns {string} Description
   */
  getDescription(localPart, category) {
    const descriptions = {
      administrative: 'Administrative account typically used for system management',
      support: 'Customer support or help desk account',
      sales_marketing: 'Sales, marketing, or general business communication account',
      automated: 'Automated system account, typically no-reply',
      legal: 'Legal, compliance, or abuse-related account',
      hr: 'Human resources or recruitment account',
      finance: 'Billing, finance, or accounting account',
      departmental: 'Department or team-specific account',
      generic: 'Generic role or functional account'
    };

    return descriptions[category] || 'Role-based email account';
  }

  /**
   * Get recommendations for handling role accounts
   * @param {string} category - Role category
   * @param {string} risk - Risk level
   * @returns {Array} Array of recommendations
   */
  getRecommendations(category, risk) {
    const recommendations = [];

    if (risk === 'high') {
      recommendations.push('Consider excluding from marketing campaigns');
      recommendations.push('May not be monitored by real users');
    }

    if (category === 'automated') {
      recommendations.push('Likely an automated account - avoid sending emails');
      recommendations.push('May bounce or be ignored');
    }

    if (category === 'support' || category === 'sales_marketing') {
      recommendations.push('May be monitored by multiple users');
      recommendations.push('Could be appropriate for business communications');
    }

    if (category === 'administrative') {
      recommendations.push('Technical account - may not be appropriate for marketing');
      recommendations.push('Could be used for system notifications');
    }

    return recommendations;
  }

  /**
   * Get deliverability impact assessment
   * @param {string} category - Role category
   * @param {string} risk - Risk level
   * @returns {Object} Deliverability impact
   */
  getDeliverabilityImpact(category, risk) {
    const impact = {
      bounceRisk: 'low',
      spamRisk: 'low',
      engagementRisk: 'medium',
      recommendations: []
    };

    if (risk === 'high' || category === 'automated') {
      impact.bounceRisk = 'high';
      impact.engagementRisk = 'high';
      impact.recommendations.push('High risk of bounce or no engagement');
    }

    if (category === 'support' || category === 'sales_marketing') {
      impact.spamRisk = 'medium';
      impact.engagementRisk = 'low';
      impact.recommendations.push('May have better engagement for relevant content');
    }

    return impact;
  }

  /**
   * Check multiple local parts
   * @param {Array} localParts - Array of local parts to check
   * @returns {Array} Array of check results
   */
  checkMultipleAccounts(localParts) {
    return localParts.map(localPart => ({
      localPart: localPart,
      ...this.getRoleAccountDetails(localPart)
    }));
  }

  /**
   * Add custom role account
   * @param {string} localPart - Local part to add
   * @param {string} category - Category for the role account
   */
  addCustomRoleAccount(localPart, category = 'custom') {
    this.roleAccounts.add(localPart.toLowerCase().trim());
  }

  /**
   * Remove role account from detection
   * @param {string} localPart - Local part to remove
   */
  removeRoleAccount(localPart) {
    this.roleAccounts.delete(localPart.toLowerCase().trim());
  }

  /**
   * Get all known role accounts
   * @returns {Array} Array of role accounts
   */
  getAllRoleAccounts() {
    return Array.from(this.roleAccounts);
  }

  /**
   * Get role accounts by category
   * @param {string} category - Category to filter by
   * @returns {Array} Array of role accounts in category
   */
  getRoleAccountsByCategory(category) {
    const accounts = [];
    
    for (const account of this.roleAccounts) {
      const result = this.isRoleAccount(account);
      if (result.category === category) {
        accounts.push(account);
      }
    }

    return accounts;
  }
}

module.exports = RoleAccountDetector; 