const dns = require('dns').promises;
const logger = require('../utils/logger');

class DNSValidator {
  constructor() {
    this.timeout = parseInt(process.env.DNS_TIMEOUT) || 5000;
  }

  /**
   * Validate domain DNS records
   * @param {string} domain - Domain to validate
   * @returns {Object} DNS validation result
   */
  async validateDomain(domain) {
    const result = {
      isValid: false,
      hasARecord: false,
      hasAAAARecord: false,
      hasCNAMERecord: false,
      records: {
        A: [],
        AAAA: [],
        CNAME: []
      },
      errors: [],
      warnings: []
    };

    try {
      // Set DNS timeout
      const originalTimeout = dns.getServers();
      
      // Try to resolve A records (IPv4)
      try {
        const aRecords = await Promise.race([
          dns.resolve4(domain),
          new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), this.timeout))
        ]);
        
        if (aRecords && aRecords.length > 0) {
          result.hasARecord = true;
          result.records.A = aRecords;
          result.isValid = true;
        }
      } catch (error) {
        if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA') {
          result.warnings.push(`A record lookup failed: ${error.message}`);
        }
      }

      // Try to resolve AAAA records (IPv6)
      try {
        const aaaaRecords = await Promise.race([
          dns.resolve6(domain),
          new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), this.timeout))
        ]);
        
        if (aaaaRecords && aaaaRecords.length > 0) {
          result.hasAAAARecord = true;
          result.records.AAAA = aaaaRecords;
          result.isValid = true;
        }
      } catch (error) {
        if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA') {
          result.warnings.push(`AAAA record lookup failed: ${error.message}`);
        }
      }

      // Try to resolve CNAME records
      try {
        const cnameRecords = await Promise.race([
          dns.resolveCname(domain),
          new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), this.timeout))
        ]);
        
        if (cnameRecords && cnameRecords.length > 0) {
          result.hasCNAMERecord = true;
          result.records.CNAME = cnameRecords;
          // CNAME records indicate the domain exists
          result.isValid = true;
        }
      } catch (error) {
        if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA') {
          result.warnings.push(`CNAME record lookup failed: ${error.message}`);
        }
      }

      if (!result.isValid) {
        result.errors.push('Domain does not resolve to any valid DNS records');
      }

      return result;

    } catch (error) {
      logger.error(`DNS validation failed for domain ${domain}:`, error);
      result.errors.push('DNS validation failed');
      return result;
    }
  }

  /**
   * Validate MX records for domain
   * @param {string} domain - Domain to validate
   * @returns {Object} MX validation result
   */
  async validateMX(domain) {
    const result = {
      isValid: false,
      mxRecords: [],
      hasBackupMX: false,
      primaryMX: null,
      errors: [],
      warnings: []
    };

    try {
      const mxRecords = await Promise.race([
        dns.resolveMx(domain),
        new Promise((_, reject) => setTimeout(() => reject(new Error('MX timeout')), this.timeout))
      ]);

      if (!mxRecords || mxRecords.length === 0) {
        result.errors.push('No MX records found for domain');
        return result;
      }

      // Sort MX records by priority (lower number = higher priority)
      const sortedMX = mxRecords.sort((a, b) => a.priority - b.priority);
      
      result.mxRecords = sortedMX;
      result.primaryMX = sortedMX[0];
      result.hasBackupMX = sortedMX.length > 1;
      result.isValid = true;

      // Validate each MX record
      for (const mx of sortedMX) {
        try {
          await this.validateMXRecord(mx.exchange);
        } catch (error) {
          result.warnings.push(`MX record ${mx.exchange} validation failed: ${error.message}`);
        }
      }

      // Check for common MX misconfigurations
      this.checkMXMisconfigurations(sortedMX, result);

      return result;

    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        result.errors.push('No MX records found for domain');
      } else {
        logger.error(`MX validation failed for domain ${domain}:`, error);
        result.errors.push('MX record lookup failed');
      }
      return result;
    }
  }

  /**
   * Validate individual MX record
   * @param {string} mxHost - MX host to validate
   * @returns {Promise} Validation promise
   */
  async validateMXRecord(mxHost) {
    try {
      // Check if MX host resolves
      const addresses = await Promise.race([
        dns.resolve4(mxHost).catch(() => dns.resolve6(mxHost)),
        new Promise((_, reject) => setTimeout(() => reject(new Error('MX host timeout')), this.timeout))
      ]);

      if (!addresses || addresses.length === 0) {
        throw new Error(`MX host ${mxHost} does not resolve`);
      }

      return addresses;
    } catch (error) {
      throw new Error(`MX host validation failed: ${error.message}`);
    }
  }

  /**
   * Check for common MX misconfigurations
   * @param {Array} mxRecords - Sorted MX records
   * @param {Object} result - Result object to update
   */
  checkMXMisconfigurations(mxRecords, result) {
    // Check for null MX (RFC 7505)
    const nullMX = mxRecords.find(mx => mx.exchange === '.' || mx.exchange === '');
    if (nullMX) {
      if (mxRecords.length === 1 && nullMX.priority === 0) {
        result.warnings.push('Domain has null MX record - does not accept email');
        result.isValid = false;
      } else {
        result.warnings.push('Domain has null MX record in addition to valid MX records');
      }
    }

    // Check for localhost/loopback MX
    const localhostMX = mxRecords.find(mx => 
      mx.exchange.toLowerCase().includes('localhost') || 
      mx.exchange === '127.0.0.1' ||
      mx.exchange === '::1'
    );
    if (localhostMX) {
      result.warnings.push('Domain has localhost MX record - likely misconfigured');
    }

    // Check for wildcard MX
    const wildcardMX = mxRecords.find(mx => mx.exchange.startsWith('*.'));
    if (wildcardMX) {
      result.warnings.push('Domain has wildcard MX record');
    }

    // Check for duplicate priorities
    const priorities = mxRecords.map(mx => mx.priority);
    const uniquePriorities = [...new Set(priorities)];
    if (priorities.length !== uniquePriorities.length) {
      result.warnings.push('Domain has MX records with duplicate priorities');
    }

    // Check for unreasonable priority values
    const highPriority = mxRecords.find(mx => mx.priority > 65535);
    if (highPriority) {
      result.warnings.push('Domain has MX record with unreasonably high priority');
    }
  }

  /**
   * Get all DNS records for a domain
   * @param {string} domain - Domain to query
   * @returns {Object} All DNS records
   */
  async getAllDNSRecords(domain) {
    const records = {
      A: [],
      AAAA: [],
      MX: [],
      CNAME: [],
      TXT: [],
      NS: [],
      SOA: null
    };

    const recordTypes = [
      { type: 'A', method: dns.resolve4 },
      { type: 'AAAA', method: dns.resolve6 },
      { type: 'MX', method: dns.resolveMx },
      { type: 'CNAME', method: dns.resolveCname },
      { type: 'TXT', method: dns.resolveTxt },
      { type: 'NS', method: dns.resolveNs },
      { type: 'SOA', method: dns.resolveSoa }
    ];

    await Promise.allSettled(
      recordTypes.map(async ({ type, method }) => {
        try {
          const result = await Promise.race([
            method(domain),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), this.timeout))
          ]);

          if (type === 'SOA') {
            records[type] = result;
          } else {
            records[type] = result || [];
          }
        } catch (error) {
          // Ignore errors for optional record types
          logger.debug(`Failed to get ${type} records for ${domain}:`, error.message);
        }
      })
    );

    return records;
  }

  /**
   * Check if domain is parked
   * @param {string} domain - Domain to check
   * @returns {Object} Parked domain check result
   */
  async isParkedDomain(domain) {
    const result = {
      isParked: false,
      indicators: [],
      confidence: 0
    };

    try {
      // Get all DNS records
      const dnsRecords = await this.getAllDNSRecords(domain);

      // Common indicators of parked domains
      const parkingIndicators = [
        'parked',
        'parking',
        'sedo',
        'domainmarket',
        'sedoparking',
        'parkingcrew',
        'above.com',
        'bodis.com'
      ];

      // Check A records for parking services
      if (dnsRecords.A && dnsRecords.A.length > 0) {
        const aRecord = dnsRecords.A[0];
        
        // Common parking IP ranges
        const parkingIPs = [
          '198.105.254', // Sedo
          '69.46.86',    // Above.com
          '209.59.159',  // ParkingCrew
          '98.124.243'   // Bodis
        ];

        for (const parkingIP of parkingIPs) {
          if (aRecord.startsWith(parkingIP)) {
            result.indicators.push(`IP address indicates parking service: ${aRecord}`);
            result.confidence += 30;
          }
        }
      }

      // Check CNAME records
      if (dnsRecords.CNAME && dnsRecords.CNAME.length > 0) {
        for (const cname of dnsRecords.CNAME) {
          for (const indicator of parkingIndicators) {
            if (cname.toLowerCase().includes(indicator)) {
              result.indicators.push(`CNAME indicates parking: ${cname}`);
              result.confidence += 25;
            }
          }
        }
      }

      // Check MX records for parking indicators
      if (dnsRecords.MX && dnsRecords.MX.length > 0) {
        for (const mx of dnsRecords.MX) {
          for (const indicator of parkingIndicators) {
            if (mx.exchange.toLowerCase().includes(indicator)) {
              result.indicators.push(`MX record indicates parking: ${mx.exchange}`);
              result.confidence += 20;
            }
          }
        }
      }

      result.isParked = result.confidence >= 50;
      return result;

    } catch (error) {
      logger.error(`Parked domain check failed for ${domain}:`, error);
      return result;
    }
  }
}

module.exports = DNSValidator; 