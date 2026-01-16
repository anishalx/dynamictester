import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, normalizeConfidence, categorizeVulnerability } from '../normalizer.js';

/**
 * Parser for OWASP Noir API security scanner output
 */
export class NoirParser extends BaseParser {
  constructor() {
    super('noir');
  }

  validate(data) {
    // Noir output has endpoints and can have vulnerabilities
    return data && (data.endpoints !== undefined);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid Noir JSON format - expected endpoints');
    }

    this.analyzerVersion = jsonData.version || 'unknown';
    const vulnerabilities = [];

    // Process endpoints for security issues
    for (const endpoint of jsonData.endpoints || []) {
      const url = endpoint.url || endpoint.path || 'unknown';
      const method = endpoint.method || 'GET';
      
      // Check for security issues in endpoint
      if (endpoint.vulnerabilities) {
        for (const vuln of endpoint.vulnerabilities) {
          const { type, subType } = categorizeVulnerability({
            description: vuln.type || vuln.message,
            checkId: vuln.id
          });

          // Extract CWE from vulnerability metadata if available
          const extractedCwe = this.extractCWE(vuln.cwe || vuln.tags || []);

          vulnerabilities.push({
            id: vuln.id || `NOIR-${method}-${url}-${Date.now()}`,
            source: 'noir',
            sourceVersion: this.analyzerVersion,
            type,
            subType,
            severity: normalizeSeverity(vuln.severity || 'MEDIUM'),
            confidence: normalizeConfidence(vuln.confidence || 'MEDIUM'),
            location: {
              file: endpoint.file ?? 'api',
              line: endpoint.line ?? 0,
              column: endpoint.column ?? 0,
              endLine: endpoint.endLine ?? endpoint.line ?? 0,
              endColumn: endpoint.endColumn ?? 0,
              snippet: `${method} ${url}`
            },
            description: vuln.message || vuln.type || '',
            remediation: vuln.remediation || '',
            cwe: extractedCwe,
            owasp: vuln.owasp || [],
            cvss: vuln.cvss ?? null,
            cve: vuln.cve || [],
            metadata: {
              endpoint: url,
              method,
              params: endpoint.params,
              headers: endpoint.headers
            },
            checkId: vuln.id,
            reference: vuln.reference || ''
          });
        }
      }

      // Check for missing security headers
      if (endpoint.missingHeaders && endpoint.missingHeaders.length > 0) {
        vulnerabilities.push({
          id: `NOIR-HEADERS-${method}-${url}`,
          source: 'noir',
          sourceVersion: this.analyzerVersion,
          type: 'config',
          subType: 'MissingSecurityHeaders',
          severity: 'LOW',
          confidence: 'HIGH',
          location: {
            file: endpoint.file || 'api',
            line: endpoint.line || 0,
            column: 0,
            endLine: 0,
            endColumn: 0,
            snippet: `${method} ${url}`
          },
          description: `Missing security headers: ${endpoint.missingHeaders.join(', ')}`,
          remediation: 'Add security headers to the response',
          cwe: [],
          owasp: ['A05:2021 – Security Misconfiguration'],
          cvss: null,
          cve: [],
          metadata: {
            endpoint: url,
            method,
            missingHeaders: endpoint.missingHeaders
          },
          checkId: 'missing-security-headers',
          reference: ''
        });
      }
    }

    return vulnerabilities;
  }

  /**
   * Extract CWE identifiers from tags or metadata
   * @param {string[]|string} tags - Array of tags or comma-separated string
   * @returns {string[]} Array of CWE identifiers
   */
  extractCWE(tags) {
    const cwePattern = /cwe[:-]?(\d+)/gi;
    const cweIds = [];
    
    const tagArray = Array.isArray(tags) ? tags : String(tags).split(',');
    for (const tag of tagArray) {
      const matches = String(tag).matchAll(cwePattern);
      for (const match of matches) {
        cweIds.push(`CWE-${match[1]}`);
      }
    }
    
    return [...new Set(cweIds)]; // Deduplicate
  }
}
