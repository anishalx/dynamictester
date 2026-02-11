import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, normalizeConfidence, categorizeVulnerability } from '../normalizer.js';

/**
 * Parser for Semgrep static analyzer output
 */
export class SemgrepParser extends BaseParser {
  constructor() {
    super('semgrep');
  }

  validate(data) {
    return data && (data.results || data.findings);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid Semgrep JSON format - missing results or findings array');
    }

    this.analyzerVersion = jsonData.version || 'unknown';
    const findings = jsonData.results || jsonData.findings || [];
    const vulnerabilities = [];

    for (const finding of findings) {
      const { type, subType } = categorizeVulnerability({
        checkId: finding.check_id,
        description: finding.extra?.message,
        cwe: finding.extra?.metadata?.cwe,
        metadata: finding.extra?.metadata
      });

      vulnerabilities.push({
        id: finding.check_id || `SEMGREP-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`,
        source: 'semgrep',
        sourceVersion: this.analyzerVersion,
        type,
        subType,
        severity: normalizeSeverity(finding.extra?.severity || 'ERROR'),
        confidence: normalizeConfidence(finding.extra?.metadata?.confidence || 'MEDIUM'),
        location: {
          file: finding.path || 'unknown',
          line: finding.start?.line || 0,
          column: finding.start?.col || 0,
          endLine: finding.end?.line || 0,
          endColumn: finding.end?.col || 0,
          snippet: finding.extra?.lines || ''
        },
        description: finding.extra?.message || '',
        remediation: finding.extra?.metadata?.fix || '',
        cwe: finding.extra?.metadata?.cwe || [],
        owasp: finding.extra?.metadata?.owasp || [],
        cvss: null,
        cve: [],
        metadata: {
          ...finding.extra?.metadata,
          vulnerability_class: finding.extra?.metadata?.vulnerability_class
        },
        checkId: finding.check_id,
        reference: finding.extra?.metadata?.shortlink || ''
      });
    }

    return vulnerabilities;
  }
}
