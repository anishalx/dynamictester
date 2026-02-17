import { BaseParser } from '../parser-interface.js';
import { generateVulnerabilityId } from '../normalizer.js';

/**
 * Parser for Gitleaks secret scanner output
 */
export class GitleaksParser extends BaseParser {
  constructor() {
    super('gitleaks');
  }

  validate(data) {
    // Gitleaks v8+ format: array of findings
    if (Array.isArray(data) && data.length > 0 && data[0].Secret !== undefined) return true;
    // Gitleaks v7 format: object with Findings array
    if (data && Array.isArray(data.Findings)) return true;
    // Empty results are valid
    if (Array.isArray(data) && data.length === 0) return true;
    return false;
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid Gitleaks JSON format');
    }

    // Support both v7 and v8+ formats
    const findings = Array.isArray(jsonData) ? jsonData : (jsonData.Findings || []);
    const vulnerabilities = [];

    for (const finding of findings) {
      const secretType = this.mapSecretType(finding.RuleID || finding.Description);
      const location = {
          file: finding.File ?? 'unknown',
          line: finding.StartLine ?? 0,
          column: finding.StartColumn ?? 0,
          endLine: finding.EndLine ?? finding.StartLine ?? 0,
          endColumn: finding.EndColumn ?? finding.StartColumn ?? 0,
          snippet: finding.Secret ? `[REDACTED - ${finding.Secret.length} chars]` : ''
        };
      
      vulnerabilities.push({
        id: generateVulnerabilityId('gitleaks', finding.RuleID, location),
        source: 'gitleaks',
        sourceVersion: this.analyzerVersion,
        type: 'secrets',
        subType: secretType,
        severity: 'HIGH', // Secrets are always high severity
        confidence: 'HIGH',
        location,
        description: finding.Description || `Secret detected: ${finding.RuleID}`,
        remediation: 'Remove hardcoded secret and use environment variables or secret management system',
        cwe: ['CWE-798'],
        owasp: ['A07:2021 – Identification and Authentication Failures'],
        cvss: null,
        cve: [],
        metadata: {
          ruleId: finding.RuleID,
          commit: finding.Commit,
          author: finding.Author,
          email: finding.Email,
          date: finding.Date,
          tags: finding.Tags,
          fingerprint: finding.Fingerprint
        },
        checkId: finding.RuleID,
        reference: ''
      });
    }

    return vulnerabilities;
  }

  mapSecretType(ruleId) {
    const rid = String(ruleId).toLowerCase();
    if (rid.includes('aws')) return 'AWSKey';
    if (rid.includes('github')) return 'GitHubToken';
    if (rid.includes('gitlab')) return 'GitLabToken';
    if (rid.includes('slack')) return 'SlackToken';
    if (rid.includes('jwt')) return 'JWT';
    if (rid.includes('private') && rid.includes('key')) return 'PrivateKey';
    if (rid.includes('api') || rid.includes('key')) return 'APIKey';
    if (rid.includes('generic')) return 'GenericSecret';
    return 'HardcodedSecret';
  }
}
