import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, normalizeConfidence } from '../normalizer.js';

/**
 * Parser for Trivy vulnerability scanner output
 */
export class TrivyParser extends BaseParser {
  constructor() {
    super('trivy');
  }

  validate(data) {
    return data && Array.isArray(data.Results);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid Trivy JSON format - missing Results array');
    }

    this.analyzerVersion = jsonData.SchemaVersion || 'unknown';
    const vulnerabilities = [];

    for (const result of jsonData.Results) {
      const target = result.Target;
      
      // Process vulnerabilities (CVEs in dependencies)
      for (const vuln of result.Vulnerabilities || []) {
        vulnerabilities.push({
          id: vuln.VulnerabilityID,
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type: 'dependency',
          subType: 'VulnerableDependency',
          severity: normalizeSeverity(vuln.Severity),
          confidence: 'HIGH',
          location: {
            file: target,
            line: 0,
            column: 0,
            endLine: 0,
            endColumn: 0,
            snippet: `${vuln.PkgName}@${vuln.InstalledVersion}`
          },
          description: vuln.Title || vuln.Description || '',
          remediation: vuln.FixedVersion ? `Update ${vuln.PkgName} to version ${vuln.FixedVersion}` : 'No fix available',
          cwe: vuln.CweIDs || [],
          owasp: [],
          cvss: vuln.CVSS ? Math.max(...Object.values(vuln.CVSS).map(c => c.V3Score || 0)) : null,
          cve: [vuln.VulnerabilityID],
          metadata: {
            pkgName: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            references: vuln.References,
            publishedDate: vuln.PublishedDate,
            lastModifiedDate: vuln.LastModifiedDate
          },
          checkId: vuln.VulnerabilityID,
          reference: vuln.PrimaryURL || ''
        });
      }

      // Process misconfigurations
      for (const misconfig of result.Misconfigurations || []) {
        const { type, subType } = this.mapMisconfigType(misconfig);
        
        vulnerabilities.push({
          id: misconfig.ID,
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type,
          subType,
          severity: normalizeSeverity(misconfig.Severity),
          confidence: 'MEDIUM',
          location: {
            file: misconfig.CauseMetadata?.Resource || target,
            line: misconfig.CauseMetadata?.StartLine || 0,
            column: 0,
            endLine: misconfig.CauseMetadata?.EndLine || 0,
            endColumn: 0,
            snippet: misconfig.CauseMetadata?.Code?.Lines?.[0]?.Content || ''
          },
          description: misconfig.Title || misconfig.Message,
          remediation: misconfig.Resolution || '',
          cwe: [],
          owasp: [],
          cvss: null,
          cve: [],
          metadata: {
            type: misconfig.Type,
            category: misconfig.Category,
            avdid: misconfig.AVDID
          },
          checkId: misconfig.ID,
          reference: misconfig.PrimaryURL || ''
        });
      }

      // Process secrets found in container images
      for (const secret of result.Secrets || []) {
        vulnerabilities.push({
          id: `TRIVY-SECRET-${secret.RuleID}-${secret.StartLine}`,
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type: 'secrets',
          subType: 'HardcodedSecret',
          severity: normalizeSeverity(secret.Severity),
          confidence: 'HIGH',
          location: {
            file: secret.Match || target,
            line: secret.StartLine || 0,
            column: 0,
            endLine: secret.EndLine || 0,
            endColumn: 0,
            snippet: secret.Match || ''
          },
          description: `Secret detected: ${secret.Title}`,
          remediation: 'Remove hardcoded secret',
          cwe: ['CWE-798'],
          owasp: ['A07:2021 – Identification and Authentication Failures'],
          cvss: null,
          cve: [],
          metadata: {
            ruleId: secret.RuleID,
            category: secret.Category
          },
          checkId: secret.RuleID,
          reference: ''
        });
      }
    }

    return vulnerabilities;
  }

  mapMisconfigType(misconfig) {
    const type = String(misconfig.Type || '').toLowerCase();
    const title = String(misconfig.Title || '').toLowerCase();
    
    if (type.includes('secret') || title.includes('secret')) {
      return { type: 'secrets', subType: 'HardcodedSecret' };
    }
    if (type.includes('crypto') || title.includes('crypto') || title.includes('encryption')) {
      return { type: 'crypto', subType: 'WeakCrypto' };
    }
    if (title.includes('auth')) {
      return { type: 'auth', subType: 'Authentication' };
    }
    
    return { type: 'config', subType: 'Misconfiguration' };
  }
}
