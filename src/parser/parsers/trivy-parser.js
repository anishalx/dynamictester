import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, generateVulnerabilityId } from '../normalizer.js';

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
        const vulnLocation = {
            file: target,
            line: 0,
            column: 0,
            endLine: 0,
            endColumn: 0,
            snippet: `${vuln.PkgName}@${vuln.InstalledVersion}`
          };

        vulnerabilities.push({
          id: generateVulnerabilityId('trivy', vuln.VulnerabilityID, vulnLocation),
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type: 'dependency',
          subType: 'VulnerableDependency',
          severity: normalizeSeverity(vuln.Severity),
          confidence: 'HIGH',
          location: vulnLocation,
          description: vuln.Title || vuln.Description || '',
          remediation: vuln.FixedVersion ? `Update ${vuln.PkgName} to version ${vuln.FixedVersion}` : 'No fix available',
          cwe: vuln.CweIDs || [],
          owasp: [],
          cvss: vuln.CVSS ? (() => {
            const scores = Object.values(vuln.CVSS).map(c => c.V3Score || 0).filter(s => s > 0);
            return scores.length > 0 ? Math.max(...scores) : null;
          })() : null,
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
        const misconfigLocation = {
            file: misconfig.CauseMetadata?.Resource || target,
            line: misconfig.CauseMetadata?.StartLine || 0,
            column: 0,
            endLine: misconfig.CauseMetadata?.EndLine || 0,
            endColumn: 0,
            snippet: misconfig.CauseMetadata?.Code?.Lines?.[0]?.Content || ''
          };
        
        vulnerabilities.push({
          id: generateVulnerabilityId('trivy', misconfig.ID, misconfigLocation),
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type,
          subType,
          severity: normalizeSeverity(misconfig.Severity),
          confidence: 'MEDIUM',
          location: misconfigLocation,
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
        const secretLocation = {
            file: target,
            line: secret.StartLine || 0,
            column: 0,
            endLine: secret.EndLine || 0,
            endColumn: 0,
            snippet: secret.Match || ''
          };

        vulnerabilities.push({
          id: generateVulnerabilityId('trivy', secret.RuleID, secretLocation),
          source: 'trivy',
          sourceVersion: this.analyzerVersion,
          type: 'secrets',
          subType: 'HardcodedSecret',
          severity: normalizeSeverity(secret.Severity),
          confidence: 'HIGH',
          location: secretLocation,
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
