import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, normalizeConfidence } from '../normalizer.js';

/**
 * Parser for Syft SBOM (Software Bill of Materials) output
 * Note: Syft generates SBOMs, not vulnerabilities. Use with Grype for vulnerability scanning.
 */
export class SyftParser extends BaseParser {
  constructor() {
    super('syft');
  }

  validate(data) {
    // Syft SBOM format has artifacts and source
    return data && (data.artifacts || data.source);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid Syft JSON format - expected SBOM structure');
    }

    this.analyzerVersion = jsonData.descriptor?.version || 'unknown';
    const vulnerabilities = [];

    // Note: Syft primarily generates SBOMs, not vulnerabilities
    // However, we can extract package information for dependency tracking
    // This is more useful when combined with Grype vulnerability data
    
    const artifacts = jsonData.artifacts || [];
    
    for (const artifact of artifacts) {
      // Only flag packages with known issues if metadata exists
      if (artifact.metadata?.vulnerabilities) {
        for (const vuln of artifact.metadata.vulnerabilities) {
          vulnerabilities.push({
            id: vuln.id || `SYFT-${artifact.name}-${artifact.version}`,
            source: 'syft',
            sourceVersion: this.analyzerVersion,
            type: 'dependency',
            subType: 'VulnerableDependency',
            severity: normalizeSeverity(vuln.severity || 'MEDIUM'),
            confidence: 'MEDIUM',
            location: {
              file: artifact.locations?.[0]?.path || 'dependencies',
              line: 0,
              column: 0,
              endLine: 0,
              endColumn: 0,
              snippet: `${artifact.name}@${artifact.version}`
            },
            description: vuln.description || `Dependency: ${artifact.name}@${artifact.version}`,
            remediation: vuln.fixedInVersion ? `Update to ${vuln.fixedInVersion}` : 'Review dependency',
            cwe: [],
            owasp: [],
            cvss: null,
            cve: [],
            metadata: {
              pkgName: artifact.name,
              installedVersion: artifact.version,
              type: artifact.type,
              purl: artifact.purl,
              cpes: artifact.cpes,
              licenses: artifact.licenses
            },
            checkId: vuln.id || artifact.id,
            reference: ''
          });
        }
      }
    }

    // If no vulnerabilities found, this is just an SBOM (which is normal for Syft)
    return vulnerabilities;
  }
}
