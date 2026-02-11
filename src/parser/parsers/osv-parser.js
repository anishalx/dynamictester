import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity } from '../normalizer.js';

/**
 * Parser for OSV (Open Source Vulnerabilities) scanner output
 */
export class OsvParser extends BaseParser {
  constructor() {
    super('osv');
  }

  validate(data) {
    // OSV scanner output format: { results: [ { packages: [], source: {} } ] }
    if (data && Array.isArray(data.results)) return true;
    // Alternative format: { vulns: [ ... ] }
    if (data && Array.isArray(data.vulns)) return true;
    return false;
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid OSV JSON format');
    }

    const vulnerabilities = [];

    // Handle new format with results array
    if (jsonData.results) {
      for (const result of jsonData.results) {
        const source = result.source || {};
        
        for (const pkg of result.packages || []) {
          const packageName = pkg.package?.name || 'unknown';
          const version = pkg.package?.version || 'unknown';
          
          for (const vuln of pkg.vulnerabilities || []) {
            vulnerabilities.push(this.createVulnerability(vuln, packageName, version, source));
          }
        }
      }
    }
    
    // Handle old format with vulns array
    if (jsonData.vulns) {
      for (const vuln of jsonData.vulns) {
        vulnerabilities.push(this.createVulnerability(vuln, 'unknown', 'unknown', {}));
      }
    }

    return vulnerabilities;
  }

  createVulnerability(vuln, packageName, version, source) {
    // Calculate severity from CVSS if available
    let severity = 'MEDIUM';
    let cvssScore = null;
    
    if (vuln.database_specific?.severity) {
      severity = normalizeSeverity(vuln.database_specific.severity);
    } else if (vuln.severity) {
      // OSV severity format: [{ type: "CVSS_V3", score: "CVSS:3.1/..." }]
      for (const sev of vuln.severity || []) {
        if (sev.type === 'CVSS_V3' && typeof sev.baseScore === 'number') {
          // Use explicit base score if provided
          cvssScore = sev.baseScore;
        } else if (sev.score && !sev.score.startsWith('CVSS:')) {
          // Numeric score provided directly (not a vector string)
          cvssScore = parseFloat(sev.score);
        }
        // Note: CVSS vector strings (e.g. "CVSS:3.1/AV:N/...") do not contain
        // the numeric base score — they require a CVSS calculator to derive it.
        // We skip vector-only entries and fall through to database_specific.severity.
        if (cvssScore !== null && !isNaN(cvssScore)) {
          if (cvssScore >= 9.0) severity = 'CRITICAL';
          else if (cvssScore >= 7.0) severity = 'HIGH';
          else if (cvssScore >= 4.0) severity = 'MEDIUM';
          else severity = 'LOW';
        }
      }
    }

    const fixedVersions = vuln.affected?.[0]?.ranges?.[0]?.events
      ?.filter(e => e.fixed)
      .map(e => e.fixed) || [];

    return {
      id: vuln.id,
      source: 'osv',
      sourceVersion: this.analyzerVersion,
      type: 'dependency',
      subType: 'VulnerableDependency',
      severity,
      confidence: 'HIGH',
      location: {
        file: source.path || 'package.json',
        line: 0,
        column: 0,
        endLine: 0,
        endColumn: 0,
        snippet: `${packageName}@${version}`
      },
      description: vuln.summary || vuln.details || '',
      remediation: fixedVersions.length > 0 
        ? `Update to version ${fixedVersions[0]} or later`
        : 'No fix available yet',
      cwe: vuln.database_specific?.cwe_ids || [],
      owasp: [],
      cvss: cvssScore,
      cve: vuln.aliases?.filter(a => a.startsWith('CVE-')) || [],
      metadata: {
        pkgName: packageName,
        installedVersion: version,
        fixedVersions,
        ecosystem: vuln.affected?.[0]?.package?.ecosystem,
        aliases: vuln.aliases,
        references: vuln.references?.map(r => r.url)
      },
      checkId: vuln.id,
      reference: vuln.references?.[0]?.url || `https://osv.dev/vulnerability/${vuln.id}`
    };
  }
}
