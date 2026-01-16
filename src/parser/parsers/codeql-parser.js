import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, normalizeConfidence, categorizeVulnerability } from '../normalizer.js';

/**
 * Parser for CodeQL SARIF output
 */
export class CodeQLParser extends BaseParser {
  constructor() {
    super('codeql');
  }

  validate(data) {
    // CodeQL uses SARIF format with runs array
    if (!data || !Array.isArray(data.runs)) return false;
    // Check if it's actually CodeQL (not just any SARIF)
    return data.runs.some(run => run.tool?.driver?.name === 'CodeQL');
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    
    if (!this.validate(jsonData)) {
      throw new Error('Invalid CodeQL SARIF format');
    }

    const vulnerabilities = [];

    for (const run of jsonData.runs) {
      this.analyzerVersion = run.tool?.driver?.version || 'unknown';
      const rules = run.tool?.driver?.rules || [];
      const results = run.results || [];

      // Create rule lookup map
      const ruleMap = new Map();
      for (const rule of rules) {
        ruleMap.set(rule.id, rule);
      }

      for (const result of results) {
        const ruleId = result.ruleId;
        const rule = ruleMap.get(ruleId) || {};
        
        // Get primary location
        const location = result.locations?.[0]?.physicalLocation;
        const file = location?.artifactLocation?.uri || 'unknown';
        const region = location?.region || {};

        // Extract CWE from tags or properties
        const cwe = this.extractCWE(rule.properties?.tags || []);
        
        // Determine severity
        const level = result.level || 'warning';
        let severity = 'MEDIUM';
        if (level === 'error') severity = 'HIGH';
        if (level === 'warning') severity = 'MEDIUM';
        if (level === 'note') severity = 'LOW';
        
        // Override with rule severity if available
        if (rule.properties?.['security-severity']) {
          const score = parseFloat(rule.properties['security-severity']);
          if (score >= 9.0) severity = 'CRITICAL';
          else if (score >= 7.0) severity = 'HIGH';
          else if (score >= 4.0) severity = 'MEDIUM';
          else severity = 'LOW';
        }

        const { type, subType } = categorizeVulnerability({
          description: result.message?.text || rule.shortDescription?.text,
          checkId: ruleId,
          cwe
        });

        vulnerabilities.push({
          id: `CODEQL-${ruleId}-${file}-${region.startLine}`,
          source: 'codeql',
          sourceVersion: this.analyzerVersion,
          type,
          subType,
          severity: normalizeSeverity(severity),
          confidence: normalizeConfidence(rule.properties?.precision || 'MEDIUM'),
          location: {
            file: file ?? 'unknown',
            line: region.startLine ?? 0,
            column: region.startColumn ?? 0,
            endLine: region.endLine ?? region.startLine ?? 0,
            endColumn: region.endColumn ?? region.startColumn ?? 0,
            snippet: region.snippet?.text ?? ''
          },
          description: result.message?.text || rule.shortDescription?.text || '',
          remediation: rule.help?.text || '',
          cwe,
          owasp: this.extractOWASP(rule.properties?.tags || []),
          cvss: rule.properties?.['security-severity'] ? parseFloat(rule.properties['security-severity']) : null,
          cve: [],
          metadata: {
            ruleId,
            kind: result.kind,
            precision: rule.properties?.precision,
            problemSeverity: rule.properties?.['problem.severity'],
            tags: rule.properties?.tags
          },
          checkId: ruleId,
          reference: rule.helpUri || ''
        });
      }
    }

    return vulnerabilities;
  }

  extractCWE(tags) {
    const cwePattern = /cwe-(\d+)/i;
    const cweIds = [];
    
    for (const tag of tags) {
      const match = tag.match(cwePattern);
      if (match) {
        cweIds.push(`CWE-${match[1]}`);
      }
    }
    
    return cweIds;
  }

  extractOWASP(tags) {
    const owaspPattern = /owasp[:-]?(a\d+)/i;
    const owaspIds = [];
    
    for (const tag of tags) {
      const match = tag.match(owaspPattern);
      if (match) {
        owaspIds.push(match[1].toUpperCase());
      }
    }
    
    return owaspIds;
  }
}
