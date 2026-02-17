import { SemgrepParser } from './parsers/semgrep-parser.js';
import { GitleaksParser } from './parsers/gitleaks-parser.js';
import { TrivyParser } from './parsers/trivy-parser.js';
import { OsvParser } from './parsers/osv-parser.js';
import { SyftParser } from './parsers/syft-parser.js';
import { NoirParser } from './parsers/noir-parser.js';
import { CodeQLParser } from './parsers/codeql-parser.js';

/**
 * Registry mapping analyzer types to their parser classes
 */
const PARSER_REGISTRY = Object.freeze({
  semgrep: SemgrepParser,
  gitleaks: GitleaksParser,
  trivy: TrivyParser,
  osv: OsvParser,
  syft: SyftParser,
  noir: NoirParser,
  codeql: CodeQLParser
});

/**
 * Detect analyzer type from JSON structure
 * @param {object} data - Parsed JSON data
 * @returns {string|null} Analyzer type or null if unknown
 */
export function detectAnalyzerType(data) {
  if (!data || typeof data !== 'object') {
    return null;
  }

  // Semgrep: has 'results' array and 'version' field
  if (data.results && data.version) {
    return 'semgrep';
  }
  
  // Gitleaks: has 'Findings' array or root is array with 'Secret'
  if (data.Findings || (Array.isArray(data) && data.length > 0 && data[0]?.Secret !== undefined)) {
    return 'gitleaks';
  }
  
  // Trivy: has 'Results' with 'Vulnerabilities' or 'Misconfigurations'
  if (data.Results && Array.isArray(data.Results)) {
    return 'trivy';
  }
  
  // OSV: has 'results' with 'packages' or 'vulns' array
  if (data.results && Array.isArray(data.results) && data.results[0]?.packages) {
    return 'osv';
  }
  if (data.vulns && Array.isArray(data.vulns)) {
    return 'osv';
  }
  
  // Syft: has 'artifacts' array and 'source'
  if (data.artifacts && data.source) {
    return 'syft';
  }
  
  // OWASP Noir: has 'endpoints' array
  if (data.endpoints && Array.isArray(data.endpoints)) {
    return 'noir';
  }
  
  // CodeQL: has 'runs' array with 'tool.driver.name' = 'CodeQL' (SARIF format)
  if (data.runs && Array.isArray(data.runs)) {
    const hasCodeQL = data.runs.some(run => run.tool?.driver?.name === 'CodeQL');
    if (hasCodeQL) {
      return 'codeql';
    }
  }
  
  return null;
}

/**
 * Create parser instance for the given analyzer type
 * @param {string} analyzerType - Type of analyzer (semgrep, gitleaks, etc.)
 * @returns {BaseParser} Parser instance
 * @throws {Error} If analyzer type is unknown
 */
export function createParser(analyzerType) {
  const ParserClass = PARSER_REGISTRY[analyzerType];
  
  if (!ParserClass) {
    throw new Error(`Unknown analyzer type: ${analyzerType}. Supported types: ${Object.keys(PARSER_REGISTRY).join(', ')}`);
  }
  
  return new ParserClass();
}

/**
 * Get list of supported analyzer types
 * @returns {string[]} Array of supported analyzer types
 */
export function getSupportedAnalyzers() {
  return Object.keys(PARSER_REGISTRY);
}

/**
 * Check if an analyzer type is supported
 * @deprecated Not imported anywhere — use createParser() which throws for unknown types.
 * @param {string} analyzerType - Type to check
 * @returns {boolean} True if supported
 */
export function isAnalyzerSupported(analyzerType) {
  return analyzerType in PARSER_REGISTRY;
}
