/**
 * Base parser interface that all static analyzer parsers must implement.
 * Provides a consistent API for parsing different analyzer outputs.
 */
export class BaseParser {
  /**
   * @param {string} analyzerName - Name of the analyzer (semgrep, gitleaks, etc.)
   * @param {string} analyzerVersion - Version of the analyzer
   */
  constructor(analyzerName, analyzerVersion = 'unknown') {
    this.analyzerName = analyzerName;
    this.analyzerVersion = analyzerVersion;
  }

  /**
   * Parse the raw analyzer output into normalized vulnerabilities
   * @param {string|object} data - Raw analyzer output (JSON string or object)
   * @returns {Promise<NormalizedVulnerability[]>}
   */
  async parse(data) {
    throw new Error('parse() must be implemented by subclass');
  }

  /**
   * Validate that the input data is valid for this parser
   * @param {object} data - Parsed JSON data
   * @returns {boolean}
   */
  validate(data) {
    throw new Error('validate() must be implemented by subclass');
  }

  /**
   * Get the analyzer type identifier
   * @returns {string}
   */
  getType() {
    return this.analyzerName;
  }
}

/**
 * @typedef {Object} NormalizedVulnerability
 * @property {string} id - Unique identifier
 * @property {string} source - Analyzer name (semgrep, gitleaks, etc.)
 * @property {string} sourceVersion - Analyzer version
 * @property {string} type - Normalized type (injection, xss, secrets, etc.)
 * @property {string} subType - Specific subtype (SQLi, ReflectedXSS, etc.)
 * @property {string} severity - Normalized: CRITICAL, HIGH, MEDIUM, LOW, INFO
 * @property {string} confidence - Normalized: HIGH, MEDIUM, LOW
 * @property {Location} location - Code location information
 * @property {string} description - Vulnerability description
 * @property {string} remediation - Fix recommendation
 * @property {string[]} cwe - CWE identifiers
 * @property {string[]} owasp - OWASP categories
 * @property {number|null} cvss - CVSS score if available
 * @property {string[]} cve - CVE IDs if applicable
 * @property {object} metadata - Analyzer-specific metadata
 * @property {string} checkId - Original check/rule ID
 * @property {string} reference - Documentation URL
 */

/**
 * @typedef {Object} Location
 * @property {string} file - File path
 * @property {number} line - Line number
 * @property {number} column - Column number
 * @property {number} endLine - End line number
 * @property {number} endColumn - End column number
 * @property {string} snippet - Code snippet if available
 */
