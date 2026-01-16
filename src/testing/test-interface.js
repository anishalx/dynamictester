/**
 * Base class for dynamic vulnerability testing
 * Implements Shannon's 3-stage exploitation workflow
 */
export class VulnerabilityTester {
  /**
   * @param {string} vulnerabilityType - Type of vulnerability (SQLi, XSS, etc.)
   * @param {string} targetUrl - Target application URL
   * @param {string} evidenceDir - Directory to store evidence
   */
  constructor(vulnerabilityType, targetUrl, evidenceDir) {
    this.vulnerabilityType = vulnerabilityType;
    this.targetUrl = targetUrl;
    this.evidenceDir = evidenceDir;
    this.testResults = [];
  }

  /**
   * Execute complete testing workflow
   * @param {object} vulnerability - Vulnerability from queue
   * @returns {Promise<TestResult>}
   */
  async test(vulnerability) {
    throw new Error(`test() must be implemented by ${this.constructor.name}`);
  }

  /**
   * Stage 1: Confirmation & Probing
   * Goal: Validate that vulnerability exists (not false positive)
   * 
   * Success indicators:
   * - Database error messages appear
   * - Response content changes based on boolean logic
   * - Measurable timing differences
   * 
   * @param {object} vuln - Vulnerability to test
   * @returns {Promise<{confirmed: boolean, attempts: Array, method: string}>}
   */
  async confirmVulnerability(vuln) {
    throw new Error(`confirmVulnerability() must be implemented by ${this.constructor.name}`);
  }

  /**
   * Stage 2: Fingerprinting & Enumeration
   * Goal: Understand environment to enable targeted exploitation
   * Only executed if Stage 1 succeeds
   * 
   * Actions:
   * - Extract database version
   * - Identify current user
   * - List table names
   * - Identify sensitive tables
   * 
   * @param {object} vuln - Vulnerability to fingerprint
   * @returns {Promise<{manipulated: boolean, fingerprint: object, attempts: Array}>}
   */
  async fingerprint(vuln) {
    throw new Error(`fingerprint() must be implemented by ${this.constructor.name}`);
  }

  /**
   * Stage 3: Targeted Exfiltration
   * Goal: Extract actual data as proof of exploitation
   * Only executed if Stage 2 succeeds
   * 
   * Evidence requirements:
   * - Actual data retrieved (not just error messages)
   * - Reproducible commands
   * - Complete payloads with context
   * 
   * @param {object} vuln - Vulnerability to exploit
   * @param {object} fingerprint - Environment fingerprint from Stage 2
   * @returns {Promise<{data: Array, critical: boolean, attempts: Array}>}
   */
  async exploit(vuln, fingerprint) {
    throw new Error(`exploit() must be implemented by ${this.constructor.name}`);
  }

  /**
   * Classify result based on evidence
   * @param {object} evidence - Test evidence
   * @returns {string} Classification: EXPLOITED, POTENTIAL, FALSE_POSITIVE
   */
  classify(evidence) {
    if (evidence.level >= 3) return 'EXPLOITED';
    if (evidence.externalBlocker) return 'POTENTIAL';
    return 'FALSE_POSITIVE';
  }

  /**
   * Generate test report
   * @param {object} result - Test result
   * @returns {string} Formatted report
   */
  generateReport(result) {
    const classification = this.classify(result.evidence);
    
    return {
      id: result.id,
      type: this.vulnerabilityType,
      classification,
      level: result.evidence.level || 0,
      confidence: result.evidence.confidence || 'UNKNOWN',
      totalAttempts: result.attempts?.length || 0,
      bypassAttempts: result.bypassAttempts || 0,
      evidence: result.evidence,
      includeInReport: classification !== 'FALSE_POSITIVE'
    };
  }
}

/**
 * @typedef {Object} TestResult
 * @property {string} id - Vulnerability ID
 * @property {object} vulnerability - Original vulnerability data
 * @property {object} evidence - Collected evidence
 * @property {boolean} evidence.injectionConfirmed - Stage 1 success
 * @property {boolean} evidence.queryManipulated - Stage 2 success
 * @property {Array} evidence.dataExtracted - Stage 3 data
 * @property {boolean} evidence.criticalImpact - Critical impact achieved
 * @property {number} evidence.level - Exploitation level (0-4)
 * @property {Array} attempts - All test attempts
 * @property {number} bypassAttempts - Number of bypass attempts
 * @property {string} [externalBlocker] - External constraint description
 * @property {string} [blockerReason] - Reason blocked
 * @property {string} [securityBlocker] - Security control description
 * @property {string} [securityReason] - Security reason
 * @property {string} [error] - Error message if test failed
 */
