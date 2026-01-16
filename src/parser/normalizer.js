/**
 * Data normalization utilities to ensure consistent field values across analyzers
 */

/**
 * Normalize severity to standard levels
 * @param {string|number} severity - Raw severity value
 * @returns {string} Normalized severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
 */
export function normalizeSeverity(severity) {
  const s = String(severity).toUpperCase();
  if (['CRITICAL', 'BLOCKER'].includes(s)) return 'CRITICAL';
  if (['HIGH', 'ERROR'].includes(s)) return 'HIGH';
  if (['MEDIUM', 'WARNING', 'MODERATE'].includes(s)) return 'MEDIUM';
  if (['LOW', 'MINOR'].includes(s)) return 'LOW';
  if (['INFO', 'INFORMATIONAL', 'NOTE'].includes(s)) return 'INFO';
  return 'MEDIUM'; // Default
}

/**
 * Normalize confidence level
 * @param {string} confidence - Raw confidence value
 * @returns {string} Normalized confidence (HIGH, MEDIUM, LOW)
 */
export function normalizeConfidence(confidence) {
  const c = String(confidence).toUpperCase();
  if (['HIGH', 'CERTAIN'].includes(c)) return 'HIGH';
  if (['MEDIUM', 'LIKELY'].includes(c)) return 'MEDIUM';
  if (['LOW', 'POSSIBLE'].includes(c)) return 'LOW';
  return 'MEDIUM'; // Default
}

/**
 * Map vulnerability to internal type categories
 * @param {object} vuln - Vulnerability object with description, checkId, cwe, etc.
 * @returns {{type: string, subType: string}}
 */
export function categorizeVulnerability(vuln) {
  const indicators = [
    vuln.description?.toLowerCase() || '',
    vuln.checkId?.toLowerCase() || '',
    vuln.cwe?.join(' ') || '',
    vuln.metadata?.vulnerability_class?.join(' ')?.toLowerCase() || ''
  ].join(' ');

  // Secrets detection
  if (/secret|password|api[_-]?key|token|credential|private[_-]?key/.test(indicators)) {
    return { type: 'secrets', subType: 'HardcodedSecret', owasp: ['A02:2021'] };
  }

  // Injection vulnerabilities
  if (/sql.*injection|cwe-89/.test(indicators)) {
    return { type: 'injection', subType: 'SQLi', owasp: ['A03:2021'] };
  }
  if (/command.*injection|cwe-78|cwe-77/.test(indicators)) {
    return { type: 'injection', subType: 'CommandInjection', owasp: ['A03:2021'] };
  }
  if (/code.*injection|cwe-94|cwe-95|eval/.test(indicators)) {
    return { type: 'injection', subType: 'CodeInjection', owasp: ['A03:2021'] };
  }
  if (/template.*injection|ssti/.test(indicators)) {
    return { type: 'injection', subType: 'SSTI', owasp: ['A03:2021'] };
  }
  if (/ldap.*injection|cwe-90/.test(indicators)) {
    return { type: 'injection', subType: 'LDAPInjection', owasp: ['A03:2021'] };
  }
  if (/xpath.*injection|cwe-643/.test(indicators)) {
    return { type: 'injection', subType: 'XPathInjection', owasp: ['A03:2021'] };
  }

  // XSS
  if (/xss|cross.*site.*script|cwe-79/.test(indicators)) {
    if (/stored/.test(indicators)) return { type: 'xss', subType: 'StoredXSS', owasp: ['A03:2021'] };
    if (/dom/.test(indicators)) return { type: 'xss', subType: 'DOMXSS', owasp: ['A03:2021'] };
    return { type: 'xss', subType: 'ReflectedXSS', owasp: ['A03:2021'] };
  }

  // XXE
  if (/xxe|xml.*external.*entity|cwe-611/.test(indicators)) {
    return { type: 'xxe', subType: 'XXE', owasp: ['A05:2021'] };
  }

  // SSRF
  if (/ssrf|server.*side.*request|cwe-918/.test(indicators)) {
    return { type: 'ssrf', subType: 'SSRF', owasp: ['A10:2021'] };
  }

  // CSRF
  if (/csrf|cross.*site.*request.*forgery|cwe-352/.test(indicators)) {
    return { type: 'csrf', subType: 'CSRF', owasp: ['A01:2021'] };
  }

  // Deserialization
  if (/deserialization|deserialize|cwe-502/.test(indicators)) {
    return { type: 'deserialization', subType: 'InsecureDeserialization', owasp: ['A08:2021'] };
  }

  // Open Redirect
  if (/open.*redirect|unvalidated.*redirect|cwe-601/.test(indicators)) {
    return { type: 'redirect', subType: 'OpenRedirect', owasp: ['A01:2021'] };
  }

  // Authentication
  if (/auth(?!z)|cwe-287|cwe-306/.test(indicators)) {
    return { type: 'auth', subType: 'Authentication', owasp: ['A07:2021'] };
  }

  // Cryptography
  if (/crypto|encrypt|hash|cwe-327|cwe-326|weak.*algorithm/.test(indicators)) {
    return { type: 'crypto', subType: 'WeakCrypto', owasp: ['A02:2021'] };
  }

  // Path Traversal
  if (/path.*traversal|directory.*traversal|cwe-22/.test(indicators)) {
    return { type: 'traversal', subType: 'PathTraversal', owasp: ['A01:2021'] };
  }

  // File Upload
  if (/file.*upload|unrestricted.*upload|cwe-434/.test(indicators)) {
    return { type: 'upload', subType: 'FileUpload', owasp: ['A04:2021'] };
  }

  // IDOR / Broken Access Control
  if (/idor|insecure.*direct.*object|cwe-639/.test(indicators)) {
    return { type: 'access', subType: 'IDOR', owasp: ['A01:2021'] };
  }

  return { type: 'other', subType: 'Unknown', owasp: [] };
}

/**
 * Generate a unique ID for a vulnerability
 * @param {string} source - Analyzer name
 * @param {string} checkId - Check/rule ID
 * @param {object} location - Location object
 * @returns {string}
 */
export function generateVulnerabilityId(source, checkId, location) {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 11);
  const fileHash = location.file ? location.file.split('/').pop() : 'unknown';
  const line = location.line || 0;
  
  return `${source.toUpperCase()}-${checkId || 'UNKNOWN'}-${fileHash}-${line}-${random}`;
}
