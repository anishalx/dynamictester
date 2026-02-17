import { createHash } from 'crypto';

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
 * Map vulnerability to internal type categories.
 * Comprehensive pattern matching for 18+ vulnerability classes with
 * CWE-based detection and keyword analysis across multiple indicators.
 *
 * @param {object} vuln - Vulnerability object with description, checkId, cwe, etc.
 * @returns {{type: string, subType: string, owasp: string[]}}
 */
export function categorizeVulnerability(vuln) {
  const cweArr = Array.isArray(vuln.cwe) ? vuln.cwe : (vuln.cwe ? [vuln.cwe] : []);
  const indicators = [
    vuln.description?.toLowerCase() || '',
    vuln.checkId?.toLowerCase() || '',
    cweArr.join(' ').toLowerCase(),
    vuln.metadata?.vulnerability_class?.join(' ')?.toLowerCase() || '',
    vuln.title?.toLowerCase() || '',
    vuln.message?.toLowerCase() || ''
  ].join(' ');

  // -------------------------------------------------------------------
  // Secrets / Hardcoded credentials (check first — very distinct)
  // -------------------------------------------------------------------
  if (/\bsecret\b|password|api[_-]?key|hardcoded.*token|token.*leak|expose.*token|credential|private[_-]?key|cwe-798|cwe-259|cwe-321/.test(indicators)) {
    if (/password/.test(indicators)) return { type: 'secrets', subType: 'HardcodedPassword', owasp: ['A02:2021'] };
    if (/api[_-]?key/.test(indicators)) return { type: 'secrets', subType: 'ExposedAPIKey', owasp: ['A02:2021'] };
    if (/private[_-]?key/.test(indicators)) return { type: 'secrets', subType: 'ExposedPrivateKey', owasp: ['A02:2021'] };
    return { type: 'secrets', subType: 'HardcodedSecret', owasp: ['A02:2021'] };
  }

  // -------------------------------------------------------------------
  // Injection vulnerabilities (NoSQL first — "nosql" contains "sql")
  // -------------------------------------------------------------------
  if (/nosql.*injection|mongodb.*injection|cwe-943/.test(indicators)) {
    return { type: 'injection', subType: 'NoSQLi', owasp: ['A03:2021'] };
  }
  if (/sql.*injection|cwe-89/.test(indicators)) {
    return { type: 'injection', subType: 'SQLi', owasp: ['A03:2021'] };
  }
  if (/command.*injection|os.*command|cwe-78|cwe-77/.test(indicators)) {
    return { type: 'injection', subType: 'CommandInjection', owasp: ['A03:2021'] };
  }
  if (/code.*injection|cwe-94|cwe-95|eval\s*\(|new\s+function/.test(indicators)) {
    return { type: 'injection', subType: 'CodeInjection', owasp: ['A03:2021'] };
  }
  if (/template.*injection|ssti|cwe-1336/.test(indicators)) {
    return { type: 'injection', subType: 'SSTI', owasp: ['A03:2021'] };
  }
  if (/ldap.*injection|cwe-90/.test(indicators)) {
    return { type: 'injection', subType: 'LDAPInjection', owasp: ['A03:2021'] };
  }
  if (/xpath.*injection|cwe-643/.test(indicators)) {
    return { type: 'injection', subType: 'XPathInjection', owasp: ['A03:2021'] };
  }
  if (/header.*injection|http.*response.*split|crlf|cwe-113|cwe-644/.test(indicators)) {
    return { type: 'injection', subType: 'HeaderInjection', owasp: ['A03:2021'] };
  }
  if (/expression.*language|el.*injection|ognl|spel|cwe-917/.test(indicators)) {
    return { type: 'injection', subType: 'ELInjection', owasp: ['A03:2021'] };
  }

  // -------------------------------------------------------------------
  // XSS — Reflected, Stored, DOM
  // -------------------------------------------------------------------
  if (/xss|cross.*site.*script|cwe-79/.test(indicators)) {
    if (/stored|persistent/.test(indicators)) return { type: 'xss', subType: 'StoredXSS', owasp: ['A03:2021'] };
    if (/dom[_-]?(xss|based)|dom[_-]?manipulation|\bdom\b/.test(indicators)) return { type: 'xss', subType: 'DOMXSS', owasp: ['A03:2021'] };
    return { type: 'xss', subType: 'ReflectedXSS', owasp: ['A03:2021'] };
  }

  // -------------------------------------------------------------------
  // XXE
  // -------------------------------------------------------------------
  if (/xxe|xml.*external.*entity|cwe-611/.test(indicators)) {
    return { type: 'xxe', subType: 'XXE', owasp: ['A05:2021'] };
  }

  // -------------------------------------------------------------------
  // SSRF
  // -------------------------------------------------------------------
  if (/ssrf|server.*side.*request|cwe-918/.test(indicators)) {
    return { type: 'ssrf', subType: 'SSRF', owasp: ['A10:2021'] };
  }

  // -------------------------------------------------------------------
  // CSRF
  // -------------------------------------------------------------------
  if (/csrf|cross.*site.*request.*forgery|cwe-352/.test(indicators)) {
    return { type: 'csrf', subType: 'CSRF', owasp: ['A01:2021'] };
  }

  // -------------------------------------------------------------------
  // Deserialization
  // -------------------------------------------------------------------
  if (/deserialization|deserialize|cwe-502|prototype.*pollut|cwe-1321/.test(indicators)) {
    if (/prototype.*pollut|cwe-1321/.test(indicators)) {
      return { type: 'deserialization', subType: 'PrototypePollution', owasp: ['A08:2021'] };
    }
    return { type: 'deserialization', subType: 'InsecureDeserialization', owasp: ['A08:2021'] };
  }

  // -------------------------------------------------------------------
  // Open Redirect
  // -------------------------------------------------------------------
  if (/open.*redirect|unvalidated.*redirect|url.*redirect|cwe-601/.test(indicators)) {
    return { type: 'redirect', subType: 'OpenRedirect', owasp: ['A01:2021'] };
  }

  // -------------------------------------------------------------------
  // Path Traversal / Local File Inclusion
  // -------------------------------------------------------------------
  if (/path.*traversal|directory.*traversal|local.*file.*inclu|lfi|cwe-22|cwe-23|cwe-36/.test(indicators)) {
    return { type: 'traversal', subType: 'PathTraversal', owasp: ['A01:2021'] };
  }

  // -------------------------------------------------------------------
  // File Upload
  // -------------------------------------------------------------------
  if (/file.*upload|unrestricted.*upload|cwe-434/.test(indicators)) {
    return { type: 'upload', subType: 'FileUpload', owasp: ['A04:2021'] };
  }

  // -------------------------------------------------------------------
  // IDOR / Broken Access Control
  // -------------------------------------------------------------------
  if (/idor|insecure.*direct.*object|broken.*access.*control|cwe-639|cwe-284|cwe-285/.test(indicators)) {
    return { type: 'access', subType: 'IDOR', owasp: ['A01:2021'] };
  }

  // -------------------------------------------------------------------
  // Authentication issues
  // -------------------------------------------------------------------
  if (/\bauthenticat(?:e|ion|ed)\b|broken.*auth|cwe-287|cwe-306|cwe-522|session.*fixat|cwe-384/.test(indicators)) {
    if (/session.*fixat|cwe-384/.test(indicators)) {
      return { type: 'auth', subType: 'SessionFixation', owasp: ['A07:2021'] };
    }
    return { type: 'auth', subType: 'Authentication', owasp: ['A07:2021'] };
  }

  // -------------------------------------------------------------------
  // CORS misconfiguration
  // -------------------------------------------------------------------
  if (/cors|cross.*origin.*resource|cwe-942|access-control-allow-origin/.test(indicators)) {
    return { type: 'config', subType: 'CORSMisconfiguration', owasp: ['A05:2021'] };
  }

  // -------------------------------------------------------------------
  // Insecure cookies / headers
  // -------------------------------------------------------------------
  if (/insecure.*cookie|missing.*httponly|missing.*secure.*flag|samesite|cwe-614|cwe-1004/.test(indicators)) {
    return { type: 'config', subType: 'InsecureCookie', owasp: ['A05:2021'] };
  }
  if (/missing.*header|security.*header|x-frame-options|x-content-type|strict-transport|cwe-693|cwe-1021/.test(indicators)) {
    return { type: 'config', subType: 'MissingSecurityHeader', owasp: ['A05:2021'] };
  }

  // -------------------------------------------------------------------
  // Cryptography
  // -------------------------------------------------------------------
  if (/crypto|encrypt|\bhash\b|cwe-327|cwe-326|cwe-328|weak.*algorithm|\bmd5\b|\bsha-?1\b|\b3?des\b|\brc4\b/.test(indicators)) {
    return { type: 'crypto', subType: 'WeakCrypto', owasp: ['A02:2021'] };
  }

  // -------------------------------------------------------------------
  // Dependency / Supply-chain
  // -------------------------------------------------------------------
  if (/\bcve-\d{4}-\d+\b|vulnerable.*depend|outdated.*package|known.*vulnerab/.test(indicators)) {
    return { type: 'dependency', subType: 'VulnerableDependency', owasp: ['A06:2021'] };
  }

  return { type: 'other', subType: 'Unknown', owasp: [] };
}

/**
 * Generate a deterministic, content-based ID for a vulnerability.
 * Uses a SHA-256 hash of (source + checkId + file + line) so the same
 * finding always produces the same ID — enabling cross-parser dedup.
 *
 * @param {string} source - Analyzer name
 * @param {string} checkId - Check/rule ID
 * @param {object} location - Location object
 * @returns {string} Deterministic vulnerability ID
 */
export function generateVulnerabilityId(source, checkId, location) {
  const loc = location || {};
  const normalizedSource = (source || 'unknown').toUpperCase();
  const file = loc.file || 'unknown';
  const line = loc.line || 0;
  const col = loc.column || 0;

  // Build a canonical key from the four identity components
  const canonical = [
    normalizedSource,
    (checkId || 'UNKNOWN'),
    file,
    String(line),
    String(col)
  ].join('|');

  const hash = createHash('sha256').update(canonical).digest('hex').substring(0, 12);
  const fileShort = file.split('/').pop();

  return `${normalizedSource}-${checkId || 'UNKNOWN'}-${fileShort}-${line}-${hash}`;
}
