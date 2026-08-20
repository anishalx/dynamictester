import { describe, it, expect } from 'vitest';
import { normalizeSeverity, normalizeConfidence, categorizeVulnerability, generateVulnerabilityId } from './normalizer.js';

describe('Normalizer', () => {
  describe('normalizeSeverity', () => {
    it('should normalize CRITICAL and BLOCKER to CRITICAL', () => {
      expect(normalizeSeverity('CRITICAL')).toBe('CRITICAL');
      expect(normalizeSeverity('BLOCKER')).toBe('CRITICAL');
      expect(normalizeSeverity('critical')).toBe('CRITICAL');
    });

    it('should normalize HIGH and ERROR to HIGH', () => {
      expect(normalizeSeverity('HIGH')).toBe('HIGH');
      expect(normalizeSeverity('ERROR')).toBe('HIGH');
      expect(normalizeSeverity('high')).toBe('HIGH');
    });

    it('should normalize MEDIUM, WARNING, MODERATE to MEDIUM', () => {
      expect(normalizeSeverity('MEDIUM')).toBe('MEDIUM');
      expect(normalizeSeverity('WARNING')).toBe('MEDIUM');
      expect(normalizeSeverity('MODERATE')).toBe('MEDIUM');
    });

    it('should normalize LOW and MINOR to LOW', () => {
      expect(normalizeSeverity('LOW')).toBe('LOW');
      expect(normalizeSeverity('MINOR')).toBe('LOW');
    });

    it('should normalize INFO, INFORMATIONAL, NOTE to INFO', () => {
      expect(normalizeSeverity('INFO')).toBe('INFO');
      expect(normalizeSeverity('INFORMATIONAL')).toBe('INFO');
      expect(normalizeSeverity('NOTE')).toBe('INFO');
    });

    it('should default unknown severity to MEDIUM', () => {
      expect(normalizeSeverity('UNKNOWN')).toBe('MEDIUM');
      expect(normalizeSeverity('')).toBe('MEDIUM');
      expect(normalizeSeverity(null)).toBe('MEDIUM');
    });
  });

  describe('normalizeConfidence', () => {
    it('should normalize HIGH and CERTAIN to HIGH', () => {
      expect(normalizeConfidence('HIGH')).toBe('HIGH');
      expect(normalizeConfidence('CERTAIN')).toBe('HIGH');
    });

    it('should normalize MEDIUM and LIKELY to MEDIUM', () => {
      expect(normalizeConfidence('MEDIUM')).toBe('MEDIUM');
      expect(normalizeConfidence('LIKELY')).toBe('MEDIUM');
    });

    it('should normalize LOW and POSSIBLE to LOW', () => {
      expect(normalizeConfidence('LOW')).toBe('LOW');
      expect(normalizeConfidence('POSSIBLE')).toBe('LOW');
    });

    it('should default unknown to MEDIUM', () => {
      expect(normalizeConfidence('UNKNOWN')).toBe('MEDIUM');
      expect(normalizeConfidence('')).toBe('MEDIUM');
    });
  });

  describe('categorizeVulnerability', () => {
    it('should detect secrets / hardcoded credentials', () => {
      const result = categorizeVulnerability({ description: 'Hardcoded api_key found', checkId: 'gitleaks' });
      expect(result.type).toBe('secrets');
    });

    it('should detect SQL injection', () => {
      const result = categorizeVulnerability({ description: 'SQL injection vulnerability', checkId: 'sql-injection' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('SQLi');
    });

    it('should detect NoSQL injection', () => {
      const result = categorizeVulnerability({ description: 'NoSQL injection in MongoDB query', checkId: 'nosql' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('NoSQLi');
    });

    it('should detect command injection', () => {
      const result = categorizeVulnerability({ description: 'OS command injection', checkId: 'cmd-inject' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('CommandInjection');
    });

    it('should detect XSS', () => {
      const result = categorizeVulnerability({ description: 'Cross-site scripting vulnerability', checkId: 'xss' });
      expect(result.type).toBe('xss');
    });

    it('should detect stored XSS', () => {
      const result = categorizeVulnerability({ description: 'Stored XSS vulnerability', checkId: 'stored-xss' });
      expect(result.type).toBe('xss');
      expect(result.subType).toBe('StoredXSS');
    });

    it('should detect DOM XSS', () => {
      const result = categorizeVulnerability({ description: 'DOM-based XSS', checkId: 'dom-xss' });
      expect(result.type).toBe('xss');
      expect(result.subType).toBe('DOMXSS');
    });

    it('should detect XXE', () => {
      const result = categorizeVulnerability({ description: 'XML external entity', checkId: 'xxe' });
      expect(result.type).toBe('xxe');
    });

    it('should detect SSRF', () => {
      const result = categorizeVulnerability({ description: 'Server-side request forgery', checkId: 'ssrf' });
      expect(result.type).toBe('ssrf');
    });

    it('should detect CSRF', () => {
      const result = categorizeVulnerability({ description: 'Cross-site request forgery', checkId: 'csrf' });
      expect(result.type).toBe('csrf');
    });

    it('should detect path traversal', () => {
      const result = categorizeVulnerability({ description: 'Path traversal vulnerability', checkId: 'traversal' });
      expect(result.type).toBe('traversal');
    });

    it('should detect open redirect', () => {
      const result = categorizeVulnerability({ description: 'Open redirect vulnerability', checkId: 'redirect' });
      expect(result.type).toBe('redirect');
    });

    it('should detect deserialization', () => {
      const result = categorizeVulnerability({ description: 'Insecure deserialization', checkId: 'deser' });
      expect(result.type).toBe('deserialization');
    });

    it('should detect prototype pollution', () => {
      const result = categorizeVulnerability({ description: 'Prototype pollution', checkId: 'proto-pollution' });
      expect(result.type).toBe('deserialization');
      expect(result.subType).toBe('PrototypePollution');
    });

    it('should detect file upload', () => {
      const result = categorizeVulnerability({ description: 'Unrestricted file upload', checkId: 'upload' });
      expect(result.type).toBe('upload');
    });

    it('should detect IDOR', () => {
      const result = categorizeVulnerability({ description: 'Insecure direct object reference', checkId: 'idor' });
      expect(result.type).toBe('access');
    });

    it('should detect authentication issues', () => {
      const result = categorizeVulnerability({ description: 'Broken authentication', checkId: 'auth' });
      expect(result.type).toBe('auth');
    });

    it('should detect session fixation', () => {
      const result = categorizeVulnerability({ description: 'Session fixation vulnerability', checkId: 'session-fix' });
      expect(result.type).toBe('auth');
      expect(result.subType).toBe('SessionFixation');
    });

    it('should detect CORS misconfiguration', () => {
      const result = categorizeVulnerability({ description: 'CORS misconfiguration', checkId: 'cors' });
      expect(result.type).toBe('config');
    });

    it('should detect weak cryptography', () => {
      const result = categorizeVulnerability({ description: 'Weak MD5 hashing algorithm', checkId: 'crypto' });
      expect(result.type).toBe('crypto');
    });

    it('should detect vulnerable dependencies via CVE', () => {
      const result = categorizeVulnerability({ description: 'CVE-2023-12345 found in lodash', checkId: 'cve' });
      expect(result.type).toBe('dependency');
    });

    it('should detect SSTI', () => {
      const result = categorizeVulnerability({ description: 'Server-side template injection', checkId: 'ssti' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('SSTI');
    });

    it('should detect LDAP injection', () => {
      const result = categorizeVulnerability({ description: 'LDAP injection', checkId: 'ldap' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('LDAPInjection');
    });

    it('should detect header injection / CRLF', () => {
      const result = categorizeVulnerability({ description: 'HTTP response splitting via CRLF', checkId: 'crlf' });
      expect(result.type).toBe('injection');
      expect(result.subType).toBe('HeaderInjection');
    });

    it('should detect missing security headers', () => {
      const result = categorizeVulnerability({ description: 'Missing X-Frame-Options header', checkId: 'missing-header' });
      expect(result.type).toBe('config');
      expect(result.subType).toBe('MissingSecurityHeader');
    });

    it('should detect insecure cookies', () => {
      const result = categorizeVulnerability({ description: 'Missing HttpOnly flag on cookie', checkId: 'cookie' });
      expect(result.type).toBe('config');
      expect(result.subType).toBe('InsecureCookie');
    });

    it('should return other for unknown vulnerability types', () => {
      const result = categorizeVulnerability({ description: 'Something unknown', checkId: 'unknown' });
      expect(result.type).toBe('other');
    });

    it('should handle null/undefined input gracefully', () => {
      const result = categorizeVulnerability({});
      expect(result.type).toBeDefined();
    });
  });

  describe('generateVulnerabilityId', () => {
    it('should generate deterministic IDs', () => {
      const id1 = generateVulnerabilityId('semgrep', 'sql-injection', { file: 'test.js', line: 10, column: 5 });
      const id2 = generateVulnerabilityId('semgrep', 'sql-injection', { file: 'test.js', line: 10, column: 5 });
      expect(id1).toBe(id2);
    });

    it('should generate different IDs for different inputs', () => {
      const id1 = generateVulnerabilityId('semgrep', 'sql-injection', { file: 'test.js', line: 10 });
      const id2 = generateVulnerabilityId('semgrep', 'sql-injection', { file: 'test.js', line: 20 });
      expect(id1).not.toBe(id2);
    });

    it('should handle missing location gracefully', () => {
      const id = generateVulnerabilityId('semgrep', 'test', null);
      expect(typeof id).toBe('string');
      expect(id).toContain('SEMGREP');
    });

    it('should include source name in uppercase', () => {
      const id = generateVulnerabilityId('gitleaks', 'rule', { file: 'test.js', line: 1 });
      expect(id).toContain('GITLEAKS');
    });
  });
});
