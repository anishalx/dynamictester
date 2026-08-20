import { describe, it, expect } from 'vitest';
import { validateVulnerability, validateVulnerabilities, checkDuplicates } from './validator.js';

describe('Validator', () => {
  const validVuln = {
    id: 'SEMGREP-test-1',
    source: 'semgrep',
    type: 'injection',
    severity: 'HIGH',
    location: { file: 'test.js', line: 10 },
    description: 'SQL injection found'
  };

  describe('validateVulnerability', () => {
    it('should validate a correct vulnerability', () => {
      const result = validateVulnerability(validVuln);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should catch missing required fields', () => {
      const result = validateVulnerability({});
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject null input', () => {
      const result = validateVulnerability(null);
      expect(result.valid).toBe(false);
    });

    it('should reject non-object input', () => {
      const result = validateVulnerability('string');
      expect(result.valid).toBe(false);
    });

    it('should catch invalid severity', () => {
      const vuln = { ...validVuln, severity: 'INVALID' };
      const result = validateVulnerability(vuln);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('severity'))).toBe(true);
    });

    it('should catch invalid confidence', () => {
      const vuln = { ...validVuln, confidence: 'INVALID' };
      const result = validateVulnerability(vuln);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('confidence'))).toBe(true);
    });

    it('should catch missing location.file', () => {
      const vuln = { ...validVuln, location: { line: 10 } };
      const result = validateVulnerability(vuln);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('location.file'))).toBe(true);
    });

    it('should accept valid severities', () => {
      for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
        const vuln = { ...validVuln, severity: sev };
        const result = validateVulnerability(vuln);
        expect(result.valid).toBe(true);
      }
    });
  });

  describe('validateVulnerabilities', () => {
    it('should validate an array of valid vulnerabilities', () => {
      const result = validateVulnerabilities([validVuln, { ...validVuln, id: 'test-2' }]);
      expect(result.valid).toBe(true);
      expect(result.totalCount).toBe(2);
      expect(result.validCount).toBe(2);
    });

    it('should handle mixed valid/invalid', () => {
      const result = validateVulnerabilities([validVuln, {}]);
      expect(result.valid).toBe(false);
      expect(result.invalidCount).toBe(1);
    });

    it('should handle non-array input', () => {
      const result = validateVulnerabilities('not-array');
      expect(result.valid).toBe(false);
    });

    it('should handle empty array', () => {
      const result = validateVulnerabilities([]);
      expect(result.valid).toBe(true);
      expect(result.totalCount).toBe(0);
    });
  });

  describe('checkDuplicates', () => {
    it('should detect duplicate IDs', () => {
      const vulns = [
        { id: 'test-1', source: 'semgrep' },
        { id: 'test-2', source: 'trivy' },
        { id: 'test-1', source: 'gitleaks' }
      ];
      const result = checkDuplicates(vulns);
      expect(result.hasDuplicates).toBe(true);
      expect(result.duplicates.length).toBe(1);
    });

    it('should return no duplicates for unique IDs', () => {
      const vulns = [
        { id: 'test-1', source: 'semgrep' },
        { id: 'test-2', source: 'trivy' }
      ];
      const result = checkDuplicates(vulns);
      expect(result.hasDuplicates).toBe(false);
    });
  });
});
