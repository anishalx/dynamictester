import { describe, it, expect } from 'vitest';
import { detectAnalyzerType, createParser, getSupportedAnalyzers, isAnalyzerSupported } from './parser-factory.js';

describe('ParserFactory', () => {
  describe('detectAnalyzerType', () => {
    it('should detect Semgrep output', () => {
      const data = { results: [], version: '1.56.0' };
      expect(detectAnalyzerType(data)).toBe('semgrep');
    });

    it('should detect Gitleaks v8+ format (array with Secret)', () => {
      const data = [{ Secret: 'my-secret', RuleID: 'generic-rule' }];
      expect(detectAnalyzerType(data)).toBe('gitleaks');
    });

    it('should detect Gitleaks v7 format (Findings array)', () => {
      const data = { Findings: [{ Secret: 'my-secret' }] };
      expect(detectAnalyzerType(data)).toBe('gitleaks');
    });

    it('should detect Trivy output', () => {
      const data = { Results: [] };
      expect(detectAnalyzerType(data)).toBe('trivy');
    });

    it('should detect OSV output (results format)', () => {
      const data = { results: [{ packages: [] }] };
      expect(detectAnalyzerType(data)).toBe('osv');
    });

    it('should detect OSV output (vulns format)', () => {
      const data = { vulns: [] };
      expect(detectAnalyzerType(data)).toBe('osv');
    });

    it('should detect Syft SBOM output', () => {
      const data = { artifacts: [], source: { id: 'test' } };
      expect(detectAnalyzerType(data)).toBe('syft');
    });

    it('should detect Noir output', () => {
      const data = { endpoints: [] };
      expect(detectAnalyzerType(data)).toBe('noir');
    });

    it('should detect CodeQL SARIF output', () => {
      const data = { runs: [{ tool: { driver: { name: 'CodeQL' } } }] };
      expect(detectAnalyzerType(data)).toBe('codeql');
    });

    it('should return null for unknown format', () => {
      expect(detectAnalyzerType({})).toBeNull();
      expect(detectAnalyzerType(null)).toBeNull();
      expect(detectAnalyzerType(undefined)).toBeNull();
    });
  });

  describe('createParser', () => {
    it('should create parsers for all supported types', () => {
      const types = getSupportedAnalyzers();
      for (const type of types) {
        const parser = createParser(type);
        expect(parser).toBeDefined();
        expect(parser.getType()).toBe(type);
      }
    });

    it('should throw for unknown analyzer type', () => {
      expect(() => createParser('unknown')).toThrow('Unknown analyzer type');
    });
  });

  describe('getSupportedAnalyzers', () => {
    it('should return array of supported analyzer names', () => {
      const analyzers = getSupportedAnalyzers();
      expect(Array.isArray(analyzers)).toBe(true);
      expect(analyzers).toContain('semgrep');
      expect(analyzers).toContain('gitleaks');
      expect(analyzers).toContain('trivy');
      expect(analyzers).toContain('osv');
      expect(analyzers).toContain('syft');
      expect(analyzers).toContain('noir');
      expect(analyzers).toContain('codeql');
    });
  });
});
