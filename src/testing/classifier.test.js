import { describe, it, expect } from 'vitest';
import { VulnerabilityClassifier } from './classifier.js';

describe('VulnerabilityClassifier', () => {
  describe('classify', () => {
    it('should classify Level 3+ as CONFIRMED', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: { dataExtracted: ['admin', 'password123'] }
      });
      expect(result.classification).toBe('CONFIRMED');
      expect(result.level).toBe(3);
      expect(result.ciExitCode).toBe(1);
      expect(result.requiresAction).toBe(true);
    });

    it('should classify Level 4 (critical impact) as CONFIRMED', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: { criticalImpact: true, adminAccess: true }
      });
      expect(result.classification).toBe('CONFIRMED');
      expect(result.level).toBe(4);
      expect(result.ciExitCode).toBe(1);
    });

    it('should classify Level 1-2 with external blocker as BLOCKED', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: { injectionConfirmed: true },
        externalBlocker: 'Authentication required'
      });
      expect(result.classification).toBe('BLOCKED');
      expect(result.ciExitCode).toBe(0);
    });

    it('should classify Level 1-2 with security blocker as NOT_REPRODUCIBLE', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: { errorDetected: true },
        securityBlocker: 'WAF blocking'
      });
      expect(result.classification).toBe('NOT_REPRODUCIBLE');
      expect(result.ciExitCode).toBe(0);
    });

    it('should classify Level 1-2 without blocker as LIKELY', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: { injectionConfirmed: true }
      });
      expect(result.classification).toBe('LIKELY');
      expect(result.ciExitCode).toBe(0);
    });

    it('should classify Level 0 as NOT_REPRODUCIBLE', () => {
      const result = VulnerabilityClassifier.classify({
        evidence: {}
      });
      expect(result.classification).toBe('NOT_REPRODUCIBLE');
      expect(result.level).toBe(0);
      expect(result.ciExitCode).toBe(0);
    });

    it('should handle null input gracefully', () => {
      const result = VulnerabilityClassifier.classify(null);
      expect(result.classification).toBe('NOT_REPRODUCIBLE');
      expect(result.ciExitCode).toBe(0);
    });

    it('should handle missing evidence', () => {
      const result = VulnerabilityClassifier.classify({});
      expect(result.classification).toBe('NOT_REPRODUCIBLE');
    });
  });

  describe('analyzeBlocker', () => {
    it('should identify security controls', () => {
      const result = VulnerabilityClassifier.analyzeBlocker({
        blockerDescription: 'WAF block detected',
        securityReason: 'Input validation prevented injection'
      });
      expect(result.isSecurityControl).toBe(true);
    });

    it('should identify external constraints', () => {
      const result = VulnerabilityClassifier.analyzeBlocker({
        blockerDescription: 'Authentication required, server unavailable'
      });
      expect(result.isExternalConstraint).toBe(true);
    });

    it('should handle both security and external', () => {
      const result = VulnerabilityClassifier.analyzeBlocker({
        blockerDescription: 'WAF block and rate limit'
      });
      expect(result.isSecurityControl).toBe(true);
      expect(result.isExternalConstraint).toBe(true);
    });

    it('should handle empty blocker', () => {
      const result = VulnerabilityClassifier.analyzeBlocker({});
      expect(result.isSecurityControl).toBe(false);
      expect(result.isExternalConstraint).toBe(false);
    });
  });

  describe('summarize', () => {
    it('should summarize classification results', () => {
      const classifications = [
        { classification: 'CONFIRMED', level: 4, requiresAction: true },
        { classification: 'CONFIRMED', level: 3, requiresAction: true },
        { classification: 'LIKELY', level: 1, requiresAction: true },
        { classification: 'BLOCKED', level: 2, requiresAction: true },
        { classification: 'NOT_REPRODUCIBLE', level: 0, requiresAction: false }
      ];

      const summary = VulnerabilityClassifier.summarize(classifications);
      expect(summary.total).toBe(5);
      expect(summary.confirmed).toBe(2);
      expect(summary.likely).toBe(1);
      expect(summary.blocked).toBe(1);
      expect(summary.notReproducible).toBe(1);
      expect(summary.ciExitCode).toBe(1);
      expect(summary.requiresAction).toBe(4);
      expect(summary.criticalImpact).toBe(1);
    });

    it('should calculate exploitable rate', () => {
      const classifications = [
        { classification: 'CONFIRMED', level: 3 },
        { classification: 'LIKELY', level: 1 },
        { classification: 'NOT_REPRODUCIBLE', level: 0 }
      ];

      const summary = VulnerabilityClassifier.summarize(classifications);
      expect(summary.exploitableRate).toBe('66.7%');
    });

    it('should handle empty classifications', () => {
      const summary = VulnerabilityClassifier.summarize([]);
      expect(summary.total).toBe(0);
      expect(summary.ciExitCode).toBe(0);
    });
  });
});
