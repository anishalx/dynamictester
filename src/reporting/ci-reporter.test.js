import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CIReporter } from './ci-reporter.js';
import { fs, path } from 'zx';

describe('CIReporter', () => {
  let tempDir;
  let evidenceDir;

  beforeEach(async () => {
    tempDir = path.join(process.cwd(), '__test_ci_' + Date.now());
    evidenceDir = path.join(tempDir, 'evidence');
    await fs.ensureDir(evidenceDir);
  });

  afterEach(async () => {
    await fs.remove(tempDir).catch(() => {});
  });

  async function writeEvidence(classification, overrides = {}) {
    // randomUUID keeps filenames unique even when two writes land in the
    // same millisecond (Date.now() allowed a fast second write to overwrite
    // the first, making this test flaky on fast CI runners).
    const id = randomUUID();
    const finding = {
      findingId: `test-${id}`,
      classification,
      status: classification,
      level: classification === 'CONFIRMED' ? 3 : 0,
      ...overrides
    };
    const filePath = path.join(evidenceDir, `evidence-test-${id}.json`);
    await fs.writeJSON(filePath, finding);
  }

  describe('summarizeFindings', () => {
    it('should count classifications correctly', () => {
      const findings = [
        { classification: 'CONFIRMED' },
        { classification: 'CONFIRMED' },
        { classification: 'LIKELY' },
        { classification: 'BLOCKED' },
        { classification: 'NOT_REPRODUCIBLE' }
      ];

      const summary = CIReporter.summarizeFindings(findings);
      expect(summary.total).toBe(5);
      expect(summary.confirmed).toBe(2);
      expect(summary.likely).toBe(1);
      expect(summary.blocked).toBe(1);
      expect(summary.notReproducible).toBe(1);
    });

    it('should handle empty findings', () => {
      const summary = CIReporter.summarizeFindings([]);
      expect(summary.total).toBe(0);
      expect(summary.confirmed).toBe(0);
    });

    it('should handle null/undefined status gracefully', () => {
      const findings = [{ classification: null }, { status: undefined }];
      const summary = CIReporter.summarizeFindings(findings);
      expect(summary.total).toBe(2);
    });
  });

  describe('determineExitCode', () => {
    it('should return 1 for confirmed exploits', () => {
      const summary = { confirmed: 1, likely: 0, blocked: 0 };
      expect(CIReporter.determineExitCode(summary)).toBe(1);
    });

    it('should return 0 when no confirmed and no flags', () => {
      const summary = { confirmed: 0, likely: 3, blocked: 2 };
      expect(CIReporter.determineExitCode(summary)).toBe(0);
    });

    it('should return 1 for likely when failOnLikely is set', () => {
      const summary = { confirmed: 0, likely: 1, blocked: 0 };
      expect(CIReporter.determineExitCode(summary, { failOnLikely: true })).toBe(1);
    });

    it('should return 1 for blocked when failOnBlocked is set', () => {
      const summary = { confirmed: 0, likely: 0, blocked: 1 };
      expect(CIReporter.determineExitCode(summary, { failOnBlocked: true })).toBe(1);
    });

    it('should return 0 for blocked without failOnBlocked', () => {
      const summary = { confirmed: 0, likely: 0, blocked: 1 };
      expect(CIReporter.determineExitCode(summary)).toBe(0);
    });
  });

  describe('getExitReason', () => {
    it('should return PASS reason for exit code 0', () => {
      const reason = CIReporter.getExitReason(0, { confirmed: 0, notReproducible: 5, blocked: 0 });
      expect(reason).toContain('PASS');
    });

    it('should return FAIL reason for confirmed exploits', () => {
      const reason = CIReporter.getExitReason(1, { confirmed: 3, likely: 0, blocked: 0 });
      expect(reason).toContain('FAIL');
      expect(reason).toContain('3');
    });

    it('should return ERROR reason for exit code 2', () => {
      const reason = CIReporter.getExitReason(2, {});
      expect(reason).toContain('ERROR');
    });
  });

  describe('generateCIReport', () => {
    it('should generate CI report from evidence', async () => {
      await writeEvidence('CONFIRMED', { exploitation: { endpoint: '/api/test' } });
      await writeEvidence('NOT_REPRODUCIBLE');

      const report = await CIReporter.generateCIReport(evidenceDir);
      expect(report.summary.total).toBe(2);
      expect(report.summary.confirmed).toBe(1);
      expect(report.exitCode).toBe(1);
      expect(report.confirmedExploits.length).toBe(1);
    });

    it('should handle empty evidence directory', async () => {
      const report = await CIReporter.generateCIReport(evidenceDir);
      expect(report.summary.total).toBe(0);
      expect(report.exitCode).toBe(0);
      expect(report.exitReason).toContain('PASS');
    });

    it('should handle missing evidence directory', async () => {
      const nonExistentDir = path.join(tempDir, 'nonexistent');
      const report = await CIReporter.generateCIReport(nonExistentDir);
      expect(report.summary.total).toBe(0);
      expect(report.exitCode).toBe(0);
    });
  });
});
