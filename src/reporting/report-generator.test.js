import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateSarifReport, generateHtmlReport, generateDeveloperSummary, generateAllReports } from './report-generator.js';
import { fs, path } from 'zx';

describe('ReportGenerator', () => {
  let tempDir;
  let evidenceDir;

  beforeEach(async () => {
    tempDir = path.join(process.cwd(), '__test_report_' + Date.now());
    evidenceDir = path.join(tempDir, 'evidence');
    await fs.ensureDir(evidenceDir);
  });

  afterEach(async () => {
    await fs.remove(tempDir).catch(() => {});
  });

  const sampleFindings = [
    {
      findingId: 'SEMGREP-sqli-1',
      timestamp: '2025-01-01T00:00:00Z',
      sourceLocation: { file: 'routes/login.js', line: 34, column: 10 },
      vulnerability: { type: 'SQL Injection', cwe: 'CWE-89', owasp: ['A03:2021'] },
      exploitation: { endpoint: '/api/login', method: 'POST', payload: "' OR '1'='1'--", success: true, proof: 'Admin access gained' },
      remediation: 'Use parameterized queries',
      classification: 'CONFIRMED',
      status: 'CONFIRMED',
      level: 4,
      levelName: 'Critical Impact Demonstrated',
      confidence: 'CRITICAL',
      classificationReason: 'Data extraction proven',
      includeInReport: true,
      requiresAction: true,
      ciExitCode: 1
    },
    {
      findingId: 'GITLEAKS-key-1',
      timestamp: '2025-01-01T00:00:00Z',
      sourceLocation: { file: 'config.js', line: 5, column: 1 },
      vulnerability: { type: 'Hardcoded Secret', cwe: 'CWE-798' },
      exploitation: { endpoint: 'N/A', method: 'N/A', payload: '', success: false, proof: '' },
      classification: 'NOT_REPRODUCIBLE',
      status: 'NOT_REPRODUCIBLE',
      level: 0,
      levelName: 'No Exploitation',
      confidence: 'N/A',
      classificationReason: 'Secret is redacted in repo',
      includeInReport: false,
      requiresAction: false,
      ciExitCode: 0
    }
  ];

  async function writeEvidenceFiles(findings) {
    for (const f of findings) {
      const filePath = path.join(evidenceDir, `evidence-${f.findingId}-${Date.now()}.json`);
      await fs.writeJSON(filePath, f, { spaces: 2 });
    }
  }

  describe('generateSarifReport', () => {
    it('should generate valid SARIF 2.1.0 report', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'report.sarif.json');
      const sarif = await generateSarifReport(evidenceDir, outputPath, {}, null);

      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe('DynamicSecurityTester');
      expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    });

    it('should assign DST-NNN rule IDs', async () => {
      await writeEvidenceFiles([sampleFindings[0]]);
      const outputPath = path.join(tempDir, 'report.sarif.json');
      const sarif = await generateSarifReport(evidenceDir, outputPath);

      const result = sarif.runs[0].results[0];
      expect(result.ruleId).toMatch(/^DST-\d{3}$/);
    });

    it('should map CONFIRMED to error level in SARIF', async () => {
      await writeEvidenceFiles([sampleFindings[0]]);
      const outputPath = path.join(tempDir, 'report.sarif.json');
      const sarif = await generateSarifReport(evidenceDir, outputPath);

      const result = sarif.runs[0].results[0];
      expect(result.level).toBe('error');
    });

    it('should write file to disk', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'report.sarif.json');
      await generateSarifReport(evidenceDir, outputPath);

      expect(await fs.pathExists(outputPath)).toBe(true);
    });

    it('should handle preCollected findings', async () => {
      const outputPath = path.join(tempDir, 'report.sarif.json');
      const sarif = await generateSarifReport(evidenceDir, outputPath, {}, sampleFindings);

      expect(sarif.runs[0].results.length).toBe(2);
    });
  });

  describe('generateHtmlReport', () => {
    it('should generate HTML report with findings', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'report.html');
      const html = await generateHtmlReport(evidenceDir, outputPath);

      expect(html).toContain('Dynamic Security Test Report');
      expect(html).toContain('Confirmed');
      expect(html).toContain('routes/login.js');
    });

    it('should write file to disk', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'report.html');
      await generateHtmlReport(evidenceDir, outputPath);

      expect(await fs.pathExists(outputPath)).toBe(true);
    });

    it('should escape HTML in findings', async () => {
      const xssFinding = {
        ...sampleFindings[0],
        exploitation: { ...sampleFindings[0].exploitation, payload: '<script>alert(1)</script>' }
      };
      await writeEvidenceFiles([xssFinding]);
      const outputPath = path.join(tempDir, 'report.html');
      const html = await generateHtmlReport(evidenceDir, outputPath);

      expect(html).not.toContain('<script>alert(1)</script>');
      expect(html).toContain('&lt;script&gt;');
    });

    it('should show risk assessment', async () => {
      await writeEvidenceFiles([sampleFindings[0]]);
      const outputPath = path.join(tempDir, 'report.html');
      const html = await generateHtmlReport(evidenceDir, outputPath);

      expect(html).toContain('RISK');
    });
  });

  describe('generateDeveloperSummary', () => {
    it('should generate summary with counts', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'developer_summary.json');
      const summary = await generateDeveloperSummary(evidenceDir, outputPath);

      expect(summary.totals.confirmed).toBe(1);
      expect(summary.totals.notReproducible).toBe(1);
      expect(summary.totals.total).toBe(2);
    });

    it('should write file to disk', async () => {
      await writeEvidenceFiles(sampleFindings);
      const outputPath = path.join(tempDir, 'developer_summary.json');
      await generateDeveloperSummary(evidenceDir, outputPath);

      expect(await fs.pathExists(outputPath)).toBe(true);
    });
  });

  describe('generateAllReports', () => {
    it('should generate all report types', async () => {
      await writeEvidenceFiles(sampleFindings);
      const result = await generateAllReports(evidenceDir, tempDir);

      expect(result.sarif).toBeDefined();
      expect(result.html).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(await fs.pathExists(path.join(tempDir, 'report.sarif.json'))).toBe(true);
      expect(await fs.pathExists(path.join(tempDir, 'report.html'))).toBe(true);
      expect(await fs.pathExists(path.join(tempDir, 'developer_summary.json'))).toBe(true);
    });
  });
});
