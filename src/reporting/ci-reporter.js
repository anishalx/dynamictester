import { promises as fs } from 'fs';
import path from 'path';

/**
 * CI Reporter
 * Generates CI-friendly output and determines exit codes
 */
export class CIReporter {
  /**
   * Generate CI summary report
   * @param {string} evidenceDir - Path to evidence directory
   * @param {object} options - Options
   * @returns {object} CI report
   */
  static async generateCIReport(evidenceDir, options = {}) {
    const {
      failOnLikely = false,
      failOnBlocked = false
    } = options;

    try {
      const evidenceFiles = await fs.readdir(evidenceDir);
      const findings = [];

      for (const file of evidenceFiles) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(evidenceDir, file), 'utf-8');
          try {
            const finding = JSON.parse(content);
            findings.push(finding);
          } catch (e) {
            // Skip invalid JSON
          }
        }
      }

      const summary = this.summarizeFindings(findings);
      const exitCode = this.determineExitCode(summary, { failOnLikely, failOnBlocked });

      return {
        timestamp: new Date().toISOString(),
        summary,
        exitCode,
        exitReason: this.getExitReason(exitCode, summary),
        confirmedExploits: findings.filter(f => 
          f.classification === 'CONFIRMED' || f.status === 'CONFIRMED'
        ).map(f => ({
          id: f.id || f.findingId,
          endpoint: f.endpoint || f.exploitation?.endpoint,
          cwe: f.cwe || f.vulnerability?.cwe,
          file: f.sourceFile || f.sourceLocation?.file,
          line: f.sourceLine || f.sourceLocation?.line
        })),
        likelyExploits: findings.filter(f => 
          f.classification === 'LIKELY' || f.status === 'LIKELY'
        ).map(f => ({
          id: f.id || f.findingId,
          endpoint: f.endpoint,
          reason: f.reason
        })),
        blockedTests: findings.filter(f => 
          f.classification === 'BLOCKED' || f.status === 'BLOCKED'
        ).map(f => ({
          id: f.id || f.findingId,
          blocker: f.blocker || f.blockerReason
        }))
      };
    } catch (error) {
      return {
        timestamp: new Date().toISOString(),
        error: error.message,
        summary: { total: 0, confirmed: 0, likely: 0, blocked: 0, notReproducible: 0 },
        exitCode: 2
      };
    }
  }

  /**
   * Summarize findings by classification
   * @param {Array} findings - Array of finding objects
   * @returns {object} Summary
   */
  static summarizeFindings(findings) {
    const summary = {
      total: findings.length,
      confirmed: 0,
      likely: 0,
      blocked: 0,
      notReproducible: 0
    };

    for (const finding of findings) {
      const classification = finding.classification || finding.status;
      
      switch (classification) {
        case 'CONFIRMED':
          summary.confirmed++;
          break;
        case 'LIKELY':
          summary.likely++;
          break;
        case 'BLOCKED':
          summary.blocked++;
          break;
        case 'NOT_REPRODUCIBLE':
        case 'NOT REPRODUCIBLE':
          summary.notReproducible++;
          break;
        default:
          // Handle legacy classifications
          if (classification === 'EXPLOITED') summary.confirmed++;
          else if (classification === 'POTENTIAL') summary.likely++;
          else if (classification === 'FALSE_POSITIVE') summary.notReproducible++;
      }
    }

    return summary;
  }

  /**
   * Determine CI exit code based on findings
   * @param {object} summary - Findings summary
   * @param {object} options - Options
   * @returns {number} Exit code
   */
  static determineExitCode(summary, options = {}) {
    const { failOnLikely = false, failOnBlocked = false } = options;

    // CONFIRMED exploits always fail
    if (summary.confirmed > 0) {
      return 1;
    }

    // LIKELY exploits fail if flag is set
    if (failOnLikely && summary.likely > 0) {
      return 1;
    }

    // BLOCKED tests fail if flag is set (strict mode)
    if (failOnBlocked && summary.blocked > 0) {
      return 1;
    }

    // All clear
    return 0;
  }

  /**
   * Get human-readable exit reason
   * @param {number} exitCode - Exit code
   * @param {object} summary - Summary
   * @returns {string} Reason
   */
  static getExitReason(exitCode, summary) {
    if (exitCode === 0) {
      return `PASS: No confirmed exploits (${summary.notReproducible} not reproducible, ${summary.blocked} blocked)`;
    }
    if (summary.confirmed > 0) {
      return `FAIL: ${summary.confirmed} CONFIRMED exploit(s) found`;
    }
    if (summary.likely > 0) {
      return `FAIL: ${summary.likely} LIKELY exploit(s) found (--fail-on-likely enabled)`;
    }
    return `FAIL: Unknown reason`;
  }

  /**
   * Write CI report to file
   * @param {object} report - CI report object
   * @param {string} outputPath - Output file path
   */
  static async writeReport(report, outputPath) {
    await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
    return outputPath;
  }

  /**
   * Print CI summary to console
   * @param {object} report - CI report
   */
  static printSummary(report) {
    const { summary, exitCode, exitReason } = report;
    
    console.log('\n' + '═'.repeat(60));
    console.log('  CI SECURITY SCAN SUMMARY');
    console.log('═'.repeat(60));
    console.log(`  Total Findings:      ${summary.total}`);
    console.log(`  🔴 CONFIRMED:        ${summary.confirmed}`);
    console.log(`  🟡 LIKELY:           ${summary.likely}`);
    console.log(`  🟠 BLOCKED:          ${summary.blocked}`);
    console.log(`  🟢 NOT REPRODUCIBLE: ${summary.notReproducible}`);
    console.log('─'.repeat(60));
    console.log(`  Exit Code: ${exitCode}`);
    console.log(`  Result: ${exitReason}`);
    console.log('═'.repeat(60) + '\n');
  }
}

/**
 * Run CI mode
 * @param {object} options - CI options
 * @returns {Promise<number>} Exit code
 */
export async function runCIMode(options) {
  const {
    evidenceDir,
    outputDir,
    failOnLikely = false,
    failOnBlocked = false
  } = options;

  const report = await CIReporter.generateCIReport(evidenceDir, {
    failOnLikely,
    failOnBlocked
  });

  // Write CI report
  const reportPath = path.join(outputDir, 'ci-report.json');
  await CIReporter.writeReport(report, reportPath);

  // Print summary
  CIReporter.printSummary(report);

  return report.exitCode;
}
