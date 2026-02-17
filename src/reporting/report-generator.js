import { fs, path } from 'zx';
import chalk from 'chalk';

// -----------------------------------------------------------------------
// Classification → SARIF level mapping
// -----------------------------------------------------------------------
const CLASSIFICATION_TO_LEVEL = {
  CONFIRMED: 'error',
  LIKELY: 'warning',
  BLOCKED: 'note',
  NOT_REPRODUCIBLE: 'none',
  TESTED_NOT_EXPLOITABLE: 'none'
};

// -----------------------------------------------------------------------
// CWE descriptions database
// -----------------------------------------------------------------------
const CWE_DESCRIPTIONS = {
  'CWE-89': 'SQL Injection: Improper neutralization of special elements used in SQL command',
  'CWE-79': 'Cross-site Scripting (XSS): Improper neutralization of input during web page generation',
  'CWE-22': 'Path Traversal: Improper limitation of pathname to restricted directory',
  'CWE-611': 'XXE: Improper restriction of XML external entity reference',
  'CWE-601': 'Open Redirect: URL redirection to untrusted site',
  'CWE-798': 'Hardcoded Credentials: Use of hard-coded credentials',
  'CWE-78': 'OS Command Injection: Improper neutralization of special elements used in OS command',
  'CWE-918': 'SSRF: Server-Side Request Forgery',
  'CWE-352': 'CSRF: Cross-Site Request Forgery',
  'CWE-502': 'Insecure Deserialization: Deserialization of untrusted data',
  'CWE-434': 'Unrestricted Upload: Unrestricted upload of file with dangerous type',
  'CWE-287': 'Broken Authentication: Improper authentication',
  'CWE-639': 'IDOR: Authorization bypass through user-controlled key',
  'CWE-943': 'NoSQL Injection: Improper neutralization of NoSQL query logic',
  'CWE-94': 'Code Injection: Improper control of generation of code',
  'CWE-327': 'Weak Cryptography: Use of broken or risky cryptographic algorithm',
  'CWE-384': 'Session Fixation: Session fixation vulnerability',
  'CWE-1321': 'Prototype Pollution: Improperly controlled modification of object prototype attributes'
};

// -----------------------------------------------------------------------
// Helper — collect evidence files from disk
// -----------------------------------------------------------------------
async function collectFindings(evidenceDir) {
  await fs.ensureDir(evidenceDir);
  const files = await fs.readdir(evidenceDir);
  const findings = [];

  for (const file of files) {
    if (file.endsWith('.json') && file.startsWith('evidence-')) {
      try {
        const data = await fs.readJSON(path.join(evidenceDir, file));
        findings.push(data);
      } catch (e) {
        console.warn(chalk.yellow(`  ⚠ Skipping corrupt evidence file: ${file} (${e.message})`));
      }
    }
  }

  return findings;
}

// -----------------------------------------------------------------------
// Helper — sort findings: CONFIRMED first, then by severity, then LIKELY, etc.
// -----------------------------------------------------------------------
function sortFindings(findings) {
  const classOrder = { CONFIRMED: 0, LIKELY: 1, BLOCKED: 2, NOT_REPRODUCIBLE: 3, TESTED_NOT_EXPLOITABLE: 3 };

  return [...findings].sort((a, b) => {
    const classA = classOrder[a.classification || a.status] ?? 9;
    const classB = classOrder[b.classification || b.status] ?? 9;
    if (classA !== classB) return classA - classB;

    // Within same classification, sort by level descending (higher = worse)
    const levelA = a.level ?? 0;
    const levelB = b.level ?? 0;
    return levelB - levelA;
  });
}

// -----------------------------------------------------------------------
// SARIF Report
// -----------------------------------------------------------------------

/**
 * Generate a SARIF 2.1.0 report with:
 * - Unique tool-scoped rule IDs (DST-001, DST-002 ...) instead of raw CWE
 * - Severity levels derived from 4-level classification
 * - Classification metadata in properties
 *
 * @param {string} evidenceDir - Path to evidence directory
 * @param {string} outputPath - Output SARIF file path
 * @param {object} [metadata] - Optional metadata (targetUrl, version)
 * @param {Array} [preCollected] - Pre-collected findings to avoid re-reading disk
 * @returns {Promise<object>} SARIF object
 */
export async function generateSarifReport(evidenceDir, outputPath, metadata = {}, preCollected = null) {
  console.log(chalk.blue('📋 Generating SARIF report...'));

  const findings = sortFindings(preCollected || await collectFindings(evidenceDir));

  // Build unique rules with tool-scoped IDs
  const rulesMap = new Map();
  let ruleCounter = 1;

  for (const finding of findings) {
    const vulnType = finding.vulnerability?.type || 'Unknown';
    const cwe = finding.vulnerability?.cwe || 'UNKNOWN';
    const ruleKey = `${vulnType}|${cwe}`;

    if (!rulesMap.has(ruleKey)) {
      const ruleId = `DST-${String(ruleCounter++).padStart(3, '0')}`;
      rulesMap.set(ruleKey, {
        id: ruleId,
        name: vulnType.replace(/\s+/g, ''),
        shortDescription: {
          text: `${vulnType} (${cwe})`
        },
        fullDescription: {
          text: CWE_DESCRIPTIONS[cwe] || `${vulnType} detected by dynamic testing`
        },
        defaultConfiguration: {
          level: 'warning'
        },
        properties: {
          cwe: cwe,
          owasp: finding.vulnerability?.owasp || null
        }
      });
    }
  }

  // Map each finding to a SARIF result
  const results = findings.map(finding => {
    const vulnType = finding.vulnerability?.type || 'Unknown';
    const cwe = finding.vulnerability?.cwe || 'UNKNOWN';
    const ruleKey = `${vulnType}|${cwe}`;
    const rule = rulesMap.get(ruleKey);
    const classification = finding.classification || finding.status || 'NOT_REPRODUCIBLE';

    return {
      ruleId: rule?.id || 'DST-000',
      level: CLASSIFICATION_TO_LEVEL[classification] || 'warning',
      message: {
        text: generateSarifMessage(finding)
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.sourceLocation?.file || 'unknown'
            },
            region: {
              startLine: finding.sourceLocation?.line || 1,
              startColumn: finding.sourceLocation?.column || 1
            }
          }
        }
      ],
      properties: {
        classification: classification,
        level: finding.level ?? null,
        levelName: finding.levelName || null,
        confidence: finding.confidence || null,
        requiresAction: finding.requiresAction ?? null,
        endpoint: finding.exploitation?.endpoint || null,
        payload: finding.exploitation?.payload || null,
        proof: finding.exploitation?.proof || null,
        cwe: cwe,
        owasp: finding.vulnerability?.owasp || null
      }
    };
  });

  const sarif = {
    '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    'version': '2.1.0',
    'runs': [
      {
        tool: {
          driver: {
            name: 'DynamicSecurityTester',
            version: metadata.version || '2.0.0',
            informationUri: 'https://github.com/dynamictester',
            rules: Array.from(rulesMap.values())
          }
        },
        results
      }
    ]
  };

  await fs.writeJSON(outputPath, sarif, { spaces: 2 });
  console.log(chalk.green(`✅ SARIF report saved: ${outputPath}`));

  return sarif;
}

/**
 * Generate a human-readable SARIF message with classification context
 * @param {object} finding
 * @returns {string}
 */
function generateSarifMessage(finding) {
  const classification = finding.classification || finding.status || 'UNKNOWN';
  const statusIcon = classification === 'CONFIRMED' ? '✓ CONFIRMED' :
                     classification === 'LIKELY' ? '? LIKELY' :
                     classification === 'BLOCKED' ? '⊘ BLOCKED' : '○ NOT REPRODUCIBLE';
  const location = finding.sourceLocation?.file
    ? `${finding.sourceLocation.file}:${finding.sourceLocation.line}`
    : 'Unknown location';
  const level = finding.level != null ? ` (Level ${finding.level})` : '';

  let msg = `[${statusIcon}${level}] ${finding.vulnerability?.type || 'Vulnerability'} at ${location}`;
  msg += `\nEndpoint: ${finding.exploitation?.endpoint || 'N/A'}`;
  msg += `\nPayload: ${finding.exploitation?.payload || 'N/A'}`;

  if (classification === 'CONFIRMED' && finding.exploitation?.proof) {
    msg += `\nPROOF: ${finding.exploitation.proof}`;
  }
  if (finding.classificationReason) {
    msg += `\nReason: ${finding.classificationReason}`;
  }

  return msg;
}

// -----------------------------------------------------------------------
// HTML Report
// -----------------------------------------------------------------------

/**
 * Generate an HTML report with:
 * - Executive summary with percentages and risk assessment
 * - 4-level classification badges (CONFIRMED / LIKELY / BLOCKED / NOT REPRODUCIBLE)
 * - Severity-based sorting
 * - Exploitation level indicators
 *
 * @param {string} evidenceDir - Path to evidence directory
 * @param {string} outputPath - Output HTML file path
 * @param {object} [metadata] - Optional metadata (targetUrl)
 * @param {Array} [preCollected] - Pre-collected findings to avoid re-reading disk
 * @returns {Promise<string>} HTML string
 */
export async function generateHtmlReport(evidenceDir, outputPath, metadata = {}, preCollected = null) {
  console.log(chalk.blue('📋 Generating HTML report...'));

  const findings = sortFindings(preCollected || await collectFindings(evidenceDir));

  const confirmed = findings.filter(f => (f.classification || f.status) === 'CONFIRMED');
  const likely = findings.filter(f => (f.classification || f.status) === 'LIKELY');
  const blocked = findings.filter(f => (f.classification || f.status) === 'BLOCKED');
  const notReproducible = findings.filter(f =>
    (f.classification || f.status) === 'NOT_REPRODUCIBLE' ||
    (f.classification || f.status) === 'TESTED_NOT_EXPLOITABLE'
  );
  const total = findings.length;

  const confirmedPct = total > 0 ? ((confirmed.length / total) * 100).toFixed(1) : '0.0';
  const likelyPct = total > 0 ? ((likely.length / total) * 100).toFixed(1) : '0.0';
  const falsePositivePct = total > 0 ? ((notReproducible.length / total) * 100).toFixed(1) : '0.0';

  // Risk assessment
  let riskLevel = 'LOW';
  let riskColor = '#22c55e';
  if (confirmed.length > 0) {
    const hasLevel4 = confirmed.some(f => f.level === 4);
    const hasLevel3 = confirmed.some(f => f.level >= 3);
    if (hasLevel4) { riskLevel = 'CRITICAL'; riskColor = '#dc2626'; }
    else if (hasLevel3) { riskLevel = 'HIGH'; riskColor = '#ef4444'; }
    else { riskLevel = 'MEDIUM'; riskColor = '#f59e0b'; }
  } else if (likely.length > 0) {
    riskLevel = 'MEDIUM'; riskColor = '#f59e0b';
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dynamic Security Test Report</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --success: #22c55e;
      --error: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --border: #334155;
      --likely: #f97316;
      --blocked: #a855f7;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { font-size: 1.5rem; margin-bottom: 1rem; }
    .executive-summary {
      background: var(--card);
      border-radius: 12px;
      padding: 1.5rem 2rem;
      margin: 1.5rem 0;
      border-left: 4px solid ${riskColor};
    }
    .executive-summary h3 { margin-bottom: 0.75rem; font-size: 1.2rem; }
    .risk-badge {
      display: inline-block;
      padding: 0.25rem 1rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 700;
      background: ${riskColor};
      color: white;
      margin-left: 0.5rem;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .summary-item { font-size: 0.9rem; }
    .summary-item .label { color: var(--muted); }
    .stats {
      display: flex;
      gap: 1rem;
      margin-top: 1rem;
      flex-wrap: wrap;
    }
    .stat {
      background: var(--card);
      padding: 1rem 1.5rem;
      border-radius: 8px;
      text-align: center;
      min-width: 120px;
    }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-value.confirmed { color: var(--error); }
    .stat-value.likely { color: var(--likely); }
    .stat-value.blocked { color: var(--blocked); }
    .stat-value.tested { color: var(--warning); }
    .stat-value.safe { color: var(--success); }
    .stat-label { color: var(--muted); font-size: 0.75rem; }
    .findings { display: flex; flex-direction: column; gap: 1rem; }
    .finding {
      background: var(--card);
      border-radius: 8px;
      padding: 1.5rem;
      border-left: 4px solid var(--border);
    }
    .finding.confirmed { border-left-color: var(--error); }
    .finding.likely { border-left-color: var(--likely); }
    .finding.blocked { border-left-color: var(--blocked); }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1rem;
    }
    .finding-title { font-weight: 600; font-size: 1.1rem; }
    .badge {
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      white-space: nowrap;
    }
    .badge.confirmed { background: var(--error); color: white; }
    .badge.likely { background: var(--likely); color: white; }
    .badge.blocked { background: var(--blocked); color: white; }
    .badge.not-reproducible { background: var(--border); color: var(--muted); }
    .level-indicator {
      font-size: 0.75rem;
      color: var(--muted);
      margin-top: 0.25rem;
    }
    .location {
      font-family: 'Fira Code', monospace;
      background: var(--bg);
      padding: 0.5rem 1rem;
      border-radius: 4px;
      margin: 0.5rem 0;
      font-size: 0.875rem;
    }
    .details { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1rem; }
    .detail-item label { color: var(--muted); font-size: 0.75rem; display: block; }
    .detail-item span { font-family: monospace; }
    .payload {
      background: var(--bg);
      padding: 0.75rem;
      border-radius: 4px;
      font-family: monospace;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .proof {
      margin-top: 1rem;
      padding: 1rem;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 4px;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .remediation {
      margin-top: 1rem;
      padding: 1rem;
      background: rgba(34, 197, 94, 0.1);
      border-radius: 4px;
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .classification-reason {
      margin-top: 0.75rem;
      font-size: 0.85rem;
      color: var(--muted);
      font-style: italic;
    }
    footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--muted);
      text-align: center;
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Dynamic Security Test Report</h1>
      <p style="color: var(--muted);">Generated: ${new Date().toISOString()}</p>
      <p style="color: var(--muted);">Target: ${escapeHtml(metadata.targetUrl || 'N/A')}</p>

      <div class="executive-summary">
        <h3>Executive Summary <span class="risk-badge">${riskLevel} RISK</span></h3>
        <p>Tested <strong>${total}</strong> static analysis findings against the live application.</p>
        <div class="summary-grid">
          <div class="summary-item"><span class="label">Confirmed exploitable:</span> <strong style="color: var(--error);">${confirmed.length}</strong> (${confirmedPct}%)</div>
          <div class="summary-item"><span class="label">Likely exploitable:</span> <strong style="color: var(--likely);">${likely.length}</strong> (${likelyPct}%)</div>
          <div class="summary-item"><span class="label">Blocked (untestable):</span> <strong style="color: var(--blocked);">${blocked.length}</strong></div>
          <div class="summary-item"><span class="label">False positives removed:</span> <strong style="color: var(--success);">${notReproducible.length}</strong> (${falsePositivePct}%)</div>
        </div>
      </div>

      <div class="stats">
        <div class="stat">
          <div class="stat-value confirmed">${confirmed.length}</div>
          <div class="stat-label">Confirmed</div>
        </div>
        <div class="stat">
          <div class="stat-value likely">${likely.length}</div>
          <div class="stat-label">Likely</div>
        </div>
        <div class="stat">
          <div class="stat-value blocked">${blocked.length}</div>
          <div class="stat-label">Blocked</div>
        </div>
        <div class="stat">
          <div class="stat-value safe">${notReproducible.length}</div>
          <div class="stat-label">Not Reproducible</div>
        </div>
        <div class="stat">
          <div class="stat-value tested">${total}</div>
          <div class="stat-label">Total Tested</div>
        </div>
      </div>
    </header>

    <main>
      <h2>Findings</h2>
      <div class="findings">
        ${findings.map(f => generateFindingHtml(f)).join('\n')}
      </div>
    </main>

    <footer>
      <p>Generated by Dynamic Security Tester v2.0</p>
    </footer>
  </div>
</body>
</html>`;

  await fs.writeFile(outputPath, html);
  console.log(chalk.green(`✅ HTML report saved: ${outputPath}`));

  return html;
}

/**
 * Generate HTML for a single finding with classification badge
 * @param {object} finding
 * @returns {string}
 */
function generateFindingHtml(finding) {
  const classification = finding.classification || finding.status || 'NOT_REPRODUCIBLE';

  const badgeMap = {
    CONFIRMED: { class: 'confirmed', text: 'Confirmed' },
    LIKELY: { class: 'likely', text: 'Likely' },
    BLOCKED: { class: 'blocked', text: 'Blocked' },
    NOT_REPRODUCIBLE: { class: 'not-reproducible', text: 'Not Reproducible' },
    TESTED_NOT_EXPLOITABLE: { class: 'not-reproducible', text: 'Not Exploitable' }
  };
  const badge = badgeMap[classification] || badgeMap.NOT_REPRODUCIBLE;

  const levelText = finding.level != null && finding.levelName
    ? `Level ${finding.level}: ${finding.levelName} (${finding.confidence || 'N/A'})`
    : '';

  const findingClass = classification === 'CONFIRMED' ? 'confirmed' :
                       classification === 'LIKELY' ? 'likely' :
                       classification === 'BLOCKED' ? 'blocked' : '';

  return `
    <div class="finding ${findingClass}">
      <div class="finding-header">
        <div>
          <div class="finding-title">${escapeHtml(finding.vulnerability?.type || 'Unknown')} - ${escapeHtml(finding.vulnerability?.cwe || 'N/A')}</div>
          <div style="color: var(--muted); font-size: 0.875rem;">${escapeHtml(finding.findingId || 'N/A')}</div>
          ${levelText ? `<div class="level-indicator">${escapeHtml(levelText)}</div>` : ''}
        </div>
        <span class="badge ${badge.class}">${badge.text}</span>
      </div>

      <div class="location">
        ${escapeHtml(finding.sourceLocation?.file || 'Unknown')}:${escapeHtml(String(finding.sourceLocation?.line || '?'))}:${escapeHtml(String(finding.sourceLocation?.column || '?'))}
      </div>

      <div class="details">
        <div class="detail-item">
          <label>Endpoint</label>
          <span>${escapeHtml(finding.exploitation?.endpoint || 'N/A')}</span>
        </div>
        <div class="detail-item">
          <label>Method</label>
          <span>${escapeHtml(finding.exploitation?.method || 'N/A')}</span>
        </div>
        <div class="detail-item">
          <label>OWASP</label>
          <span>${escapeHtml(finding.vulnerability?.owasp || 'N/A')}</span>
        </div>
        <div class="detail-item">
          <label>CWE</label>
          <span>${escapeHtml(finding.vulnerability?.cwe || 'N/A')}</span>
        </div>
      </div>

      <div style="margin-top: 1rem;">
        <label style="color: var(--muted); font-size: 0.75rem; display: block; margin-bottom: 0.25rem;">Payload</label>
        <div class="payload">${escapeHtml(finding.exploitation?.payload || 'N/A')}</div>
      </div>

      ${classification === 'CONFIRMED' && finding.exploitation?.proof ? `
        <div class="proof">
          <label style="font-weight: 600; display: block; margin-bottom: 0.5rem;">Exploitation Proof</label>
          <div>${escapeHtml(finding.exploitation.proof)}</div>
        </div>
      ` : ''}

      ${finding.classificationReason ? `
        <div class="classification-reason">
          ${escapeHtml(finding.classificationReason)}
        </div>
      ` : ''}

      ${finding.remediation ? `
        <div class="remediation">
          <label style="font-weight: 600; display: block; margin-bottom: 0.5rem;">Remediation</label>
          <div>${escapeHtml(finding.remediation)}</div>
        </div>
      ` : ''}
    </div>
  `;
}

/**
 * Escape HTML entities to prevent XSS in report output
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// -----------------------------------------------------------------------
// Developer Summary
// -----------------------------------------------------------------------

/**
 * Generate developer summary with 4-level classification breakdown.
 *
 * @param {string} evidenceDir - Path to evidence directory
 * @param {string} outputPath - Output JSON file path
 * @param {Array} [preCollected] - Pre-collected findings to avoid re-reading disk
 * @returns {Promise<object>} Summary object
 */
export async function generateDeveloperSummary(evidenceDir, outputPath, preCollected = null) {
  console.log(chalk.blue('\n📊 Developer Summary:'));

  // Read summary file
  let findings = [];
  if (preCollected) {
    findings = preCollected;
  } else {
    const summaryPath = path.join(path.dirname(evidenceDir), 'findings_summary.json');
    try {
      findings = await fs.readJSON(summaryPath);
    } catch (e) {
      // Build from evidence files
      const collected = await collectFindings(evidenceDir);
      findings = collected;
    }
  }

  // Group by classification
  const confirmed = findings.filter(f =>
    (f.classification || f.status) === 'CONFIRMED'
  );
  const likely = findings.filter(f =>
    (f.classification || f.status) === 'LIKELY'
  );
  const blocked = findings.filter(f =>
    (f.classification || f.status) === 'BLOCKED'
  );
  const notReproducible = findings.filter(f => {
    const c = f.classification || f.status;
    return c === 'NOT_REPRODUCIBLE' || c === 'TESTED_NOT_EXPLOITABLE';
  });

  const total = findings.length;
  const falsePositivePct = total > 0 ? ((notReproducible.length / total) * 100).toFixed(1) : '0.0';

  console.log(chalk.red(`\n  🔴 CONFIRMED: ${confirmed.length}`));
  for (const f of confirmed) {
    const loc = f.sourceLocation || {};
    console.log(chalk.red(`     • ${loc.file || f.file}:${loc.line || f.line} - ${f.vulnerability?.type || f.type} (Level ${f.level ?? '?'})`));
  }

  console.log(chalk.yellow(`\n  🟡 LIKELY: ${likely.length}`));
  for (const f of likely.slice(0, 5)) {
    const loc = f.sourceLocation || {};
    console.log(chalk.yellow(`     • ${loc.file || f.file}:${loc.line || f.line} - ${f.vulnerability?.type || f.type}`));
  }
  if (likely.length > 5) {
    console.log(chalk.yellow(`     ... and ${likely.length - 5} more`));
  }

  console.log(chalk.magenta(`\n  🟠 BLOCKED: ${blocked.length}`));
  for (const f of blocked.slice(0, 3)) {
    const loc = f.sourceLocation || {};
    console.log(chalk.magenta(`     • ${loc.file || f.file}:${loc.line || f.line} - ${f.vulnerability?.type || f.type}`));
  }

  console.log(chalk.green(`\n  🟢 NOT REPRODUCIBLE: ${notReproducible.length} (${falsePositivePct}% false positive rate)`));

  // Write summary to file
  const summary = {
    generated: new Date().toISOString(),
    totals: {
      confirmed: confirmed.length,
      likely: likely.length,
      blocked: blocked.length,
      notReproducible: notReproducible.length,
      total,
      falsePositiveRate: `${falsePositivePct}%`
    },
    confirmed: confirmed.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type,
      cwe: f.vulnerability?.cwe || f.cwe,
      endpoint: f.exploitation?.endpoint || f.endpoint,
      level: f.level,
      confidence: f.confidence
    })),
    likely: likely.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type,
      cwe: f.vulnerability?.cwe || f.cwe,
      level: f.level
    })),
    blocked: blocked.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type,
      reason: f.classificationReason
    })),
    notReproducible: notReproducible.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type
    }))
  };

  await fs.writeJSON(outputPath, summary, { spaces: 2 });
  console.log(chalk.green(`\n  ✅ Summary saved: ${outputPath}`));

  return summary;
}

// -----------------------------------------------------------------------
// All-in-one report generation — reads evidence directory once
// -----------------------------------------------------------------------

/**
 * Generate all reports (SARIF, HTML, Developer Summary) in one pass.
 * Collects evidence files once from disk and passes them to each generator,
 * avoiding redundant I/O.
 *
 * @param {string} evidenceDir - Path to evidence directory
 * @param {string} outputDir - Output directory for all report files
 * @param {object} [metadata] - Optional metadata (targetUrl, version)
 * @returns {Promise<{sarif: object, html: string, summary: object}>}
 */
export async function generateAllReports(evidenceDir, outputDir, metadata = {}) {
  const findings = await collectFindings(evidenceDir);

  const [sarif, html, summary] = await Promise.all([
    generateSarifReport(evidenceDir, path.join(outputDir, 'report.sarif.json'), metadata, findings),
    generateHtmlReport(evidenceDir, path.join(outputDir, 'report.html'), metadata, findings),
    generateDeveloperSummary(evidenceDir, path.join(outputDir, 'developer_summary.json'), findings)
  ]);

  return { sarif, html, summary };
}
