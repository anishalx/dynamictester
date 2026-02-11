import { fs, path } from 'zx';
import chalk from 'chalk';

/**
 * SARIF (Static Analysis Results Interchange Format) Generator
 * Generates industry-standard output for IDE integration (VS Code, etc.)
 */
export async function generateSarifReport(evidenceDir, outputPath, metadata = {}) {
  console.log(chalk.blue('📋 Generating SARIF report...'));
  
  // Ensure evidence directory exists (may not if no findings were saved)
  await fs.ensureDir(evidenceDir);
  
  // Collect all evidence files
  const evidenceFiles = await fs.readdir(evidenceDir);
  const findings = [];
  
  for (const file of evidenceFiles) {
    if (file.endsWith('.json') && file.startsWith('evidence-')) {
      const data = await fs.readJSON(path.join(evidenceDir, file));
      findings.push(data);
    }
  }
  
  // Build SARIF structure
  const sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "DynamicSecurityTester",
            "version": metadata.version || "1.0.0",
            "informationUri": "https://github.com/dynamictester",
            "rules": generateRules(findings)
          }
        },
        "results": findings.map(finding => ({
          "ruleId": finding.vulnerability?.cwe || finding.findingId || "UNKNOWN",
          "level": finding.exploitation?.success ? "error" : "warning",
          "message": {
            "text": generateMessage(finding)
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": finding.sourceLocation?.file || "unknown"
                },
                "region": {
                  "startLine": finding.sourceLocation?.line || 1,
                  "startColumn": finding.sourceLocation?.column || 1
                }
              }
            }
          ],
          "properties": {
            "status": finding.status,
            "endpoint": finding.exploitation?.endpoint,
            "payload": finding.exploitation?.payload,
            "proof": finding.exploitation?.proof
          }
        }))
      }
    ]
  };
  
  await fs.writeJSON(outputPath, sarif, { spaces: 2 });
  console.log(chalk.green(`✅ SARIF report saved: ${outputPath}`));
  
  return sarif;
}

/**
 * Generate unique rules from findings
 */
function generateRules(findings) {
  const rulesMap = new Map();
  
  for (const finding of findings) {
    const cwe = finding.vulnerability?.cwe || 'UNKNOWN';
    if (!rulesMap.has(cwe)) {
      rulesMap.set(cwe, {
        id: cwe,
        name: finding.vulnerability?.type || 'Security Vulnerability',
        shortDescription: {
          text: `${finding.vulnerability?.type || 'Vulnerability'} (${cwe})`
        },
        fullDescription: {
          text: getVulnerabilityDescription(cwe, finding.vulnerability?.type)
        },
        defaultConfiguration: {
          level: "error"
        },
        properties: {
          owasp: finding.vulnerability?.owasp || null
        }
      });
    }
  }
  
  return Array.from(rulesMap.values());
}

/**
 * Generate human-readable message
 */
function generateMessage(finding) {
  const status = finding.status === 'CONFIRMED' ? '✓ CONFIRMED' : '○ NOT EXPLOITABLE';
  const location = finding.sourceLocation?.file 
    ? `${finding.sourceLocation.file}:${finding.sourceLocation.line}`
    : 'Unknown location';
  
  return `[${status}] ${finding.vulnerability?.type || 'Vulnerability'} at ${location}
Endpoint: ${finding.exploitation?.endpoint || 'N/A'}
Payload: ${finding.exploitation?.payload || 'N/A'}
${finding.exploitation?.success ? 'PROOF: ' + (finding.exploitation?.proof || 'Exploitation successful') : ''}`;
}

/**
 * Get vulnerability description from CWE
 */
function getVulnerabilityDescription(cwe, type) {
  const descriptions = {
    'CWE-89': 'SQL Injection: Improper neutralization of special elements used in SQL command',
    'CWE-79': 'Cross-site Scripting (XSS): Improper neutralization of input during web page generation',
    'CWE-22': 'Path Traversal: Improper limitation of pathname to restricted directory',
    'CWE-611': 'XXE: Improper restriction of XML external entity reference',
    'CWE-601': 'Open Redirect: URL redirection to untrusted site',
    'CWE-798': 'Hardcoded Credentials: Use of hard-coded credentials',
    'CWE-78': 'OS Command Injection: Improper neutralization of special elements used in OS command'
  };
  
  return descriptions[cwe] || `${type || 'Security vulnerability'} detected`;
}

/**
 * Generate HTML Report for human review
 */
export async function generateHtmlReport(evidenceDir, outputPath, metadata = {}) {
  console.log(chalk.blue('📋 Generating HTML report...'));
  
  // Ensure evidence directory exists (may not if no findings were saved)
  await fs.ensureDir(evidenceDir);
  
  // Collect all evidence files
  const evidenceFiles = await fs.readdir(evidenceDir);
  const findings = [];
  
  for (const file of evidenceFiles) {
    if (file.endsWith('.json') && file.startsWith('evidence-')) {
      const data = await fs.readJSON(path.join(evidenceDir, file));
      findings.push(data);
    }
  }
  
  // Sort by status (confirmed first) then by severity
  findings.sort((a, b) => {
    if (a.status === 'CONFIRMED' && b.status !== 'CONFIRMED') return -1;
    if (b.status === 'CONFIRMED' && a.status !== 'CONFIRMED') return 1;
    return 0;
  });
  
  const confirmedCount = findings.filter(f => f.status === 'CONFIRMED').length;
  const testedCount = findings.length;
  
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
      --border: #334155;
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
    .stats {
      display: flex;
      gap: 2rem;
      margin-top: 1rem;
    }
    .stat {
      background: var(--card);
      padding: 1rem 1.5rem;
      border-radius: 8px;
      text-align: center;
    }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-value.confirmed { color: var(--error); }
    .stat-value.tested { color: var(--warning); }
    .stat-label { color: var(--muted); font-size: 0.875rem; }
    .findings { display: flex; flex-direction: column; gap: 1rem; }
    .finding {
      background: var(--card);
      border-radius: 8px;
      padding: 1.5rem;
      border-left: 4px solid var(--border);
    }
    .finding.confirmed { border-left-color: var(--error); }
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
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge.confirmed { background: var(--error); color: white; }
    .badge.not-exploitable { background: var(--border); color: var(--muted); }
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
      <h1>🔒 Dynamic Security Test Report</h1>
      <p style="color: var(--muted);">Generated: ${new Date().toISOString()}</p>
      <p style="color: var(--muted);">Target: ${escapeHtml(metadata.targetUrl || 'N/A')}</p>
      <div class="stats">
        <div class="stat">
          <div class="stat-value confirmed">${confirmedCount}</div>
          <div class="stat-label">Confirmed Vulnerabilities</div>
        </div>
        <div class="stat">
          <div class="stat-value tested">${testedCount}</div>
          <div class="stat-label">Total Tested</div>
        </div>
        <div class="stat">
          <div class="stat-value">${testedCount - confirmedCount}</div>
          <div class="stat-label">Not Exploitable</div>
        </div>
      </div>
    </header>
    
    <main>
      <h2 style="margin-bottom: 1rem;">Findings</h2>
      <div class="findings">
        ${findings.map(f => generateFindingHtml(f)).join('\n')}
      </div>
    </main>
    
    <footer>
      <p>Generated by Dynamic Security Tester</p>
    </footer>
  </div>
</body>
</html>`;

  await fs.writeFile(outputPath, html);
  console.log(chalk.green(`✅ HTML report saved: ${outputPath}`));
  
  return html;
}

function generateFindingHtml(finding) {
  const isConfirmed = finding.status === 'CONFIRMED';
  const badgeClass = isConfirmed ? 'confirmed' : 'not-exploitable';
  const badgeText = isConfirmed ? 'Confirmed' : 'Not Exploitable';
  
  return `
    <div class="finding ${isConfirmed ? 'confirmed' : ''}">
      <div class="finding-header">
        <div>
          <div class="finding-title">${escapeHtml(finding.vulnerability?.type || 'Unknown')} - ${escapeHtml(finding.vulnerability?.cwe || 'N/A')}</div>
          <div style="color: var(--muted); font-size: 0.875rem;">${escapeHtml(finding.findingId || 'N/A')}</div>
        </div>
        <span class="badge ${badgeClass}">${badgeText}</span>
      </div>
      
      <div class="location">
        📁 ${escapeHtml(finding.sourceLocation?.file || 'Unknown')}:${escapeHtml(String(finding.sourceLocation?.line || '?'))}:${escapeHtml(String(finding.sourceLocation?.column || '?'))}
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
      
      ${isConfirmed && finding.exploitation?.proof ? `
        <div class="proof">
          <label style="font-weight: 600; display: block; margin-bottom: 0.5rem;">⚠️ Exploitation Proof</label>
          <div>${escapeHtml(finding.exploitation.proof)}</div>
        </div>
      ` : ''}
      
      ${finding.remediation ? `
        <div class="remediation">
          <label style="font-weight: 600; display: block; margin-bottom: 0.5rem;">✅ Remediation</label>
          <div>${escapeHtml(finding.remediation)}</div>
        </div>
      ` : ''}
    </div>
  `;
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generate developer summary (console + file)
 */
export async function generateDeveloperSummary(evidenceDir, outputPath) {
  console.log(chalk.blue('\n📊 Developer Summary:'));
  
  // Read summary file
  let findings = [];
  const summaryPath = path.join(path.dirname(evidenceDir), 'findings_summary.json');
  try {
    findings = await fs.readJSON(summaryPath);
  } catch (e) {
    // Try to build from evidence files
    await fs.ensureDir(evidenceDir);
    const evidenceFiles = await fs.readdir(evidenceDir);
    for (const file of evidenceFiles) {
      if (file.endsWith('.json') && file.startsWith('evidence-')) {
        const data = await fs.readJSON(path.join(evidenceDir, file));
        findings.push(data);
      }
    }
  }
  
  // Group by status
  const confirmed = findings.filter(f => f.status === 'CONFIRMED' || f.success === true);
  const notExploitable = findings.filter(f => f.status !== 'CONFIRMED' && f.success !== true);
  
  console.log(chalk.red(`\n  🔴 CONFIRMED: ${confirmed.length}`));
  for (const f of confirmed) {
    const loc = f.sourceLocation || {};
    console.log(chalk.red(`     • ${loc.file || f.file}:${loc.line || f.line} - ${f.vulnerability?.type || f.type}`));
  }
  
  console.log(chalk.gray(`\n  ⚪ NOT EXPLOITABLE: ${notExploitable.length}`));
  for (const f of notExploitable.slice(0, 5)) {
    const loc = f.sourceLocation || {};
    console.log(chalk.gray(`     • ${loc.file || f.file}:${loc.line || f.line} - ${f.vulnerability?.type || f.type}`));
  }
  if (notExploitable.length > 5) {
    console.log(chalk.gray(`     ... and ${notExploitable.length - 5} more`));
  }
  
  // Write summary to file
  const summary = {
    generated: new Date().toISOString(),
    totals: {
      confirmed: confirmed.length,
      notExploitable: notExploitable.length,
      total: findings.length
    },
    confirmed: confirmed.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type,
      cwe: f.vulnerability?.cwe || f.cwe,
      endpoint: f.exploitation?.endpoint || f.endpoint
    })),
    notExploitable: notExploitable.map(f => ({
      file: f.sourceLocation?.file || f.file,
      line: f.sourceLocation?.line || f.line,
      type: f.vulnerability?.type || f.type
    }))
  };
  
  await fs.writeJSON(outputPath, summary, { spaces: 2 });
  console.log(chalk.green(`\n  ✅ Summary saved: ${outputPath}`));
  
  return summary;
}
