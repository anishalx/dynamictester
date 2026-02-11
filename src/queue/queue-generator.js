import { fs, path } from 'zx';
import chalk from 'chalk';

/**
 * Generate exploitation queue from normalized vulnerabilities
 * Supports vulnerabilities from multiple analyzers (Semgrep, Gitleaks, Trivy, etc.)
 */
export async function generateExploitationQueue(vulnerabilities, outputDir) {
  const queues = {
    injection: [],
    xss: [],
    ssrf: [],
    auth: [],
    secrets: [],
    crypto: [],
    dependency: [],
    config: [],
    other: []
  };
  
  // Group vulnerabilities by type
  for (const vuln of vulnerabilities) {
    const queueType = vuln.type || 'other';
    
    if (!queues[queueType]) {
      queues[queueType] = [];
    }
    
    const loc = vuln.location || {};
    queues[queueType].push({
      id: vuln.id,
      source: vuln.source, // Track which analyzer found it
      sourceVersion: vuln.sourceVersion,
      checkId: vuln.checkId,
      verdict: 'vulnerable',
      confidence: vuln.confidence,
      vulnerabilityType: vuln.subType || queueType,
      location: `${loc.file || 'unknown'}:${loc.line || 0}`,
      file: loc.file || 'unknown',
      line: loc.line || 0,
      column: loc.column || 0,
      snippet: loc.snippet || '',
      description: vuln.description,
      remediation: vuln.remediation,
      cwe: vuln.cwe,
      owasp: vuln.owasp,
      cvss: vuln.cvss,
      cve: vuln.cve,
      witnessPayload: generateWitnessPayload(vuln),
      reference: vuln.reference,
      metadata: vuln.metadata
    });
  }
  
  // Save queues to files
  const deliverablesDir = path.join(outputDir, 'deliverables');
  await fs.ensureDir(deliverablesDir);
  
  const createdQueues = {};
  
  for (const [type, queue] of Object.entries(queues)) {
    if (queue.length > 0) {
      const queuePath = path.join(deliverablesDir, `${type}_exploitation_queue.json`);
      await fs.writeJSON(queuePath, { vulnerabilities: queue }, { spaces: 2 });
      
      // Show breakdown by source analyzer
      const sourceBreakdown = {};
      for (const vuln of queue) {
        sourceBreakdown[vuln.source] = (sourceBreakdown[vuln.source] || 0) + 1;
      }
      
      console.log(chalk.green(`✅ Created ${type}_exploitation_queue.json with ${queue.length} vulnerabilities`));
      for (const [source, count] of Object.entries(sourceBreakdown)) {
        console.log(chalk.gray(`   - from ${source}: ${count}`));
      }
      
      createdQueues[type] = queue;
    }
  }
  
  return createdQueues;
}

/**
 * Generate witness payload based on vulnerability type and subtype
 */
function generateWitnessPayload(vuln) {
  const subType = vuln.subType || '';
  const type = vuln.type || '';
  
  // Injection payloads
  if (subType === 'SQLi' || type === 'injection' && vuln.description?.toLowerCase().includes('sql')) {
    return "' OR '1'='1' --";
  }
  if (subType === 'CommandInjection' || vuln.description?.toLowerCase().includes('command')) {
    return "; whoami";
  }
  if (subType === 'CodeInjection' || subType === 'EvalInjection') {
    return "require('child_process').execSync('id')";
  }
  if (subType === 'SSTI') {
    return "{{7*7}}";
  }
  
  // XSS payloads
  if (type === 'xss' || subType.includes('XSS')) {
    return "<img src=x onerror=alert(1)>";
  }
  
  // SSRF payloads
  if (type === 'ssrf') {
    return "http://169.254.169.254/latest/meta-data/";
  }
  
  // Default payload
  return "test_payload";
}
