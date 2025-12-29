import { fs, path } from 'zx';
import chalk from 'chalk';

/**
 * Generate exploitation queue from parsed vulnerabilities
 */
export async function generateExploitationQueue(vulnerabilities, outputDir) {
  const queues = {
    injection: [],
    xss: [],
    ssrf: [],
    auth: [],
    secrets: [],
    crypto: [],
    other: []
  };
  
  // Group vulnerabilities by type
  for (const vuln of vulnerabilities) {
    if (queues[vuln.type]) {
      queues[vuln.type].push({
        id: vuln.id,
        checkId: vuln.checkId,
        verdict: 'vulnerable',
        confidence: vuln.confidence,
        vulnerabilityType: getVulnerabilitySubType(vuln),
        source: `${vuln.location.file}:${vuln.location.line}`,
        file: vuln.location.file,
        line: vuln.location.line,
        description: vuln.description,
        cwe: vuln.cwe,
        owasp: vuln.owasp,
        witnessPayload: generateWitnessPayload(vuln),
        shortlink: vuln.shortlink
      });
    }
  }
  
  // Save queues to files
  const deliverablesDir = path.join(outputDir, 'deliverables');
  await fs.ensureDir(deliverablesDir);
  
  const createdQueues = {};
  
  for (const [type, queue] of Object.entries(queues)) {
    if (queue.length > 0) {
      const queuePath = path.join(deliverablesDir, `${type}_exploitation_queue.json`);
      await fs.writeJSON(queuePath, { vulnerabilities: queue }, { spaces: 2 });
      console.log(chalk.green(`✅ Created ${type}_exploitation_queue.json with ${queue.length} vulnerabilities`));
      createdQueues[type] = queue;
    }
  }
  
  return createdQueues;
}

function getVulnerabilitySubType(vuln) {
  const desc = vuln.description.toLowerCase();
  const checkId = vuln.checkId?.toLowerCase() || '';
  
  if (desc.includes('sql') || checkId.includes('sql')) return 'SQLi';
  if (desc.includes('command') || checkId.includes('command')) return 'CommandInjection';
  if (desc.includes('eval') || checkId.includes('eval')) return 'EvalInjection';
  if (desc.includes('template') || checkId.includes('template')) return 'SSTI';
  if (desc.includes('reflected')) return 'ReflectedXSS';
  if (desc.includes('stored')) return 'StoredXSS';
  if (desc.includes('dom')) return 'DOMXSS';
  if (desc.includes('innerhtml') || desc.includes('document.write')) return 'DOMXSS';
  
  return vuln.type.charAt(0).toUpperCase() + vuln.type.slice(1);
}

function generateWitnessPayload(vuln) {
  const subType = getVulnerabilitySubType(vuln);
  
  switch (subType) {
    case 'SQLi':
      return "' OR '1'='1' --";
    case 'CommandInjection':
      return "; whoami";
    case 'EvalInjection':
      return "require('child_process').execSync('id')";
    case 'SSTI':
      return "{{7*7}}";
    case 'ReflectedXSS':
    case 'StoredXSS':
    case 'DOMXSS':
      return "<img src=x onerror=alert(1)>";
    default:
      return "test_payload";
  }
}
