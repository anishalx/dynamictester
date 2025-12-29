import { fs } from 'zx';
import chalk from 'chalk';

/**
 * Parse Semgrep static analyzer result.json file
 */
export async function parseStaticAnalysisResult(resultJsonPath) {
  try {
    const content = await fs.readFile(resultJsonPath, 'utf8');
    const result = JSON.parse(content);
    
    const vulnerabilities = [];
    
    // Semgrep uses 'results' array
    const findings = result.results || result.findings || [];
    
    for (const finding of findings) {
      const vulnType = mapVulnerabilityType(finding);
      
      if (vulnType) {
        vulnerabilities.push({
          id: finding.check_id || `VULN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: vulnType,
          severity: finding.extra?.severity || 'ERROR',
          confidence: finding.extra?.metadata?.confidence || 'MEDIUM',
          location: {
            file: finding.path,
            line: finding.start?.line,
            column: finding.start?.col,
            endLine: finding.end?.line,
            endColumn: finding.end?.col
          },
          description: finding.extra?.message || '',
          cwe: finding.extra?.metadata?.cwe || [],
          owasp: finding.extra?.metadata?.owasp || [],
          vulnerabilityClass: finding.extra?.metadata?.vulnerability_class || [],
          checkId: finding.check_id,
          shortlink: finding.extra?.metadata?.shortlink || ''
        });
      }
    }
    
    console.log(chalk.green(`✅ Parsed ${vulnerabilities.length} vulnerabilities from ${findings.length} total findings`));
    
    // Group by type for summary
    const summary = {};
    for (const v of vulnerabilities) {
      summary[v.type] = (summary[v.type] || 0) + 1;
    }
    for (const [type, count] of Object.entries(summary)) {
      console.log(chalk.cyan(`   - ${type}: ${count}`));
    }
    
    return vulnerabilities;
    
  } catch (error) {
    console.error(chalk.red(`❌ Failed to parse result.json: ${error.message}`));
    throw error;
  }
}

/**
 * Map Semgrep check_id and vulnerability_class to our internal types
 */
function mapVulnerabilityType(finding) {
  const checkId = finding.check_id?.toLowerCase() || '';
  const vulnClass = finding.extra?.metadata?.vulnerability_class || [];
  const cwe = finding.extra?.metadata?.cwe || [];
  
  // Check vulnerability_class first
  for (const vc of vulnClass) {
    const vcLower = vc.toLowerCase();
    if (vcLower.includes('sql injection')) return 'injection';
    if (vcLower.includes('command injection')) return 'injection';
    if (vcLower.includes('code injection')) return 'injection';
    if (vcLower.includes('xss') || vcLower.includes('cross-site scripting')) return 'xss';
    if (vcLower.includes('ssrf')) return 'ssrf';
    if (vcLower.includes('secret') || vcLower.includes('credential')) return 'secrets';
    if (vcLower.includes('crypto')) return 'crypto';
  }
  
  // Check CWE codes
  for (const c of cwe) {
    if (c.includes('CWE-89')) return 'injection'; // SQL Injection
    if (c.includes('CWE-78') || c.includes('CWE-77')) return 'injection'; // Command Injection
    if (c.includes('CWE-95') || c.includes('CWE-94')) return 'injection'; // Code Injection
    if (c.includes('CWE-79')) return 'xss'; // XSS
    if (c.includes('CWE-918')) return 'ssrf'; // SSRF
    if (c.includes('CWE-798') || c.includes('CWE-321')) return 'secrets'; // Hardcoded credentials
  }
  
  // Check check_id patterns
  if (checkId.includes('injection') || checkId.includes('sqli')) return 'injection';
  if (checkId.includes('xss')) return 'xss';
  if (checkId.includes('ssrf')) return 'ssrf';
  if (checkId.includes('secret') || checkId.includes('credential') || checkId.includes('jwt')) return 'secrets';
  if (checkId.includes('auth')) return 'auth';
  
  // Default: include as 'other' so we don't miss anything
  return 'other';
}
