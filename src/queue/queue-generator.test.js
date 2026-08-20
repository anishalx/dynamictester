import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateExploitationQueue } from './queue-generator.js';
import { fs, path } from 'zx';

describe('QueueGenerator', () => {
  let tempDir;

  beforeEach(async () => {
    tempDir = path.join(process.cwd(), '__test_output_' + Date.now());
    await fs.ensureDir(tempDir);
  });

  afterEach(async () => {
    await fs.remove(tempDir).catch(() => {});
  });

  const makeVuln = (overrides = {}) => ({
    id: 'TEST-vuln-1',
    source: 'semgrep',
    type: 'injection',
    subType: 'SQLi',
    severity: 'HIGH',
    confidence: 'HIGH',
    location: { file: 'routes/login.js', line: 34, column: 10 },
    description: 'SQL injection in login',
    remediation: 'Use parameterized queries',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    cvss: 8.5,
    cve: [],
    checkId: 'sql-injection',
    reference: '',
    metadata: {},
    ...overrides
  });

  it('should group vulnerabilities by type', async () => {
    const vulns = [
      makeVuln({ id: '1', type: 'injection', subType: 'SQLi' }),
      makeVuln({ id: '2', type: 'xss', subType: 'ReflectedXSS' }),
      makeVuln({ id: '3', type: 'injection', subType: 'NoSQLi' }),
      makeVuln({ id: '4', type: 'secrets', subType: 'HardcodedSecret' })
    ];

    const queues = await generateExploitationQueue(vulns, tempDir);

    expect(queues.injection).toHaveLength(2);
    expect(queues.xss).toHaveLength(1);
    expect(queues.secrets).toHaveLength(1);
  });

  it('should sort by priority descending within each type', async () => {
    const vulns = [
      makeVuln({ id: 'low-inj', severity: 'LOW', confidence: 'LOW', type: 'injection', subType: 'SQLi' }),
      makeVuln({ id: 'high-inj', severity: 'CRITICAL', confidence: 'HIGH', type: 'injection', subType: 'SQLi' })
    ];

    const queues = await generateExploitationQueue(vulns, tempDir);

    expect(queues.injection[0].id).toBe('high-inj'); // CRITICAL+HIGH gets higher score
  });

  it('should save queue files to deliverables directory', async () => {
    const vulns = [makeVuln({ id: '1', type: 'injection' })];
    await generateExploitationQueue(vulns, tempDir);

    const deliverablesDir = path.join(tempDir, 'deliverables');
    expect(await fs.pathExists(deliverablesDir)).toBe(true);

    const queueFile = path.join(deliverablesDir, 'injection_exploitation_queue.json');
    expect(await fs.pathExists(queueFile)).toBe(true);
  });

  it('should skip malformed entries', async () => {
    const vulns = [null, undefined, 'string', 123, makeVuln({ id: 'valid' })];
    const queues = await generateExploitationQueue(vulns, tempDir);

    const total = Object.values(queues).reduce((sum, q) => sum + q.length, 0);
    expect(total).toBe(1);
  });

  it('should handle empty input', async () => {
    const queues = await generateExploitationQueue([], tempDir);
    const total = Object.values(queues).reduce((sum, q) => sum + q.length, 0);
    expect(total).toBe(0);
  });

  it('should include endpoint data from route enrichment', async () => {
    const vulns = [makeVuln({
      id: '1',
      type: 'injection',
      suggestedEndpoint: '/api/login',
      suggestedMethod: 'POST'
    })];

    const queues = await generateExploitationQueue(vulns, tempDir);
    expect(queues.injection[0].suggestedEndpoint).toBe('/api/login');
    expect(queues.injection[0].suggestedMethod).toBe('POST');
  });

  it('should route unknown types to other queue', async () => {
    const vulns = [makeVuln({ id: '1', type: 'unknown_type' })];
    const queues = await generateExploitationQueue(vulns, tempDir);
    expect(queues.other).toHaveLength(1);
  });    it('should generate witness payloads for known types', async () => {
    const vulns = [
      makeVuln({ id: '1', type: 'injection', subType: 'SQLi' }),
      makeVuln({ id: '2', type: 'xss', subType: 'ReflectedXSS' }),
      makeVuln({ id: '3', type: 'ssrf', subType: 'SSRF' })
    ];

    const queues = await generateExploitationQueue(vulns, tempDir);
    expect(queues.injection[0].witnessPayload).toContain("' OR");
    expect(queues.xss[0].witnessPayload).toBeDefined();
    expect(queues.ssrf[0].witnessPayload).toContain('169.254');
  });
});
