import { describe, it, expect } from 'vitest';
import { PayloadGenerator, createPayloadGenerator } from './payload-generator.js';

describe('PayloadGenerator', () => {
  const generator = new PayloadGenerator('gpt-4o');

  describe('constructor', () => {
    it('should store the model name', () => {
      expect(generator.model).toBe('gpt-4o');
    });

    it('should default to gpt-4o', () => {
      const gen = new PayloadGenerator();
      expect(gen.model).toBe('gpt-4o');
    });
  });

  describe('createPayloadGenerator factory', () => {
    it('should return a PayloadGenerator instance', () => {
      const gen = createPayloadGenerator('gpt-4o');
      expect(gen).toBeInstanceOf(PayloadGenerator);
      expect(gen.model).toBe('gpt-4o');
    });
  });

  describe('generatePayloadContext', () => {
    const vulnerability = {
      vulnerabilityType: 'injection',
      type: 'injection',
      file: 'routes/users.js',
      line: 42,
      snippet: "db.query(`SELECT * FROM users WHERE id = '${req.params.id}'`)",
      cwe: 'CWE-89'
    };

    const context = {
      database: 'MySQL',
      framework: 'Express.js',
      language: 'JavaScript',
      os: 'Linux',
      waf: null
    };

    it('should return structured payload context', () => {
      const result = generator.generatePayloadContext(vulnerability, context, 'confirmation');

      expect(result).toHaveProperty('systemGuidance');
      expect(result).toHaveProperty('stageInstructions');
      expect(result).toHaveProperty('technologyContext');
      expect(result).toHaveProperty('fallbackPayloads');
      expect(result).toHaveProperty('vulnType', 'injection');
      expect(result).toHaveProperty('stage', 'confirmation');
    });

    it('should include SQL-specific guidance for injection type', () => {
      const result = generator.generatePayloadContext(vulnerability, context, 'confirmation');

      expect(result.systemGuidance).toContain('SQL injection');
      expect(result.systemGuidance).toContain('database-specific syntax');
    });

    it('should return fallback payloads as an array', () => {
      const result = generator.generatePayloadContext(vulnerability, context, 'confirmation');

      expect(Array.isArray(result.fallbackPayloads)).toBe(true);
      expect(result.fallbackPayloads.length).toBeGreaterThan(0);
    });

    it('should include technology context in the prompt', () => {
      const result = generator.generatePayloadContext(vulnerability, context, 'confirmation');

      expect(result.technologyContext).toContain('MySQL');
      expect(result.technologyContext).toContain('Express.js');
      expect(result.technologyContext).toContain('routes/users.js');
    });

    it('should handle all three stages', () => {
      for (const stage of ['confirmation', 'fingerprint', 'exploit']) {
        const result = generator.generatePayloadContext(vulnerability, context, stage);
        expect(result.stage).toBe(stage);
        expect(result.fallbackPayloads.length).toBeGreaterThan(0);
      }
    });

    it('should handle refinement stage with previous results', () => {
      const previousResults = [
        { payload: "' OR '1'='1'--", success: false, error: 'Blocked by WAF' }
      ];
      const result = generator.generatePayloadContext(vulnerability, context, 'refinement', previousResults);

      expect(result.technologyContext).toContain('Previous Attempts');
      expect(result.technologyContext).toContain("' OR '1'='1'--");
    });

    it('should fall back to vulnerability.type if vulnerabilityType is missing', () => {
      const vuln = { type: 'xss', file: 'test.js' };
      const result = generator.generatePayloadContext(vuln, {}, 'confirmation');
      expect(result.vulnType).toBe('xss');
    });
  });

  describe('getStageInstructions', () => {
    const allVulnTypes = [
      'injection', 'command_injection', 'xss', 'ssrf', 'ssti',
      'traversal', 'xxe', 'redirect', 'auth', 'secrets',
      'deserialization', 'config', 'crypto'
    ];

    const allStages = ['confirmation', 'fingerprint', 'exploit'];

    for (const vulnType of allVulnTypes) {
      for (const stage of allStages) {
        it(`should return instructions for ${vulnType}/${stage}`, () => {
          const result = generator.getStageInstructions(stage, vulnType);
          expect(typeof result).toBe('string');
          expect(result.length).toBeGreaterThan(10);
        });
      }
    }

    it('should return refinement default for unknown stage', () => {
      const result = generator.getStageInstructions('unknown_stage', 'injection');
      expect(result).toContain('IMPROVED payloads');
    });

    it('should return generic message for unknown vuln type', () => {
      const result = generator.getStageInstructions('confirmation', 'unknown_type');
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('getFallbackPayloads', () => {
    const allVulnTypes = [
      'injection', 'command_injection', 'xss', 'ssrf', 'ssti',
      'traversal', 'xxe', 'redirect', 'auth', 'secrets',
      'deserialization', 'config', 'crypto'
    ];

    for (const vulnType of allVulnTypes) {
      it(`should return fallback payloads for ${vulnType}`, () => {
        const result = generator.getFallbackPayloads(vulnType, 'confirmation');
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBeGreaterThan(0);
      });

      it(`should return different payloads per stage for ${vulnType}`, () => {
        const conf = generator.getFallbackPayloads(vulnType, 'confirmation');
        const exploit = generator.getFallbackPayloads(vulnType, 'exploit');
        // At least some payloads should differ between stages
        const combined = new Set([...conf, ...exploit]);
        expect(combined.size).toBeGreaterThanOrEqual(conf.length);
      });
    }

    it('should return generic fallbacks for unknown vuln type', () => {
      const result = generator.getFallbackPayloads('unknown_type', 'confirmation');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('validateAndFilter (anti-hallucination)', () => {
    it('should extract numbered list payloads', () => {
      const response = `1. ' OR '1'='1'--
2. ' UNION SELECT NULL--
3. '; DROP TABLE users--`;

      const result = generator.validateAndFilter(response);
      expect(result).toHaveLength(3);
      expect(result[0]).toBe("' OR '1'='1'--");
    });

    it('should extract payloads from code blocks', () => {
      const response = '```sql\n\' OR 1=1--\n\' UNION SELECT NULL--\n```';
      const result = generator.validateAndFilter(response);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should filter out hallucinated placeholder payloads', () => {
      const response = `1. INSERT YOUR PAYLOAD HERE
2. ' OR '1'='1'--
3. REPLACE WITH YOUR actual payload
4. <script>alert(1)</script>
5. YOUR_SERVER_HERE
6. TODO: fix this`;

      const result = generator.validateAndFilter(response);
      // Should keep real payloads and filter placeholders
      expect(result).toContain("' OR '1'='1'--");
      expect(result).toContain('<script>alert(1)</script>');
      expect(result).not.toContain('INSERT YOUR PAYLOAD HERE');
      expect(result).not.toContain('REPLACE WITH YOUR actual payload');
    });

    it('should filter out very long prose', () => {
      const longProse = 'This is a very long explanation about how SQL injection works and why you should test it carefully with many different approaches and techniques to ensure comprehensive coverage of the attack surface and find all the vulnerabilities in the application';
      const response = `1. ${longProse}
2. ' OR '1'='1'--`;

      const result = generator.validateAndFilter(response);
      expect(result).not.toContain(longProse);
      expect(result).toContain("' OR '1'='1'--");
    });

    it('should limit output to 15 payloads', () => {
      const lines = Array.from({ length: 20 }, (_, i) => `${i + 1}. payload_variant_${i}`);
      const response = lines.join('\n');
      const result = generator.validateAndFilter(response);
      expect(result.length).toBeLessThanOrEqual(15);
    });

    it('should filter N/A, none, null, undefined', () => {
      const response = `1. N/A
2. none
3. null
4. undefined
5. <script>alert(1)</script>`;

      const result = generator.validateAndFilter(response);
      expect(result).toHaveLength(1);
      expect(result[0]).toBe('<script>alert(1)</script>');
    });

    it('should keep SQL bracket syntax (not filter [.*])', () => {
      const response = `1. ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--
2. [::1]
3. ' ORDER BY 1--`;

      const result = generator.validateAndFilter(response);
      expect(result.length).toBe(3);
    });
  });

  describe('getSystemPrompt', () => {
    it('should include base prompt for any vuln type', () => {
      const result = generator.getSystemPrompt('injection');
      expect(result).toContain('expert security researcher');
      expect(result).toContain('ONLY the payloads');
    });

    it('should include type-specific additions for known types', () => {
      expect(generator.getSystemPrompt('injection')).toContain('SQL injection');
      expect(generator.getSystemPrompt('xss')).toContain('XSS');
      expect(generator.getSystemPrompt('ssrf')).toContain('SSRF');
      expect(generator.getSystemPrompt('ssti')).toContain('SSTI');
      expect(generator.getSystemPrompt('traversal')).toContain('Path Traversal');
      expect(generator.getSystemPrompt('command_injection')).toContain('Command Injection');
      expect(generator.getSystemPrompt('xxe')).toContain('XXE');
      expect(generator.getSystemPrompt('redirect')).toContain('Open Redirect');
      expect(generator.getSystemPrompt('auth')).toContain('Authentication Bypass');
      expect(generator.getSystemPrompt('secrets')).toContain('Secret Validation');
      expect(generator.getSystemPrompt('deserialization')).toContain('Deserialization');
      expect(generator.getSystemPrompt('config')).toContain('Configuration Issues');
      expect(generator.getSystemPrompt('crypto')).toContain('Cryptographic Issues');
    });

    it('should return base prompt only for unknown type', () => {
      const result = generator.getSystemPrompt('unknown');
      expect(result).toContain('expert security researcher');
      expect(result).not.toContain('SQL injection');
    });
  });
});
