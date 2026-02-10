import { describe, it, expect, beforeEach } from 'vitest';
import { BypassEngine, createBypassEngine } from './bypass-engine.js';

describe('BypassEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new BypassEngine(10);
  });

  describe('constructor', () => {
    it('should initialize with default state', () => {
      expect(engine.attemptCount).toBe(0);
      expect(engine.maxAttempts).toBe(10);
      expect(engine.blockedPayloads).toEqual([]);
      expect(engine.successfulBypass).toBeNull();
    });
  });

  describe('createBypassEngine factory', () => {
    it('should return a BypassEngine instance', () => {
      const eng = createBypassEngine(15);
      expect(eng).toBeInstanceOf(BypassEngine);
      expect(eng.maxAttempts).toBe(15);
    });
  });

  describe('generateBypasses', () => {
    const blockingContext = {
      reason: 'WAF blocked',
      httpStatus: 403,
      wafName: 'cloudflare',
      wafDetected: true
    };

    const vulnerability = {
      vulnerabilityType: 'injection',
      type: 'injection'
    };

    const techContext = {
      database: 'MySQL'
    };

    it('should return structured bypass result', () => {
      const result = engine.generateBypasses(
        "' OR '1'='1'--",
        blockingContext,
        vulnerability,
        techContext
      );

      expect(result).toHaveProperty('bypasses');
      expect(result).toHaveProperty('guidance');
      expect(result).toHaveProperty('techniques');
      expect(result).toHaveProperty('blockedHistory');
      expect(result).toHaveProperty('attemptsUsed');
      expect(result).toHaveProperty('attemptsRemaining');
      expect(Array.isArray(result.bypasses)).toBe(true);
      expect(Array.isArray(result.techniques)).toBe(true);
    });

    it('should generate encoding bypasses', () => {
      const result = engine.generateBypasses(
        "' OR '1'='1'--",
        { httpStatus: 400 },
        vulnerability,
        {}
      );

      // Should have URL-encoded, double-URL-encoded, unicode, html, hex variants
      expect(result.bypasses.length).toBeGreaterThan(0);

      // At least one should contain percent-encoded single quote
      const hasUrlEncoded = result.bypasses.some(b => b.includes('%27'));
      expect(hasUrlEncoded).toBe(true);
    });

    it('should generate SQL technique bypasses for injection', () => {
      const result = engine.generateBypasses(
        "' UNION SELECT NULL--",
        blockingContext,
        vulnerability,
        techContext
      );

      // Should have comment injection (/**/)
      const hasCommentInjection = result.bypasses.some(b => b.includes('/**/'));
      expect(hasCommentInjection).toBe(true);
    });

    it('should generate XSS technique bypasses', () => {
      const xssVuln = { vulnerabilityType: 'xss', type: 'xss' };
      const result = engine.generateBypasses(
        '<script>alert(1)</script>',
        blockingContext,
        xssVuln,
        {}
      );

      // Should have case variations or alternative tags
      const hasVariation = result.bypasses.some(b =>
        b.includes('ScRiPt') || b.includes('svg') || b.includes('prompt') || b.includes('confirm')
      );
      expect(hasVariation).toBe(true);
    });

    it('should generate traversal bypasses', () => {
      const travVuln = { vulnerabilityType: 'traversal', type: 'traversal' };
      const result = engine.generateBypasses(
        '../../../etc/passwd',
        { httpStatus: 403 },
        travVuln,
        {}
      );

      // Should have encoding variations
      const hasEncoded = result.bypasses.some(b =>
        b.includes('%2f') || b.includes('%2e') || b.includes('....//') || b.includes('..;/')
      );
      expect(hasEncoded).toBe(true);
    });

    it('should generate SSRF IP obfuscation bypasses', () => {
      const ssrfVuln = { vulnerabilityType: 'ssrf', type: 'ssrf' };
      const result = engine.generateBypasses(
        'http://127.0.0.1/',
        blockingContext,
        ssrfVuln,
        {}
      );

      // Should have decimal, hex, or IPv6 variations
      const hasObfuscation = result.bypasses.some(b =>
        b.includes('2130706433') || b.includes('0x7f') || b.includes('[::1]')
      );
      expect(hasObfuscation).toBe(true);
    });

    it('should track blocked payloads', () => {
      engine.generateBypasses("payload1", blockingContext, vulnerability, techContext);
      engine.generateBypasses("payload2", blockingContext, vulnerability, techContext);

      const result = engine.generateBypasses("payload3", blockingContext, vulnerability, techContext);

      expect(result.blockedHistory.length).toBe(3);
      expect(result.blockedHistory).toContain('payload1');
    });

    it('should not return previously blocked payloads', () => {
      const result1 = engine.generateBypasses("' OR 1=1--", blockingContext, vulnerability, techContext);

      // Now block one of the bypass payloads
      if (result1.bypasses.length > 0) {
        const blockedBypass = result1.bypasses[0];
        const result2 = engine.generateBypasses(blockedBypass, blockingContext, vulnerability, techContext);

        // The original blocked bypass should not appear in new results
        expect(result2.bypasses).not.toContain(blockedBypass);
      }
    });

    it('should include WAF-specific guidance', () => {
      const result = engine.generateBypasses(
        "' OR 1=1--",
        { httpStatus: 403, wafName: 'cloudflare', wafDetected: true },
        vulnerability,
        techContext
      );

      expect(result.guidance).toContain('WAF detected');
    });

    it('should include 403-specific guidance', () => {
      const result = engine.generateBypasses(
        "' OR 1=1--",
        { httpStatus: 403 },
        vulnerability,
        {}
      );

      expect(result.guidance).toContain('403');
    });

    it('should generate MySQL-specific bypasses', () => {
      const result = engine.generateBypasses(
        "' OR SLEEP(5)--",
        blockingContext,
        vulnerability,
        { database: 'MySQL' }
      );

      // MySQL specific: /*!*/ or BENCHMARK
      const hasMysqlBypass = result.bypasses.some(b =>
        b.includes('/*!*/') || b.includes('BENCHMARK')
      );
      expect(hasMysqlBypass).toBe(true);
    });

    it('should generate PostgreSQL-specific bypasses', () => {
      const result = engine.generateBypasses(
        "'; SELECT SLEEP(5)--",
        blockingContext,
        vulnerability,
        { database: 'PostgreSQL' }
      );

      const hasPgBypass = result.bypasses.some(b =>
        b.includes('PG_SLEEP')
      );
      expect(hasPgBypass).toBe(true);
    });
  });

  describe('state management', () => {
    it('should track attempts', () => {
      const result = engine.generateBypasses(
        "test",
        { httpStatus: 403 },
        { vulnerabilityType: 'injection' },
        {}
      );

      expect(engine.getTotalAttempts()).toBeGreaterThan(0);
      expect(result.attemptsUsed).toBeGreaterThan(0);
    });

    it('should report exhaustion when max attempts reached', () => {
      const smallEngine = new BypassEngine(1);
      smallEngine.generateBypasses(
        "test payload",
        { httpStatus: 403 },
        { vulnerabilityType: 'injection' },
        {}
      );

      expect(smallEngine.isExhausted()).toBe(true);
    });

    it('should record successful bypass', () => {
      engine.recordSuccess("encoded_payload", "URL encoding");
      const success = engine.getSuccessfulBypass();

      expect(success).not.toBeNull();
      expect(success.payload).toBe("encoded_payload");
      expect(success.technique).toBe("URL encoding");
      expect(success.timestamp).toBeDefined();
    });

    it('should reset state', () => {
      engine.generateBypasses("test", { httpStatus: 403 }, { vulnerabilityType: 'xss' }, {});
      engine.recordSuccess("bypass", "technique");

      engine.reset();

      expect(engine.attemptCount).toBe(0);
      expect(engine.blockedPayloads).toEqual([]);
      expect(engine.successfulBypass).toBeNull();
    });
  });
});
