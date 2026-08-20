import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from './rate-limiter.js';

describe('RateLimiter', () => {
  let limiter;

  beforeEach(() => {
    limiter = new RateLimiter({ maxRetries: 3, enableLogging: false });
  });

  describe('constructor', () => {
    it('should initialize with default options', () => {
      const rl = new RateLimiter();
      expect(rl.maxRetries).toBe(3);
      expect(rl.errorLog).toEqual([]);
      expect(rl.retriedSuccessCount).toBe(0);
    });

    it('should accept custom options', () => {
      const rl = new RateLimiter({ maxRetries: 5, enableLogging: false });
      expect(rl.maxRetries).toBe(5);
    });
  });

  describe('executeWithRetry', () => {
    it('should succeed on first attempt', async () => {
      const result = await limiter.executeWithRetry(async () => 42, 'test');
      expect(result).toBe(42);
    });

    it('should retry on retryable errors', async () => {
      let attempts = 0;
      const result = await limiter.executeWithRetry(async () => {
        attempts++;
        if (attempts < 3) {
          const err = new Error('timeout');
          err.status = 408;
          throw err;
        }
        return 'success';
      }, 'test', { maxRetries: 3 });

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    }, 30000);

    it('should fail after max retries', async () => {
      let attempts = 0;
      try {
        await limiter.executeWithRetry(async () => {
          attempts++;
          const err = new Error('timeout');
          err.status = 408;
          throw err;
        }, 'test', { maxRetries: 2 });
      } catch (e) {
        expect(attempts).toBe(2);
        expect(e.message).toContain('timeout');
      }
    }, 30000);

    it('should not retry non-retryable errors', async () => {
      let attempts = 0;
      try {
        await limiter.executeWithRetry(async () => {
          attempts++;
          const err = new Error('Unauthorized');
          err.status = 401;
          throw err;
        }, 'test');
      } catch (e) {
        expect(attempts).toBe(1); // Only 1 attempt — no retry
        expect(e.message).toContain('Unauthorized');
      }
    });

    it('should throw if maxRetries < 1', async () => {
      try {
        await limiter.executeWithRetry(async () => 'ok', 'test', { maxRetries: 0 });
        expect(true).toBe(false); // Should not reach here
      } catch (e) {
        expect(e.message).toContain('maxRetries must be >= 1');
      }
    });

    it('should track retried success count', async () => {
      let attempts = 0;
      await limiter.executeWithRetry(async () => {
        attempts++;
        if (attempts === 1) {
          const err = new Error('timeout');
          err.status = 408;
          throw err;
        }
        return 'ok';
      }, 'test');

      expect(limiter.retriedSuccessCount).toBe(1);
    });
  });

  describe('executeParallelWithStagger', () => {
    it('should execute multiple tasks', async () => {
      const tasks = [
        { name: 'task1', fn: async () => 'result1' },
        { name: 'task2', fn: async () => 'result2' }
      ];

      const summary = await limiter.executeParallelWithStagger(tasks, { staggerDelay: 10 });
      expect(summary.total).toBe(2);
      expect(summary.succeeded).toBe(2);
      expect(summary.failed).toBe(0);
    });

    it('should handle task failures', async () => {
      const tasks = [
        { name: 'task1', fn: async () => 'result1' },
        {
          name: 'task2', fn: async () => {
            throw new Error('failed');
          }
        }
      ];

      const summary = await limiter.executeParallelWithStagger(tasks, { staggerDelay: 10, maxAttempts: 1 });
      expect(summary.succeeded).toBe(1);
      expect(summary.failed).toBe(1);
    });

    it('should throw if maxAttempts < 1', async () => {
      try {
        await limiter.executeParallelWithStagger([], { maxAttempts: 0 });
        expect(true).toBe(false);
      } catch (e) {
        expect(e.message).toContain('maxAttempts must be >= 1');
      }
    });
  });

  describe('executeWithFallback', () => {
    it('should use primary when it succeeds', async () => {
      const result = await limiter.executeWithFallback(
        async () => 'primary',
        async () => 'fallback',
        'test'
      );
      expect(result.result).toBe('primary');
      expect(result.usedFallback).toBe(false);
    });

    it('should use fallback when primary fails', async () => {
      const result = await limiter.executeWithFallback(
        async () => { throw new Error('primary failed'); },
        async () => 'fallback result',
        'test'
      );
      expect(result.result).toBe('fallback result');
      expect(result.usedFallback).toBe(true);
    });

    it('should throw when both fail', async () => {
      try {
        await limiter.executeWithFallback(
          async () => { throw new Error('primary failed'); },
          async () => { throw new Error('fallback failed'); },
          'test'
        );
      } catch (e) {
        expect(e.message).toContain('fallback failed');
      }
    });
  });

  describe('error logging', () => {
    it('should log errors', async () => {
      try {
        await limiter.executeWithRetry(async () => {
          const err = new Error('rate limit');
          err.status = 429;
          throw err;
        }, 'test', { maxRetries: 1 });
      } catch (e) {
        // expected
      }

      const log = limiter.getErrorLog();
      expect(log.length).toBeGreaterThan(0);
      expect(log[0].error.type).toBe('RATE_LIMIT');
    });

    it('should provide error stats', async () => {
      try {
        await limiter.executeWithRetry(async () => {
          const err = new Error('rate limit');
          err.status = 429;
          throw err;
        }, 'test', { maxRetries: 1 });
      } catch (e) {
        // expected
      }

      const stats = limiter.getErrorStats();
      expect(stats.total).toBeGreaterThan(0);
      expect(stats.rateLimitErrors).toBe(1);
    });

    it('should clear error log', () => {
      limiter.getErrorLog().push({ test: true });
      limiter.clearErrorLog();
      expect(limiter.getErrorLog()).toHaveLength(0);
    });
  });
});
