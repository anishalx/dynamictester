import { describe, it, expect } from 'vitest';
import {
  isRetryableError,
  isRateLimitError,
  isModelNotFoundError,
  getRetryDelay,
  formatDelay,
  classifyError,
  parseRetryAfter,
  sleep
} from './error-handling.js';

describe('Error Handling Utilities', () => {
  describe('isRetryableError', () => {
    it('should retry on rate limit (429)', () => {
      const err = new Error('Too many requests');
      err.status = 429;
      expect(isRetryableError(err)).toBe(true);
    });

    it('should retry on server errors (5xx)', () => {
      for (const status of [500, 502, 503, 504]) {
        const err = new Error(`Server error ${status}`);
        err.status = status;
        expect(isRetryableError(err)).toBe(true);
      }
    });

    it('should retry on timeout (408)', () => {
      const err = new Error('Request timeout');
      err.status = 408;
      expect(isRetryableError(err)).toBe(true);
    });

    it('should retry on APIConnectionError', () => {
      const err = new Error('Connection failed');
      err.name = 'APIConnectionError';
      expect(isRetryableError(err)).toBe(true);
    });

    it('should retry on network error messages', () => {
      const messages = ['fetch failed', 'ECONNRESET', 'ECONNREFUSED', 'socket hang up'];
      for (const msg of messages) {
        const err = new Error(msg);
        expect(isRetryableError(err)).toBe(true);
      }
    });

    it('should retry on timeout messages', () => {
      const err = new Error('Request timed out');
      expect(isRetryableError(err)).toBe(true);
    });

    it('should NOT retry on auth errors (401/403)', () => {
      const err401 = new Error('Unauthorized');
      err401.status = 401;
      expect(isRetryableError(err401)).toBe(false);

      const err403 = new Error('Forbidden');
      err403.status = 403;
      expect(isRetryableError(err403)).toBe(false);
    });

    it('should NOT retry on random errors', () => {
      const err = new Error('Something went wrong');
      expect(isRetryableError(err)).toBe(false);
    });

    it('should NOT match "5000" as "500" in non-timeout context', () => {
      // "5000ms" is a timeout message — it SHOULD be retryable via timeout detection
      // The word boundary test applies to HTTP status codes, not timeout values
      const err = new Error('Connection reset after 5000 items processed');
      expect(isRetryableError(err)).toBe(false);
    });

    it('should NOT match "4291 items" as "429" (word boundary)', () => {
      const err = new Error('Processed 4291 items');
      expect(isRetryableError(err)).toBe(false);
    });
  });

  describe('isRateLimitError', () => {
    it('should detect rate limit by status code', () => {
      const err = new Error('rate limited');
      err.status = 429;
      expect(isRateLimitError(err)).toBe(true);
    });

    it('should detect rate limit by message', () => {
      const err = new Error('rate limit exceeded');
      expect(isRateLimitError(err)).toBe(true);
    });

    it('should detect 429 in message', () => {
      const err = new Error('Error 429: too many requests');
      expect(isRateLimitError(err)).toBe(true);
    });

    it('should not false positive on non-rate-limit errors', () => {
      const err = new Error('Connection refused');
      expect(isRateLimitError(err)).toBe(false);
    });
  });

  describe('isModelNotFoundError', () => {
    it('should detect model not found (404)', () => {
      const err = new Error('model does not exist');
      err.status = 404;
      expect(isModelNotFoundError(err)).toBe(true);
    });

    it('should detect no access to model', () => {
      const err = new Error('You do not have access to this model');
      expect(isModelNotFoundError(err)).toBe(true);
    });

    it('should not false positive on other 404 errors', () => {
      const err = new Error('Page not found');
      err.status = 404;
      expect(isModelNotFoundError(err)).toBe(false);
    });
  });

  describe('getRetryDelay', () => {
    it('should return longer delays for rate limit errors', () => {
      const err = new Error('rate limit');
      err.status = 429;
      const delay1 = getRetryDelay(err, 1);
      const delay2 = getRetryDelay(err, 2);
      expect(delay1).toBeGreaterThan(10000);
      expect(delay2).toBeGreaterThan(delay1);
    });

    it('should return medium delays for server errors', () => {
      const err = new Error('server error');
      err.status = 500;
      const delay = getRetryDelay(err, 1);
      expect(delay).toBeGreaterThan(5000);
      expect(delay).toBeLessThan(60000);
    });

    it('should cap rate limit delays at 120s', () => {
      const err = new Error('rate limit');
      err.status = 429;
      const delay = getRetryDelay(err, 10);
      expect(delay).toBeLessThanOrEqual(120000);
    });

    it('should cap server error delays at 60s', () => {
      const err = new Error('server error');
      err.status = 503;
      const delay = getRetryDelay(err, 10);
      expect(delay).toBeLessThanOrEqual(60000);
    });
  });

  describe('parseRetryAfter', () => {
    it('should parse Retry-After header from error.headers', () => {
      const err = new Error('rate limit');
      err.headers = { 'retry-after': '30' };
      const delay = parseRetryAfter(err);
      expect(delay).toBe(30000);
    });

    it('should parse from error.response.headers', () => {
      const err = new Error('rate limit');
      err.response = { headers: { 'Retry-After': '45' } };
      const delay = parseRetryAfter(err);
      expect(delay).toBe(45000);
    });

    it('should return null when no header present', () => {
      const err = new Error('rate limit');
      expect(parseRetryAfter(err)).toBeNull();
    });

    it('should cap at 2 minutes', () => {
      const err = new Error('rate limit');
      err.headers = { 'retry-after': '300' };
      const delay = parseRetryAfter(err);
      expect(delay).toBe(120000);
    });
  });

  describe('formatDelay', () => {
    it('should format milliseconds to seconds string', () => {
      expect(formatDelay(1000)).toBe('1.0s');
      expect(formatDelay(5000)).toBe('5.0s');
      expect(formatDelay(1500)).toBe('1.5s');
    });
  });

  describe('classifyError', () => {
    it('should classify rate limit errors', () => {
      const err = new Error('rate limit');
      err.status = 429;
      expect(classifyError(err)).toBe('RATE_LIMIT');
    });

    it('should classify server errors', () => {
      const err = new Error('server error');
      err.status = 500;
      expect(classifyError(err)).toBe('SERVER_ERROR');
    });

    it('should classify timeout errors', () => {
      const err = new Error('timeout');
      err.status = 408;
      expect(classifyError(err)).toBe('TIMEOUT');
    });

    it('should classify network errors', () => {
      const err = new Error('fetch failed');
      expect(classifyError(err)).toBe('NETWORK_ERROR');
    });

    it('should classify auth errors', () => {
      const err = new Error('Unauthorized');
      err.status = 401;
      expect(classifyError(err)).toBe('AUTH_ERROR');
    });

    it('should classify TOS errors', () => {
      const err = new Error('Terms of service violation');
      err.status = 403;
      expect(classifyError(err)).toBe('TOS_ERROR');
    });

    it('should return UNKNOWN for unrecognized errors', () => {
      const err = new Error('something weird');
      expect(classifyError(err)).toBe('UNKNOWN');
    });
  });

  describe('sleep', () => {
    it('should resolve after specified time', async () => {
      const start = Date.now();
      await sleep(50);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(40);
    });
  });
});
