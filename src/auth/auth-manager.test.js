import { describe, it, expect, beforeEach } from 'vitest';
import { AuthManager, getAuthManager } from './auth-manager.js';

describe('AuthManager', () => {
  let auth;

  beforeEach(() => {
    auth = new AuthManager();
  });

  describe('JWT Token', () => {
    it('should store valid JWT token (3 parts)', () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.abc123';
      const result = auth.setJwtToken(token);
      expect(result.success).toBe(true);
      expect(result.type).toBe('jwt');
    });

    it('should store non-JWT token as Bearer', () => {
      const token = 'some-random-token-value';
      const result = auth.setJwtToken(token);
      expect(result.success).toBe(true);
      expect(result.type).toBe('bearer');
    });

    it('should reject invalid tokens', () => {
      const result = auth.setJwtToken(null);
      expect(result.success).toBe(false);
    });

    it('should reject empty string', () => {
      const result = auth.setJwtToken('');
      expect(result.success).toBe(false);
    });
  });

  describe('Cookies', () => {
    it('should store cookies from array', () => {
      const cookies = [
        { name: 'session', value: 'abc123' },
        { name: 'token', value: 'xyz' }
      ];
      const result = auth.setCookies(cookies);
      expect(result.success).toBe(true);
      expect(result.cookieCount).toBe(2);
    });

    it('should store cookies from object', () => {
      const cookies = { session: 'abc123', token: 'xyz' };
      const result = auth.setCookies(cookies);
      expect(result.success).toBe(true);
      expect(result.cookieCount).toBe(2);
    });

    it('should set authType to cookie when cookies stored first', () => {
      auth.setCookies([{ name: 'sid', value: 'abc' }]);
      expect(auth.authType).toBe('cookie');
    });
  });

  describe('Custom Headers', () => {
    it('should store custom header', () => {
      const result = auth.setCustomHeader('X-Auth-Token', 'my-token');
      expect(result.success).toBe(true);
      expect(result.header).toBe('X-Auth-Token');
    });

    it('should set authType to custom', () => {
      auth.setCustomHeader('X-Custom', 'value');
      expect(auth.authType).toBe('custom');
    });
  });

  describe('getAuthHeaders', () => {
    it('should return JWT Bearer header', () => {
      auth.setJwtToken('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.abc123');
      const headers = auth.getAuthHeaders();
      expect(headers['Authorization']).toContain('Bearer');
    });

    it('should return Cookie header from cookies', () => {
      auth.setCookies([{ name: 'sid', value: 'abc123' }]);
      const headers = auth.getAuthHeaders();
      expect(headers['Cookie']).toContain('sid=abc123');
    });

    it('should include custom headers', () => {
      auth.setCustomHeader('X-API-Key', 'key123');
      const headers = auth.getAuthHeaders();
      expect(headers['X-API-Key']).toBe('key123');
    });

    it('should merge all auth types', () => {
      auth.setJwtToken('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.abc123');
      auth.setCookies([{ name: 'sid', value: 'abc' }]);
      auth.setCustomHeader('X-API-Key', 'key');
      const headers = auth.getAuthHeaders();
      expect(headers['Authorization']).toBeDefined();
      expect(headers['Cookie']).toBeDefined();
      expect(headers['X-API-Key']).toBe('key');
    });
  });

  describe('hasAuth', () => {
    it('should return false when empty', () => {
      expect(auth.hasAuth()).toBe(false);
    });

    it('should return true after setting JWT', () => {
      auth.setJwtToken('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.abc');
      expect(auth.hasAuth()).toBe(true);
    });

    it('should return true after setting cookies', () => {
      auth.setCookies([{ name: 'sid', value: 'abc' }]);
      expect(auth.hasAuth()).toBe(true);
    });
  });

  describe('getStatus', () => {
    it('should return complete status', () => {
      const status = auth.getStatus();
      expect(status).toHaveProperty('hasAuth');
      expect(status).toHaveProperty('authType');
      expect(status).toHaveProperty('cookieCount');
    });
  });

  describe('clear', () => {
    it('should clear all auth data', () => {
      auth.setJwtToken('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.abc');
      auth.setCookies([{ name: 'sid', value: 'abc' }]);
      auth.setCustomHeader('X-Key', 'val');

      auth.clear();
      expect(auth.hasAuth()).toBe(false);
      expect(auth.getStatus().authType).toBeNull();
    });
  });

  describe('getAuthManager singleton', () => {
    it('should return the same instance', () => {
      const m1 = getAuthManager();
      const m2 = getAuthManager();
      expect(m1).toBe(m2);
    });
  });

  describe('JWT_STORAGE_KEYS', () => {
    it('should contain common token key names', () => {
      const keys = AuthManager.JWT_STORAGE_KEYS;
      expect(keys).toContain('token');
      expect(keys).toContain('jwt');
      expect(keys).toContain('accessToken');
      expect(keys).toContain('Authorization');
    });
  });

  describe('AUTH_COOKIE_NAMES', () => {
    it('should contain common auth cookie names', () => {
      const names = AuthManager.AUTH_COOKIE_NAMES;
      expect(names).toContain('session');
      expect(names).toContain('JSESSIONID');
      expect(names).toContain('connect.sid');
    });
  });
});
