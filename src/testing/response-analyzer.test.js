import { describe, it, expect } from 'vitest';
import { ResponseAnalyzer } from './response-analyzer.js';

describe('ResponseAnalyzer', () => {
  describe('detectDatabaseErrors', () => {
    it('should detect MySQL errors', () => {
      const response = {
        body: 'You have an error in your SQL syntax near \'test\'',
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('mysql');
      expect(result.confidence).toBe('HIGH');
    });

    it('should detect PostgreSQL errors', () => {
      const response = {
        body: 'ERROR: syntax error at or near "test"',
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('postgresql');
    });

    it('should detect MSSQL errors', () => {
      const response = {
        body: 'Unclosed quotation mark after the character string',
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('mssql');
    });

    it('should detect Oracle errors', () => {
      const response = {
        body: 'ORA-00933: SQL command not properly ended',
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('oracle');
    });

    it('should detect SQLite errors', () => {
      const response = {
        body: 'SQLite error: unrecognized token',
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('sqlite');
    });

    it('should return not detected for clean responses', () => {
      const response = {
        body: '{"users": [{"name": "John"}]}',
        status: 200
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(false);
      expect(result.database).toBeNull();
    });

    it('should handle JSON body objects', () => {
      const response = {
        body: { error: 'You have an error in your SQL syntax' },
        status: 500
      };
      const result = ResponseAnalyzer.detectDatabaseErrors(response);

      expect(result.detected).toBe(true);
      expect(result.database).toBe('mysql');
    });
  });

  describe('detectWAFBlocking', () => {
    it('should detect Cloudflare WAF', () => {
      const response = {
        body: 'Attention Required! | Cloudflare',
        status: 403
      };
      const result = ResponseAnalyzer.detectWAFBlocking(response);

      expect(result.detected).toBe(true);
      expect(result.waf).toBe('cloudflare');
    });

    it('should detect ModSecurity WAF', () => {
      const response = {
        body: 'ModSecurity Action: Access denied',
        status: 403
      };
      const result = ResponseAnalyzer.detectWAFBlocking(response);

      expect(result.detected).toBe(true);
      expect(result.waf).toBe('modsecurity');
    });

    it('should detect generic blocking on 403', () => {
      const response = {
        body: 'Forbidden',
        status: 403
      };
      const result = ResponseAnalyzer.detectWAFBlocking(response);

      expect(result.detected).toBe(true);
    });

    it('should detect generic blocking on 406', () => {
      const response = {
        body: 'Not Acceptable',
        status: 406
      };
      const result = ResponseAnalyzer.detectWAFBlocking(response);

      expect(result.detected).toBe(true);
    });

    it('should return not detected for normal responses', () => {
      const response = {
        body: '{"status": "ok"}',
        status: 200
      };
      const result = ResponseAnalyzer.detectWAFBlocking(response);

      expect(result.detected).toBe(false);
    });
  });

  describe('isValidationError', () => {
    it('should detect HTTP 400 as validation error', () => {
      const response = { body: 'Bad Request', status: 400 };
      expect(ResponseAnalyzer.isValidationError(response)).toBe(true);
    });

    it('should detect "invalid input" pattern', () => {
      const response = { body: 'Invalid input provided', status: 422 };
      expect(ResponseAnalyzer.isValidationError(response)).toBe(true);
    });

    it('should detect "validation failed" pattern', () => {
      const response = { body: 'Validation failed for field: email', status: 422 };
      expect(ResponseAnalyzer.isValidationError(response)).toBe(true);
    });

    it('should return false for normal responses', () => {
      const response = { body: '{"data": []}', status: 200 };
      expect(ResponseAnalyzer.isValidationError(response)).toBe(false);
    });
  });

  describe('compareBooleanResponses', () => {
    it('should detect different responses (content + status)', () => {
      const trueResp = { body: 'Welcome, admin!', status: 200 };
      const falseResp = { body: 'Access denied', status: 403 };

      const result = ResponseAnalyzer.compareBooleanResponses(trueResp, falseResp);

      expect(result.different).toBe(true);
      expect(result.contentDifference).toBe(true);
      expect(result.statusDifference).toBe(true);
      expect(result.confidence).toBe('HIGH');
    });

    it('should detect different content with same status', () => {
      const trueResp = { body: 'Found 5 results', status: 200 };
      const falseResp = { body: 'No results found', status: 200 };

      const result = ResponseAnalyzer.compareBooleanResponses(trueResp, falseResp);

      expect(result.different).toBe(true);
      expect(result.contentDifference).toBe(true);
      expect(result.statusDifference).toBe(false);
    });

    it('should detect identical responses', () => {
      const trueResp = { body: 'Same response', status: 200 };
      const falseResp = { body: 'Same response', status: 200 };

      const result = ResponseAnalyzer.compareBooleanResponses(trueResp, falseResp);

      expect(result.different).toBe(false);
      expect(result.confidence).toBe('NONE');
    });
  });

  describe('measureTimingDifference', () => {
    it('should confirm time-based injection with matching delay', () => {
      const result = ResponseAnalyzer.measureTimingDifference(0.5, 5.5, 5);

      expect(result.confirmed).toBe(true);
      expect(result.confidence).toBe('HIGH');
    });

    it('should have medium confidence for partial delay', () => {
      const result = ResponseAnalyzer.measureTimingDifference(0.5, 4.2, 5);

      expect(result.confirmed).toBe(false);
      expect(result.confidence).toBe('MEDIUM');
    });

    it('should reject when no significant delay', () => {
      const result = ResponseAnalyzer.measureTimingDifference(0.5, 1.0, 5);

      expect(result.confirmed).toBe(false);
      expect(result.confidence).toBe('LOW');
    });
  });

  describe('extractData', () => {
    it('should extract data from JSON array response', () => {
      const response = {
        body: [{ username: 'admin' }, { username: 'user1' }],
        status: 200
      };
      const result = ResponseAnalyzer.extractData(response);

      expect(result).toHaveLength(2);
      expect(result[0].username).toBe('admin');
    });

    it('should extract data from JSON results field', () => {
      const response = {
        body: { results: [{ id: 1 }, { id: 2 }] },
        status: 200
      };
      const result = ResponseAnalyzer.extractData(response);

      expect(result).toHaveLength(2);
    });

    it('should use regex pattern for text extraction', () => {
      const response = {
        body: 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:',
        status: 200
      };
      const result = ResponseAnalyzer.extractData(response, '(\\w+):x:\\d+');

      expect(result.length).toBeGreaterThan(0);
    });

    it('should return empty array for no matches', () => {
      const response = {
        body: 'No data here',
        status: 200
      };
      const result = ResponseAnalyzer.extractData(response, 'password=(\\w+)');

      expect(result).toHaveLength(0);
    });
  });
});
