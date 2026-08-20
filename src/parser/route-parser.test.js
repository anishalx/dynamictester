import { describe, it, expect } from 'vitest';
import { RouteParser, enrichWithRouteInfo, createRouteParser } from './route-parser.js';

describe('RouteParser', () => {
  describe('deriveEndpointsFromPath', () => {
    it('should derive endpoints from routes/ files', () => {
      const endpoints = RouteParser.deriveEndpointsFromPath('routes/users.js');
      expect(endpoints).toContain('/users');
      expect(endpoints).toContain('/api/users');
    });

    it('should derive endpoints from controllers/ files', () => {
      const endpoints = RouteParser.deriveEndpointsFromPath('controllers/auth.js');
      expect(endpoints.length).toBeGreaterThan(0);
    });

    it('should derive from nested paths', () => {
      const endpoints = RouteParser.deriveEndpointsFromPath('api/v1/products.js');
      expect(endpoints.some(e => e.includes('products'))).toBe(true);
    });

    it('should not include /index', () => {
      const endpoints = RouteParser.deriveEndpointsFromPath('routes/index.js');
      expect(endpoints).not.toContain('/index');
    });

    it('should handle Windows-style paths', () => {
      const endpoints = RouteParser.deriveEndpointsFromPath('routes\\users.js');
      expect(endpoints.length).toBeGreaterThan(0);
    });
  });

  describe('normalizePath', () => {
    it('should add leading slash if missing', () => {
      const parser = createRouteParser();
      const result = parser.normalizePath('users');
      expect(result).toBe('/users');
    });

    it('should remove trailing slash', () => {
      const parser = createRouteParser();
      const result = parser.normalizePath('/users/');
      expect(result).toBe('/users');
    });

    it('should keep root as /', () => {
      const parser = createRouteParser();
      const result = parser.normalizePath('/');
      expect(result).toBe('/');
    });
  });

  describe('extractParams', () => {
    it('should extract route parameters', () => {
      const parser = createRouteParser();
      const params = parser.extractParams('/users/:id/posts/:postId');
      expect(params).toEqual(['id', 'postId']);
    });

    it('should return empty array for no params', () => {
      const parser = createRouteParser();
      const params = parser.extractParams('/users');
      expect(params).toEqual([]);
    });
  });

  describe('createRouteParser factory', () => {
    it('should return a RouteParser instance', () => {
      const parser = createRouteParser();
      expect(parser).toBeInstanceOf(RouteParser);
    });
  });

  describe('enrichWithRouteInfo', () => {
    it('should add suggestedEndpoint when routes match', () => {
      const vulns = [
        { location: { file: 'routes/login.js', line: 10 }, id: 'v1' }
      ];
      const routeMapping = {
        routes: [
          { method: 'POST', path: '/login', file: 'routes/login.js', line: 5 }
        ]
      };

      const enriched = enrichWithRouteInfo(vulns, routeMapping);
      expect(enriched[0].suggestedEndpoint).toBe('/login');
      expect(enriched[0].suggestedMethod).toBe('POST');
    });

    it('should add derivedEndpoints when no routes match', () => {
      const vulns = [
        { location: { file: 'routes/users.js', line: 10 }, id: 'v1' }
      ];
      const routeMapping = { routes: [] };

      const enriched = enrichWithRouteInfo(vulns, routeMapping);
      expect(enriched[0].derivedEndpoints).toBeDefined();
    });

    it('should handle vulns without location', () => {
      const vulns = [{ id: 'v1' }];
      const routeMapping = { routes: [] };

      const enriched = enrichWithRouteInfo(vulns, routeMapping);
      expect(enriched[0].id).toBe('v1');
    });
  });
});
