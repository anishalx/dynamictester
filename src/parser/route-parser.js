import { promises as fs } from 'fs';
import path from 'path';

/**
 * Route Intelligence Parser
 * Parses Express router files to build endpoint-to-file mappings
 * Enables intelligent endpoint discovery for vulnerability testing
 */
export class RouteParser {
  constructor() {
    this.routes = [];
    this.routerMounts = new Map(); // Maps router variable names to mount paths
  }

  /**
   * Parse a directory recursively for route definitions
   * @param {string} dirPath - Path to source code directory
   * @param {object} options - Parsing options
   * @returns {object} Route mapping
   */
  async parseDirectory(dirPath, options = {}) {
    const {
      extensions = ['.js', '.ts', '.mjs'],
      ignore = ['node_modules', 'dist', 'build', '.git']
    } = options;

    this.routes = [];
    this.routerMounts.clear();

    try {
      await this.scanDirectory(dirPath, extensions, ignore);
      return {
        routes: this.routes,
        summary: {
          totalRoutes: this.routes.length,
          methods: this.countByMethod(),
          files: this.getUniqueFiles()
        }
      };
    } catch (error) {
      return {
        error: error.message,
        routes: [],
        summary: { totalRoutes: 0, methods: {}, files: [] }
      };
    }
  }

  /**
   * Recursively scan directory for route files
   * @private
   */
  async scanDirectory(dirPath, extensions, ignore) {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        if (!ignore.includes(entry.name)) {
          await this.scanDirectory(fullPath, extensions, ignore);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (extensions.includes(ext)) {
          await this.parseFile(fullPath);
        }
      }
    }
  }

  /**
   * Parse a single file for route definitions
   * @param {string} filePath - Path to the file
   */
  async parseFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n');

      // Detect router variable names
      this.detectRouterVariables(content, filePath);

      // Parse route definitions
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        
        // Parse app.use() mounts
        this.parseRouterMount(line, lineNum + 1, filePath);
        
        // Parse route definitions (app.get, router.post, etc.)
        this.parseRouteDefinition(line, lineNum + 1, filePath);
      }
    } catch (error) {
      // Skip files that can't be read
    }
  }

  /**
   * Detect router variable names (e.g., const router = express.Router())
   * @private
   */
  detectRouterVariables(content, filePath) {
    // Match: const|let|var <name> = express.Router()
    const routerPattern = /(?:const|let|var)\s+(\w+)\s*=\s*(?:express\.Router\(\)|Router\(\))/g;
    let match;

    while ((match = routerPattern.exec(content)) !== null) {
      const varName = match[1];
      // Store that this variable is a router (mount path will be determined later)
      if (!this.routerMounts.has(varName)) {
        this.routerMounts.set(varName, { file: filePath, mountPath: '' });
      }
    }
  }

  /**
   * Parse app.use() router mounts
   * @private
   */
  parseRouterMount(line, lineNum, filePath) {
    // Match: app.use('/path', router) or app.use('/path', require('./routes'))
    const mountPatterns = [
      /app\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)/,
      /app\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/
    ];

    for (const pattern of mountPatterns) {
      const match = line.match(pattern);
      if (match) {
        const mountPath = match[1];
        const routerRef = match[2];

        // Update the mount path for this router
        if (this.routerMounts.has(routerRef)) {
          this.routerMounts.set(routerRef, {
            ...this.routerMounts.get(routerRef),
            mountPath
          });
        }
      }
    }
  }

  /**
   * Parse individual route definitions
   * @private
   */
  parseRouteDefinition(line, lineNum, filePath) {
    // Match: app.get('/path', ...) or router.post('/path', ...)
    const routePattern = /(?:app|router|\w+)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/i;
    const match = line.match(routePattern);

    if (match) {
      const method = match[1].toUpperCase();
      let routePath = match[2];

      // Normalize the path
      routePath = this.normalizePath(routePath);

      this.routes.push({
        method,
        path: routePath,
        file: filePath,
        line: lineNum,
        fullPath: routePath, // Will be updated if mounted under a prefix
        params: this.extractParams(routePath)
      });
    }
  }

  /**
   * Normalize a route path
   * @private
   */
  normalizePath(routePath) {
    // Ensure path starts with /
    if (!routePath.startsWith('/')) {
      routePath = '/' + routePath;
    }
    // Remove trailing slash (except for root)
    if (routePath.length > 1 && routePath.endsWith('/')) {
      routePath = routePath.slice(0, -1);
    }
    return routePath;
  }

  /**
   * Extract path parameters from a route
   * @private
   */
  extractParams(routePath) {
    const params = [];
    const paramPattern = /:(\w+)/g;
    let match;

    while ((match = paramPattern.exec(routePath)) !== null) {
      params.push(match[1]);
    }

    return params;
  }

  /**
   * Count routes by HTTP method
   * @private
   */
  countByMethod() {
    const counts = {};
    for (const route of this.routes) {
      counts[route.method] = (counts[route.method] || 0) + 1;
    }
    return counts;
  }

  /**
   * Get unique files containing routes
   * @private
   */
  getUniqueFiles() {
    return [...new Set(this.routes.map(r => r.file))];
  }

  /**
   * Find routes matching a source file location
   * @param {string} filePath - Source file path
   * @param {number} line - Line number (optional)
   * @returns {Array} Matching routes
   */
  findRoutesForFile(filePath, line = null) {
    return this.routes.filter(route => {
      const fileMatch = route.file.endsWith(filePath) || filePath.endsWith(route.file);
      if (line) {
        // Return routes within 10 lines of the target
        return fileMatch && Math.abs(route.line - line) <= 10;
      }
      return fileMatch;
    });
  }

  /**
   * Derive likely endpoints from a source file path (fallback when parsing fails)
   * @param {string} filePath - Source file path  
   * @returns {Array} Derived endpoints
   */
  static deriveEndpointsFromPath(filePath) {
    const endpoints = [];
    
    // Extract meaningful path segments
    const normalizedPath = filePath.replace(/\\/g, '/');
    const segments = normalizedPath.split('/').filter(Boolean);
    
    // Find the filename without extension
    const filename = segments[segments.length - 1];
    const basename = filename.replace(/\.(js|ts|mjs|cjs)$/, '');
    
    // Common route derivation patterns
    const patterns = [];
    
    // Direct mapping: routes/users.js -> /users
    if (basename !== 'index') {
      patterns.push(`/${basename}`);
      patterns.push(`/api/${basename}`);
      patterns.push(`/rest/${basename}`);
    }
    
    // Check if in routes/api/controllers folder
    const routesIndex = segments.findIndex(s => 
      ['routes', 'api', 'controllers', 'handlers'].includes(s)
    );
    
    if (routesIndex >= 0) {
      const relevantSegments = segments.slice(routesIndex + 1);
      if (relevantSegments.length > 0) {
        const lastSegment = relevantSegments[relevantSegments.length - 1].replace(/\.(js|ts|mjs|cjs)$/, '');
        if (lastSegment !== 'index') {
          const routePath = '/' + relevantSegments
            .map(s => s.replace(/\.(js|ts|mjs|cjs)$/, ''))
            .filter(s => s !== 'index')
            .join('/');
          patterns.push(routePath);
        }
      }
    }

    // Deduplicate and filter
    return [...new Set(patterns)].filter(p => p.length > 1);
  }
}

/**
 * Enrich vulnerabilities with route information
 * @param {Array} vulnerabilities - Vulnerabilities from queue
 * @param {object} routeMapping - Parsed route mapping
 * @returns {Array} Enriched vulnerabilities
 */
export function enrichWithRouteInfo(vulnerabilities, routeMapping) {
  return vulnerabilities.map(vuln => {
    const enriched = { ...vuln };
    
    if (!vuln.file) return enriched;

    // Try to find matching routes
    const matchingRoutes = routeMapping.routes.filter(route => {
      const fileMatch = route.file.includes(vuln.file) || vuln.file.includes(route.file);
      return fileMatch;
    });
    
    if (matchingRoutes.length > 0) {
      // Sort by line proximity if vulnerability has line info
      if (vuln.line) {
        matchingRoutes.sort((a, b) => 
          Math.abs(a.line - vuln.line) - Math.abs(b.line - vuln.line)
        );
      }
      
      enriched.discoveredRoutes = matchingRoutes.map(r => ({
        method: r.method,
        path: r.path,
        line: r.line
      }));
      
      enriched.suggestedEndpoint = matchingRoutes[0].path;
      enriched.suggestedMethod = matchingRoutes[0].method;
    } else {
      // Fall back to path-based derivation
      enriched.derivedEndpoints = RouteParser.deriveEndpointsFromPath(vuln.file);
    }
    
    return enriched;
  });
}

/**
 * Create a RouteParser instance
 * @returns {RouteParser}
 */
export function createRouteParser() {
  return new RouteParser();
}
