import { fs, path } from 'zx';
import chalk from 'chalk';

/**
 * Intelligence context aggregator
 * Gathers context from multiple intelligence files for payload generation
 */
export class IntelligenceAggregator {
  constructor(analysisDir) {
    this.analysisDir = analysisDir;
    this.cache = {};
  }

  /**
   * Aggregate all intelligence for a vulnerability
   * @param {string} vulnType - Vulnerability type (injection, xss, etc.)
   * @returns {Promise<object>} Aggregated context
   */
  async aggregateContext(vulnType) {
    const context = {
      database: null,
      os: null,
      framework: null,
      language: null,
      architecture: null,
      waf: null,
      queryStructure: null,
      codeSnippet: null,
      endpoints: [],
      authentication: null
    };

    try {
      // Read pre-reconnaissance deliverable
      const preRecon = await this.readDeliverable('pre_recon_deliverable.md');
      if (preRecon) {
        context.database = this.extractDatabase(preRecon);
        context.os = this.extractOS(preRecon);
        context.framework = this.extractFramework(preRecon);
        context.language = this.extractLanguage(preRecon);
        context.architecture = this.extractArchitecture(preRecon);
        context.codeSnippet = this.extractCodeSnippet(preRecon, vulnType);
      }

      // Read reconnaissance deliverable
      const recon = await this.readDeliverable('recon_deliverable.md');
      if (recon) {
        context.endpoints = this.extractEndpoints(recon);
        context.authentication = this.extractAuthentication(recon);
      }

      // Read vulnerability-specific analysis
      const analysis = await this.readDeliverable(`${vulnType}_analysis_deliverable.md`);
      if (analysis) {
        context.waf = this.extractWAF(analysis);
        context.queryStructure = this.extractQueryStructure(analysis, vulnType);
        
        // Prefer more detailed code snippet from analysis
        const analysisSnippet = this.extractCodeSnippet(analysis, vulnType);
        if (analysisSnippet) {
          context.codeSnippet = analysisSnippet;
        }
      }

      return context;
    } catch (error) {
      console.warn(chalk.yellow('Failed to aggregate intelligence:'), error.message);
      return context;
    }
  }

  /**
   * Read deliverable file
   * @private
   */
  async readDeliverable(filename) {
    if (this.cache[filename]) {
      return this.cache[filename];
    }

    const filePath = path.join(this.analysisDir, 'deliverables', filename);
    
    try {
      // Read directly instead of pathExists+readFile (avoids TOCTOU race)
      const content = await fs.readFile(filePath, 'utf8');
      this.cache[filename] = content;
      return content;
    } catch (error) {
      // File doesn't exist or can't be read — return null
      return null;
    }
  }

  /**
   * Extract database type from intelligence
   * @private
   */
  extractDatabase(content) {
    const dbPatterns = {
      'MySQL': /mysql|mariadb/i,
      'PostgreSQL': /postgres|postgresql|pg_/i,
      'Microsoft SQL Server': /mssql|sql server|microsoft sql/i,
      'Oracle': /oracle|ora-\d+/i,
      'SQLite': /sqlite/i,
      'MongoDB': /mongodb|mongo/i,
      'Redis': /redis/i
    };

    for (const [db, pattern] of Object.entries(dbPatterns)) {
      if (pattern.test(content)) {
        return db;
      }
    }

    return null;
  }

  /**
   * Extract OS type
   * @private
   */
  extractOS(content) {
    if (/linux|ubuntu|debian|centos|rhel/i.test(content)) return 'Linux';
    if (/windows|win32|win64/i.test(content)) return 'Windows';
    if (/darwin|macos|osx/i.test(content)) return 'macOS';
    return null;
  }

  /**
   * Extract framework
   * @private
   */
  extractFramework(content) {
    const frameworks = {
      'Express.js': /express|app\.get|app\.post/i,
      'Flask': /flask|@app\.route/i,
      'Django': /django|from django/i,
      'Rails': /rails|ruby on rails/i,
      'Spring': /spring|@springboot|@restcontroller/i,
      'Laravel': /laravel|artisan/i,
      'ASP.NET': /asp\.net|\.cshtml|\.aspx/i
    };

    for (const [framework, pattern] of Object.entries(frameworks)) {
      if (pattern.test(content)) {
        return framework;
      }
    }

    return null;
  }

  /**
   * Extract programming language
   * @private
   */
  extractLanguage(content) {
    const languages = {
      'JavaScript': /javascript|node\.js|\.js\b/i,
      'TypeScript': /typescript|\.ts\b/i,
      'Python': /\bpython\b|\.py\b|import\s+\w+\s*\n|from\s+\w+\s+import\b|def\s+\w+\s*\(/i,
      'Ruby': /\bruby\b|\.rb\b|require\s+['"]|class\s+\w+\s*<\s*\w/i,
      'PHP': /\bphp\b|<\?php|\$_GET|\$_POST/i,
      'Java': /\bjava\b|\.java\b|public\s+class\s+|import\s+java\./i,
      'C#': /\bc#\b|\.cs\b|using\s+System|namespace\s+\w+/i,
      'Go': /\bgolang\b|\.go\b|package\s+main|import\s+"/i
    };

    for (const [language, pattern] of Object.entries(languages)) {
      if (pattern.test(content)) {
        return language;
      }
    }

    return null;
  }

  /**
   * Extract architecture details
   * @private
   */
  extractArchitecture(content) {
    const architectures = {
      'Microservices': /microservice|service mesh|api gateway/i,
      'Monolithic': /monolith/i,
      'Serverless': /lambda|cloud function|serverless/i,
      'REST API': /rest api|restful/i,
      'GraphQL': /graphql/i
    };

    for (const [arch, pattern] of Object.entries(architectures)) {
      if (pattern.test(content)) {
        return arch;
      }
    }

    return null;
  }

  /**
   * Extract WAF information
   * @private
   */
  extractWAF(content) {
    const wafPatterns = {
      'Cloudflare': /cloudflare|cf-ray/i,
      'AWS WAF': /aws waf|awswaf/i,
      'ModSecurity': /modsecurity|mod_security/i,
      'Akamai': /akamai/i,
      'Imperva': /imperva|incapsula/i,
      'Sucuri': /sucuri/i
    };

    for (const [waf, pattern] of Object.entries(wafPatterns)) {
      if (pattern.test(content)) {
        return waf;
      }
    }

    if (/waf|firewall|blocked.*security/i.test(content)) {
      return 'Unknown WAF';
    }

    return null;
  }

  /**
   * Extract query structure for SQL injection
   * @private
   */
  extractQueryStructure(content, vulnType) {
    if (vulnType !== 'injection') return null;

    // Look for SQL query patterns
    const queryPatterns = [
      /SELECT\s+.+?\s+FROM\s+.+?(?:WHERE|;)/i,
      /INSERT\s+INTO\s+.+?\s+VALUES/i,
      /UPDATE\s+.+?\s+SET\s+.+?(?:WHERE|;)/i,
      /DELETE\s+FROM\s+.+?(?:WHERE|;)/i
    ];

    for (const pattern of queryPatterns) {
      const match = content.match(pattern);
      if (match) {
        return match[0];
      }
    }

    return null;
  }

  /**
   * Extract code snippet related to vulnerability
   * @private
   */
  extractCodeSnippet(content, vulnType) {
    // Look for code blocks in markdown
    const codeBlockPattern = /```[\w]*\n([\s\S]+?)\n```/g;
    let match;
    const snippets = [];

    while ((match = codeBlockPattern.exec(content)) !== null) {
      snippets.push(match[1]);
    }

    // Return first snippet if found
    if (snippets.length > 0) {
      return snippets[0].substring(0, 500); // Limit to 500 chars
    }

    // Try to extract inline code or SQL queries
    const relevantPatterns = {
      injection: /(?:SELECT|INSERT|UPDATE|DELETE).{0,200}/i,
      xss: /(?:innerHTML|document\.write|dangerouslySetInner).{0,200}/i,
      ssrf: /(?:http\.get|requests\.get|fetch\().{0,200}/i
    };

    const pattern = relevantPatterns[vulnType];
    if (pattern) {
      const match = content.match(pattern);
      if (match) {
        return match[0];
      }
    }

    return null;
  }

  /**
   * Extract API endpoints
   * @private
   */
  extractEndpoints(content) {
    const endpoints = [];
    
    // Match common endpoint patterns
    const patterns = [
      /(?:GET|POST|PUT|DELETE|PATCH)\s+([\/\w\-\:\{\}]+)/gi,
      /route\(['"]([^'"]+)['"]/gi,
      /(?:@app\.route|@route)\(['"]([^'"]+)['"]/gi
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        endpoints.push(match[1]);
      }
    }

    return [...new Set(endpoints)]; // Remove duplicates
  }

  /**
   * Extract authentication information
   * @private
   */
  extractAuthentication(content) {
    const authPatterns = {
      'JWT': /jwt|json web token/i,
      'OAuth': /oauth|oauth2/i,
      'Basic Auth': /basic auth|authorization: basic/i,
      'Session': /session|cookie.*auth/i,
      'API Key': /api.?key|x-api-key/i,
      'None': /no auth|unauthenticated/i
    };

    for (const [type, pattern] of Object.entries(authPatterns)) {
      if (pattern.test(content)) {
        return type;
      }
    }

    return null;
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache = {};
  }
}

/**
 * Create intelligence aggregator
 */
export function createIntelligenceAggregator(analysisDir) {
  return new IntelligenceAggregator(analysisDir);
}
