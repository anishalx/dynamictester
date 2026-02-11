import OpenAI from 'openai';
import { fs, path } from 'zx';
import chalk from 'chalk';
import { BrowserManager } from '../mcp/browser-server.js';
import { StagehandManager } from '../mcp/stagehand-manager.js';
import { 
  RateLimiter, 
  isRateLimitError, 
  formatDelay,
  sleep 
} from '../utils/rate-limiter.js';
import { PayloadGenerator } from '../testing/payload-generator.js';
import { BypassEngine } from '../testing/bypass-engine.js';
import { ResponseAnalyzer } from '../testing/response-analyzer.js';
import { IntelligenceAggregator } from '../testing/intelligence-aggregator.js';

const openai = new OpenAI();

// Maximum characters for tool results to avoid token limits
const MAX_TOOL_RESULT_LENGTH = 8000;

/**
 * Truncate a string to a maximum length
 */
function truncateResult(obj, maxLen = MAX_TOOL_RESULT_LENGTH) {
  const str = JSON.stringify(obj);
  if (str.length <= maxLen) return str;
  
  // Try to return a meaningful truncated version
  if (obj.content) {
    return JSON.stringify({ ...obj, content: obj.content.slice(0, maxLen - 500) + '... [TRUNCATED]' });
  }
  if (obj.text) {
    return JSON.stringify({ ...obj, text: obj.text.slice(0, maxLen - 500) + '... [TRUNCATED]' });
  }
  
  return str.slice(0, maxLen) + '... [TRUNCATED]';
}

/**
 * Execute LLM agent for dynamic testing using OpenAI
 */
export async function executeExploitationAgent(
  promptTemplate,
  queuePath,
  targetUrl,
  outputDir,
  options = {}
) {
  const model = options.model || 'gpt-4o';
  const maxRetries = options.maxRetries || 3;
  const rateLimiter = new RateLimiter({ maxRetries, enableLogging: true });
  
  console.log(chalk.cyan(`🚀 Starting OpenAI exploitation agent (${model})...`));
  console.log(chalk.gray(`   Rate limit handling: ${maxRetries} retries with exponential backoff`));
  
  // Load prompt template
  let systemPrompt = await fs.readFile(promptTemplate, 'utf8');
  
  // Load queue data
  let queueData = {};
  try {
    queueData = await fs.readJSON(queuePath);
    console.log(chalk.gray(`   Loaded ${queueData.vulnerabilities?.length || 0} vulnerabilities from queue`));
  } catch (e) {
    console.log(chalk.yellow(`   Warning: Could not load queue file: ${e.message}`));
  }
  
  // Interpolate variables
  systemPrompt = systemPrompt
    .replace(/{{WEB_URL}}/g, targetUrl)
    .replace(/{{QUEUE_PATH}}/g, queuePath);
  
  // Add universal context (no app-specific content)
  systemPrompt += `

CRITICAL INSTRUCTIONS:
1. You MUST test EVERY vulnerability in the queue, not just a sample
2. Do NOT stop early - continue until all vulnerabilities are tested
3. ALWAYS use static analysis context (file, line, technology) to craft payloads
4. Use browser_http_request for API endpoints - faster and more reliable
5. If browser_click fails with timeout, use browser_force_click instead
6. Save evidence for EACH vulnerability with FULL source mapping

TESTING METHODOLOGY (3-STAGE WORKFLOW):
For EACH vulnerability, follow this sequence:

Stage 1 - CONFIRMATION: Call generate_payloads with stage="confirmation" first.
  Use the returned guidance and fallback payloads to detect if the vuln exists.
  After each request, call analyze_response to interpret the result.

Stage 2 - FINGERPRINT: If confirmed, call generate_payloads with stage="fingerprint".
  Identify the specific technology (database type, template engine, etc.).
  Call analyze_response to detect database errors and technology signatures.

Stage 3 - EXPLOIT: Call generate_payloads with stage="exploit".
  Extract data or demonstrate impact using technology-specific payloads.

BYPASS WORKFLOW:
- If a payload returns 403, WAF blocking, or is rejected, call generate_bypasses
  with the blocked payload. It returns encoded/obfuscated alternatives.
- Try the bypass payloads and analyze responses again.
- If all bypasses fail, move on (the vulnerability may be properly mitigated).

RESPONSE ANALYSIS:
- ALWAYS call analyze_response after receiving test results
- It detects: database errors (SQLi confirmed), WAF blocking, input validation
- For blind injection: provide true/false response bodies for boolean comparison
- For time-based: provide normalTime, delayedTime, expectedDelay

ENDPOINT DISCOVERY FROM SOURCE FILES:
- routes/users.js    → /users, /api/users
- controllers/auth.js → /auth, /login
- api/products.js    → /api/products
- views/search.ejs   → /search
Use the file path pattern to derive likely endpoints

TOOL USAGE:
- read_queue_file: Get ALL vulnerabilities with source context FIRST
- generate_payloads: Call BEFORE testing each vuln (returns context + fallback payloads)
- analyze_response: Call AFTER each test request (interprets results)
- generate_bypasses: Call when payload is BLOCKED (returns bypass variations)
- browser_http_request: PREFERRED for API testing
- browser_force_click: Use when normal click times out
- save_evidence: Include full source mapping (file, line, column)

AI BROWSER TOOLS (Stagehand):
- stagehand_act: AI-powered click/fill/interact — use when exact CSS selectors are unknown or page is dynamic/SPA
- stagehand_extract: AI-powered data extraction — use to parse complex pages, extract error messages or form structures
- stagehand_observe: AI-powered element discovery — use to map attack surface on unfamiliar pages, find injection points
- stagehand_agent: AI-powered multi-step workflow — use for login sequences, multi-page flows, CSRF token harvesting

WHEN TO USE STAGEHAND vs LOW-LEVEL TOOLS:
- Use browser_http_request for direct API/REST testing (fastest, no browser needed)
- Use browser_click/browser_fill when you HAVE exact CSS selectors
- Use stagehand_act when selectors are unknown, elements are dynamic, or previous browser_click/fill failed
- Use stagehand_extract to intelligently parse complex response pages
- Use stagehand_observe to discover interactive elements on unfamiliar pages`;
  
  // ---------------------------------------------------------------------------
  // Initialize Stagehand (AI browser) → pass page/context to BrowserManager
  // ---------------------------------------------------------------------------
  const stagehandManager = new StagehandManager();
  let browserManager;

  try {
    console.log(chalk.gray('   Initializing Stagehand AI browser...'));
    await stagehandManager.init();
    const stagehandPage = stagehandManager.getPage();
    const stagehandContext = stagehandManager.getContext();
    const stagehandBrowser = stagehandManager.getBrowser();

    if (stagehandPage && stagehandContext) {
      // Stagehand owns the browser process; BrowserManager uses the CDP-connected
      // Playwright page/context/browser for full API compatibility.
      browserManager = new BrowserManager({
        page: stagehandPage,
        context: stagehandContext,
        browser: stagehandBrowser
      });
      console.log(chalk.green('   Stagehand initialized — CDP browser shared with BrowserManager'));
    } else {
      // Stagehand init succeeded but CDP connection failed — fall back
      console.log(chalk.yellow('   Stagehand page not available — falling back to standalone browser'));
      browserManager = new BrowserManager();
    }
  } catch (stagehandError) {
    // Stagehand failed to initialize — fall back to standalone BrowserManager
    console.log(chalk.yellow(`   Stagehand init failed: ${stagehandError.message}`));
    console.log(chalk.yellow('   Falling back to standalone Playwright browser'));
    browserManager = new BrowserManager();
  }
  
  // Initialize testing utilities (shared across all tool calls within this agent)
  const payloadGenerator = new PayloadGenerator(model);
  const bypassEngine = new BypassEngine(50);
  const intelligenceAggregator = new IntelligenceAggregator(outputDir);

  // ---------------------------------------------------------------------------
  // New tool handlers: generate_payloads, analyze_response, generate_bypasses
  // ---------------------------------------------------------------------------

  /**
   * Generate structured payload context for the LLM to craft accurate payloads.
   * Combines intelligence aggregation + payload templates + fallback payloads.
   */
  async function generate_payloads(params) {
    const {
      vulnerabilityId,
      vulnerabilityType,
      stage = 'confirmation',
      file,
      line,
      snippet,
      cwe,
      previousResults
    } = params;

    try {
      // Build a vulnerability object from the parameters
      const vulnerability = {
        id: vulnerabilityId,
        vulnerabilityType: vulnerabilityType,
        type: vulnerabilityType,
        file: file || 'unknown',
        line: line || null,
        snippet: snippet || null,
        cwe: cwe || null
      };

      // Gather technology context from intelligence deliverables
      const techContext = await intelligenceAggregator.aggregateContext(vulnerabilityType);

      // Generate structured payload context (no LLM call — pure utility)
      const payloadContext = payloadGenerator.generatePayloadContext(
        vulnerability,
        techContext,
        stage,
        previousResults || null
      );

      return {
        status: 'success',
        guidance: payloadContext.systemGuidance,
        stageInstructions: payloadContext.stageInstructions,
        technologyContext: payloadContext.technologyContext,
        fallbackPayloads: payloadContext.fallbackPayloads,
        detectedTech: {
          database: techContext.database,
          framework: techContext.framework,
          language: techContext.language,
          os: techContext.os,
          waf: techContext.waf
        },
        stage: payloadContext.stage,
        vulnType: payloadContext.vulnType
      };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Analyze an HTTP response for vulnerability indicators.
   * Detects DB errors, WAF blocking, validation errors, and performs boolean comparison.
   */
  async function analyze_response(params) {
    const {
      responseBody,
      responseStatus,
      responseHeaders,
      testType,
      // Optional: for boolean-based comparison
      trueResponseBody,
      trueResponseStatus,
      falseResponseBody,
      falseResponseStatus,
      // Optional: for timing analysis
      normalTime,
      delayedTime,
      expectedDelay
    } = params;

    try {
      const response = {
        body: responseBody || '',
        status: responseStatus || 200,
        headers: responseHeaders || ''
      };

      const analysis = {
        status: 'success'
      };

      // Detect database errors (indicates SQL injection)
      analysis.databaseErrors = ResponseAnalyzer.detectDatabaseErrors(response);

      // Detect WAF blocking (indicates payload was caught)
      analysis.wafBlocking = ResponseAnalyzer.detectWAFBlocking(response);

      // Check for input validation errors (often false positive)
      analysis.isValidationError = ResponseAnalyzer.isValidationError(response);

      // Boolean comparison (if both true/false responses provided)
      if (trueResponseBody !== undefined && falseResponseBody !== undefined) {
        analysis.booleanComparison = ResponseAnalyzer.compareBooleanResponses(
          { body: trueResponseBody, status: trueResponseStatus || 200 },
          { body: falseResponseBody, status: falseResponseStatus || 200 }
        );
      }

      // Timing analysis (if timing data provided)
      if (normalTime !== undefined && delayedTime !== undefined && expectedDelay !== undefined) {
        analysis.timingAnalysis = ResponseAnalyzer.measureTimingDifference(
          normalTime,
          delayedTime,
          expectedDelay
        );
      }

      // Provide interpretation guidance
      analysis.interpretation = _buildInterpretation(analysis, testType);

      return analysis;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Generate bypass variations when a payload is blocked by WAF/filter.
   * Returns encoding-based and technique-based alternatives.
   */
  async function generate_bypasses(params) {
    const {
      blockedPayload,
      blockReason,
      httpStatus,
      wafName,
      vulnerabilityType,
      database
    } = params;

    try {
      const blockingContext = {
        reason: blockReason || 'unknown',
        httpStatus: httpStatus || null,
        wafName: wafName || null,
        wafDetected: !!wafName
      };

      const vulnerability = {
        vulnerabilityType: vulnerabilityType || 'injection',
        type: vulnerabilityType || 'injection'
      };

      const techContext = {
        database: database || null
      };

      const result = bypassEngine.generateBypasses(
        blockedPayload,
        blockingContext,
        vulnerability,
        techContext
      );

      return {
        status: 'success',
        bypasses: result.bypasses,
        guidance: result.guidance,
        techniques: result.techniques,
        blockedHistory: result.blockedHistory,
        attemptsUsed: result.attemptsUsed,
        attemptsRemaining: result.attemptsRemaining,
        exhausted: bypassEngine.isExhausted()
      };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Build human-readable interpretation of response analysis
   * @private
   */
  function _buildInterpretation(analysis, testType) {
    const parts = [];

    if (analysis.databaseErrors.detected) {
      parts.push(`DATABASE ERROR DETECTED (${analysis.databaseErrors.database}): Strong indicator of SQL injection. Confidence: ${analysis.databaseErrors.confidence}.`);
    }

    if (analysis.wafBlocking.detected) {
      parts.push(`WAF BLOCKING DETECTED (${analysis.wafBlocking.waf}): Payload was caught by security filter. Use generate_bypasses to get bypass variations.`);
    }

    if (analysis.isValidationError) {
      parts.push('INPUT VALIDATION: Response suggests input validation rejected the payload (this is NOT a vulnerability indicator — it means the app has proper validation).');
    }

    if (analysis.booleanComparison) {
      const bc = analysis.booleanComparison;
      if (bc.different) {
        parts.push(`BOOLEAN DIFFERENCE DETECTED: True/false conditions produce different responses (confidence: ${bc.confidence}). This suggests boolean-based blind injection.`);
      } else {
        parts.push('BOOLEAN COMPARISON: No significant difference between true/false conditions.');
      }
    }

    if (analysis.timingAnalysis) {
      const ta = analysis.timingAnalysis;
      if (ta.confirmed) {
        parts.push(`TIMING CONFIRMED: Delay of ${ta.actualDelay}s detected (expected ${ta.expectedDelay}s). Confidence: ${ta.confidence}. Time-based blind injection likely.`);
      } else {
        parts.push(`TIMING INCONCLUSIVE: Only ${ta.actualDelay}s delay vs expected ${ta.expectedDelay}s.`);
      }
    }

    if (parts.length === 0) {
      parts.push('No strong vulnerability indicators detected in this response. Consider trying different payloads or techniques.');
    }

    return parts.join('\n');
  }

  // Enhanced evidence collection tool with developer-friendly output
  async function save_evidence(params) {
    const {
      id, type, evidence, payload, success,
      // New source mapping fields
      sourceFile, sourceLine, sourceColumn, cwe, owasp,
      endpoint, method, response, exploitationProof, remediation,
      // Additional context
      xssType, injectionContext, secretType, vulnerabilityType
    } = params;
    
    const evidenceDir = path.join(outputDir, 'evidence');
    await fs.ensureDir(evidenceDir);
    
    const fileName = `evidence-${id || 'unknown'}-${Date.now()}.json`;
    const filePath = path.join(evidenceDir, fileName);
    
    // Create developer-friendly structured output
    const evidenceData = {
      // Finding identification
      findingId: id,
      timestamp: new Date().toISOString(),
      
      // Source code mapping (for developers)
      sourceLocation: {
        file: sourceFile || null,
        line: sourceLine || null,
        column: sourceColumn || null
      },
      
      // Vulnerability classification
      vulnerability: {
        type: vulnerabilityType || type,
        cwe: cwe || null,
        owasp: owasp || null,
        xssType: xssType || null,
        injectionContext: injectionContext || null,
        secretType: secretType || null
      },
      
      // Exploitation details
      exploitation: {
        endpoint: endpoint || null,
        method: method || null,
        payload: payload,
        response: response || null,
        success: success,
        proof: exploitationProof || evidence
      },
      
      // Remediation guidance
      remediation: remediation || null,
      
      // Status classification
      status: success ? 'CONFIRMED' : 'TESTED_NOT_EXPLOITABLE'
    };
    
    await fs.writeJSON(filePath, evidenceData, { spaces: 2 });
    console.log(chalk.green(`   📝 Evidence saved: ${fileName}`));
    
    // Also append to summary file for easy developer review
    const summaryPath = path.join(outputDir, 'findings_summary.json');
    let summary = [];
    try {
      summary = await fs.readJSON(summaryPath);
    } catch (e) { /* File doesn't exist yet */ }
    
    summary.push({
      id: id,
      status: evidenceData.status,
      file: sourceFile,
      line: sourceLine,
      type: vulnerabilityType || type,
      cwe: cwe,
      endpoint: endpoint,
      success: success
    });
    await fs.writeJSON(summaryPath, summary, { spaces: 2 });
    
    return { status: 'success', path: filePath };
  }

  // Read queue file tool - returns ALL vulnerabilities (no limit)
  async function read_queue_file({ filePath }) {
    try {
      const data = await fs.readJSON(filePath || queuePath);
      // Return all vulnerabilities with summary stats
      const count = data.vulnerabilities?.length || 0;
      data.totalCount = count;
      data.note = `Loaded ${count} vulnerabilities. You MUST test ALL of them.`;
      return { status: 'success', data };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  const browserTools = browserManager.getTools();
  const stagehandTools = stagehandManager.getTools();
  
  const tools = [
    ...browserTools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters
      }
    })),
    ...stagehandTools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters
      }
    })),
    {
      type: 'function',
      function: {
        name: 'save_evidence',
        description: 'Save exploitation evidence with FULL source code mapping. Include all source location fields for developer output.',
        parameters: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Vulnerability ID from queue' },
            type: { type: 'string', description: 'Vulnerability type (SQLi, XSS, etc.)' },
            evidence: { type: 'string', description: 'Description of evidence found' },
            payload: { type: 'string', description: 'The exact payload used' },
            success: { type: 'boolean', description: 'Whether the exploit was successful' },
            // Source code mapping (for developers)
            sourceFile: { type: 'string', description: 'Source file path from static analysis' },
            sourceLine: { type: 'number', description: 'Line number in source file' },
            sourceColumn: { type: 'number', description: 'Column number in source file' },
            cwe: { type: 'string', description: 'CWE identifier (e.g., CWE-89)' },
            owasp: { type: 'string', description: 'OWASP category' },
            // Exploitation details
            endpoint: { type: 'string', description: 'The endpoint that was tested' },
            method: { type: 'string', description: 'HTTP method used (GET, POST, etc.)' },
            response: { type: 'string', description: 'Key parts of the response' },
            exploitationProof: { type: 'string', description: 'What proves the exploitation worked' },
            remediation: { type: 'string', description: 'Suggested fix for the vulnerability' },
            // Context-specific fields
            vulnerabilityType: { type: 'string', description: 'Specific vulnerability type' },
            xssType: { type: 'string', description: 'For XSS: DOM, Reflected, or Stored' },
            injectionContext: { type: 'string', description: 'Injection context (HTML, Attribute, etc.)' },
            secretType: { type: 'string', description: 'For secrets: APIKey, Password, Token, etc.' }
          },
          required: ['id', 'payload', 'success', 'sourceFile', 'sourceLine']
        }
      }
    },
    {
      type: 'function',
      function: {
        name: 'read_queue_file',
        description: 'Read the vulnerability queue JSON file. Returns ALL vulnerabilities. You MUST test every single vulnerability.',
        parameters: {
          type: 'object',
          properties: {
            filePath: { type: 'string', description: 'Path to the queue file (optional)' }
          }
        }
      }
    },
    {
      type: 'function',
      function: {
        name: 'generate_payloads',
        description: 'Generate context-aware payload guidance for a vulnerability. Call this BEFORE testing each vulnerability to get technology-specific payloads, stage instructions, and fallback payloads. Returns structured context so you can craft accurate payloads.',
        parameters: {
          type: 'object',
          properties: {
            vulnerabilityId: { type: 'string', description: 'Vulnerability ID from queue' },
            vulnerabilityType: { type: 'string', description: 'Type: injection, xss, ssrf, ssti, traversal, xxe, redirect, auth, secrets, command_injection, deserialization, config, crypto' },
            stage: { type: 'string', description: 'Testing stage: confirmation (detect), fingerprint (identify), exploit (extract data), refinement (improve)' },
            file: { type: 'string', description: 'Source file path from static analysis' },
            line: { type: 'number', description: 'Line number in source file' },
            snippet: { type: 'string', description: 'Code snippet from static analysis' },
            cwe: { type: 'string', description: 'CWE identifier (e.g., CWE-89)' },
            previousResults: {
              type: 'array',
              description: 'Results from prior test attempts for refinement',
              items: {
                type: 'object',
                properties: {
                  payload: { type: 'string' },
                  success: { type: 'boolean' },
                  error: { type: 'string' },
                  response: { type: 'string' }
                }
              }
            }
          },
          required: ['vulnerabilityId', 'vulnerabilityType', 'stage']
        }
      }
    },
    {
      type: 'function',
      function: {
        name: 'analyze_response',
        description: 'Analyze an HTTP response for vulnerability indicators. Detects database errors (SQLi), WAF blocking, validation errors. Supports boolean-based comparison and timing analysis. Call this AFTER receiving test results to determine if the payload worked.',
        parameters: {
          type: 'object',
          properties: {
            responseBody: { type: 'string', description: 'The HTTP response body text' },
            responseStatus: { type: 'number', description: 'HTTP status code' },
            responseHeaders: { type: 'string', description: 'Response headers as string' },
            testType: { type: 'string', description: 'Type of test: injection, xss, ssrf, etc.' },
            trueResponseBody: { type: 'string', description: 'For boolean-based: response body with true condition' },
            trueResponseStatus: { type: 'number', description: 'For boolean-based: status with true condition' },
            falseResponseBody: { type: 'string', description: 'For boolean-based: response body with false condition' },
            falseResponseStatus: { type: 'number', description: 'For boolean-based: status with false condition' },
            normalTime: { type: 'number', description: 'For timing-based: normal response time in seconds' },
            delayedTime: { type: 'number', description: 'For timing-based: delayed response time in seconds' },
            expectedDelay: { type: 'number', description: 'For timing-based: expected delay in seconds' }
          },
          required: ['responseBody', 'responseStatus']
        }
      }
    },
    {
      type: 'function',
      function: {
        name: 'generate_bypasses',
        description: 'Generate WAF/filter bypass variations for a blocked payload. Returns encoded and technique-based alternatives. Call this when a payload is blocked (403, WAF detection, filter rejection).',
        parameters: {
          type: 'object',
          properties: {
            blockedPayload: { type: 'string', description: 'The payload that was blocked' },
            blockReason: { type: 'string', description: 'Why it was blocked (WAF, validation, 403, etc.)' },
            httpStatus: { type: 'number', description: 'HTTP status code received' },
            wafName: { type: 'string', description: 'Detected WAF name (cloudflare, modsecurity, etc.)' },
            vulnerabilityType: { type: 'string', description: 'Type: injection, xss, ssrf, traversal, etc.' },
            database: { type: 'string', description: 'Database type if known (mysql, postgresql, etc.)' }
          },
          required: ['blockedPayload', 'vulnerabilityType']
        }
      }
    }
  ];

  // Tool handlers map
  const toolHandlers = {
    save_evidence,
    read_queue_file,
    generate_payloads,
    analyze_response,
    generate_bypasses,
    ...Object.fromEntries(browserTools.map(t => [t.name, t.handler])),
    ...Object.fromEntries(stagehandTools.map(t => [t.name, t.handler]))
  };

  // Build initial user message with queue summary
  const vulnSummary = queueData.vulnerabilities?.slice(0, 5).map((v, i) => 
    `${i + 1}. ${v.vulnerabilityType} at ${v.source}`
  ).join('\n') || 'No vulnerabilities loaded';

  const messages = [
    { role: 'system', content: systemPrompt },
    { 
      role: 'user', 
      content: `Target: ${targetUrl}\n\nVulnerabilities to test:\n${vulnSummary}\n\nStart testing. First call read_queue_file to get all vulnerabilities. For each vulnerability, call generate_payloads to get context-aware payloads before testing. After each test request, call analyze_response to interpret results. If blocked, call generate_bypasses for alternatives.` 
    }
  ];

  let turnCount = 0;
  const maxTurns = 50; // Increased from 30 to allow thorough testing
  let consecutiveErrors = 0;
  const maxConsecutiveErrors = 5;

  try {
    while (turnCount < maxTurns) {
      console.log(chalk.blue(`\n🤖 Turn ${turnCount + 1}:`));

      // Use rate limiter for API call with retry logic
      let response;
      try {
        response = await rateLimiter.executeWithRetry(
          async () => {
            return await openai.chat.completions.create({
              model: model,
              messages: messages,
              tools: tools,
              tool_choice: 'auto',
              max_tokens: 4096,
              temperature: 0.2,
            });
          },
          `OpenAI API request (turn ${turnCount + 1})`,
          { maxRetries }
        );
        // Only count the turn after a successful API response
        turnCount++;
        consecutiveErrors = 0; // Reset on success
      } catch (apiError) {
        consecutiveErrors++;
        console.log(chalk.red(`   ❌ API call failed: ${apiError.message}`));
        
        if (consecutiveErrors >= maxConsecutiveErrors) {
          console.log(chalk.red(`\n   ❌ Too many consecutive errors (${maxConsecutiveErrors}), stopping agent`));
          break;
        }
        
        // If rate limit, add extra cooldown
        if (isRateLimitError(apiError)) {
          const cooldown = 60000; // 1 minute cooldown
          console.log(chalk.yellow(`   ⏳ Rate limit cooldown: waiting ${formatDelay(cooldown)}...`));
          await sleep(cooldown);
        }
        
        continue; // Try next turn
      }

      // Guard against empty response (e.g., content filter refusal)
      if (!response.choices || response.choices.length === 0) {
        console.log(chalk.yellow('   ⚠️ Empty response from API, retrying...'));
        consecutiveErrors++;
        continue;
      }

      const assistantMessage = response.choices[0].message;
      messages.push(assistantMessage);

      if (assistantMessage.content) {
        console.log(chalk.gray(assistantMessage.content.slice(0, 400)));
        if (assistantMessage.content.length > 400) {
          console.log(chalk.gray('... (truncated)'));
        }
      }

      if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
        for (const toolCall of assistantMessage.tool_calls) {
          const toolName = toolCall.function.name;
          const handler = toolHandlers[toolName];
          
          if (handler) {
            console.log(chalk.yellow(`   🔧 ${toolName}`));
            try {
              const args = JSON.parse(toolCall.function.arguments);
              const result = await handler(args);
              
              // Truncate result for both display and API
              const truncatedResult = truncateResult(result);
              
              if (truncatedResult.length < 200) {
                console.log(chalk.gray(`      → ${truncatedResult}`));
              } else {
                console.log(chalk.gray(`      → (${truncatedResult.length} chars)`));
              }

              messages.push({
                role: 'tool',
                tool_call_id: toolCall.id,
                content: truncatedResult
              });
            } catch (e) {
              console.log(chalk.red(`      → Error: ${e.message}`));
              messages.push({
                role: 'tool',
                tool_call_id: toolCall.id,
                content: JSON.stringify({ status: 'error', message: e.message })
              });
            }
          } else {
            console.log(chalk.red(`   ❌ Unknown tool: ${toolName}`));
            messages.push({
              role: 'tool',
              tool_call_id: toolCall.id,
              content: JSON.stringify({ status: 'error', message: `Unknown tool: ${toolName}` })
            });
          }
        }
      } else {
        // No more tool calls, agent is finished
        console.log(chalk.green('\n   ✅ Agent completed its work'));
        break;
      }

      // Check for stop reason
      if (response.choices[0].finish_reason === 'stop') {
        break;
      }
    }

    if (turnCount >= maxTurns) {
      console.log(chalk.yellow(`\n   ⚠️ Reached maximum turns (${maxTurns})`));
    }

    // Log error stats if any
    const errorStats = rateLimiter.getErrorStats();
    if (errorStats.total > 0) {
      console.log(chalk.gray(`\n📊 Error statistics:`));
      console.log(chalk.gray(`   Total errors: ${errorStats.total}`));
      console.log(chalk.gray(`   Rate limit errors: ${errorStats.rateLimitErrors}`));
      if (Object.keys(errorStats.byType).length > 0) {
        console.log(chalk.gray(`   By type: ${JSON.stringify(errorStats.byType)}`));
      }
    }
    
    return {
      success: true,
      turns: turnCount,
      errorStats
    };
    
  } catch (error) {
    console.error(chalk.red(`❌ Agent failed: ${error.message}`));
    return {
      success: false,
      error: error.message,
      errorStats: rateLimiter.getErrorStats()
    };
  } finally {
    try { await browserManager.close(); } catch (e) { /* cleanup error */ }
    try { await stagehandManager.close(); } catch (e) { /* cleanup error */ }
  }
}

/**
 * Execute multiple agents in parallel with staggered starts
 * Prevents API overwhelm and handles rate limits gracefully
 * 
 * @param {Array<{promptTemplate: string, queuePath: string, targetUrl: string, outputDir: string, name: string}>} agents
 * @param {object} options - Execution options
 * @returns {Promise<object>} Results summary
 */
export async function executeAgentsInParallel(agents, options = {}) {
  const staggerDelay = options.staggerDelay || 2000; // 2 seconds between agent starts
  const maxRetries = options.maxRetries || 3;
  const rateLimiter = new RateLimiter({ 
    maxRetries, 
    staggerDelay,
    enableLogging: true 
  });

  console.log(chalk.cyan(`\n🚀 Starting ${agents.length} agents in parallel with ${staggerDelay}ms stagger...`));
  console.log(chalk.gray(`   Timeline:`));
  agents.forEach((agent, i) => {
    console.log(chalk.gray(`   - ${agent.name}: starts after ${formatDelay(i * staggerDelay)}`));
  });

  const tasks = agents.map(agent => ({
    name: agent.name,
    fn: async () => {
      return await executeExploitationAgent(
        agent.promptTemplate,
        agent.queuePath,
        agent.targetUrl,
        agent.outputDir,
        { ...options, model: agent.model || options.model }
      );
    }
  }));

  const results = await rateLimiter.executeParallelWithStagger(tasks, {
    staggerDelay,
    maxAttempts: maxRetries
  });

  // Summary
  console.log(chalk.cyan(`\n📊 Parallel execution summary:`));
  console.log(chalk.gray(`   Total: ${results.total}`));
  console.log(chalk.green(`   Succeeded: ${results.succeeded}`));
  if (results.failed > 0) {
    console.log(chalk.red(`   Failed: ${results.failed}`));
  }

  return results;
}
