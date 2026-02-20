import OpenAI from 'openai';
import { fs, path } from 'zx';
import chalk from 'chalk';
import { BrowserManager } from '../mcp/browser-server.js';
import { 
  RateLimiter, 
  isRateLimitError, 
  isModelNotFoundError,
  classifyError,
  formatDelay,
  sleep 
} from '../utils/rate-limiter.js';
import { createClientForProvider, getProvider } from '../providers/provider-registry.js';
import { PayloadGenerator } from '../testing/payload-generator.js';
import { BypassEngine } from '../testing/bypass-engine.js';
import { ResponseAnalyzer } from '../testing/response-analyzer.js';
import { IntelligenceAggregator } from '../testing/intelligence-aggregator.js';
import { VulnerabilityClassifier } from '../testing/classifier.js';
import { formatLevel } from '../testing/exploitation-levels.js';

// Maximum characters for tool results to avoid token limits
const MAX_TOOL_RESULT_LENGTH = 8000;

// Maximum number of messages before pruning old context
const MAX_MESSAGES_BEFORE_PRUNE = 80;

// Number of recent messages to preserve when pruning
const MESSAGES_TO_KEEP = 30;

// Maximum agent turns before stopping the exploitation loop
const MAX_AGENT_TURNS = 75;

// Default stagger delay (ms) between parallel agent starts
const DEFAULT_STAGGER_DELAY = 2000;

// Default max retries for parallel agent execution
const DEFAULT_PARALLEL_RETRIES = 3;

// Base delay (ms) between successful API turns to prevent rate limiting
const DEFAULT_TURN_DELAY = 2000;

// Delay (ms) for free-tier models (more aggressive rate limits)
const FREE_TIER_TURN_DELAY = 15000;

// Multiplier applied to turn delay after recovering from a rate limit error
const POST_RATE_LIMIT_DELAY_MULTIPLIER = 3;

// Maximum turn delay (ms) to prevent excessively long waits
const MAX_TURN_DELAY = 60000;

/**
 * Detect if a model is a free-tier model that needs aggressive rate limiting.
 * Free-tier models on OpenRouter end with ":free".
 * @param {string} modelId - The model identifier
 * @returns {boolean} True if the model is free-tier
 */
function isFreeTierModel(modelId) {
  if (!modelId) return false;
  // OpenRouter free-tier models end with ":free"
  if (modelId.endsWith(':free')) return true;
  // OpenRouter free-tier models may also have "(free)" in the name
  if (modelId.toLowerCase().includes('(free)')) return true;
  return false;
}

/**
 * Prune old messages from the conversation to prevent context window overflow.
 * Keeps the system message, a summary of older context, and the most recent messages.
 * @param {Array<object>} messages - The conversation messages array
 * @returns {Array<object>} Pruned messages array
 */
function pruneMessages(messages) {
  if (messages.length <= MAX_MESSAGES_BEFORE_PRUNE) return messages;

  const systemMsg = messages[0]; // Always keep system message
  const recentMessages = messages.slice(-MESSAGES_TO_KEEP);
  const prunedCount = messages.length - MESSAGES_TO_KEEP - 1;

  // Create a summary of what was pruned
  const summaryMsg = {
    role: 'user',
    content: `[CONTEXT NOTE: ${prunedCount} older messages were summarized to fit context window. ` +
      `You have been testing vulnerabilities. Continue where you left off — ` +
      `check the most recent tool results and evidence save calls to see your progress.]`
  };

  return [systemMsg, summaryMsg, ...recentMessages];
}

/**
 * Truncate a tool result to a maximum length while preserving valid JSON.
 * @param {*} obj - The tool result object
 * @param {number} [maxLen=MAX_TOOL_RESULT_LENGTH] - Max character length
 * @returns {string} JSON string within the length limit
 */
function truncateResult(obj, maxLen = MAX_TOOL_RESULT_LENGTH) {
  if (obj === undefined || obj === null) {
    return JSON.stringify({ status: 'success', result: obj ?? null });
  }
  const str = JSON.stringify(obj);
  if (str.length <= maxLen) return str;
  
  // Try to return a meaningful truncated version with valid JSON
  if (typeof obj.content === 'string' && maxLen > 500) {
    return JSON.stringify({ ...obj, content: obj.content.slice(0, maxLen - 500) + '... [TRUNCATED]' });
  }
  if (typeof obj.text === 'string' && maxLen > 500) {
    return JSON.stringify({ ...obj, text: obj.text.slice(0, maxLen - 500) + '... [TRUNCATED]' });
  }
  
  // Fallback: wrap the truncated data in a valid JSON envelope
  // instead of slicing raw JSON which produces invalid syntax
  return JSON.stringify({
    status: obj.status || 'success',
    truncated: true,
    partialData: str.slice(0, maxLen - 200),
    message: `Result truncated from ${str.length} to ${maxLen} characters`
  });
}

/**
 * Execute LLM agent for dynamic testing.
 * Accepts an OpenAI-SDK-compatible client from any provider (OpenAI, DeepSeek, etc.).
 *
 * @param {string} promptTemplate - Path to the prompt template file
 * @param {string} queuePath - Path to the vulnerability queue JSON
 * @param {string} targetUrl - Target URL for dynamic testing
 * @param {string} outputDir - Output directory for results
 * @param {object} [options]
 * @param {string} [options.model='gpt-4o'] - Model identifier
 * @param {number} [options.maxRetries=3] - Max API retries
 * @param {import('openai').default} [options.client] - Pre-configured OpenAI SDK client
 * @param {string} [options.providerName] - Provider key (openai, deepseek, qwen, copilot, google, openrouter, nvidia)
 * @param {object} [options.providerConfig] - Stored provider config (apiKey, baseURL, token, etc.)
 * @param {Array<{name: string, model: string}>} [options.fallbackProviders] - Fallback providers to try on quota exhaustion
 */
export async function executeExploitationAgent(
  promptTemplate,
  queuePath,
  targetUrl,
  outputDir,
  options = {}
) {
  let model = options.model || 'gpt-4o';
  const maxRetries = options.maxRetries ?? 5;
  let llmClient = options.client || new OpenAI();
  let providerName = options.providerName || 'openai';
  const providerConfig = options.providerConfig || {};
  const fallbackProviders = options.fallbackProviders || [];
  const triedProviders = new Set(); // Track which providers have been tried for fallback
  const rateLimiter = new RateLimiter({ maxRetries, enableLogging: true });
  const initialTurnDelay = isFreeTierModel(model) ? FREE_TIER_TURN_DELAY : DEFAULT_TURN_DELAY;
  
  console.log(chalk.cyan(`🚀 Starting exploitation agent (${model})...`));
  console.log(chalk.gray(`   Rate limit handling: ${maxRetries} retries with exponential backoff`));
  console.log(chalk.gray(`   Inter-turn delay: ${formatDelay(initialTurnDelay)}${isFreeTierModel(model) ? ' (free-tier model detected)' : ''}`));
  
  // Load prompt template
  let systemPrompt = await fs.readFile(promptTemplate, 'utf8');
  
  // Load queue data
  let queueData = {};
  let totalVulnerabilities = 0;
  try {
    queueData = await fs.readJSON(queuePath);
    totalVulnerabilities = queueData.vulnerabilities?.length || 0;
    console.log(chalk.gray(`   Loaded ${totalVulnerabilities} vulnerabilities from queue`));
  } catch (e) {
    console.log(chalk.yellow(`   Warning: Could not load queue file: ${e.message}`));
  }
  
  // Interpolate variables (using replacer functions to avoid $ backreference issues)
  systemPrompt = systemPrompt
    .replace(/{{WEB_URL}}/g, () => targetUrl)
    .replace(/{{QUEUE_PATH}}/g, () => queuePath);
  
  // Add universal context (no app-specific content)
  systemPrompt += `

CRITICAL INSTRUCTIONS:
1. You MUST test EVERY vulnerability in the queue, not just a sample
2. Do NOT stop early - continue until all vulnerabilities are tested
3. ALWAYS use static analysis context (file, line, technology) to craft payloads
4. Use browser_http_request for API endpoints - faster and more reliable
5. If browser_click fails with timeout, use browser_force_click instead
6. Save evidence for EACH vulnerability with FULL source mapping

MANDATORY TESTING REQUIREMENT:
- You MUST make at least one HTTP request (browser_http_request or browser_navigate) for EACH web vulnerability BEFORE calling save_evidence
- Do NOT call save_evidence immediately after read_queue_file — reading the queue is NOT testing
- Do NOT call save_evidence based solely on static analysis findings — you must actually probe the target
- For each vulnerability: send a request, observe the response, THEN save evidence with the actual result
- Exception: secrets/config/credential findings may not require HTTP testing. For these, explain in the evidence field why no HTTP request was needed
- The system tracks HTTP requests between save_evidence calls. Evidence saved without prior HTTP requests is flagged as untested

TESTING METHODOLOGY (3-STAGE WORKFLOW):
For EACH vulnerability, follow this sequence:

Stage 1 - CONFIRMATION: Call generate_payloads with stage="confirmation" first.
  Use the returned guidance and fallback payloads to detect if the vuln exists.
  Send the payload via browser_http_request and observe the response.
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
- browser_http_request: REQUIRED — send the payload to the target and get a real response
- analyze_response: Call AFTER each test request (interprets results)
- generate_bypasses: Call when payload is BLOCKED (returns bypass variations)
- browser_force_click: Use when normal click times out
- save_evidence: Call AFTER testing — include full source mapping, actual HTTP response, and observed behavior

EVIDENCE QUALITY REQUIREMENTS:
- The 'response' field MUST contain the actual HTTP status code and key response data from your test
- The 'endpoint' field MUST contain the actual URL you tested
- The 'method' field MUST contain the HTTP method you used
- The 'payload' field MUST contain the exact payload you sent
- The 'evidence' field MUST describe what you observed (not what you expected)
- If exploitation failed, describe what the response actually showed (e.g., "HTTP 200, response contained sanitized output, no injection detected")
- Set securityBlocker if security controls prevented exploitation (WAF, input validation, parameterized queries)

COMPLETION:
- You are NOT done until you have called save_evidence for EVERY vulnerability
- Do NOT stop after just reading the queue — you must test each vulnerability
- Do NOT respond with text-only messages — always make tool calls`;
  
  // ---------------------------------------------------------------------------
  // Initialize Playwright browser for dynamic testing
  // ---------------------------------------------------------------------------
  const browserManager = new BrowserManager({ targetUrl });
  
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

      // SSRF indicators (metadata, internal IPs)
      analysis.ssrfIndicators = ResponseAnalyzer.detectSSRFIndicators(response);

      // XXE indicators (file content disclosure)
      analysis.xxeIndicators = ResponseAnalyzer.detectXXEIndicators(response);

      // XSS reflection detection
      analysis.xssReflection = ResponseAnalyzer.detectXSSReflection(response);

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

    if (analysis.ssrfIndicators?.detected) {
      parts.push(`SSRF DETECTED (${analysis.ssrfIndicators.source}): Server-side request returned internal/metadata content. Confidence: ${analysis.ssrfIndicators.confidence}.`);
    }

    if (analysis.xxeIndicators?.detected) {
      parts.push(`XXE DETECTED: Response contains file content or XML entity reflection. Confidence: ${analysis.xxeIndicators.confidence}.`);
    }

    if (analysis.xssReflection?.detected) {
      parts.push(`XSS REFLECTION DETECTED (${analysis.xssReflection.type}): Payload appears unescaped in response. Confidence: ${analysis.xssReflection.confidence}.`);
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
  // Integrates the 4-level VulnerabilityClassifier for accurate status assignment
  async function save_evidence(params) {
    const {
      id, type, evidence, payload, success,
      // New source mapping fields
      sourceFile, sourceLine, sourceColumn, cwe, owasp,
      endpoint, method, response, exploitationProof, remediation,
      // Additional context
      xssType, injectionContext, secretType, vulnerabilityType,
      // Classification evidence fields (optional — classifier infers from them)
      dataExtracted, criticalImpact, adminAccess, commandExecution,
      queryManipulated, unionSuccess, booleanConfirmed,
      injectionConfirmed, errorDetected, timingConfirmed,
      externalBlocker, blockerReason, securityBlocker, securityReason,
      // Injected by tool tracking (not from LLM)
      _httpRequestsMade
    } = params;
    
    const evidenceDir = path.join(outputDir, 'evidence');
    await fs.ensureDir(evidenceDir);
    
    // Sanitize ID for safe filename — Gitleaks IDs contain '/' and ':' (e.g.
    // "GITLEAKS-target/lib/insecurity.ts:private-key:23") which would create
    // nonexistent subdirectory paths and crash with ENOENT.
    const safeId = (id || 'unknown').replace(/[\/\\:*?"<>|]/g, '-');
    const fileName = `evidence-${safeId}-${Date.now()}.json`;
    const filePath = path.join(evidenceDir, fileName);

    // ---------------------------------------------------------------
    // Build evidence object for the classifier
    // ---------------------------------------------------------------
    const classifierEvidence = {
      dataExtracted: dataExtracted || null,
      criticalImpact: criticalImpact || false,
      adminAccess: adminAccess || false,
      commandExecution: commandExecution || false,
      queryManipulated: queryManipulated || false,
      unionSuccess: unionSuccess || false,
      booleanConfirmed: booleanConfirmed || false,
      injectionConfirmed: injectionConfirmed || false,
      errorDetected: errorDetected || false,
      timingConfirmed: timingConfirmed || false
    };

    // Infer evidence flags from boolean success + exploitationProof
    if (success && exploitationProof && !classifierEvidence.injectionConfirmed) {
      classifierEvidence.injectionConfirmed = true;
    }
    if (success && dataExtracted && dataExtracted.length > 0) {
      // Already set above
    } else if (success && exploitationProof && /extracted|dumped|retrieved|obtained/i.test(exploitationProof)) {
      classifierEvidence.dataExtracted = [exploitationProof];
    }

    const testResult = {
      evidence: classifierEvidence,
      externalBlocker: externalBlocker || null,
      blockerReason: blockerReason || null,
      securityBlocker: securityBlocker || null,
      securityReason: securityReason || null,
      blockerDescription: blockerReason || securityReason || '',
      error: ''
    };

    // ---------------------------------------------------------------
    // Run the classifier
    // ---------------------------------------------------------------
    const classification = VulnerabilityClassifier.classify(testResult);
    
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
      
      // 4-level classification (replaces binary status)
      classification: classification.classification,
      status: classification.classification,
      level: classification.level,
      levelName: classification.levelName,
      confidence: classification.confidence,
      classificationReason: classification.reason,
      includeInReport: classification.includeInReport,
      requiresAction: classification.requiresAction,
      ciExitCode: classification.ciExitCode,

      // Testing thoroughness audit trail
      httpRequestsMade: _httpRequestsMade || 0
    };
    
    await fs.writeJSON(filePath, evidenceData, { spaces: 2 });

    const levelStr = formatLevel(classification.level);
    const statusIcon = classification.classification === 'CONFIRMED' ? '🔴' :
                       classification.classification === 'LIKELY' ? '🟡' :
                       classification.classification === 'BLOCKED' ? '🟠' : '🟢';
    console.log(chalk.green(`   📝 Evidence saved: ${fileName}`));
    console.log(chalk.gray(`      ${statusIcon} ${classification.classification} — ${levelStr}`));
    
    // Also append to summary file for easy developer review
    // Uses a lock file to prevent race conditions during parallel agent execution
    const summaryPath = path.join(outputDir, 'findings_summary.json');
    const lockPath = summaryPath + '.lock';
    const summaryEntry = {
      id: id,
      classification: classification.classification,
      status: classification.classification,
      level: classification.level,
      confidence: classification.confidence,
      file: sourceFile,
      line: sourceLine,
      type: vulnerabilityType || type,
      cwe: cwe,
      endpoint: endpoint,
      success: success,
      requiresAction: classification.requiresAction
    };

    // Retry loop for lock acquisition
    const maxLockRetries = 10;
    for (let lockAttempt = 0; lockAttempt < maxLockRetries; lockAttempt++) {
      try {
        // Acquire lock (exclusive create — fails if lock already exists)
        await fs.writeFile(lockPath, String(process.pid), { flag: 'wx' });
        try {
          let summary = [];
          try {
            summary = await fs.readJSON(summaryPath);
            if (!Array.isArray(summary)) summary = [];
          } catch (e) { /* File doesn't exist yet or corrupt — start fresh array */ }
          summary.push(summaryEntry);
          await fs.writeJSON(summaryPath, summary, { spaces: 2 });
        } finally {
          // Release lock
          await fs.remove(lockPath).catch(() => {});
        }
        break; // Success — exit retry loop
      } catch (lockErr) {
        if (lockErr.code === 'EEXIST' && lockAttempt < maxLockRetries - 1) {
          // Lock held by another agent — wait and retry
          await sleep(100 + Math.random() * 200);
          continue;
        }
        // Final attempt or unexpected error — write without lock as fallback
        console.log(chalk.yellow(`      ⚠️ Summary lock contention, writing without lock`));
        let summary = [];
        try {
          summary = await fs.readJSON(summaryPath);
          if (!Array.isArray(summary)) summary = [];
        } catch (e) { /* start fresh */ }
        summary.push(summaryEntry);
        await fs.writeJSON(summaryPath, summary, { spaces: 2 });
        break;
      }
    }
    
    return { status: 'success', path: filePath, classification: classification.classification, level: classification.level };
  }

  // Read queue file tool - returns ALL vulnerabilities (no limit)
  // Path is restricted to the output directory or the original queue path
  async function read_queue_file({ filePath }) {
    try {
      const resolvedPath = path.resolve(filePath || queuePath);
      const resolvedOutputDir = path.resolve(outputDir);
      const resolvedQueuePath = path.resolve(queuePath);

      // Only allow reading the original queue file or files within the output directory
      const isQueueFile = resolvedPath === resolvedQueuePath;
      const isInOutputDir = resolvedPath.startsWith(resolvedOutputDir + path.sep) || resolvedPath === resolvedOutputDir;
      if (!isQueueFile && !isInOutputDir) {
        return { status: 'error', message: 'Access denied: file path must be the queue file or within the output directory' };
      }

      const data = await fs.readJSON(resolvedPath);
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
  
  const tools = [
    ...browserTools.map(t => ({
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
        description: 'Save exploitation evidence with FULL source code mapping. IMPORTANT: You MUST make at least one HTTP request (browser_http_request or browser_navigate) BEFORE calling this tool for web vulnerabilities. Do NOT call save_evidence immediately after read_queue_file — you must actually test the vulnerability first. For secrets/config findings that do not require HTTP testing, set endpoint to "N/A" and explain in the evidence field why no HTTP request was needed. Include the actual HTTP response status, body excerpt, and observed behavior as proof of testing.',
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
            secretType: { type: 'string', description: 'For secrets: APIKey, Password, Token, etc.' },
            // Classification evidence fields (for 4-level classification)
            dataExtracted: { type: 'array', items: { type: 'string' }, description: 'Data extracted from target (e.g., db version, table names, user records). Presence = Level 3+ CONFIRMED.' },
            criticalImpact: { type: 'boolean', description: 'True if admin creds obtained, sensitive data dumped, or system commands executed (Level 4).' },
            errorDetected: { type: 'boolean', description: 'True if database/server error messages were triggered by payload (Level 1).' },
            timingConfirmed: { type: 'boolean', description: 'True if time-based blind injection was confirmed via delay (Level 1).' },
            booleanConfirmed: { type: 'boolean', description: 'True if boolean-based blind injection was confirmed (Level 2).' },
            queryManipulated: { type: 'boolean', description: 'True if UNION SELECT or ORDER BY manipulation succeeded (Level 2).' },
            externalBlocker: { type: 'string', description: 'If testing was blocked by external factor (auth required, server down, rate limit). Sets BLOCKED status.' },
            securityBlocker: { type: 'string', description: 'If security controls prevented exploitation (WAF, prepared statements, input validation). Sets NOT_REPRODUCIBLE status.' }
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
    ...Object.fromEntries(browserTools.map(t => [t.name, t.handler]))
  };

  // Build initial user message with queue summary
  const vulnSummary = queueData.vulnerabilities?.slice(0, 5).map((v, i) => 
    `${i + 1}. ${v.vulnerabilityType} at ${v.location}`
  ).join('\n') || 'No vulnerabilities loaded';

  const messages = [
    { role: 'system', content: systemPrompt },
    { 
      role: 'user', 
      content: `Target: ${targetUrl}\n\nVulnerabilities to test (${totalVulnerabilities} total):\n${vulnSummary}\n\nYou MUST test ALL ${totalVulnerabilities} vulnerabilities. Follow this workflow for EACH one:\n1. Call read_queue_file to load the full vulnerability queue\n2. For each vulnerability: call generate_payloads with stage="confirmation"\n3. Use browser_http_request to ACTUALLY SEND test payloads to the target — this is REQUIRED before saving evidence\n4. Call analyze_response to interpret the ACTUAL response you received\n5. If blocked, call generate_bypasses and retry with bypass payloads\n6. Call save_evidence with the REAL results — include the actual HTTP status, response body, and observed behavior\n\nIMPORTANT: Every save_evidence call for a web vulnerability MUST be preceded by at least one browser_http_request. Do NOT save evidence without testing. The system tracks this and will flag untested evidence.\n\nDo NOT stop until you have called save_evidence for every vulnerability. Start by calling read_queue_file NOW.` 
    }
  ];

  let turnCount = 0;
  const maxTurns = MAX_AGENT_TURNS;
  let consecutiveErrors = 0;
  const maxConsecutiveErrors = 5;
  let consecutiveNudges = 0;
  const maxNudges = 3; // Max times to nudge model before accepting it's done
  let evidenceSavedCount = 0; // Track how many vulnerabilities have been tested
  let lastEvidenceTurn = 0; // Track when last evidence was saved (stall detection)
  let httpRequestsSinceLastEvidence = 0; // Track HTTP requests between save_evidence calls
  let toolChoiceSupported = true; // Set to false if provider rejects tool_choice: "required"
  // Proactive pacing: delay between turns to prevent rate limits
  let turnDelay = isFreeTierModel(model) ? FREE_TIER_TURN_DELAY : DEFAULT_TURN_DELAY;
  const failedModelsByProvider = new Map();

  function _recordModelFailure(providerKey, modelId) {
    if (!modelId) return;
    if (!failedModelsByProvider.has(providerKey)) {
      failedModelsByProvider.set(providerKey, new Set());
    }
    failedModelsByProvider.get(providerKey).add(modelId);
  }

  function _getNextModelForProvider(providerKey, currentModel) {
    try {
      const provider = getProvider(providerKey);
      const models = provider.getModels().map((m) => m.id).filter(Boolean);
      if (models.length === 0) return null;

      const failed = failedModelsByProvider.get(providerKey) || new Set();
      const remaining = models.filter((id) => !failed.has(id));
      if (remaining.length === 0) return null;

      const next = remaining.find((id) => id !== currentModel) || remaining[0];
      return next === currentModel ? null : next;
    } catch (e) {
      console.log(chalk.gray(`   Model cycling failed: ${e.message}`));
      return null;
    }
  }

  try {
    while (turnCount < maxTurns) {
      // Proactive pacing: delay between turns to avoid hitting rate limits
      if (turnCount > 0) {
        await sleep(turnDelay);
      }

      // Prune messages if context is growing too large
      if (messages.length > MAX_MESSAGES_BEFORE_PRUNE) {
        const before = messages.length;
        const pruned = pruneMessages(messages);
        messages.length = 0;
        messages.push(...pruned);
        console.log(chalk.gray(`   Context pruned: ${before} → ${messages.length} messages`));
      }

      console.log(chalk.blue(`\n🤖 Turn ${turnCount + 1}:`));

      // Force tool use until evidence has been saved; use 'auto' once testing has started
      // Some providers (e.g. Qwen in thinking mode) reject tool_choice: "required"
      let effectiveToolChoice = (evidenceSavedCount === 0 && toolChoiceSupported) ? 'required' : 'auto';

      // Use rate limiter for API call with retry logic
      let response;
      try {
        response = await rateLimiter.executeWithRetry(
          async () => {
            return await llmClient.chat.completions.create({
              model: model,
              messages: messages,
              tools: tools,
              tool_choice: effectiveToolChoice,
              max_tokens: 4096,
              temperature: 0.2
            });
          },
          `${providerName} API request (turn ${turnCount + 1})`,
          { maxRetries }
        );
        // Only count the turn after a successful API response
        turnCount++;
        consecutiveErrors = 0; // Reset on success
        // Gradually reduce elevated turn delay after consecutive successes
        const baseTurnDelay = isFreeTierModel(model) ? FREE_TIER_TURN_DELAY : DEFAULT_TURN_DELAY;
        if (turnDelay > baseTurnDelay) {
          turnDelay = Math.max(Math.round(turnDelay * 0.8), baseTurnDelay);
        }
      } catch (apiError) {
        // If 'required' tool_choice is not supported, fall back to 'auto' permanently
        if (effectiveToolChoice === 'required' &&
            (apiError.status === 400 || apiError.message?.includes('tool_choice') ||
             /unsupported|invalid.*param|not.*support/i.test(apiError.message || ''))) {
          console.log(chalk.yellow(`   ⚠️ tool_choice "required" not supported — falling back to "auto"`));
          toolChoiceSupported = false;
          effectiveToolChoice = 'auto';
          try {
            response = await rateLimiter.executeWithRetry(
              async () => {
                return await llmClient.chat.completions.create({
                  model: model,
                  messages: messages,
                  tools: tools,
                  tool_choice: 'auto',
                  max_tokens: 4096,
                  temperature: 0.2
                });
              },
              `${providerName} API request fallback (turn ${turnCount + 1})`,
              { maxRetries }
            );
            turnCount++;
            consecutiveErrors = 0;
          } catch (fallbackError) {
            consecutiveErrors++;
            console.log(chalk.red(`   ❌ API call failed (fallback): ${fallbackError.message}`));
            continue;
          }
          // Fall through to response processing below
        } else {
          consecutiveErrors++;
          console.log(chalk.red(`   ❌ API call failed: ${apiError.message}`));
          
          // Auth errors (401/403) are fatal — no point retrying a banned/invalid key
          const errorType = classifyError(apiError);
          if (errorType === 'AUTH_ERROR' || errorType === 'TOS_ERROR') {
            const isTos = errorType === 'TOS_ERROR';
            console.log(chalk.red(`\n   ❌ ${isTos ? 'Terms of Service violation' : 'Authentication/authorization error'} — stopping agent immediately`));
            console.log(chalk.yellow(`\n   Possible actions:`));
            if (isTos) {
              console.log(chalk.yellow(`      • Try a different Google account`));
              console.log(chalk.yellow(`      • Use a Gemini API key instead of Antigravity OAuth`));
              console.log(chalk.yellow(`      • Switch to a different provider`));
            } else {
              console.log(chalk.yellow(`      • Re-authenticate: node src/main.js auth login`));
              console.log(chalk.yellow(`      • Switch to a different provider or account`));
              console.log(chalk.yellow(`      • Check provider dashboard for account status`));
            }
            break;
          }

          // --- Model cycling and provider fallback ---
          // For 404 model-not-found errors, try a different model on the SAME provider
          // before falling back to a different provider.
          const isQuota = isRateLimitError(apiError);
          const isModelMissing = isModelNotFoundError(apiError);

          if (isModelMissing) {
            _recordModelFailure(providerName, model);
            const nextModel = _getNextModelForProvider(providerName, model);
            if (nextModel) {
              console.log(chalk.yellow(`   ⚠️ Model "${model}" not accessible on ${providerName}. Trying ${nextModel}...`));
              model = nextModel;
              payloadGenerator.model = nextModel;
              consecutiveErrors = 0;
              continue; // Retry the same turn with a new model
            }

            console.log(chalk.yellow(`   ⚠️ No accessible models left on ${providerName}.`));
          }

          // Try immediately for rate-limit/quota errors (the rate limiter already
          // retried internally, so if it's still 429 the quota is genuinely gone).
          // Also try immediately for model-not-found errors when no models remain.
          // For non-quota errors, wait until consecutiveErrors reaches the threshold.
          const shouldTryFallback = isQuota || isModelMissing || consecutiveErrors >= maxConsecutiveErrors;

          if (shouldTryFallback && fallbackProviders.length > 0 && (isQuota || isModelMissing)) {
            let swapped = false;
            triedProviders.add(providerName); // Mark current provider as tried
            for (const fb of fallbackProviders) {
              if (fb.name === providerName || triedProviders.has(fb.name)) continue; // skip current and already-tried providers
              try {
                const reason = isModelMissing
                  ? `Model "${model}" not accessible on ${providerName}`
                  : `Provider quota exhausted (${providerName})`;
                console.log(chalk.yellow(`\n   ⚡ ${reason}. Falling back to ${fb.name}...`));
                llmClient = await createClientForProvider(fb.name);
                const fbProvider = getProvider(fb.name);
                model = fb.model || fbProvider.getDefaultModel();
                providerName = fb.name;
                payloadGenerator.model = model; // Keep payload generator in sync
                consecutiveErrors = 0;
                toolChoiceSupported = true; // Reset for new provider
                // Reset turn delay for new provider, with free-tier detection
                turnDelay = isFreeTierModel(model) ? FREE_TIER_TURN_DELAY : DEFAULT_TURN_DELAY;
                swapped = true;
                console.log(chalk.green(`   ✅ Switched to ${fb.name}/${model}`));
                break;
              } catch (fbError) {
                triedProviders.add(fb.name); // Mark failed fallback as tried
                console.log(chalk.gray(`   Fallback ${fb.name} failed: ${fbError.message}`));
              }
            }
            if (swapped) continue; // Retry the turn with the new provider
          }

          if (consecutiveErrors >= maxConsecutiveErrors) {
            console.log(chalk.red(`\n   ❌ Too many consecutive errors (${maxConsecutiveErrors}), stopping agent`));
            if (isQuota) {
              console.log(chalk.yellow(`\n   Provider quota exhausted (${providerName}). Possible actions:`));
              console.log(chalk.yellow(`      • Wait and retry later`));
              console.log(chalk.yellow(`      • Switch to a different provider: node src/main.js auth login`));
              console.log(chalk.yellow(`      • Check your quota/billing at the provider dashboard`));
            }
            if (isModelMissing) {
              console.log(chalk.yellow(`\n   Model "${model}" is not accessible on ${providerName}. Possible actions:`));
              console.log(chalk.yellow(`      • Try a different model: re-run and select another model`));
              console.log(chalk.yellow(`      • Switch to a different provider: node src/main.js auth login`));
              console.log(chalk.yellow(`      • Check your plan at the provider dashboard`));
            }
            break;
          }
          
          // If rate limit but no fallback available, add extra cooldown
          if (isQuota) {
            const cooldown = 60000; // 1 minute cooldown
            console.log(chalk.yellow(`   ⏳ Rate limit cooldown: waiting ${formatDelay(cooldown)}...`));
            await sleep(cooldown);
            // Increase turn delay after rate limit to prevent re-triggering
            turnDelay = Math.min(turnDelay * POST_RATE_LIMIT_DELAY_MULTIPLIER, MAX_TURN_DELAY);
            console.log(chalk.gray(`   Turn delay increased to ${formatDelay(turnDelay)}`));
          }
          
          continue; // Try next turn
        }
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
        consecutiveNudges = 0; // Reset nudge counter on successful tool call
        for (const toolCall of assistantMessage.tool_calls) {
          const toolName = toolCall.function.name;
          const handler = toolHandlers[toolName];
          
           if (handler) {
            console.log(chalk.yellow(`   🔧 ${toolName}`));
            try {
              const args = JSON.parse(toolCall.function.arguments);

              // Track HTTP tool calls BEFORE handler call (so save_evidence can see the count)
               const HTTP_TOOLS = ['browser_http_request', 'browser_navigate'];
              if (HTTP_TOOLS.includes(toolName)) {
                httpRequestsSinceLastEvidence++;
              }

              // Inject HTTP request count into save_evidence args BEFORE the handler runs
              if (toolName === 'save_evidence') {
                const isSecretsOrConfig = /secret|config|credential|key|token|password/i.test(args.type || '');
                if (!isSecretsOrConfig && httpRequestsSinceLastEvidence === 0) {
                  console.log(chalk.yellow(`      ⚠️ save_evidence called without any HTTP requests — evidence may be untested`));
                }
                args._httpRequestsMade = httpRequestsSinceLastEvidence;
              }

              const result = await handler(args);

              // Post-handler tracking: completion counts + reset HTTP counter + reset bypass engine
              if (toolName === 'save_evidence') {
                httpRequestsSinceLastEvidence = 0;
                evidenceSavedCount++;
                lastEvidenceTurn = turnCount;
                bypassEngine.reset(); // Fresh bypass budget for next vulnerability
                console.log(chalk.cyan(`      📊 Evidence saved: ${evidenceSavedCount}/${totalVulnerabilities}`));
              }

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
        // Model responded with text only — no tool calls
        // Accept completion only if the agent has saved evidence for at least some vulnerabilities
        if (evidenceSavedCount > 0) {
          console.log(chalk.green(`\n   ✅ Agent completed its work (${evidenceSavedCount}/${totalVulnerabilities} vulnerabilities tested)`));
          break;
        }

        // Agent has NOT saved any evidence — nudge it to keep working
        consecutiveNudges++;
        if (consecutiveNudges > maxNudges) {
          console.log(chalk.red(`\n   ❌ Agent failed to test any vulnerabilities after ${maxNudges} nudges — aborting`));
          console.log(chalk.yellow('   This may indicate the model/provider does not support function calling,'));
          console.log(chalk.yellow('   or the target application is not accessible.'));
          console.log(chalk.yellow('   Try a different model (e.g., gpt-4o) or check that the target URL is reachable.'));
          break;
        }

        console.log(chalk.yellow(`\n   ⚠️ No tool calls received (nudge ${consecutiveNudges}/${maxNudges}) — agent has not tested any vulnerabilities yet`));

        // Debug: log response structure to help diagnose tool calling issues
        const finishReason = response.choices[0]?.finish_reason;
        console.log(chalk.gray(`      finish_reason: ${finishReason}`));
        console.log(chalk.gray(`      has tool_calls field: ${assistantMessage.tool_calls !== undefined}`));
        console.log(chalk.gray(`      tool_choice was: ${effectiveToolChoice}`));

        // Inject a nudge message to force the model to use tools
        messages.push({
          role: 'user',
          content: `You have not tested any vulnerabilities yet. You MUST use tools NOW. Call read_queue_file to load the queue, then use browser_http_request to test each vulnerability, and call save_evidence for each one. There are ${totalVulnerabilities} vulnerabilities to test. Do not respond with text only — make tool calls.`
        });
        continue; // Re-enter the loop to retry with the nudge message
      }

      // Check for stop reason after tool execution — only break if we've done real work
      if (response.choices[0].finish_reason === 'stop' && evidenceSavedCount > 0) {
        console.log(chalk.green(`\n   ✅ Agent finished (${evidenceSavedCount}/${totalVulnerabilities} vulnerabilities tested)`));
        break;
      }

      // Stall detection: if we've saved some evidence but haven't saved any in
      // the last 15 turns, the agent is likely stuck. Nudge it once, then stop.
      if (evidenceSavedCount > 0 && (turnCount - lastEvidenceTurn) > 15) {
        if (evidenceSavedCount >= totalVulnerabilities) {
          console.log(chalk.green(`\n   ✅ All ${totalVulnerabilities} vulnerabilities tested`));
          break;
        }
        console.log(chalk.yellow(`\n   ⚠️ Agent has not saved evidence for 15 turns. Remaining: ${totalVulnerabilities - evidenceSavedCount}`));
        messages.push({
          role: 'user',
          content: `You have tested ${evidenceSavedCount}/${totalVulnerabilities} vulnerabilities but have not saved any evidence for the last 15 turns. Please continue testing the remaining vulnerabilities and call save_evidence for each one. If you are unable to test them, call save_evidence with success=false and explain why in the evidence field.`
        });
        lastEvidenceTurn = turnCount; // Reset stall timer
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
      evidenceSaved: evidenceSavedCount,
      totalVulnerabilities,
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
  }
}

/**
 * Execute multiple agents in parallel with staggered starts
 * Prevents API overwhelm and handles rate limits gracefully
 * 
 * @param {Array<{promptTemplate: string, queuePath: string, targetUrl: string, outputDir: string, name: string, model?: string}>} agents
 * @param {object} options - Execution options
 * @param {import('openai').default} [options.client] - Pre-configured OpenAI SDK client
 * @returns {Promise<object>} Results summary
 */
export async function executeAgentsInParallel(agents, options = {}) {
  const staggerDelay = options.staggerDelay ?? DEFAULT_STAGGER_DELAY;
  const maxRetries = options.maxRetries ?? DEFAULT_PARALLEL_RETRIES;
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
        { ...options, model: agent.model || options.model, client: options.client }
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
