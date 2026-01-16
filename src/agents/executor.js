import OpenAI from 'openai';
import { fs, path } from 'zx';
import chalk from 'chalk';
import { BrowserManager } from '../mcp/browser-server.js';
import { 
  RateLimiter, 
  isRetryableError, 
  isRateLimitError, 
  getRetryDelay, 
  formatDelay,
  sleep 
} from '../utils/rate-limiter.js';

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
    obj.content = obj.content.slice(0, maxLen - 500) + '... [TRUNCATED]';
    return JSON.stringify(obj);
  }
  if (obj.text) {
    obj.text = obj.text.slice(0, maxLen - 500) + '... [TRUNCATED]';
    return JSON.stringify(obj);
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
  
  // Add context about available tools and critical instructions
  systemPrompt += `

CRITICAL INSTRUCTIONS:
1. You MUST test EVERY vulnerability in the queue, not just a sample
2. Do NOT stop early - continue until all vulnerabilities are tested
3. Use browser_http_request for API endpoints (/rest/*, /api/*, /profile, /search)
4. If browser_click fails with timeout, use browser_force_click instead
5. Use browser_scroll to reveal hidden elements before interacting

JUICE SHOP ATTACK SURFACES:
- Login: /#/login with #email and #password fields (SQLi target)
- Search: /#/search?q=PAYLOAD or /rest/products/search?q=PAYLOAD (SQLi/XSS)
- User profile: /profile (requires auth, has file upload)
- REST API: /api/Users, /api/Products, /api/BasketItems
- Feedback: /#/contact with #comment field (XSS target)
- File uploads: /file-upload, /profile (XXE, traversal)
- Redirect: /redirect?to=URL (open redirect)

TOOL USAGE:
- browser_get_response: Use FIRST to find valid selectors
- browser_http_request: PREFERRED for API testing - faster and more reliable than UI
- browser_force_click: Use when normal click times out
- save_evidence: Must save evidence for EACH vulnerability tested`;
  
  const browserManager = new BrowserManager();
  
  // Evidence collection tool
  async function save_evidence({ id, type, evidence, payload, success }) {
    const evidenceDir = path.join(outputDir, 'evidence');
    await fs.ensureDir(evidenceDir);
    const fileName = `evidence-${id || 'unknown'}-${Date.now()}.json`;
    const filePath = path.join(evidenceDir, fileName);
    await fs.writeJSON(filePath, { 
      id, 
      type, 
      evidence, 
      payload, 
      success, 
      timestamp: new Date().toISOString() 
    }, { spaces: 2 });
    console.log(chalk.green(`   📝 Evidence saved: ${fileName}`));
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
        description: 'Save exploitation evidence to a file',
        parameters: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Vulnerability ID' },
            type: { type: 'string', description: 'Vulnerability type' },
            evidence: { type: 'string', description: 'Description of evidence found' },
            payload: { type: 'string', description: 'The payload used' },
            success: { type: 'boolean', description: 'Whether the exploit was successful' }
          },
          required: ['id', 'type', 'evidence', 'payload', 'success']
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
    }
  ];

  // Tool handlers map
  const toolHandlers = {
    save_evidence,
    read_queue_file,
    ...Object.fromEntries(browserTools.map(t => [t.name, t.handler]))
  };

  // Build initial user message with queue summary
  const vulnSummary = queueData.vulnerabilities?.slice(0, 5).map((v, i) => 
    `${i + 1}. ${v.vulnerabilityType} at ${v.source}`
  ).join('\n') || 'No vulnerabilities loaded';

  const messages = [
    { role: 'system', content: systemPrompt },
    { 
      role: 'user', 
      content: `Target: ${targetUrl}\n\nVulnerabilities to test:\n${vulnSummary}\n\nStart testing. Use browser_get_response to find form inputs, then test with payloads.` 
    }
  ];

  let turnCount = 0;
  const maxTurns = 50; // Increased from 30 to allow thorough testing
  let consecutiveErrors = 0;
  const maxConsecutiveErrors = 5;

  try {
    while (turnCount < maxTurns) {
      turnCount++;
      console.log(chalk.blue(`\n🤖 Turn ${turnCount}:`));

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
              max_tokens: 1000,
            });
          },
          `OpenAI API request (turn ${turnCount})`,
          { maxRetries }
        );
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

    await browserManager.close();
    
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
    await browserManager.close();
    return {
      success: false,
      error: error.message,
      errorStats: rateLimiter.getErrorStats()
    };
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
