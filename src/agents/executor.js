import OpenAI from 'openai';
import { fs, path } from 'zx';
import chalk from 'chalk';
import { BrowserManager } from '../mcp/browser-server.js';

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
  const model = options.model || 'gpt-4o-mini'; // Use mini by default to avoid rate limits
  
  console.log(chalk.cyan(`🚀 Starting OpenAI exploitation agent (${model})...`));
  
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
  
  // Add context about available tools
  systemPrompt += `\n\nIMPORTANT: When using browser_get_response, it returns a summary with forms, inputs, and links. Use this to find the right selectors for testing.`;
  
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

  // Read queue file tool
  async function read_queue_file({ filePath }) {
    try {
      const data = await fs.readJSON(filePath || queuePath);
      // Limit to first 5 vulnerabilities to reduce tokens
      if (data.vulnerabilities && data.vulnerabilities.length > 5) {
        data.vulnerabilities = data.vulnerabilities.slice(0, 5);
        data.note = 'Showing first 5 vulnerabilities only';
      }
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
        description: 'Read the vulnerability queue JSON file (returns first 5 vulnerabilities)',
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
  const maxTurns = 30;

  try {
    while (turnCount < maxTurns) {
      turnCount++;
      console.log(chalk.blue(`\n🤖 Turn ${turnCount}:`));

      const response = await openai.chat.completions.create({
        model: model,
        messages: messages,
        tools: tools,
        tool_choice: 'auto',
        max_tokens: 1000, // Limit response size
      });

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
    
    return {
      success: true,
      turns: turnCount
    };
    
  } catch (error) {
    console.error(chalk.red(`❌ Agent failed: ${error.message}`));
    await browserManager.close();
    return {
      success: false,
      error: error.message
    };
  }
}
