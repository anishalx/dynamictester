import { randomBytes, randomUUID } from 'crypto';
import { platform, arch } from 'os';

/**
 * Antigravity endpoint URLs in fallback order.
 * @type {string[]}
 */
const ANTIGRAVITY_ENDPOINTS = [
  'https://daily-cloudcode-pa.sandbox.googleapis.com',
  'https://cloudcode-pa.googleapis.com'
];

/**
 * Antigravity sandbox base URL (default primary).
 * @type {string}
 */
const DEFAULT_SANDBOX_URL = ANTIGRAVITY_ENDPOINTS[0];

/**
 * Default project ID when none is configured.
 * This fallback is used only if project discovery fails entirely.
 * @type {string}
 */
const DEFAULT_PROJECT_ID = 'rising-fact-p41fc';

/**
 * Antigravity version string pool — randomized to blend in with legitimate clients.
 * Matches the pattern used by the opencode-antigravity-auth plugin.
 * @type {string[]}
 */
const ANTIGRAVITY_VERSIONS = [
  '1.15.8',
  '1.16.5',
  '1.16.0'
];

/**
 * X-Goog-Api-Client header value pool — randomized per session.
 * @type {string[]}
 */
const API_CLIENT_VALUES = [
  'google-cloud-sdk vscode_cloudshelleditor/0.1',
  'google-cloud-sdk vscode/1.96.0',
  'google-cloud-sdk vscode/1.95.0',
  'google-cloud-sdk vscode/1.87.0',
  'google-cloud-sdk vscode/1.86.0'
];

/**
 * Map Node.js platform strings to Antigravity platform names.
 * @type {Record<string, string>}
 */
const PLATFORM_MAP = {
  linux: 'LINUX',
  darwin: 'MACOS',
  win32: 'WINDOWS'
};

/**
 * Build a randomized User-Agent string matching the opencode plugin pattern.
 * @returns {string}
 */
function buildUserAgent() {
  const version = ANTIGRAVITY_VERSIONS[Math.floor(Math.random() * ANTIGRAVITY_VERSIONS.length)];
  const plat = platform();
  const archStr = arch();
  // Match the pattern: antigravity/1.16.5 linux/x64
  return `antigravity/${version} ${plat}/${archStr}`;
}

/**
 * Pick a random value from an array.
 * @param {string[]} arr
 * @returns {string}
 */
function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * AntigravityClient — an adapter that exposes the same interface as the OpenAI
 * SDK's `chat.completions.create()` method but translates requests to the
 * Antigravity Gemini-style API format.
 *
 * The Antigravity API at `daily-cloudcode-pa.sandbox.googleapis.com` uses a
 * Google Gemini request/response format, NOT OpenAI chat completions. This
 * class handles the bidirectional translation so the rest of the codebase
 * (executor, payload generator, etc.) can use it as a drop-in replacement
 * for the OpenAI SDK client.
 *
 * @example
 * const client = new AntigravityClient({
 *   accessToken: 'ya29.xxx',
 *   projectId: 'rising-fact-p41fc'
 * });
 * const resp = await client.chat.completions.create({
 *   model: 'claude-sonnet-4-5',
 *   messages: [{ role: 'user', content: 'Hello' }]
 * });
 */
export class AntigravityClient {
  /**
   * @param {object} options
   * @param {string} options.accessToken - OAuth access token
   * @param {string} [options.projectId] - Google Cloud project ID
   * @param {string} [options.defaultModel] - Default model if not specified per-request
   * @param {string} [options.sandboxUrl] - Override sandbox base URL
   */
  constructor(options = {}) {
    this._accessToken = options.accessToken;
    this._projectId = options.projectId || DEFAULT_PROJECT_ID;
    this._defaultModel = options.defaultModel || 'gemini-2.5-flash';
    this._sandboxUrl = options.sandboxUrl || DEFAULT_SANDBOX_URL;

    // Generate a stable per-session fingerprint (matches opencode plugin behavior)
    this._sessionFingerprint = {
      deviceId: randomUUID(),
      sessionToken: randomBytes(16).toString('hex'),
      userAgent: buildUserAgent(),
      apiClient: pickRandom(API_CLIENT_VALUES),
      platform: PLATFORM_MAP[platform()] || 'LINUX'
    };

    // Mimic OpenAI SDK interface: client.chat.completions.create(...)
    this.chat = {
      completions: {
        create: this._createCompletion.bind(this)
      }
    };
  }

  /**
   * Update the access token (e.g. after a refresh).
   * @param {string} token
   */
  setAccessToken(token) {
    this._accessToken = token;
  }

  // ---------------------------------------------------------------------------
  // OpenAI → Gemini request translation
  // ---------------------------------------------------------------------------

  /**
   * Convert OpenAI-format messages to Gemini contents + systemInstruction.
   *
   * OpenAI roles: system, user, assistant, tool
   * Gemini roles: user, model (plus systemInstruction for system messages)
   *
   * @param {Array<object>} messages - OpenAI-format messages
   * @returns {{ contents: Array<object>, systemInstruction: object|null }}
   * @private
   */
  _convertMessages(messages) {
    let systemInstruction = null;
    const contents = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        // Gemini puts system messages in systemInstruction
        const text = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
        if (systemInstruction) {
          // Multiple system messages — concatenate
          systemInstruction.parts.push({ text });
        } else {
          systemInstruction = { parts: [{ text }] };
        }
        continue;
      }

      if (msg.role === 'user') {
        const parts = [];
        if (typeof msg.content === 'string') {
          parts.push({ text: msg.content });
        } else if (Array.isArray(msg.content)) {
          // Multimodal content array
          for (const part of msg.content) {
            if (part.type === 'text') {
              parts.push({ text: part.text });
            }
            // Other content types (images, etc.) could be added here
          }
        }
        contents.push({ role: 'user', parts });
        continue;
      }

      if (msg.role === 'assistant') {
        const parts = [];

        // Text content
        if (msg.content) {
          const text = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
          parts.push({ text });
        }

        // Tool calls → functionCall parts
        if (msg.tool_calls && msg.tool_calls.length > 0) {
          for (const toolCall of msg.tool_calls) {
            if (toolCall.type === 'function') {
              let args;
              try {
                args = typeof toolCall.function.arguments === 'string'
                  ? JSON.parse(toolCall.function.arguments)
                  : toolCall.function.arguments;
              } catch (e) {
                args = { raw: toolCall.function.arguments };
              }
              parts.push({
                functionCall: {
                  name: toolCall.function.name,
                  args
                }
              });
            }
          }
        }

        if (parts.length > 0) {
          contents.push({ role: 'model', parts });
        }
        continue;
      }

      if (msg.role === 'tool') {
        // Tool responses become user messages with functionResponse parts
        let responseContent;
        try {
          responseContent = typeof msg.content === 'string'
            ? JSON.parse(msg.content)
            : msg.content;
        } catch (e) {
          responseContent = { result: msg.content };
        }

        // Find the function name from the tool_call_id by looking back
        // through previous messages. Fallback to 'unknown_tool'.
        let functionName = 'unknown_tool';
        if (msg.tool_call_id) {
          for (const prev of messages) {
            if (prev.tool_calls) {
              const match = prev.tool_calls.find(tc => tc.id === msg.tool_call_id);
              if (match) {
                functionName = match.function.name;
                break;
              }
            }
          }
        }

        // Gemini groups consecutive tool responses into a single user turn
        const lastContent = contents[contents.length - 1];
        if (lastContent && lastContent.role === 'user' &&
            lastContent.parts.some(p => p.functionResponse)) {
          // Append to existing tool response group
          lastContent.parts.push({
            functionResponse: {
              name: functionName,
              response: { content: responseContent }
            }
          });
        } else {
          contents.push({
            role: 'user',
            parts: [{
              functionResponse: {
                name: functionName,
                response: { content: responseContent }
              }
            }]
          });
        }
        continue;
      }

      // Unknown role — skip with warning
      console.warn(`AntigravityClient: unknown message role "${msg.role}", skipping`);
    }

    return { contents, systemInstruction };
  }

  /**
   * Convert OpenAI tool definitions to Gemini functionDeclarations.
   *
   * @param {Array<object>} tools - OpenAI tools array
   * @returns {Array<object>|undefined} Gemini tools array or undefined if empty
   * @private
   */
  _convertTools(tools) {
    if (!tools || tools.length === 0) return undefined;

    const declarations = [];
    for (const tool of tools) {
      if (tool.type === 'function' && tool.function) {
        declarations.push({
          name: tool.function.name,
          description: tool.function.description || '',
          parameters: tool.function.parameters || {}
        });
      }
    }

    if (declarations.length === 0) return undefined;
    return [{ functionDeclarations: declarations }];
  }

  // ---------------------------------------------------------------------------
  // Gemini → OpenAI response translation
  // ---------------------------------------------------------------------------

  /**
   * Convert a Gemini response to OpenAI chat completion format.
   *
   * @param {object} geminiResponse - Raw Gemini API response
   * @param {string} model - Model ID used
   * @returns {object} OpenAI-format chat completion response
   * @private
   */
  _convertResponse(geminiResponse, model) {
    const id = 'chatcmpl-ag-' + randomBytes(12).toString('hex');
    const created = Math.floor(Date.now() / 1000);

    const candidate = geminiResponse.candidates?.[0];
    if (!candidate) {
      // Empty response — return a stop completion with no content
      return {
        id,
        object: 'chat.completion',
        created,
        model,
        choices: [{
          index: 0,
          message: { role: 'assistant', content: '', tool_calls: undefined },
          finish_reason: 'stop'
        }],
        usage: this._convertUsage(geminiResponse.usageMetadata)
      };
    }

    const parts = candidate.content?.parts || [];
    let textContent = '';
    const toolCalls = [];

    for (const part of parts) {
      if (part.text !== undefined) {
        textContent += part.text;
      }
      if (part.functionCall) {
        toolCalls.push({
          id: 'call_' + randomBytes(12).toString('hex'),
          type: 'function',
          function: {
            name: part.functionCall.name,
            arguments: JSON.stringify(part.functionCall.args || {})
          }
        });
      }
    }

    const hasToolCalls = toolCalls.length > 0;

    // Map Gemini finish reasons to OpenAI
    let finishReason = 'stop';
    if (hasToolCalls) {
      finishReason = 'tool_calls';
    } else if (candidate.finishReason === 'MAX_TOKENS') {
      finishReason = 'length';
    } else if (candidate.finishReason === 'SAFETY') {
      finishReason = 'content_filter';
    }

    const message = {
      role: 'assistant',
      content: textContent || null
    };
    if (hasToolCalls) {
      message.tool_calls = toolCalls;
    }

    return {
      id,
      object: 'chat.completion',
      created,
      model,
      choices: [{
        index: 0,
        message,
        finish_reason: finishReason
      }],
      usage: this._convertUsage(geminiResponse.usageMetadata)
    };
  }

  /**
   * Convert Gemini usage metadata to OpenAI usage format.
   * @param {object} [usageMetadata]
   * @returns {object}
   * @private
   */
  _convertUsage(usageMetadata) {
    if (!usageMetadata) {
      return { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
    }
    return {
      prompt_tokens: usageMetadata.promptTokenCount || 0,
      completion_tokens: usageMetadata.candidatesTokenCount || 0,
      total_tokens: usageMetadata.totalTokenCount || 0
    };
  }

  // ---------------------------------------------------------------------------
  // Main API call
  // ---------------------------------------------------------------------------

  /**
   * Create a chat completion — the main entry point, matching the OpenAI SDK
   * `client.chat.completions.create()` signature.
   *
   * @param {object} params - OpenAI-format completion params
   * @param {string} [params.model] - Model ID (e.g. 'claude-sonnet-4-5', 'gemini-3-flash')
   * @param {Array<object>} params.messages - OpenAI-format messages
   * @param {Array<object>} [params.tools] - OpenAI-format tool definitions
   * @param {number} [params.temperature] - Sampling temperature
   * @param {number} [params.max_tokens] - Maximum output tokens
   * @param {string} [params.tool_choice] - Tool choice mode (ignored — Gemini handles automatically)
   * @returns {Promise<object>} OpenAI-format chat completion response
   */
  async _createCompletion(params) {
    const model = params.model || this._defaultModel;
    const { contents, systemInstruction } = this._convertMessages(params.messages || []);
    const geminiTools = this._convertTools(params.tools);

    // Build generationConfig
    const generationConfig = {};
    if (params.temperature !== undefined) {
      generationConfig.temperature = params.temperature;
    }
    if (params.max_tokens !== undefined) {
      generationConfig.maxOutputTokens = params.max_tokens;
    }

    // Build the inner request (Gemini format)
    const innerRequest = { contents };

    if (systemInstruction) {
      // Set role to 'user' for CLIProxyAPI compatibility (matches opencode plugin)
      systemInstruction.role = 'user';
      innerRequest.systemInstruction = systemInstruction;
    }
    if (Object.keys(generationConfig).length > 0) {
      innerRequest.generationConfig = generationConfig;
    }
    if (geminiTools) {
      innerRequest.tools = geminiTools;
    }

    // Build request body — Antigravity envelope format
    // Matches the opencode-antigravity-auth plugin's prepareAntigravityRequest()
    const requestBody = {
      project: this._projectId,
      model,
      request: innerRequest,
      requestType: 'agent',
      userAgent: 'antigravity',
      requestId: `agent-${randomUUID()}`
    };

    // Build headers matching the opencode plugin's antigravity mode.
    // IMPORTANT: In antigravity mode, only User-Agent is sent as an HTTP header
    // for content requests. X-Goog-Api-Client and Client-Metadata are NOT sent
    // as HTTP headers. The x-goog-user-project header is stripped to prevent 403.
    const url = `${this._sandboxUrl}/v1internal:generateContent`;
    const headers = {
      'Authorization': `Bearer ${this._accessToken}`,
      'Content-Type': 'application/json',
      'User-Agent': this._sessionFingerprint.userAgent
    };

    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody)
    });

    if (!resp.ok) {
      const errorText = await resp.text();
      const error = this._buildApiError(resp.status, errorText, model);

      // Attach headers so parseRetryAfter() in error-handling.js can use them
      const retryAfter = resp.headers.get('retry-after');
      if (retryAfter) {
        error.headers = { 'retry-after': retryAfter };
      }

      // For 429: extract retry delay from Antigravity response body
      if (resp.status === 429) {
        try {
          const errorData = JSON.parse(errorText);
          const retryInfo = errorData.error?.details?.find(
            d => d['@type']?.includes('RetryInfo')
          );
          if (retryInfo?.retryDelay) {
            const seconds = parseFloat(retryInfo.retryDelay);
            if (!isNaN(seconds)) {
              error.headers = { ...error.headers, 'retry-after': String(seconds) };
            }
          }
        } catch (e) { /* Not JSON or no retry info */ }
      }

      throw error;
    }

    const geminiResponse = await resp.json();

    // Antigravity wraps responses: { response: { candidates: [...] }, traceId: ... }
    const actualResponse = geminiResponse.response || geminiResponse;
    return this._convertResponse(actualResponse, model);
  }

  /**
   * Build a descriptive Error from an API error response.
   * Provides actionable messages for common Antigravity error codes.
   *
   * @param {number} status - HTTP status code
   * @param {string} errorText - Raw error response body
   * @param {string} model - Model ID that was used
   * @returns {Error}
   * @private
   */
  _buildApiError(status, errorText, model) {
    let message;
    let errorData;

    try {
      errorData = JSON.parse(errorText);
    } catch (e) {
      errorData = null;
    }

    const apiMessage = errorData?.error?.message || errorText;
    const apiStatus = errorData?.error?.status || '';

    switch (status) {
      case 400:
        message = `Antigravity API error (400 INVALID_ARGUMENT): ${apiMessage}`;
        if (/model/i.test(apiMessage)) {
          message += `\n  Model "${model}" may not be available. Try a different model.`;
        }
        break;

      case 401:
        message = 'Antigravity API error (401 UNAUTHENTICATED): ' + apiMessage
          + '\n  Your access token is invalid or expired.'
          + '\n  Fix: Run "node src/main.js auth login" and select Google Antigravity.';
        break;

      case 403:
        if (/terms of service/i.test(apiMessage) || /disabled/i.test(apiMessage)) {
          message = 'Antigravity API error (403 PERMISSION_DENIED): ' + apiMessage
            + '\n  Your account may be flagged for ToS violation.'
            + '\n  Possible fixes:'
            + '\n    1. Try a different Google account'
            + '\n    2. Re-authenticate: node src/main.js auth login'
            + '\n    3. Use a Gemini API key instead (simpler, more reliable)'
            + '\n    4. Switch to GitHub Copilot provider';
        } else {
          message = 'Antigravity API error (403 PERMISSION_DENIED): ' + apiMessage
            + '\n  You may not have access to this model or project.'
            + '\n  Fix: Re-authenticate or try a different model.';
        }
        break;

      case 404:
        message = `Antigravity API error (404 NOT_FOUND): Model "${model}" not found.`
          + '\n  Supported models: claude-sonnet-4-5, claude-opus-4-5-thinking, gemini-3-pro-low, gemini-3-pro-high';
        break;

      case 429:
        message = 'Antigravity API error (429 RESOURCE_EXHAUSTED): ' + apiMessage
          + '\n  Quota exhausted. The request will be retried automatically.';
        break;

      default:
        message = `Antigravity API error (${status}${apiStatus ? ' ' + apiStatus : ''}): ${apiMessage}`;
    }

    const error = new Error(message);
    error.status = status;
    error.type = status === 429 ? 'rate_limit_error' : 'api_error';
    return error;
  }
}
