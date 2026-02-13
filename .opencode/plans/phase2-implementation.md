# Phase 3: Fix Agent Loop — Remove Stagehand, Fix Completion Logic

## Overview

The agent loop exits after 1-2 turns because:
1. `hasExecutedAnyTool` becomes `true` after just `read_queue_file` — then any text-only response breaks the loop
2. Stagehand adds 4 overlapping tools (24 total), is broken for Copilot, and adds complexity
3. `finish_reason === 'stop'` check can break after tool execution on non-OpenAI providers
4. No explicit completion criteria in prompts

## File: `src/agents/executor.js`

### Change 1: Remove Stagehand import (line 5)

**Delete:**
```js
import { StagehandManager } from '../mcp/stagehand-manager.js';
```

### Change 2: Remove `buildStagehandConfig` function (lines 60-144)

**Delete the entire function** `buildStagehandConfig` including the JSDoc and all switch cases. It's ~85 lines.

### Change 3: Remove Stagehand initialization (lines 262-301)

**Replace** this entire block:
```js
const stagehandConfig = buildStagehandConfig(providerName, model, providerConfig);
let stagehandManager = null;
let browserManager;

if (stagehandConfig.disableAI) {
  ...
} else {
  stagehandManager = new StagehandManager({...});
  try {
    ...
  } catch (...) {
    ...
  }
}
```

**With:**
```js
const browserManager = new BrowserManager();
```

### Change 4: Remove Stagehand tools from tools array (lines ~643-650)

**Delete:**
```js
...stagehandTools.map(t => ({
  type: 'function',
  function: {
    name: t.name,
    description: t.description,
    parameters: t.parameters
  }
})),
```

### Change 5: Remove Stagehand from tool handlers (lines ~785-786)

Change the toolHandlers to remove the stagehandTools line:
```js
// BEFORE:
const toolHandlers = {
  save_evidence,
  read_queue_file,
  generate_payloads,
  analyze_response,
  generate_bypasses,
  ...Object.fromEntries(browserTools.map(t => [t.name, t.handler])),
  ...Object.fromEntries(stagehandTools.map(t => [t.name, t.handler]))
};

// AFTER:
const toolHandlers = {
  save_evidence,
  read_queue_file,
  generate_payloads,
  analyze_response,
  generate_bypasses,
  ...Object.fromEntries(browserTools.map(t => [t.name, t.handler]))
};
```

### Change 6: Remove Stagehand system prompt section (lines ~248-259)

**Delete** the entire block from `AI BROWSER TOOLS (Stagehand):` to the end of `stagehand_observe` guidance.

Replace with just a blank line or nothing.

### Change 7: Remove Stagehand cleanup in `finally` (lines ~976-978)

**Delete:**
```js
if (stagehandManager) {
  try { await stagehandManager.close(); } catch (e) { /* cleanup error */ }
}
```

### Change 8: Fix completion logic — Replace `hasExecutedAnyTool` with `evidenceSavedCount`

**Replace:**
```js
let consecutiveNudges = 0;
const maxNudges = 3;
let hasExecutedAnyTool = false;
```

**With:**
```js
let consecutiveNudges = 0;
const maxNudges = 3;
let evidenceSavedCount = 0;
const totalVulnerabilities = queueData.vulnerabilities?.length || 0;
```

### Change 9: Track evidence saves in tool execution

In the tool execution block, after `const result = await handler(args);`, add:
```js
// Track evidence saves for completion detection
if (toolName === 'save_evidence') {
  evidenceSavedCount++;
  console.log(chalk.cyan(`      📊 Evidence saved: ${evidenceSavedCount}/${totalVulnerabilities}`));
}
```

Also remove the line `hasExecutedAnyTool = true;` (it was inside the `if (handler)` block).

### Change 10: Fix the completion check in the `else` branch (no tool_calls)

**Replace:**
```js
} else {
  if (hasExecutedAnyTool) {
    console.log(chalk.green('\n   ✅ Agent completed its work'));
    break;
  }

  consecutiveNudges++;
  if (consecutiveNudges > maxNudges) {
    console.log(chalk.red(`\n   ❌ Agent failed to use tools after ${maxNudges} nudges — aborting`));
    ...
    break;
  }

  console.log(chalk.yellow(`\n   ⚠️ No tool calls received (nudge ${consecutiveNudges}/${maxNudges})...`));
  ...
  messages.push({
    role: 'user',
    content: 'You MUST use tools to test vulnerabilities...'
  });
  continue;
}
```

**With:**
```js
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

  // Debug: log response structure
  const finishReason = response.choices[0]?.finish_reason;
  console.log(chalk.gray(`      finish_reason: ${finishReason}`));
  console.log(chalk.gray(`      has tool_calls field: ${assistantMessage.tool_calls !== undefined}`));
  console.log(chalk.gray(`      tool_choice was: ${effectiveToolChoice}`));

  // Inject a nudge message
  messages.push({
    role: 'user',
    content: `You have not tested any vulnerabilities yet. You MUST use tools NOW. Call read_queue_file to load the queue, then use browser_http_request to test each vulnerability, and call save_evidence for each one. There are ${totalVulnerabilities} vulnerabilities to test. Do not respond with text only — make tool calls.`
  });
  continue;
}
```

### Change 11: Fix `tool_choice` to stay `'required'` until evidence is saved

**Replace:**
```js
let effectiveToolChoice = (!hasExecutedAnyTool) ? 'required' : 'auto';
```

**With:**
```js
let effectiveToolChoice = (evidenceSavedCount === 0) ? 'required' : 'auto';
```

### Change 12: Fix `finish_reason === 'stop'` check

**Replace:**
```js
// Check for stop reason (only reached after successful tool execution)
if (response.choices[0].finish_reason === 'stop') {
  // Model signalled stop after tool use — agent is done
  console.log(chalk.green('\n   ✅ Agent finished (stop signal)'));
  break;
}
```

**With:**
```js
// Check for stop reason after tool execution — only break if we've done real work
if (response.choices[0].finish_reason === 'stop' && evidenceSavedCount > 0) {
  console.log(chalk.green(`\n   ✅ Agent finished (${evidenceSavedCount}/${totalVulnerabilities} vulnerabilities tested)`));
  break;
}
```

### Change 13: Strengthen user message (line ~798)

**Replace:**
```js
content: `Target: ${targetUrl}\n\nVulnerabilities to test:\n${vulnSummary}\n\nStart testing. First call read_queue_file to get all vulnerabilities. For each vulnerability, call generate_payloads to get context-aware payloads before testing. After each test request, call analyze_response to interpret results. If blocked, call generate_bypasses for alternatives.`
```

**With:**
```js
content: `Target: ${targetUrl}\n\nVulnerabilities to test (${totalVulnerabilities} total):\n${vulnSummary}\n\nYou MUST test ALL ${totalVulnerabilities} vulnerabilities. Follow this workflow for EACH one:\n1. Call read_queue_file to load the full vulnerability queue\n2. For each vulnerability: call generate_payloads with stage="confirmation"\n3. Use browser_http_request to send test payloads to the target\n4. Call analyze_response to interpret the result\n5. If blocked, call generate_bypasses and retry\n6. Call save_evidence with the results (REQUIRED for every vulnerability)\n\nDo NOT stop until you have called save_evidence for every vulnerability. Start by calling read_queue_file NOW.`
```

### Change 14: Move `totalVulnerabilities` declaration before the user message

Currently `totalVulnerabilities` is declared at line ~808. But the user message at line ~798 needs it. So declare it earlier:

After `queueData = await fs.readJSON(queuePath);` (around line 184), add:
```js
const totalVulnerabilities = queueData.vulnerabilities?.length || 0;
```

And remove the duplicate declaration from the `let` block at line ~808.

## Verification

After all changes:
1. `node --check src/agents/executor.js` — must pass
2. `node -e "import('./src/agents/executor.js')"` — must import cleanly
3. Run: `node src/main.js` with the same semgrep.json to verify the agent continues past Turn 2

---

# Phase 2 Implementation Plan — Multi-Provider LLM Integration (COMPLETED)

## Order: D → F → E → A → B → C

---

## Task D: Remove API Validation from All Providers

Remove the try/catch validation blocks from `authenticate()` in all 5 providers. Just prompt for the key and save immediately.

### D1: `src/providers/openai-provider.js`
**Remove lines 60-77** (the entire try/catch block including the "save anyway?" prompt):
```js
// DELETE THIS BLOCK:
    // Validate with a lightweight call
    try {
      console.log(chalk.gray('Validating API key...'));
      const client = new OpenAI({ apiKey: apiKey.trim() });
      await client.models.list();
      console.log(chalk.green('API key validated successfully.'));
    } catch (e) {
      console.log(chalk.red(`Validation failed: ${e.message}`));
      const { proceed } = await inquirer.prompt([...]);
      if (!proceed) return false;
    }
```
The `import OpenAI from 'openai';` on line 1 can also be removed since `createClient` is the only remaining user, but leave it since `createClient` still uses it.

### D2: `src/providers/deepseek-provider.js`
**Remove lines 59-79** (same pattern — try/catch with `client.models.list()` + "save anyway?" prompt).

### D3: `src/providers/qwen-provider.js`
**Remove lines 80-105** (try/catch with `client.chat.completions.create()` + "save anyway?" prompt).

### D4: `src/providers/github-provider.js`
**Remove lines 70-94** (try/catch with `client.chat.completions.create()` + "save anyway?" prompt).

### D5: `src/providers/google-provider.js`
**Remove lines 119-143** in `_authenticateApiKey()` (try/catch with `client.chat.completions.create()` + "save anyway?" prompt).

---

## Task F: Pass Provider Context from `main.js` to Executor

### F1: `src/main.js` — Update `selectProviderAndModel()` return value

All code paths must return `providerConfig` alongside existing values:

**Line 401** (env var fallback path):
```js
// BEFORE:
return { providerName: 'openai', modelId: 'gpt-4o', client };

// AFTER:
const providerConfig = { apiKey: process.env.OPENAI_API_KEY };
return { providerName: 'openai', modelId: 'gpt-4o', client, providerConfig };
```

**Line 431** (default provider path):
```js
// BEFORE:
const client = await createClientForProvider(config.defaultProvider);
return { providerName: config.defaultProvider, modelId: config.defaultModel, client };

// AFTER:
const providerConfig = await getProviderConfig(config.defaultProvider);
const client = await createClientForProvider(config.defaultProvider);
return { providerName: config.defaultProvider, modelId: config.defaultModel, client, providerConfig };
```

**Line 468-469** (normal selection path):
```js
// BEFORE:
const client = await createClientForProvider(providerName);
return { providerName, modelId, client };

// AFTER:
const providerConfig = await getProviderConfig(providerName);
const client = await createClientForProvider(providerName);
return { providerName, modelId, client, providerConfig };
```

### F2: `src/main.js` — Pass provider context to executor

**Line 241** — destructure `providerConfig`:
```js
const { providerName, modelId, client, providerConfig } = await selectProviderAndModel();
```

**Line 330** — pass to executor:
```js
{ model: modelId, client, providerName, providerConfig }
```

### F3: `src/agents/executor.js` — Accept provider context in options

**Lines 50-52** — add JSDoc params:
```js
 * @param {string} [options.providerName] - Provider key (openai, deepseek, qwen, github, google)
 * @param {object} [options.providerConfig] - Stored provider config (apiKey, baseURL, etc.)
```

**Lines 61-63** — extract from options:
```js
const providerName = options.providerName || 'openai';
const providerConfig = options.providerConfig || {};
```

---

## Task E: Wire Model Propagation to Stagehand

### E1: `src/agents/executor.js` — Add `buildStagehandConfig()` helper

Add this function before `executeExploitationAgent`:

```js
/**
 * Build Stagehand model configuration from provider info.
 * Maps each provider to a Stagehand-compatible model format + client options.
 *
 * @param {string} providerName - Provider key
 * @param {string} model - Model ID
 * @param {object} providerConfig - Stored provider config
 * @returns {{ stagehandModel: string, modelClientOptions: object, disableAI: boolean }}
 */
function buildStagehandConfig(providerName, model, providerConfig) {
  switch (providerName) {
    case 'openai':
      return {
        stagehandModel: `openai/${model}`,
        modelClientOptions: providerConfig?.apiKey
          ? { apiKey: providerConfig.apiKey }
          : {},
        disableAI: false
      };

    case 'deepseek':
      return {
        stagehandModel: `openai/${model}`,
        modelClientOptions: {
          apiKey: providerConfig?.apiKey || process.env.DEEPSEEK_API_KEY,
          baseURL: 'https://api.deepseek.com'
        },
        disableAI: false
      };

    case 'qwen': {
      const QWEN_ENDPOINTS = {
        international: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
        us: 'https://dashscope-us.aliyuncs.com/compatible-mode/v1',
        china: 'https://dashscope.aliyuncs.com/compatible-mode/v1'
      };
      const region = providerConfig?.region || 'international';
      return {
        stagehandModel: `openai/${model}`,
        modelClientOptions: {
          apiKey: providerConfig?.apiKey || process.env.DASHSCOPE_API_KEY,
          baseURL: QWEN_ENDPOINTS[region] || QWEN_ENDPOINTS.international
        },
        disableAI: false
      };
    }

    case 'github':
      return {
        stagehandModel: `openai/${model}`,
        modelClientOptions: {
          apiKey: providerConfig?.token || process.env.GITHUB_TOKEN,
          baseURL: 'https://models.inference.ai.azure.com'
        },
        disableAI: false
      };

    case 'google':
      if (providerConfig?.authMode === 'antigravity') {
        // Antigravity API is NOT OpenAI-compatible — Stagehand cannot use it
        // Disable Stagehand AI features, use basic Playwright only
        return {
          stagehandModel: 'openai/gpt-4o',
          modelClientOptions: {},
          disableAI: true
        };
      }
      // Standard Gemini API key — Stagehand supports google provider
      return {
        stagehandModel: `google/${model}`,
        modelClientOptions: {
          apiKey: providerConfig?.apiKey || process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY
        },
        disableAI: false
      };

    default:
      return {
        stagehandModel: `openai/${model}`,
        modelClientOptions: {},
        disableAI: false
      };
  }
}
```

### E2: `src/agents/executor.js` — Use `buildStagehandConfig` when creating StagehandManager

**Replace line 155:**
```js
// BEFORE:
const stagehandManager = new StagehandManager();

// AFTER:
const stagehandConfig = buildStagehandConfig(providerName, model, providerConfig);
const stagehandManager = stagehandConfig.disableAI
  ? null  // Antigravity: skip Stagehand, use standalone Playwright
  : new StagehandManager({
      stagehandModel: stagehandConfig.stagehandModel,
      modelClientOptions: stagehandConfig.modelClientOptions
    });
```

**Update the init block (lines 158-184) to handle `stagehandManager === null`:**
```js
if (stagehandManager) {
  try {
    console.log(chalk.gray('   Initializing Stagehand AI browser...'));
    await stagehandManager.init();
    // ... existing CDP bridge code ...
  } catch (stagehandError) {
    // ... existing fallback ...
  }
} else {
  console.log(chalk.gray('   Stagehand AI disabled (Antigravity provider) — using standalone Playwright'));
  browserManager = new BrowserManager();
}
```

### E3: `src/mcp/stagehand-manager.js` — Accept and pass `modelClientOptions`

**Constructor (lines 111-123):**
```js
constructor(options = {}) {
  this._stagehandModel = options.stagehandModel || 'openai/gpt-4o';
  this._modelClientOptions = options.modelClientOptions || {};
  // ... rest unchanged
}
```

**`init()` method (lines 132-143) — add `modelClientOptions`:**
```js
this.stagehand = new Stagehand({
  env: 'LOCAL',
  model: this._stagehandModel,
  modelClientOptions: this._modelClientOptions,
  // ... rest unchanged
});
```

---

## Task A: Rewrite `google-oauth.js`

### A1: Add client secret
```js
const CLIENT_SECRET = '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';
```

Add to token exchange body (line 181-187):
```js
const body = new URLSearchParams({
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,  // ADD THIS
  code,
  code_verifier: codeVerifier,
  grant_type: 'authorization_code',
  redirect_uri: REDIRECT_URI
});
```

Add to refresh body (line 209-214):
```js
const body = new URLSearchParams({
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,  // ADD THIS
  refresh_token: refreshToken,
  grant_type: 'refresh_token'
});
```

### A2: Fix scopes
```js
const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'openid',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs'
];
```

### A3: Fix redirect URI
```js
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/oauth-callback`;
```

Update callback server to listen for `/oauth-callback` path instead of `/`:
```js
if (url.pathname !== '/oauth-callback') {
```

### A4: Add paste fallback

In `runAntigravityOAuthFlow()`, replace the simple `waitForCallback(state)` with a race:

```js
// Race: local callback server vs manual paste
const code = await Promise.race([
  waitForCallback(state),
  waitForManualPaste(state)
]);
```

New function `waitForManualPaste()`:
```js
async function waitForManualPaste(expectedState) {
  // Wait a few seconds for local server, then prompt
  await sleep(10000);
  console.log(chalk.yellow('\nLocal callback not received. You can paste the redirect URL manually.'));
  console.log(chalk.gray('Copy the URL from your browser address bar after authenticating.\n'));

  const { redirectUrl } = await inquirer.prompt([{
    type: 'input',
    name: 'redirectUrl',
    message: 'Paste the redirect URL (or press Enter to keep waiting):',
    validate: (input) => {
      if (!input.trim()) return true; // keep waiting
      try {
        const url = new URL(input.trim());
        if (!url.searchParams.get('code')) return 'URL must contain a "code" parameter';
        return true;
      } catch {
        return 'Invalid URL';
      }
    }
  }]);

  if (!redirectUrl.trim()) {
    // User pressed Enter — just keep waiting (this promise never resolves, callback server wins)
    return new Promise(() => {});
  }

  const url = new URL(redirectUrl.trim());
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (state !== expectedState) {
    throw new Error('OAuth state mismatch from pasted URL');
  }

  return code;
}
```

Note: Need to import `inquirer` in `google-oauth.js` for the paste fallback.

### A5: Fix project ID discovery

Replace `discoverProjectId()` (lines 237-249):

```js
export async function discoverProjectId(accessToken) {
  const DEFAULT_PROJECT = 'rising-fact-p41fc';
  try {
    const resp = await fetch(`${SANDBOX_BASE_URL}/v1internal:loadCodeAssist`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': 'antigravity/dynamictester',
        'X-Goog-Api-Client': 'google-cloud-sdk vscode_cloudshelleditor/0.1'
      },
      body: JSON.stringify({})
    });
    if (!resp.ok) return DEFAULT_PROJECT;
    const data = await resp.json();
    return data.projectId || DEFAULT_PROJECT;
  } catch (e) {
    return DEFAULT_PROJECT;
  }
}
```

---

## Task B: Create `src/providers/antigravity-client.js`

New file — full OpenAI-to-Gemini format adapter.

### Class structure:
```js
export class AntigravityClient {
  constructor({ accessToken, projectId, model, sandboxUrl }) {
    this._accessToken = accessToken;
    this._projectId = projectId || 'rising-fact-p41fc';
    this._model = model;
    this._sandboxUrl = sandboxUrl || 'https://daily-cloudcode-pa.sandbox.googleapis.com';
    this.chat = { completions: { create: this._createCompletion.bind(this) } };
  }

  async _createCompletion(params) {
    // 1. Convert OpenAI messages → Gemini contents + systemInstruction
    // 2. Convert OpenAI tools → Gemini functionDeclarations
    // 3. POST to /v1internal:generateContent
    // 4. Parse Gemini response → OpenAI format
  }
}
```

### Message translation:
- `role: 'system'` → extract into `systemInstruction.parts[{text}]`
- `role: 'user'` → `role: 'user'`, `parts: [{text: content}]`
- `role: 'assistant'` → `role: 'model'`, `parts: [{text: content}]`
- `role: 'assistant'` with `tool_calls` → `role: 'model'`, `parts: [{functionCall: {name, args}}]`
- `role: 'tool'` → `role: 'user'`, `parts: [{functionResponse: {name, response: {content}}}]`

### Tool translation:
```js
// OpenAI:
tools: [{ type: 'function', function: { name, description, parameters } }]
// Gemini:
tools: [{ functionDeclarations: [{ name, description, parameters }] }]
```

### Request format:
```js
const body = {
  project: this._projectId,
  model: this._model,
  request: {
    contents,
    systemInstruction,
    generationConfig: {
      temperature: params.temperature ?? 0.7,
      maxOutputTokens: params.max_tokens
    },
    tools: geminiTools
  }
};
```

### Required headers:
```js
{
  'Authorization': `Bearer ${this._accessToken}`,
  'Content-Type': 'application/json',
  'User-Agent': 'antigravity/dynamictester',
  'X-Goog-Api-Client': 'google-cloud-sdk vscode_cloudshelleditor/0.1',
  'Client-Metadata': JSON.stringify({
    ideType: 'ANTIGRAVITY',
    ideVersion: '0.1'
  })
}
```

### Response translation (Gemini → OpenAI):
```js
// Gemini response:
{ candidates: [{ content: { parts: [{text}] | [{functionCall: {name, args}}] } }] }

// → OpenAI format:
{
  id: 'chatcmpl-' + randomId,
  object: 'chat.completion',
  model: this._model,
  choices: [{
    index: 0,
    message: { role: 'assistant', content: text, tool_calls: [...] },
    finish_reason: hasToolCalls ? 'tool_calls' : 'stop'
  }]
}
```

---

## Task C: Update `google-provider.js`

### C1: Fix model IDs
```js
getModels() {
  return [
    // Gemini models (available via both auth modes)
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', description: 'Fast, multimodal, 1M context' },
    { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Best Gemini model, 1M context' },
    { id: 'gemini-2.0-flash', name: 'Gemini 2.0 Flash', description: 'Previous gen fast model' },
    // Antigravity-only models (bare names matching API)
    { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5 (Antigravity)', description: 'Anthropic Claude via Google' },
    { id: 'claude-opus-4-5-thinking', name: 'Claude Opus 4.5 Thinking (Antigravity)', description: 'Claude reasoning via Google' },
    { id: 'gemini-3-pro-high', name: 'Gemini 3 Pro High (Antigravity)', description: 'Gemini 3 via Antigravity' },
    { id: 'gemini-3-flash', name: 'Gemini 3 Flash (Antigravity)', description: 'Fast Gemini 3 via Antigravity' },
    { id: 'gpt-oss-120b-medium', name: 'GPT-OSS 120B (Antigravity)', description: 'OpenAI OSS model via Google' }
  ];
}
```

### C2: Return AntigravityClient for antigravity mode

Import the adapter:
```js
import { AntigravityClient } from './antigravity-client.js';
```

Update `createClient()` antigravity branch (lines 220-226):
```js
if (providerConfig.authMode === 'antigravity') {
  return new AntigravityClient({
    accessToken: providerConfig.accessToken,
    projectId: providerConfig.projectId
  });
}
```

Update `createClientAsync()` (lines 259-262):
```js
return new AntigravityClient({
  accessToken: freshTokenData.accessToken,
  projectId: providerConfig.projectId
});
```

Note: The AntigravityClient model will be set per-request by the executor via `chat.completions.create({ model: ... })`, so we don't set it in the constructor from the provider. The constructor should accept an optional default model but `create()` should override it.

---

## Verification Steps

After all tasks are complete:

1. **Syntax check**: `node -c src/providers/*.js src/agents/executor.js src/mcp/stagehand-manager.js src/main.js`
2. **Import check**: `node -e "import('./src/providers/provider-registry.js')"` — all providers load
3. **Auth login flow**: `node src/main.js auth login` — select each provider, confirm no validation calls
4. **Auth status**: `node src/main.js auth status` — shows configured providers
5. **Manual test** with each provider type (requires actual API keys)
