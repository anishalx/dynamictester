import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * GitHub Copilot API endpoint — OpenAI-compatible proxy that routes to
 * Claude, Gemini, GPT, and other models via a GitHub Copilot subscription.
 * @type {string}
 */
const COPILOT_API_BASE_URL = 'https://api.githubcopilot.com';

/**
 * GitHub OAuth client ID used for the device code flow.
 * Same client ID that OpenCode and other Copilot-integrated tools use.
 * @type {string}
 */
const GITHUB_CLIENT_ID = 'Ov23li8tweQw6odWQebz';

/**
 * GitHub device code grant endpoints.
 */
const DEVICE_CODE_URL = 'https://github.com/login/device/code';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';

/**
 * Polling interval safety margin (ms) added to the server-specified interval.
 * @type {number}
 */
const POLLING_SAFETY_MARGIN_MS = 3000;

/**
 * Maximum time (ms) to wait for the user to complete device code auth.
 * @type {number}
 */
const MAX_POLL_DURATION_MS = 300000; // 5 minutes

/**
 * GitHub Copilot provider — access Claude, Gemini, GPT, and other models
 * through the GitHub Copilot proxy using your GitHub Copilot subscription.
 *
 * Authentication uses the GitHub Device Code OAuth flow (same flow as OpenCode).
 * The Copilot proxy is fully OpenAI-compatible, so no format translation is needed.
 */
export class CopilotProvider extends BaseProvider {
  constructor() {
    super();
    /** @type {import('./provider-interface.js').ModelInfo[]|null} */
    this._dynamicModels = null;
  }

  get name() {
    return 'copilot';
  }

  get displayName() {
    return 'GitHub Copilot';
  }

  /**
   * Hardcoded model list — used as fallback when dynamic fetching fails.
   * Updated from https://docs.github.com/en/copilot/reference/ai-models/supported-models
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    // Return dynamically fetched models if available, else the hardcoded fallback
    if (this._dynamicModels && this._dynamicModels.length > 0) {
      return this._dynamicModels;
    }
    return this._getHardcodedModels();
  }

  /**
   * Hardcoded fallback model list, kept in sync with GitHub Copilot docs.
   * @returns {import('./provider-interface.js').ModelInfo[]}
   * @private
   */
  _getHardcodedModels() {
    return [
      // Claude models (Anthropic) — use dots, not dashes, in version numbers
      { id: 'claude-opus-4.6', name: 'Claude Opus 4.6', description: 'Anthropic Claude Opus 4.6 via Copilot (supports adaptive thinking)' },
      { id: 'claude-opus-4.6-fast', name: 'Claude Opus 4.6 Fast (Preview)', description: 'Anthropic Claude Opus 4.6 fast preview via Copilot' },
      { id: 'claude-opus-4.5', name: 'Claude Opus 4.5', description: 'Anthropic Claude Opus 4.5 via Copilot' },
      { id: 'claude-sonnet-4.5', name: 'Claude Sonnet 4.5', description: 'Anthropic Claude Sonnet 4.5 via Copilot' },
      { id: 'claude-sonnet-4', name: 'Claude Sonnet 4', description: 'Anthropic Claude Sonnet 4 via Copilot' },
      { id: 'claude-haiku-4.5', name: 'Claude Haiku 4.5', description: 'Anthropic Claude Haiku 4.5 via Copilot (lightweight)' },
      // Gemini models (Google)
      { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Google Gemini 2.5 Pro via Copilot' },
      { id: 'gemini-3-pro', name: 'Gemini 3 Pro', description: 'Google Gemini 3 Pro via Copilot' },
      { id: 'gemini-3-flash', name: 'Gemini 3 Flash', description: 'Google Gemini 3 Flash via Copilot (lightweight)' },
      // GPT models (OpenAI)
      { id: 'gpt-5.3-codex', name: 'GPT-5.3-Codex', description: 'OpenAI GPT-5.3-Codex via Copilot (latest)' },
      { id: 'gpt-5.2-codex', name: 'GPT-5.2-Codex', description: 'OpenAI GPT-5.2-Codex via Copilot (powerful)' },
      { id: 'gpt-5.2', name: 'GPT-5.2', description: 'OpenAI GPT-5.2 via Copilot' },
      { id: 'gpt-5.1-codex-max', name: 'GPT-5.1-Codex-Max', description: 'OpenAI GPT-5.1-Codex-Max via Copilot (powerful)' },
      { id: 'gpt-5.1-codex-mini', name: 'GPT-5.1-Codex-Mini', description: 'OpenAI GPT-5.1-Codex-Mini via Copilot' },
      { id: 'gpt-5.1-codex', name: 'GPT-5.1-Codex', description: 'OpenAI GPT-5.1-Codex via Copilot' },
      { id: 'gpt-5.1', name: 'GPT-5.1', description: 'OpenAI GPT-5.1 via Copilot' },
      { id: 'gpt-5-codex', name: 'GPT-5-Codex', description: 'OpenAI GPT-5-Codex via Copilot' },
      { id: 'gpt-5', name: 'GPT-5', description: 'OpenAI GPT-5 via Copilot' },
      { id: 'gpt-5-mini', name: 'GPT-5 mini', description: 'OpenAI GPT-5 mini via Copilot (lightweight)' },
      { id: 'gpt-4.1', name: 'GPT-4.1', description: 'OpenAI GPT-4.1 via Copilot' },
      // Other
      { id: 'grok-code-fast-1', name: 'Grok Code Fast 1', description: 'xAI Grok Code Fast 1 via Copilot (lightweight)' },
      { id: 'raptor-mini', name: 'Raptor Mini', description: 'Raptor Mini via Copilot' }
    ];
  }

  /**
   * Check whether a model ID is valid for this provider.
   * Checks both hardcoded and dynamically fetched models.
   *
   * @param {string} modelId - Model identifier to validate
   * @returns {boolean}
   */
  isValidModel(modelId) {
    const allModels = this.getModels();
    return allModels.some(m => m.id === modelId);
  }

  /**
   * Fetch available models from the Copilot API dynamically.
   * Falls back silently to the hardcoded list on failure.
   *
   * @param {string} [token] - OAuth token (uses stored config if not provided)
   * @returns {Promise<import('./provider-interface.js').ModelInfo[]>}
   */
  async fetchModels(token) {
    try {
      const apiKey = token || (await getProviderConfig('copilot'))?.token || process.env.GITHUB_COPILOT_TOKEN;
      if (!apiKey) return this._getHardcodedModels();

      const resp = await fetch(`${COPILOT_API_BASE_URL}/models`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Accept': 'application/json'
        }
      });

      if (!resp.ok) {
        // API may not support /models endpoint — fall back silently
        return this._getHardcodedModels();
      }

      const data = await resp.json();
      const models = (data.data || data.models || data || []);

      if (!Array.isArray(models) || models.length === 0) {
        return this._getHardcodedModels();
      }

      this._dynamicModels = models.map(m => ({
        id: m.id || m.name,
        name: m.id || m.name,
        description: m.description || `${m.id} via Copilot`
      }));

      return this._dynamicModels;
    } catch (e) {
      // Network error or parsing error — fall back silently
      return this._getHardcodedModels();
    }
  }

  getDefaultModel() {
    return 'claude-sonnet-4.5';
  }

  /**
   * Run the GitHub Device Code OAuth flow to get a Copilot access token.
   *
   * Flow:
   * 1. Request a device code from GitHub
   * 2. Show the user a verification URL and code
   * 3. Poll GitHub until the user completes authorization
   * 4. Save the resulting gho_* token
   *
   * @returns {Promise<boolean>} true if auth succeeded
   */
  async authenticate() {
    console.log(chalk.cyan('\n--- GitHub Copilot Authentication ---'));
    console.log(chalk.gray('This uses the GitHub Device Code flow (same as OpenCode).'));
    console.log(chalk.gray('You need an active GitHub Copilot subscription.\n'));

    try {
      // Step 1: Request device code
      const deviceCode = await this._requestDeviceCode();

      // Step 2: Show user the code
      console.log(chalk.yellow('\n  To authenticate, visit:'));
      console.log(chalk.bold.white(`    ${deviceCode.verification_uri}`));
      console.log(chalk.yellow('\n  And enter this code:'));
      console.log(chalk.bold.green(`    ${deviceCode.user_code}\n`));

      // Step 3: Poll for token
      console.log(chalk.gray('Waiting for authorization...'));
      const token = await this._pollForToken(
        deviceCode.device_code,
        deviceCode.interval || 5
      );

      // Step 4: Save token with type and expiry tracking
      const expiresIn = Number(token.expires_in) || 28800; // Default 8 hours
      await setProviderConfig('copilot', {
        token: token.access_token,
        tokenType: token.token_type || 'bearer',
        expiresAt: Date.now() + (expiresIn * 1000)
      });

      console.log(chalk.green('\nGitHub Copilot authenticated successfully.'));
      return true;
    } catch (e) {
      console.log(chalk.red(`\nCopilot authentication failed: ${e.message}`));
      return false;
    }
  }

  async validateAuth() {
    const config = await getProviderConfig('copilot');
    if (config?.token) {
      // Check if token has expired (with 5-minute grace period)
      if (config.expiresAt && Date.now() > config.expiresAt - 300000) {
        console.log(chalk.yellow('Copilot token has expired. Please re-authenticate.'));
        return false;
      }
      return true;
    }
    // Also check env var fallback
    if (process.env.GITHUB_COPILOT_TOKEN) return true;
    return false;
  }

  /**
   * Create an OpenAI SDK client configured for the GitHub Copilot proxy.
   *
   * @param {object} providerConfig - Stored provider config
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.token || process.env.GITHUB_COPILOT_TOKEN;
    if (!apiKey) {
      throw new Error(
        'GitHub Copilot token not found. Run "node src/main.js auth login" and select GitHub Copilot.'
      );
    }
    // Disable SDK built-in retries — our RateLimiter handles retry with proper backoff
    return new OpenAI({
      apiKey,
      baseURL: COPILOT_API_BASE_URL,
      maxRetries: 0
    });
  }

  // -- Private helpers ---------------------------------------------------

  /**
   * Request a device code from GitHub.
   *
   * @returns {Promise<{device_code: string, user_code: string, verification_uri: string, interval: number, expires_in: number}>}
   * @private
   */
  async _requestDeviceCode() {
    const resp = await fetch(DEVICE_CODE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        scope: 'read:user'
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Failed to request device code: ${resp.status} ${text}`);
    }

    return resp.json();
  }

  /**
   * Poll GitHub's token endpoint until the user completes authorization.
   *
   * @param {string} deviceCode - The device code from step 1
   * @param {number} interval - Polling interval in seconds (from GitHub)
   * @returns {Promise<{access_token: string, token_type: string, scope: string}>}
   * @private
   */
  async _pollForToken(deviceCode, interval) {
    const pollIntervalMs = (interval * 1000) + POLLING_SAFETY_MARGIN_MS;
    const deadline = Date.now() + MAX_POLL_DURATION_MS;

    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

      const resp = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          client_id: GITHUB_CLIENT_ID,
          device_code: deviceCode,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
        })
      });

      if (!resp.ok) {
        throw new Error(`Token endpoint returned ${resp.status}`);
      }

      const data = await resp.json();

      if (data.access_token) {
        return data;
      }

      if (data.error === 'authorization_pending') {
        // User hasn't completed auth yet — keep polling
        continue;
      }

      if (data.error === 'slow_down') {
        // GitHub is telling us to slow down — add extra delay
        await new Promise((resolve) => setTimeout(resolve, 5000));
        continue;
      }

      if (data.error === 'expired_token') {
        throw new Error('Device code expired. Please try again.');
      }

      if (data.error === 'access_denied') {
        throw new Error('Authorization was denied by the user.');
      }

      // Unknown error
      throw new Error(`OAuth error: ${data.error} — ${data.error_description || 'unknown'}`);
    }

    throw new Error('Authentication timed out (5 minutes). Please try again.');
  }
}
