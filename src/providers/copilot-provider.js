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
  get name() {
    return 'copilot';
  }

  get displayName() {
    return 'GitHub Copilot';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      // Claude models
      { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5', description: 'Anthropic Claude Sonnet via Copilot' },
      { id: 'claude-sonnet-4-5-thinking', name: 'Claude Sonnet 4.5 Thinking', description: 'Claude reasoning via Copilot' },
      { id: 'claude-opus-4-5-thinking', name: 'Claude Opus 4.5 Thinking', description: 'Claude Opus reasoning via Copilot' },
      // Gemini models
      { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Google Gemini 2.5 Pro via Copilot' },
      { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', description: 'Google Gemini 2.5 Flash via Copilot' },
      // GPT models
      { id: 'gpt-4o', name: 'GPT-4o', description: 'OpenAI GPT-4o via Copilot' },
      { id: 'gpt-4.1', name: 'GPT-4.1', description: 'OpenAI GPT-4.1 via Copilot' },
      { id: 'o3-pro', name: 'o3 Pro', description: 'OpenAI o3 Pro reasoning via Copilot' },
      { id: 'o4-mini', name: 'o4 Mini', description: 'OpenAI o4 Mini via Copilot' }
    ];
  }

  getDefaultModel() {
    return 'claude-sonnet-4-5';
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

      // Step 4: Save token
      await setProviderConfig('copilot', {
        token: token.access_token
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
    if (config?.token) return true;
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
    return new OpenAI({
      apiKey,
      baseURL: COPILOT_API_BASE_URL
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
