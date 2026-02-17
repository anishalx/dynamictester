import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Qwen OAuth client ID — same ID used by OpenClaw and Qwen Code CLI.
 * @type {string}
 */
const QWEN_CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56';

/** @type {string} */
const QWEN_DEVICE_CODE_URL = 'https://chat.qwen.ai/api/v1/oauth2/device/code';

/** @type {string} */
const QWEN_TOKEN_URL = 'https://chat.qwen.ai/api/v1/oauth2/token';

/** @type {string} */
const QWEN_PORTAL_BASE_URL = 'https://portal.qwen.ai/v1';

/** @type {string} */
const QWEN_OAUTH_SCOPE = 'openid profile email model.completion';

/** @type {string} */
const QWEN_OAUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Maximum time (ms) to wait for the user to complete OAuth.
 * @type {number}
 */
const MAX_POLL_DURATION_MS = 300000; // 5 minutes

/**
 * Safety margin (ms) added to the server-specified polling interval.
 * @type {number}
 */
const POLLING_SAFETY_MARGIN_MS = 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Encode an object as application/x-www-form-urlencoded.
 * @param {Record<string, string>} data
 * @returns {string}
 */
function toFormUrlEncoded(data) {
  return Object.entries(data)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/**
 * Generate a PKCE code_verifier + code_challenge (S256).
 * @returns {{ verifier: string, challenge: string }}
 */
function generatePkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/**
 * Normalize a base URL returned by the Qwen OAuth server.
 * The `resource_url` field may be bare (e.g. "portal.qwen.ai") — missing
 * the scheme and /v1 path — which the OpenAI SDK rejects as "Invalid URL".
 *
 * @param {string|undefined} raw - The raw URL string from the server or config
 * @returns {string} A well-formed base URL
 */
function normalizeBaseUrl(raw) {
  if (!raw) return QWEN_PORTAL_BASE_URL;
  let url = raw.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }
  if (!url.endsWith('/v1')) {
    url = url.replace(/\/+$/, '') + '/v1';
  }
  return url;
}

/**
 * Try to load cached Qwen Code CLI credentials from ~/.qwen/oauth_creds.json.
 * Returns null if the file doesn't exist or is malformed.
 *
 * @returns {Promise<{accessToken: string, refreshToken: string, expiresAt: number}|null>}
 */
async function loadQwenCliCredentials() {
  try {
    const credsPath = join(homedir(), '.qwen', 'oauth_creds.json');
    const raw = await readFile(credsPath, 'utf8');
    const data = JSON.parse(raw);
    if (data.access_token && data.refresh_token) {
      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: data.expires_at || (data.expires_in ? Date.now() + data.expires_in * 1000 : 0)
      };
    }
  } catch (e) { /* File doesn't exist or is invalid — fall through */ }
  return null;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Qwen Portal provider — free-tier access to Qwen Coder and Qwen Vision
 * via the chat.qwen.ai OAuth device-code flow.
 *
 * Uses PKCE (S256) for security. The resulting access token is used as
 * an API key with the OpenAI-compatible endpoint at portal.qwen.ai/v1.
 *
 * Rate limit: ~2,000 requests/day on the free tier.
 */
export class QwenPortalProvider extends BaseProvider {
  get name() {
    return 'qwen-portal';
  }

  get displayName() {
    return 'Qwen Portal (Free OAuth)';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      { id: 'coder-model', name: 'Qwen Coder', description: 'Code generation and tool calling (free)' },
      { id: 'vision-model', name: 'Qwen Vision', description: 'Text + image understanding (free)' }
    ];
  }

  getDefaultModel() {
    return 'coder-model';
  }

  // -----------------------------------------------------------------------
  // Authentication
  // -----------------------------------------------------------------------

  /**
   * Run the Qwen device-code OAuth flow with PKCE.
   *
   * 1. Generate PKCE verifier/challenge
   * 2. Request a device code from chat.qwen.ai
   * 3. Display verification URL + user code
   * 4. Poll until the user approves
   * 5. Save the access/refresh tokens
   *
   * @returns {Promise<boolean>} true if auth succeeded
   */
  async authenticate() {
    console.log(chalk.cyan('\n--- Qwen Portal (Free OAuth) Authentication ---'));
    console.log(chalk.gray('This uses the Qwen device-code OAuth flow.'));
    console.log(chalk.gray('You need a chat.qwen.ai account (free).\n'));

    try {
      // Step 1: PKCE
      const { verifier, challenge } = generatePkce();

      // Step 2: Request device code
      const deviceAuth = await this._requestDeviceCode(challenge);

      // Step 3: Show the user the code
      const verificationUrl = deviceAuth.verification_uri_complete || deviceAuth.verification_uri;
      console.log(chalk.yellow('\n  To authenticate, visit:'));
      console.log(chalk.bold.white(`    ${verificationUrl}`));
      console.log(chalk.yellow('\n  And enter this code:'));
      console.log(chalk.bold.green(`    ${deviceAuth.user_code}\n`));

      // Step 4: Poll for token
      console.log(chalk.gray('Waiting for authorization...'));
      const token = await this._pollForToken(
        deviceAuth.device_code,
        deviceAuth.interval || 2,
        deviceAuth.expires_in,
        verifier
      );

      // Step 5: Save
      await setProviderConfig('qwen-portal', {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        expiresAt: token.expiresAt,
        baseURL: normalizeBaseUrl(token.resourceUrl)
      });

      console.log(chalk.green('\nQwen Portal authenticated successfully.'));
      console.log(chalk.gray('Tokens auto-refresh. Re-run login if refresh fails.'));
      return true;
    } catch (e) {
      console.log(chalk.red(`\nQwen Portal authentication failed: ${e.message}`));
      return false;
    }
  }

  /**
   * Check for valid credentials. Auto-refreshes expired tokens.
   * Also checks for Qwen Code CLI credentials as a fallback.
   *
   * @returns {Promise<boolean>}
   */
  async validateAuth() {
    const config = await getProviderConfig('qwen-portal');
    if (config?.accessToken) {
      // Auto-refresh if expired (with 60s buffer)
      if (config.expiresAt && config.expiresAt < Date.now() + 60000) {
        try {
          await this._refreshAndSave(config.refreshToken);
        } catch (e) {
          // Refresh failed — credentials are stale
          return false;
        }
      }
      return true;
    }

    // Fallback: check Qwen Code CLI credentials
    const cliCreds = await loadQwenCliCredentials();
    if (cliCreds) {
      // Import CLI credentials into our config store
      await setProviderConfig('qwen-portal', {
        accessToken: cliCreds.accessToken,
        refreshToken: cliCreds.refreshToken,
        expiresAt: cliCreds.expiresAt,
        baseURL: QWEN_PORTAL_BASE_URL
      });
      return true;
    }

    return false;
  }

  /**
   * Create an OpenAI SDK client for the Qwen Portal endpoint.
   * Auto-refreshes expired tokens before creating the client.
   *
   * @param {object} providerConfig - Stored provider config
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    let apiKey = providerConfig?.accessToken;
    if (!apiKey) {
      throw new Error(
        'Qwen Portal access token not found. Run "node src/main.js auth login" and select Qwen Portal.'
      );
    }

    const baseURL = normalizeBaseUrl(providerConfig?.baseURL);
    return new OpenAI({ apiKey, baseURL });
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /**
   * Request a device code from Qwen's OAuth server.
   *
   * @param {string} challenge - PKCE code_challenge (S256)
   * @returns {Promise<{device_code: string, user_code: string, verification_uri: string, verification_uri_complete?: string, expires_in: number, interval?: number}>}
   * @private
   */
  async _requestDeviceCode(challenge) {
    const resp = await fetch(QWEN_DEVICE_CODE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'x-request-id': randomUUID()
      },
      body: toFormUrlEncoded({
        client_id: QWEN_CLIENT_ID,
        scope: QWEN_OAUTH_SCOPE,
        code_challenge: challenge,
        code_challenge_method: 'S256'
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Qwen device code request failed: ${resp.status} ${text}`);
    }

    const payload = await resp.json();
    if (!payload.device_code || !payload.user_code || !payload.verification_uri) {
      throw new Error(
        payload.error || 'Qwen device authorization returned incomplete payload (missing user_code or verification_uri).'
      );
    }
    return payload;
  }

  /**
   * Poll Qwen's token endpoint until the user completes authorization.
   *
   * @param {string} deviceCode - The device code from step 1
   * @param {number} interval - Server-suggested polling interval (seconds)
   * @param {number} expiresIn - Device code lifetime (seconds)
   * @param {string} verifier - PKCE code_verifier
   * @returns {Promise<{accessToken: string, refreshToken: string, expiresAt: number, resourceUrl?: string}>}
   * @private
   */
  async _pollForToken(deviceCode, interval, expiresIn, verifier) {
    let pollIntervalMs = (interval * 1000) + POLLING_SAFETY_MARGIN_MS;
    const timeoutMs = Math.min((expiresIn || 300) * 1000, MAX_POLL_DURATION_MS);
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

      const resp = await fetch(QWEN_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: toFormUrlEncoded({
          grant_type: QWEN_OAUTH_GRANT_TYPE,
          client_id: QWEN_CLIENT_ID,
          device_code: deviceCode,
          code_verifier: verifier
        })
      });

      // Handle non-OK responses (authorization_pending comes as a non-2xx)
      if (!resp.ok) {
        let payload;
        try {
          payload = await resp.json();
        } catch (e) {
          const text = await resp.text();
          throw new Error(`Qwen token endpoint error: ${text || resp.statusText}`);
        }

        if (payload.error === 'authorization_pending') {
          continue;
        }

        if (payload.error === 'slow_down') {
          pollIntervalMs = Math.min(pollIntervalMs * 1.5, 10000);
          continue;
        }

        if (payload.error === 'expired_token') {
          throw new Error('Device code expired. Please try again.');
        }

        if (payload.error === 'access_denied') {
          throw new Error('Authorization was denied by the user.');
        }

        throw new Error(`Qwen OAuth error: ${payload.error_description || payload.error || 'unknown'}`);
      }

      // Success response
      const tokenPayload = await resp.json();

      if (!tokenPayload.access_token || !tokenPayload.refresh_token) {
        throw new Error('Qwen OAuth returned incomplete token payload.');
      }

      return {
        accessToken: tokenPayload.access_token,
        refreshToken: tokenPayload.refresh_token,
        expiresAt: Date.now() + (tokenPayload.expires_in || 3600) * 1000,
        resourceUrl: tokenPayload.resource_url
      };
    }

    throw new Error('Qwen OAuth timed out (5 minutes). Please try again.');
  }

  /**
   * Refresh an expired access token using the stored refresh token
   * and update the config.
   *
   * @param {string} refreshToken
   * @returns {Promise<{accessToken: string, refreshToken: string, expiresAt: number}>}
   * @private
   */
  async _refreshAndSave(refreshToken) {
    if (!refreshToken) {
      throw new Error('No refresh token available. Re-run auth login.');
    }

    const resp = await fetch(QWEN_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: toFormUrlEncoded({
        grant_type: 'refresh_token',
        client_id: QWEN_CLIENT_ID,
        refresh_token: refreshToken
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Qwen token refresh failed: ${resp.status} ${text}`);
    }

    const data = await resp.json();

    if (!data.access_token) {
      throw new Error('Qwen token refresh returned no access_token.');
    }

    const result = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken,
      expiresAt: Date.now() + (data.expires_in || 3600) * 1000
    };

    // Persist updated tokens
    const existingConfig = await getProviderConfig('qwen-portal') || {};
    await setProviderConfig('qwen-portal', {
      ...existingConfig,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresAt: result.expiresAt
    });

    return result;
  }
}
