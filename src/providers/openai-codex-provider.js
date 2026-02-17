import { homedir } from 'node:os';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import OpenAI from 'openai';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

// ---------------------------------------------------------------------------
// Constants — sourced from the Codex CLI Rust codebase (codex-rs/core/src/auth.rs)
// ---------------------------------------------------------------------------

/**
 * OpenAI OAuth client ID — same as the official Codex CLI.
 * @type {string}
 */
const OPENAI_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';

/**
 * Device-code endpoints on auth.openai.com.
 * @type {string}
 */
const DEVICE_USERCODE_URL = 'https://auth.openai.com/api/accounts/deviceauth/usercode';

/** @type {string} */
const DEVICE_TOKEN_URL = 'https://auth.openai.com/api/accounts/deviceauth/token';

/**
 * Standard OAuth token endpoint (code exchange, refresh, API-key exchange).
 * @type {string}
 */
const OAUTH_TOKEN_URL = 'https://auth.openai.com/oauth/token';

/**
 * URL shown to the user so they can enter the device code.
 * @type {string}
 */
const VERIFICATION_URL = 'https://auth.openai.com/codex/device';

/**
 * Redirect URI used during the authorization-code exchange.
 * For device-code flow this is a fixed callback on auth.openai.com.
 * @type {string}
 */
const REDIRECT_URI = 'https://auth.openai.com/deviceauth/callback';

/**
 * Scope used when refreshing (offline_access is omitted per Codex CLI).
 * @type {string}
 */
const REFRESH_SCOPE = 'openid profile email';

/**
 * OpenAI API base URL — the API key obtained via token-exchange works here.
 * @type {string}
 */
const OPENAI_API_BASE_URL = 'https://api.openai.com/v1';

/**
 * Maximum time (ms) to wait for the user to complete device-code auth.
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
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/**
 * Try to load cached Codex CLI credentials from ~/.codex/auth.json.
 * Returns null if the file doesn't exist or is malformed.
 *
 * @returns {Promise<{apiKey: string, refreshToken: string, idToken: string}|null>}
 */
async function loadCodexCliCredentials() {
  try {
    const authPath = join(homedir(), '.codex', 'auth.json');
    const raw = await readFile(authPath, 'utf8');
    const data = JSON.parse(raw);
    // The Codex CLI stores the exchanged API key as OPENAI_API_KEY
    if (data.OPENAI_API_KEY && data.tokens?.refresh_token) {
      return {
        apiKey: data.OPENAI_API_KEY,
        refreshToken: data.tokens.refresh_token,
        idToken: data.tokens.id_token || null
      };
    }
  } catch (e) { /* File doesn't exist or is invalid — fall through */ }
  return null;
}

/**
 * Full catalog of known Codex-compatible models, ordered by preference.
 * During auth, we probe GET /v1/models to discover which are actually
 * accessible with the user's token and plan. The static getModels() returns
 * this full list; getDefaultModel() returns the first available model
 * (populated after discoverAvailableModels runs, falls back to first entry).
 *
 * @type {import('./provider-interface.js').ModelInfo[]}
 */
const ALL_CODEX_MODELS = [
  { id: 'gpt-5.3-codex', name: 'GPT-5.3 Codex', description: 'Latest frontier agentic coding model' },
  { id: 'gpt-5.2-codex', name: 'GPT-5.2 Codex', description: 'Advanced coding model for real-world engineering' },
  { id: 'gpt-5.2', name: 'GPT-5.2', description: 'Best general agentic model' },
  { id: 'gpt-5.1-codex-max', name: 'GPT-5.1 Codex Max', description: 'Optimized for long-horizon agentic coding' },
  { id: 'gpt-5.1-codex', name: 'GPT-5.1 Codex', description: 'Agentic coding model' },
  { id: 'gpt-5.1', name: 'GPT-5.1', description: 'General coding and agentic tasks' },
  { id: 'gpt-5-codex', name: 'GPT-5 Codex', description: 'GPT-5 tuned for agentic coding' },
  { id: 'gpt-5-codex-mini', name: 'GPT-5 Codex Mini', description: 'Smaller, cost-effective Codex model' },
  { id: 'gpt-5', name: 'GPT-5', description: 'Reasoning model for coding and agentic tasks' },
  // Older models that may still be accessible on some plans
  { id: 'o3', name: 'o3', description: 'Reasoning model (legacy)' },
  { id: 'o4-mini', name: 'o4-mini', description: 'Fast reasoning model (legacy)' },
  { id: 'gpt-4.1', name: 'GPT-4.1', description: 'General-purpose model (legacy)' },
  { id: 'codex-mini-latest', name: 'Codex Mini', description: 'Lightweight Codex model (legacy)' }
];

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * OpenAI Codex provider — free-tier access to Codex models (gpt-5.3-codex, etc.)
 * via the ChatGPT device-code OAuth flow.
 *
 * The device-code flow is non-standard: the server generates PKCE values and
 * returns them alongside the authorization_code during polling. After OAuth,
 * the id_token is exchanged for an OpenAI API key via a token-exchange grant.
 * The API key works with the standard OpenAI SDK at api.openai.com/v1.
 *
 * After authentication, probes GET /v1/models to discover which models are
 * actually accessible on the user's plan. Falls back through the full catalog
 * until an accessible model is found.
 *
 * This is a separate provider from 'openai' (which uses a manually-entered
 * API key). Both can coexist.
 */
export class OpenAICodexProvider extends BaseProvider {
  /** @type {string[]} Models confirmed accessible via GET /v1/models probe */
  _availableModelIds = [];

  /** @type {string|null} Discovered default model (first accessible from catalog) */
  _discoveredDefault = null;

  get name() {
    return 'openai-codex';
  }

  get displayName() {
    return 'OpenAI Codex (Free OAuth)';
  }

  /**
   * Returns the full catalog of known Codex models.
   * If model discovery has run, models are annotated with availability.
   *
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    if (this._availableModelIds.length > 0) {
      // Return only models confirmed accessible
      return ALL_CODEX_MODELS.filter((m) => this._availableModelIds.includes(m.id));
    }
    return ALL_CODEX_MODELS;
  }

  getDefaultModel() {
    return this._discoveredDefault || ALL_CODEX_MODELS[0].id;
  }

  // -----------------------------------------------------------------------
  // Authentication
  // -----------------------------------------------------------------------

  /**
   * Run the OpenAI device-code OAuth flow.
   *
   * 1. Request a device code from auth.openai.com (server generates PKCE)
   * 2. Display verification URL + user code
   * 3. Poll until the user approves (returns authorization_code + code_verifier)
   * 4. Exchange the authorization_code for id_token + refresh_token (using server-provided code_verifier)
   * 5. Exchange the id_token for an OpenAI API key
   * 6. Save everything
   *
   * @returns {Promise<boolean>} true if auth succeeded
   */
  async authenticate() {
    console.log(chalk.cyan('\n--- OpenAI Codex (Free OAuth) Authentication ---'));
    console.log(chalk.gray('This uses the same auth flow as the Codex CLI.'));
    console.log(chalk.gray('You need a ChatGPT account (free tier works).\n'));

    try {
      // Step 1: Request device code (no client-side PKCE — server handles it)
      const deviceAuth = await this._requestDeviceCode();

      // Step 2: Show the user the code
      console.log(chalk.yellow('\n  To authenticate, visit:'));
      console.log(chalk.bold.white(`    ${VERIFICATION_URL}`));
      console.log(chalk.yellow('\n  And enter this code:'));
      console.log(chalk.bold.green(`    ${deviceAuth.user_code}\n`));

      // Step 3: Poll for authorization code + server-generated PKCE verifier
      console.log(chalk.gray('Waiting for authorization...'));
      const { authorizationCode, codeVerifier } = await this._pollForAuthCode(
        deviceAuth.device_auth_id,
        deviceAuth.user_code,
        deviceAuth.interval,
        deviceAuth.expires_in
      );

      // Step 4: Exchange authorization code for tokens (using server-provided code_verifier)
      console.log(chalk.gray('Exchanging authorization code for tokens...'));
      const tokens = await this._exchangeCodeForTokens(authorizationCode, codeVerifier);

      // Step 5: Exchange id_token for an OpenAI API key (optional — errors are non-fatal)
      let apiKey;
      try {
        console.log(chalk.gray('Obtaining OpenAI API key...'));
        apiKey = await this._exchangeForApiKey(tokens.idToken);
      } catch (e) {
        // Codex CLI treats this as non-fatal (.ok() in Rust source)
        console.log(chalk.yellow(`API key exchange failed (non-fatal): ${e.message}`));
        console.log(chalk.gray('Will use id_token directly for authentication.'));
        apiKey = tokens.accessToken || tokens.idToken;
      }

      // Step 6: Save
      await setProviderConfig('openai-codex', {
        apiKey,
        idToken: tokens.idToken,
        refreshToken: tokens.refreshToken,
        expiresAt: Date.now() + (tokens.expiresIn || 3600) * 1000
      });

      console.log(chalk.green('\nOpenAI Codex authenticated successfully.'));

      // Step 7: Discover which models are accessible on this plan
      console.log(chalk.gray('Discovering available models...'));
      await this._discoverAvailableModels(apiKey);

      console.log(chalk.gray('Tokens auto-refresh. Re-run login if refresh fails.'));
      return true;
    } catch (e) {
      console.log(chalk.red(`\nOpenAI Codex authentication failed: ${e.message}`));
      return false;
    }
  }

  /**
   * Check for valid credentials. Auto-refreshes expired tokens.
   * Also checks for Codex CLI credentials (~/.codex/auth.json) as fallback.
   *
   * @returns {Promise<boolean>}
   */
  async validateAuth() {
    const config = await getProviderConfig('openai-codex');
    if (config?.apiKey) {
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

    // Fallback: check Codex CLI credentials
    const cliCreds = await loadCodexCliCredentials();
    if (cliCreds) {
      // Import CLI credentials into our config store
      await setProviderConfig('openai-codex', {
        apiKey: cliCreds.apiKey,
        idToken: cliCreds.idToken,
        refreshToken: cliCreds.refreshToken,
        expiresAt: 0 // Unknown — will refresh on next validateAuth
      });
      return true;
    }

    return false;
  }

  /**
   * Create an OpenAI SDK client using the exchanged API key.
   *
   * @param {object} providerConfig - Stored provider config
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey;
    if (!apiKey) {
      throw new Error(
        'OpenAI Codex API key not found. Run "node src/main.js auth login" and select OpenAI Codex.'
      );
    }

    return new OpenAI({ apiKey, baseURL: OPENAI_API_BASE_URL });
  }

  /**
   * Probe GET /v1/models to discover which models are actually accessible
   * with the current API key. Filters the full catalog to only accessible
   * models and sets the default to the first accessible one.
   *
   * This is best-effort — if the probe fails, the full catalog is kept
   * and the first model is used as default (may still 404 at call time).
   *
   * @param {string} apiKey - The API key to probe with
   * @returns {Promise<void>}
   * @private
   */
  async _discoverAvailableModels(apiKey) {
    try {
      const resp = await fetch(`${OPENAI_API_BASE_URL}/models`, {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Accept': 'application/json'
        }
      });

      if (!resp.ok) {
        console.log(chalk.gray(`   Model discovery probe returned ${resp.status} — using full catalog.`));
        return;
      }

      const data = await resp.json();
      const remoteIds = new Set((data.data || []).map((m) => m.id));

      // Filter our catalog to only models that exist on the server
      const catalogIds = ALL_CODEX_MODELS.map((m) => m.id);
      const available = catalogIds.filter((id) => remoteIds.has(id));

      if (available.length > 0) {
        this._availableModelIds = available;
        this._discoveredDefault = available[0];
        console.log(chalk.green(`   ✅ Discovered ${available.length} accessible model(s): ${available.join(', ')}`));
        console.log(chalk.green(`   Default model: ${this._discoveredDefault}`));
      } else {
        // None of our known catalog models were listed — report what IS available
        const allRemote = [...remoteIds].sort();
        console.log(chalk.yellow(`   ⚠️ None of the known Codex models are accessible on your plan.`));
        console.log(chalk.gray(`   Available models on your account (${allRemote.length}): ${allRemote.slice(0, 20).join(', ')}${allRemote.length > 20 ? '...' : ''}`));
        // Use the first remote model that looks like a chat model as a heuristic
        const chatModel = allRemote.find((id) => id.startsWith('gpt-') || id.startsWith('o') || id.includes('codex'));
        if (chatModel) {
          this._availableModelIds = [chatModel];
          this._discoveredDefault = chatModel;
          console.log(chalk.green(`   Using best-guess model: ${chatModel}`));
        }
      }
    } catch (e) {
      console.log(chalk.gray(`   Model discovery failed (non-fatal): ${e.message}`));
    }
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /**
   * Request a device code from OpenAI's auth server.
   * Only sends client_id — no scope or PKCE (PKCE is server-generated in this flow).
   *
   * @returns {Promise<{device_auth_id: string, user_code: string, interval: number, expires_in?: number}>}
   * @private
   */
  async _requestDeviceCode() {
    const resp = await fetch(DEVICE_USERCODE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: OPENAI_CLIENT_ID
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Device code request failed: ${resp.status} ${text}`);
    }

    const payload = await resp.json();
    if (!payload.device_auth_id || !payload.user_code) {
      throw new Error(
        payload.error_description || payload.error || 'Device code response missing device_auth_id or user_code.'
      );
    }

    // interval comes back as a string (e.g. "5") — parse to number
    return {
      device_auth_id: payload.device_auth_id,
      user_code: payload.user_code,
      interval: parseInt(payload.interval, 10) || 5,
      expires_in: payload.expires_in
    };
  }

  /**
   * Poll the device-token endpoint until the user completes authorization.
   * Returns the authorization_code and server-generated PKCE code_verifier.
   *
   * OpenAI's device-code flow is non-standard:
   * - Request body sends device_auth_id + user_code (NOT device_code + grant_type)
   * - HTTP 403/404 means "user hasn't approved yet" (NOT a JSON error field)
   * - On 2xx success, response contains authorization_code + code_verifier
   *
   * @param {string} deviceAuthId - device_auth_id from step 1
   * @param {string} userCode - user_code from step 1
   * @param {number} interval - Server-suggested polling interval (seconds)
   * @param {number} [expiresIn] - Device code lifetime (seconds)
   * @returns {Promise<{authorizationCode: string, codeVerifier: string}>}
   * @private
   */
  async _pollForAuthCode(deviceAuthId, userCode, interval, expiresIn) {
    let pollIntervalMs = (interval * 1000) + POLLING_SAFETY_MARGIN_MS;
    const timeoutMs = Math.min((expiresIn || 300) * 1000, MAX_POLL_DURATION_MS);
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

      const resp = await fetch(DEVICE_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          device_auth_id: deviceAuthId,
          user_code: userCode
        })
      });

      // 403 or 404 = user hasn't approved yet — keep polling
      if (resp.status === 403 || resp.status === 404) {
        continue;
      }

      // 429 = slow down
      if (resp.status === 429) {
        pollIntervalMs = Math.min(pollIntervalMs * 1.5, 15000);
        continue;
      }

      // Any other non-2xx is a real error
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Device token endpoint error: ${resp.status} ${text}`);
      }

      // 2xx — parse the success response
      let payload;
      try {
        payload = await resp.json();
      } catch (e) {
        throw new Error(`Device token endpoint returned invalid JSON: ${e.message}`);
      }

      if (!payload.authorization_code || !payload.code_verifier) {
        throw new Error(
          'Device token response missing authorization_code or code_verifier.'
        );
      }

      return {
        authorizationCode: payload.authorization_code,
        codeVerifier: payload.code_verifier
      };
    }

    throw new Error('OAuth timed out (5 minutes). Please try again.');
  }

  /**
   * Exchange an authorization code for id_token, access_token, and refresh_token.
   *
   * @param {string} authCode - Authorization code from the device-token poll
   * @param {string} verifier - PKCE code_verifier (server-provided from the poll response)
   * @returns {Promise<{idToken: string, accessToken: string, refreshToken: string, expiresIn: number}>}
   * @private
   */
  async _exchangeCodeForTokens(authCode, verifier) {
    const resp = await fetch(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: toFormUrlEncoded({
        grant_type: 'authorization_code',
        code: authCode,
        redirect_uri: REDIRECT_URI,
        client_id: OPENAI_CLIENT_ID,
        code_verifier: verifier
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Token exchange failed: ${resp.status} ${text}`);
    }

    const data = await resp.json();
    if (!data.id_token) {
      throw new Error('Token exchange returned no id_token.');
    }

    return {
      idToken: data.id_token,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in || 3600
    };
  }

  /**
   * Exchange an id_token for an OpenAI API key via the token-exchange grant.
   * This is the key step that converts OAuth credentials into something the
   * OpenAI SDK can use directly.
   *
   * @param {string} idToken - JWT id_token from the OAuth flow
   * @returns {Promise<string>} OpenAI API key
   * @private
   */
  async _exchangeForApiKey(idToken) {
    const resp = await fetch(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: toFormUrlEncoded({
        client_id: OPENAI_CLIENT_ID,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        requested_token: 'openai-api-key',
        subject_token: idToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token'
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`API key exchange failed: ${resp.status} ${text}`);
    }

    const data = await resp.json();
    if (!data.access_token) {
      throw new Error('API key exchange returned no access_token.');
    }

    return data.access_token;
  }

  /**
   * Refresh expired tokens and re-exchange for a fresh API key.
   *
   * 1. Use the refresh_token to get new id_token + refresh_token
   * 2. Exchange the new id_token for a fresh API key
   * 3. Persist everything
   *
   * @param {string} refreshToken
   * @returns {Promise<void>}
   * @private
   */
  async _refreshAndSave(refreshToken) {
    if (!refreshToken) {
      throw new Error('No refresh token available. Re-run auth login.');
    }

    // Step 1: Refresh tokens
    const resp = await fetch(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: OPENAI_CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: REFRESH_SCOPE
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Token refresh failed: ${resp.status} ${text}`);
    }

    const data = await resp.json();
    if (!data.id_token) {
      throw new Error('Token refresh returned no id_token.');
    }

    // Step 2: Exchange new id_token for a fresh API key
    const apiKey = await this._exchangeForApiKey(data.id_token);

    // Step 3: Persist
    await setProviderConfig('openai-codex', {
      apiKey,
      idToken: data.id_token,
      refreshToken: data.refresh_token || refreshToken,
      expiresAt: Date.now() + (data.expires_in || 3600) * 1000
    });
  }
}
