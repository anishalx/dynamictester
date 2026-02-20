import { createServer } from 'http';
import { URL } from 'url';
import { randomBytes, createHash, randomUUID } from 'crypto';
import { platform } from 'os';
import chalk from 'chalk';
import inquirer from 'inquirer';

/**
 * Antigravity OAuth client ID — shared by all opencode-compatible tools.
 * @type {string}
 */
const CLIENT_ID = '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com';

/**
 * Antigravity OAuth client secret.
 * Required for token exchange and refresh. Shared by opencode-compatible tools.
 * Loaded from GOOGLE_OAUTH_CLIENT_SECRET env var, with hardcoded fallback for
 * installed-app flows (Google considers these non-confidential).
 * @type {string}
 */
const CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET || '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';

/**
 * Local callback port for OAuth redirect.
 * @type {number}
 */
const CALLBACK_PORT = 51121;

/**
 * Redirect URI for the local callback server.
 * Must include the /oauth-callback path to match opencode's convention.
 * @type {string}
 */
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/oauth-callback`;

/**
 * Google token endpoint.
 * @type {string}
 */
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

/**
 * Google authorization endpoint.
 * @type {string}
 */
const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';

/**
 * Antigravity sandbox base URL for proxied API calls.
 * @type {string}
 */
const SANDBOX_BASE_URL = 'https://daily-cloudcode-pa.sandbox.googleapis.com';

/**
 * Default fallback project ID when discovery fails.
 * @type {string}
 */
const DEFAULT_PROJECT_ID = 'rising-fact-p41fc';

/**
 * Production Antigravity endpoint.
 * The opencode plugin tries production first, then falls back to sandbox/daily.
 * @type {string}
 */
const PRODUCTION_BASE_URL = 'https://cloudcode-pa.googleapis.com';

/**
 * Antigravity version pool — randomized to match legitimate client patterns.
 * @type {string[]}
 */
const ANTIGRAVITY_VERSIONS = ['1.15.8', '1.16.5', '1.16.0'];

/**
 * Scopes required for Antigravity access.
 * Matches the 5 scopes used by opencode.
 * @type {string[]}
 */
const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs'
];

/**
 * Delay (ms) before showing the manual paste fallback prompt.
 * Gives the local callback server time to receive the redirect automatically.
 * @type {number}
 */
const PASTE_FALLBACK_DELAY_MS = 15000;

/**
 * Generate a PKCE code verifier (43-128 character random string).
 * @returns {string}
 */
function generateCodeVerifier() {
  return randomBytes(32).toString('base64url');
}

/**
 * Derive the PKCE code challenge from a verifier using S256.
 * @param {string} verifier
 * @returns {string}
 */
function generateCodeChallenge(verifier) {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Simple sleep utility.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Build the full Google OAuth authorization URL with PKCE.
 * @param {string} codeVerifier - The PKCE code verifier
 * @param {string} state - CSRF state token
 * @returns {string} The authorization URL to open in the browser
 */
export function buildAuthorizationUrl(codeVerifier, state) {
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPES.join(' '),
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    access_type: 'offline',
    prompt: 'consent'
  });
  return `${AUTH_URL}?${params.toString()}`;
}

/**
 * Start a local HTTP server to receive the OAuth callback.
 * Resolves with the authorization code when Google redirects back.
 *
 * The server listens for GET requests on /oauth-callback and validates
 * the state parameter against the expected value to prevent CSRF.
 *
 * @param {string} expectedState - The state parameter to validate
 * @param {number} [timeoutMs=120000] - Maximum time to wait for callback
 * @returns {Promise<{code: string, closeServer: Function}>} The authorization code and a cleanup function
 */
export function waitForCallback(expectedState, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const server = createServer((req, res) => {
      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);

      if (url.pathname !== '/oauth-callback') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const error = url.searchParams.get('error');

      if (error) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Authentication failed</h2><p>You can close this window.</p></body></html>');
        if (!settled) {
          settled = true;
          server.close();
          reject(new Error(`OAuth error: ${error}`));
        }
        return;
      }

      if (state !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Invalid state</h2><p>CSRF validation failed.</p></body></html>');
        if (!settled) {
          settled = true;
          server.close();
          reject(new Error('OAuth state mismatch — possible CSRF attack'));
        }
        return;
      }

      if (!code) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Missing code</h2></body></html>');
        if (!settled) {
          settled = true;
          server.close();
          reject(new Error('No authorization code in callback'));
        }
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h2>Authentication successful!</h2><p>You can close this window and return to the terminal.</p></body></html>');
      if (!settled) {
        settled = true;
        const closeServer = () => { try { server.close(); } catch (e) { /* already closed */ } };
        resolve({ code, closeServer });
      }
    });

    server.listen(CALLBACK_PORT, () => {
      /* Server ready */
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        server.close();
        reject(new Error(`OAuth callback timed out after ${timeoutMs / 1000}s`));
      }
    }, timeoutMs);

    server.on('close', () => clearTimeout(timer));
    server.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Callback server error: ${err.message}`));
      }
    });
  });
}

/**
 * Prompt the user to paste the redirect URL manually.
 * Fallback for environments where the local callback server cannot receive
 * the redirect (WSL, SSH, Docker, remote machines).
 *
 * @param {string} expectedState - The expected state parameter
 * @returns {Promise<string>} The authorization code from the pasted URL
 */
async function promptManualPaste(expectedState) {
  console.log(chalk.yellow('\n  Local callback not received yet.'));
  console.log(chalk.gray('  If your browser redirected but the CLI did not pick it up,'));
  console.log(chalk.gray('  copy the full URL from your browser address bar and paste it below.\n'));

  const { redirectUrl } = await inquirer.prompt([
    {
      type: 'input',
      name: 'redirectUrl',
      message: 'Paste the redirect URL (or press Enter to keep waiting):',
      validate: (input) => {
        if (!input || !input.trim()) return true; // empty = keep waiting
        try {
          const url = new URL(input.trim());
          if (!url.searchParams.get('code')) {
            return 'URL must contain a "code" parameter';
          }
          return true;
        } catch {
          return 'Invalid URL — paste the full URL starting with http://';
        }
      }
    }
  ]);

  if (!redirectUrl || !redirectUrl.trim()) {
    // User pressed Enter — signal that they want to keep waiting
    return null;
  }

  const url = new URL(redirectUrl.trim());
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!state || state !== expectedState) {
    throw new Error('OAuth state mismatch or missing from pasted URL — possible CSRF attack');
  }

  return code;
}

/**
 * Wait for the OAuth callback with a manual paste fallback.
 *
 * Strategy: Start the local callback server immediately. After a delay,
 * show a prompt allowing the user to paste the redirect URL manually.
 * The first to resolve wins.
 *
 * @param {string} state - Expected state parameter
 * @param {string} codeVerifier - PKCE code verifier (unused here, passed for context)
 * @returns {Promise<string>} The authorization code
 */
async function waitForCallbackWithFallback(state) {
  // Start the local callback server
  let serverCloseRef = null;

  const callbackPromise = (async () => {
    const result = await waitForCallback(state);
    serverCloseRef = result.closeServer;
    return { source: 'server', code: result.code, closeServer: result.closeServer };
  })();

  // Capture server close ref from the promise's internal server via a side-channel:
  // waitForCallback will either resolve (setting serverCloseRef) or reject/timeout.
  // We also extract the closeServer when the callbackPromise settles.
  let raceSettled = false;

  // After a delay, offer the paste fallback
  const pastePromise = (async () => {
    await sleep(PASTE_FALLBACK_DELAY_MS);

    // Loop: keep asking until user provides a code or callback server resolves
    while (!raceSettled) {
      const code = await promptManualPaste(state);
      if (code) {
        return { source: 'paste', code, closeServer: null };
      }
      // User pressed Enter — wait a bit more and ask again
      console.log(chalk.gray('  Still waiting for callback...'));
      await sleep(5000);
    }
  })();

  // Race: whichever resolves first wins
  const result = await Promise.race([callbackPromise, pastePromise]);
  raceSettled = true;

  // Clean up the callback server if paste won
  if (result.source === 'paste') {
    // Try to close the server that's still listening
    if (serverCloseRef) {
      serverCloseRef();
    }
    // Suppress the unhandled rejection when the server times out
    callbackPromise.catch(() => { /* Server will time out and reject — safe to ignore */ });
  } else if (result.closeServer) {
    result.closeServer();
  }

  return result.code;
}

/**
 * Exchange an authorization code for access and refresh tokens.
 *
 * @param {string} code - Authorization code from the callback
 * @param {string} codeVerifier - PKCE code verifier used during authorization
 * @returns {Promise<object>} Token response { access_token, refresh_token, expires_in, token_type, scope }
 */
export async function exchangeCodeForTokens(code, codeVerifier) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    code_verifier: codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI
  });

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token exchange failed (${resp.status}): ${text}`);
  }

  return resp.json();
}

/**
 * Refresh an access token using a stored refresh token.
 *
 * @param {string} refreshToken - The stored refresh token
 * @returns {Promise<object>} Refreshed token response { access_token, expires_in, token_type, scope }
 */
export async function refreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: 'refresh_token'
  });

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token refresh failed (${resp.status}): ${text}`);
  }

  return resp.json();
}

/**
 * Discover the user's Cloud project ID via Antigravity endpoints.
 *
 * Strategy (matching the opencode plugin):
 * 1. Try `onboardUser` on production endpoint first
 * 2. Try `loadCodeAssist` on production endpoint
 * 3. Try both on sandbox endpoint
 * 4. Fall back to the hardcoded default project
 *
 * Uses randomized User-Agent matching the opencode plugin pattern.
 *
 * @param {string} accessToken
 * @returns {Promise<string>} The project ID (never null — always returns a value)
 */
export async function discoverProjectId(accessToken) {
  const discoveryPlatform = platform() === 'win32' ? 'WINDOWS' : (platform() === 'darwin' ? 'MACOS' : platform().toUpperCase());
  const headers = {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'User-Agent': 'google-api-nodejs-client/9.15.1',
    'X-Goog-Api-Client': 'google-cloud-sdk vscode_cloudshelleditor/0.1',
    'Client-Metadata': `{"ideType":"ANTIGRAVITY","platform":"${discoveryPlatform}","pluginType":"GEMINI"}`
  };

  // Metadata for onboardUser (matches opencode plugin)
  const onboardBody = JSON.stringify({
    metadata: {
      ideType: 'IDE_UNSPECIFIED',
      platform: discoveryPlatform,
      pluginType: 'GEMINI'
    }
  });

  // Try endpoints in order: production first (matches opencode plugin)
  const endpoints = [PRODUCTION_BASE_URL, SANDBOX_BASE_URL];

  for (const baseUrl of endpoints) {
    // Try onboardUser first
    try {
      const resp = await fetch(`${baseUrl}/v1internal:onboardUser`, {
        method: 'POST',
        headers,
        body: onboardBody
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.projectId) return data.projectId;
      }
    } catch (e) { /* Try next */ }

    // Try loadCodeAssist
    try {
      const resp = await fetch(`${baseUrl}/v1internal:loadCodeAssist`, {
        method: 'POST',
        headers,
        body: JSON.stringify({})
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.projectId) return data.projectId;
      }
    } catch (e) { /* Try next */ }
  }

  return DEFAULT_PROJECT_ID;
}

/**
 * Check whether an access token is still valid (not expired).
 *
 * @param {object} tokenData - Stored token data { accessToken, expiresAt }
 * @returns {boolean}
 */
export function isTokenValid(tokenData) {
  if (!tokenData?.accessToken || !tokenData?.expiresAt) return false;
  // Add 60-second buffer before expiry
  return Date.now() < (tokenData.expiresAt - 60000);
}

/**
 * Run the full Antigravity OAuth flow interactively.
 * Opens the browser for consent, receives the callback (with manual paste
 * fallback for WSL/SSH/Docker), exchanges tokens, discovers project ID.
 *
 * @returns {Promise<object>} Token data ready for storage:
 *   { accessToken, refreshToken, expiresAt, projectId }
 */
export async function runAntigravityOAuthFlow() {
  const state = randomBytes(16).toString('hex');
  const codeVerifier = generateCodeVerifier();
  const authUrl = buildAuthorizationUrl(codeVerifier, state);

  console.log(chalk.cyan('\nOpen this URL in your browser to authenticate:'));
  console.log(chalk.white.underline(authUrl));
  console.log(chalk.gray(`\nWaiting for callback on ${REDIRECT_URI} ...`));
  console.log(chalk.gray('(If the callback does not arrive automatically, you will be prompted to paste the URL.)'));

  // Try to auto-open the URL (using execFile to avoid shell injection)
  try {
    const { execFile } = await import('child_process');
    const cmd = process.platform === 'darwin' ? 'open'
      : process.platform === 'win32' ? 'start'
      : 'xdg-open';
    execFile(cmd, [authUrl], (err) => { /* best-effort — user can open manually */ });
  } catch (e) { /* User can open manually */ }

  // Wait for callback with paste fallback
  const code = await waitForCallbackWithFallback(state);
  console.log(chalk.green('Authorization code received.'));

  console.log(chalk.gray('Exchanging code for tokens...'));
  const tokens = await exchangeCodeForTokens(code, codeVerifier);

  const expiresInMs = (typeof tokens.expires_in === 'number' && !isNaN(tokens.expires_in))
    ? tokens.expires_in * 1000
    : 3600 * 1000; // Default to 1 hour if expires_in is missing/invalid
  const expiresAt = Date.now() + expiresInMs;

  // Discover project ID (best-effort — always returns a value)
  console.log(chalk.gray('Discovering project ID...'));
  const projectId = await discoverProjectId(tokens.access_token);
  console.log(chalk.gray(`Project: ${projectId}`));

  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt,
    projectId
  };
}

/**
 * Ensure the access token is fresh, refreshing if needed.
 *
 * @param {object} tokenData - Stored token data { accessToken, refreshToken, expiresAt }
 * @returns {Promise<object>} Updated token data (may have new accessToken + expiresAt)
 */
export async function ensureFreshToken(tokenData) {
  if (isTokenValid(tokenData)) return tokenData;

  if (!tokenData?.refreshToken) {
    throw new Error('Access token expired and no refresh token available. Re-authenticate with "node src/main.js auth login".');
  }

  console.log(chalk.gray('Refreshing access token...'));
  const refreshed = await refreshAccessToken(tokenData.refreshToken);
  const refreshExpiresMs = (typeof refreshed.expires_in === 'number' && !isNaN(refreshed.expires_in))
    ? refreshed.expires_in * 1000
    : 3600 * 1000;
  return {
    ...tokenData,
    accessToken: refreshed.access_token,
    expiresAt: Date.now() + refreshExpiresMs
  };
}

/**
 * Get the Antigravity sandbox base URL.
 * @returns {string}
 */
export function getSandboxBaseUrl() {
  return SANDBOX_BASE_URL;
}

/**
 * Get the OpenAI-compatible base URL for Antigravity.
 * Proxied through the sandbox, uses the v1beta chat completions endpoint.
 * @returns {string}
 */
export function getAntigravityBaseUrl() {
  return `${SANDBOX_BASE_URL}/v1beta`;
}
