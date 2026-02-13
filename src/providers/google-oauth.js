import { createServer } from 'http';
import { URL } from 'url';
import { randomBytes, createHash } from 'crypto';
import chalk from 'chalk';

/**
 * Antigravity OAuth client ID — shared by all opencode-compatible tools.
 * @type {string}
 */
const CLIENT_ID = '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com';

/**
 * Local callback port for OAuth redirect.
 * @type {number}
 */
const CALLBACK_PORT = 51121;

/**
 * Redirect URI for the local callback server.
 * @type {string}
 */
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}`;

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
 * Scopes required for Antigravity access.
 * @type {string[]}
 */
const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'openid'
];

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
 * @param {string} expectedState - The state parameter to validate
 * @param {number} [timeoutMs=120000] - Maximum time to wait for callback
 * @returns {Promise<string>} The authorization code
 */
export function waitForCallback(expectedState, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const server = createServer((req, res) => {
      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);

      if (url.pathname !== '/') {
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
        settled = true;
        server.close();
        reject(new Error(`OAuth error: ${error}`));
        return;
      }

      if (state !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Invalid state</h2><p>CSRF validation failed.</p></body></html>');
        settled = true;
        server.close();
        reject(new Error('OAuth state mismatch — possible CSRF attack'));
        return;
      }

      if (!code) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Missing code</h2></body></html>');
        settled = true;
        server.close();
        reject(new Error('No authorization code in callback'));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h2>Authentication successful!</h2><p>You can close this window and return to the terminal.</p></body></html>');
      settled = true;
      server.close();
      resolve(code);
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
 * Exchange an authorization code for access and refresh tokens.
 *
 * @param {string} code - Authorization code from the callback
 * @param {string} codeVerifier - PKCE code verifier used during authorization
 * @returns {Promise<object>} Token response { access_token, refresh_token, expires_in, token_type, scope }
 */
export async function exchangeCodeForTokens(code, codeVerifier) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
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
 * Discover the user's Cloud project ID by listing projects with the access token.
 * Falls back to null if the user has no projects or the API call fails.
 *
 * @param {string} accessToken
 * @returns {Promise<string|null>} The first project ID or null
 */
export async function discoverProjectId(accessToken) {
  try {
    const resp = await fetch('https://cloudresourcemanager.googleapis.com/v1/projects?pageSize=1', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    const project = data.projects?.[0];
    return project?.projectId || null;
  } catch (e) {
    return null;
  }
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
 * Opens the browser for consent, receives the callback, exchanges tokens.
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
  console.log(chalk.gray(`\nWaiting for callback on http://localhost:${CALLBACK_PORT} ...`));

  // Try to auto-open the URL
  try {
    const { exec } = await import('child_process');
    const cmd = process.platform === 'darwin' ? 'open'
      : process.platform === 'win32' ? 'start'
      : 'xdg-open';
    exec(`${cmd} "${authUrl}"`);
  } catch (e) { /* User can open manually */ }

  const code = await waitForCallback(state);
  console.log(chalk.green('Authorization code received.'));

  console.log(chalk.gray('Exchanging code for tokens...'));
  const tokens = await exchangeCodeForTokens(code, codeVerifier);

  const expiresAt = Date.now() + (tokens.expires_in * 1000);

  // Discover project ID (best-effort)
  console.log(chalk.gray('Discovering project ID...'));
  const projectId = await discoverProjectId(tokens.access_token);
  if (projectId) {
    console.log(chalk.gray(`Project: ${projectId}`));
  }

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
  return {
    ...tokenData,
    accessToken: refreshed.access_token,
    expiresAt: Date.now() + (refreshed.expires_in * 1000)
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
