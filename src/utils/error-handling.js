/**
 * Error handling utilities for rate limit management
 * Implements multi-layered approach to API rate limits
 *
 * Key design decisions:
 * - Status codes are the PRIMARY detection mechanism (reliable, unambiguous)
 * - Message matching uses word-boundary regex to avoid false positives
 *   (e.g. "5000ms" no longer matches "500", "4291 items" no longer matches "429")
 * - Retry-After header from OpenAI 429 responses is respected when available
 */

/**
 * Extract the Retry-After value from an error object (seconds).
 * OpenAI SDK attaches response headers on rate-limit errors.
 *
 * @param {Error} error - The error to inspect
 * @returns {number|null} Retry-After value in milliseconds, or null
 */
export function parseRetryAfter(error) {
  // OpenAI SDK v4+ attaches headers on the error object
  const raw = error.headers?.['retry-after']
    || error.headers?.['Retry-After']
    || error.response?.headers?.['retry-after']
    || error.response?.headers?.['Retry-After'];

  if (raw == null) return null;

  const seconds = parseFloat(raw);
  if (!isNaN(seconds) && seconds > 0) {
    return Math.min(seconds * 1000, 120000); // Cap at 2 minutes
  }
  return null;
}

/**
 * Check if an error should trigger a retry.
 * Uses status codes as the primary mechanism, with word-boundary regex fallback.
 *
 * @param {Error} error - The error to check
 * @returns {boolean} True if the error is retryable
 */
export function isRetryableError(error) {
  const message = (error.message || '').toLowerCase();
  const status = error.status || error.statusCode;

  // --- Status code checks (most reliable) ---

  // Rate limiting
  if (status === 429) return true;

  // Temporary server errors
  if ([500, 502, 503, 504].includes(status)) return true;

  // Request timeout
  if (status === 408) return true;

  // --- Message-based checks (word-boundary regex to avoid false positives) ---

  // Rate limiting phrases
  if (/rate.?limit/i.test(message) ||
      /\b429\b/.test(message) ||
      /too many requests/i.test(message)) {
    return true;
  }

  // Server error codes — \b ensures "5000" does NOT match "500"
  if (/\b500\b/.test(message) ||
      /\b502\b/.test(message) ||
      /\b503\b/.test(message) ||
      /\b504\b/.test(message) ||
      /internal server error/i.test(message) ||
      /service unavailable/i.test(message) ||
      /gateway timeout/i.test(message)) {
    return true;
  }

  // Network errors (these are specific enough to not need word boundaries)
  if (/econnreset/i.test(message) ||
      /econnrefused/i.test(message) ||
      /etimedout/i.test(message) ||
      /network error/i.test(message) ||
      /socket hang up/i.test(message)) {
    return true;
  }

  // OpenAI specific errors
  if (/\boverloaded\b/i.test(message) ||
      /\bcapacity\b/i.test(message)) {
    return true;
  }

  return false;
}

/**
 * Check if error is specifically a rate limit error
 * @param {Error} error - The error to check
 * @returns {boolean} True if this is a rate limit error
 */
export function isRateLimitError(error) {
  const message = (error.message || '').toLowerCase();
  const status = error.status || error.statusCode;

  // Status code first (most reliable)
  if (status === 429) return true;

  // Message fallback with word-boundary matching
  return /rate.?limit/i.test(message) ||
         /\b429\b/.test(message) ||
         /too many requests/i.test(message);
}

/**
 * Check if an error is a server error (5xx)
 * @param {Error} error - The error to check
 * @returns {boolean} True if this is a server error
 * @private
 */
function _isServerError(error) {
  const status = error.status || error.statusCode;
  const message = (error.message || '').toLowerCase();

  if ([500, 502, 503, 504].includes(status)) return true;

  return /\b50[0234]\b/.test(message) ||
         /\boverloaded\b/i.test(message) ||
         /internal server error/i.test(message) ||
         /service unavailable/i.test(message) ||
         /gateway timeout/i.test(message);
}

/**
 * Get retry delay based on error type and attempt number.
 * Rate limits get longer delays than other errors.
 * Respects Retry-After header from OpenAI 429 responses when available.
 *
 * @param {Error} error - The error that occurred
 * @param {number} attempt - Current attempt number (1-based)
 * @returns {number} Delay in milliseconds
 */
export function getRetryDelay(error, attempt) {
  // Rate limiting gets MUCH longer delays
  if (isRateLimitError(error)) {
    // Prefer the server-provided Retry-After value when available
    const retryAfterMs = parseRetryAfter(error);
    if (retryAfterMs !== null) {
      // Add small jitter (0-2s) to avoid thundering herd even with server hint
      const jitter = Math.random() * 2000;
      return Math.min(retryAfterMs + jitter, 120000);
    }

    // Fallback: calculated delays
    // Attempt 1: ~30 seconds
    // Attempt 2: ~40 seconds
    // Attempt 3: ~50 seconds
    // Maximum: 120 seconds (2 minutes)
    const base = 20000 + (attempt * 10000);
    const jitter = Math.random() * 5000; // 0-5s jitter to avoid thundering herd
    return Math.min(base + jitter, 120000);
  }

  // Server errors get medium delays (uses status + word-boundary checks)
  if (_isServerError(error)) {
    // ~10s, ~20s, ~30s, max 60s
    const base = 10000 * attempt;
    const jitter = Math.random() * 2000; // 0-2s jitter
    return Math.min(base + jitter, 60000);
  }

  // Exponential backoff with jitter for other retryable errors
  // 2s, 4s, 8s, 16s... max 30s
  const baseDelay = Math.pow(2, attempt) * 1000;
  const jitter = Math.random() * 1000; // 0-1s random jitter
  return Math.min(baseDelay + jitter, 30000);
}

/**
 * Format delay for human-readable logging
 * @param {number} delayMs - Delay in milliseconds
 * @returns {string} Formatted string like "30.0s"
 */
export function formatDelay(delayMs) {
  return (delayMs / 1000).toFixed(1) + 's';
}

/**
 * Sleep helper
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Classify error for logging purposes.
 * Uses status codes as the primary mechanism, with word-boundary regex fallback.
 *
 * @param {Error} error - The error to classify
 * @returns {string} Error classification
 */
export function classifyError(error) {
  if (isRateLimitError(error)) return 'RATE_LIMIT';

  const message = (error.message || '').toLowerCase();
  const status = error.status || error.statusCode;

  // Server errors — check both status and message
  if ([500, 502, 503, 504].includes(status) ||
      /\b50[0234]\b/.test(message) ||
      /internal server error/i.test(message) ||
      /service unavailable/i.test(message) ||
      /\boverloaded\b/i.test(message) ||
      /\bcapacity\b/i.test(message)) {
    return 'SERVER_ERROR';
  }

  // Timeout — check status 408 and message patterns
  if (status === 408 ||
      /\btimeout\b/i.test(message) ||
      /\betimedout\b/i.test(message)) {
    return 'TIMEOUT';
  }

  // Network errors
  if (/\beconnreset\b/i.test(message) ||
      /\beconnrefused\b/i.test(message) ||
      /network error/i.test(message) ||
      /socket hang up/i.test(message)) {
    return 'NETWORK_ERROR';
  }

  // Auth errors
  if (status === 401 || status === 403 ||
      /\bunauthorized\b/i.test(message) ||
      /\bforbidden\b/i.test(message)) {
    return 'AUTH_ERROR';
  }

  return 'UNKNOWN';
}
