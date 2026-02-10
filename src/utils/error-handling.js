/**
 * Error handling utilities for rate limit management
 * Implements Shannon's multi-layered approach to API rate limits
 */

/**
 * Check if an error should trigger a retry
 * @param {Error} error - The error to check
 * @returns {boolean} True if the error is retryable
 */
export function isRetryableError(error) {
  const message = (error.message || '').toLowerCase();
  const status = error.status || error.statusCode;

  // Rate limiting - retryable with longer backoff
  if (message.includes('rate limit') || 
      message.includes('429') ||
      message.includes('too many requests') ||
      status === 429) {
    return true;
  }

  // Temporary server errors
  if (message.includes('500') || 
      message.includes('502') ||
      message.includes('503') ||
      message.includes('504') ||
      message.includes('internal server error') ||
      message.includes('service unavailable') ||
      message.includes('gateway timeout') ||
      [500, 502, 503, 504].includes(status)) {
    return true;
  }

  // Network errors
  if (message.includes('econnreset') ||
      message.includes('econnrefused') ||
      message.includes('etimedout') ||
      message.includes('network error') ||
      message.includes('socket hang up')) {
    return true;
  }

  // OpenAI specific errors
  if (message.includes('overloaded') ||
      message.includes('capacity')) {
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

  return message.includes('rate limit') ||
         message.includes('429') ||
         message.includes('too many requests') ||
         status === 429;
}

/**
 * Get retry delay based on error type and attempt number
 * Rate limits get longer delays than other errors
 * 
 * @param {Error} error - The error that occurred
 * @param {number} attempt - Current attempt number (1-based)
 * @returns {number} Delay in milliseconds
 */
export function getRetryDelay(error, attempt) {
  // Rate limiting gets MUCH longer delays
  if (isRateLimitError(error)) {
    // Attempt 1: ~30 seconds
    // Attempt 2: ~40 seconds
    // Attempt 3: ~50 seconds
    // Maximum: 120 seconds (2 minutes)
    const base = 20000 + (attempt * 10000);
    const jitter = Math.random() * 5000; // 0-5s jitter to avoid thundering herd
    return Math.min(base + jitter, 120000);
  }

  // Server errors get medium delays
  const message = (error.message || '').toLowerCase();
  if (message.includes('500') || message.includes('503') || message.includes('overloaded')) {
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
 * Classify error for logging purposes
 * @param {Error} error - The error to classify
 * @returns {string} Error classification
 */
export function classifyError(error) {
  if (isRateLimitError(error)) return 'RATE_LIMIT';
  
  const message = (error.message || '').toLowerCase();
  const status = error.status || error.statusCode;

  if ([500, 502, 503, 504].includes(status)) return 'SERVER_ERROR';
  if (message.includes('network') || message.includes('econn')) return 'NETWORK_ERROR';
  if (message.includes('timeout')) return 'TIMEOUT';
  if (message.includes('auth') || status === 401 || status === 403) return 'AUTH_ERROR';
  
  return 'UNKNOWN';
}
