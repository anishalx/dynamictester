import chalk from 'chalk';
import { 
  isRetryableError, 
  isRateLimitError, 
  getRetryDelay, 
  formatDelay, 
  sleep, 
  classifyError 
} from './error-handling.js';

/**
 * Rate Limiter - Shannon-style API rate limit management
 * 
 * Features:
 * - Intelligent retry with exponential backoff
 * - Rate limit-specific longer delays (30s → 40s → 50s)
 * - Staggered parallel execution
 * - Fault-tolerant Promise.allSettled pattern
 */
export class RateLimiter {
  constructor(options = {}) {
    this.maxRetries = options.maxRetries || 3;
    this.staggerDelay = options.staggerDelay || 2000; // 2 seconds between parallel starts
    this.retryDelay = options.retryDelay || 5000; // 5 seconds between retries in parallel
    this.enableLogging = options.enableLogging !== false;
    this.errorLog = [];
    this.retriedSuccessCount = 0;
  }

  /**
   * Execute a function with retry logic
   * Uses exponential backoff with rate limit-specific delays
   * 
   * @param {Function} fn - Async function to execute
   * @param {string} description - Description for logging
   * @param {object} options - Additional options
   * @returns {Promise<any>} Result of the function
   */
  async executeWithRetry(fn, description = 'Operation', options = {}) {
    const maxRetries = options.maxRetries || this.maxRetries;
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const result = await fn();
        
        if (attempt > 1 && this.enableLogging) {
          console.log(chalk.green(`   ✅ ${description} succeeded on attempt ${attempt}`));
        }
        
        // Track successful retries
        if (attempt > 1) {
          this.retriedSuccessCount++;
        }
        
        return result;
      } catch (error) {
        lastError = error;
        
        // Log the error
        this._logError(error, description, attempt, maxRetries);

        // Check if error is retryable
        if (!isRetryableError(error)) {
          if (this.enableLogging) {
            console.log(chalk.red(`   ❌ ${description} failed with non-retryable error: ${error.message}`));
          }
          throw error;
        }

        // If we have retries left, wait and retry
        if (attempt < maxRetries) {
          const delay = getRetryDelay(error, attempt);
          
          if (this.enableLogging) {
            const errorType = classifyError(error);
            console.log(chalk.yellow(`   ⚠️ ${description} failed (attempt ${attempt}/${maxRetries})`));
            console.log(chalk.gray(`      Error: ${error.message} [${errorType}]`));
            console.log(chalk.gray(`      Retrying in ${formatDelay(delay)}...`));
          }

          await sleep(delay);
        } else {
          // All retries exhausted
          if (this.enableLogging) {
            console.log(chalk.red(`   ❌ ${description} failed after ${maxRetries} attempts`));
          }
        }
      }
    }

    throw lastError;
  }

  /**
   * Execute multiple functions in parallel with staggered starts
   * Prevents overwhelming the API with simultaneous requests
   * 
   * @param {Array<{fn: Function, name: string}>} tasks - Array of tasks with fn and name
   * @param {object} options - Execution options
   * @returns {Promise<Array>} Array of results with status
   */
  async executeParallelWithStagger(tasks, options = {}) {
    const staggerDelay = options.staggerDelay || this.staggerDelay;
    const retryDelay = options.retryDelay || this.retryDelay;
    const maxAttempts = options.maxAttempts || this.maxRetries;

    if (this.enableLogging) {
      console.log(chalk.cyan(`\n🚀 Starting ${tasks.length} parallel tasks with ${staggerDelay}ms stagger...`));
    }

    const results = await Promise.allSettled(
      tasks.map(async (task, index) => {
        // Stagger start times to prevent API overwhelm
        // Task 0: starts immediately
        // Task 1: starts after staggerDelay
        // Task 2: starts after staggerDelay * 2
        // etc.
        await sleep(index * staggerDelay);

        let lastError;
        let attempts = 0;

        while (attempts < maxAttempts) {
          attempts++;
          
          try {
            const result = await task.fn();
            return { 
              name: task.name, 
              success: true, 
              result, 
              attempts 
            };
          } catch (error) {
            lastError = error;
            
            this._logError(error, task.name, attempts, maxAttempts);

            if (!isRetryableError(error)) {
              // Non-retryable error, fail immediately
              const err = new Error(`${task.name} failed with non-retryable error: ${lastError.message}`);
              err.details = { name: task.name, error: lastError, attempts, retryable: false };
              throw err;
            }

            if (attempts < maxAttempts) {
              const delay = isRateLimitError(error) 
                ? getRetryDelay(error, attempts) 
                : retryDelay;
              
              if (this.enableLogging) {
                console.log(chalk.yellow(`   ⚠️ ${task.name} failed attempt ${attempts}/${maxAttempts}, retrying in ${formatDelay(delay)}...`));
              }
              
              await sleep(delay);
            }
          }
        }

        // All attempts exhausted
        const err = new Error(`${task.name} failed after ${attempts} attempts: ${lastError.message}`);
        err.details = { name: task.name, error: lastError, attempts, retryable: true };
        throw err;
      })
    );

    // Process results
    const summary = {
      total: tasks.length,
      succeeded: 0,
      failed: 0,
      results: []
    };

    for (const result of results) {
      if (result.status === 'fulfilled') {
        summary.succeeded++;
        summary.results.push(result.value);
      } else {
        summary.failed++;
        const details = result.reason.details || {};
        summary.results.push({
          name: details.name || 'unknown',
          success: false,
          error: details.error?.message || result.reason.message || 'Unknown error',
          attempts: details.attempts,
          retryable: details.retryable
        });
      }
    }

    if (this.enableLogging) {
      console.log(chalk.cyan(`\n📊 Parallel execution complete: ${summary.succeeded}/${summary.total} succeeded`));
      if (summary.failed > 0) {
        console.log(chalk.yellow(`   ${summary.failed} task(s) failed`));
      }
    }

    return summary;
  }

  /**
   * Execute with fallback - try primary function, fall back on failure
   * 
   * @param {Function} primaryFn - Primary function to execute
   * @param {Function} fallbackFn - Fallback function if primary fails
   * @param {string} description - Description for logging
   * @returns {Promise<{result: any, usedFallback: boolean}>}
   */
  async executeWithFallback(primaryFn, fallbackFn, description = 'Operation') {
    try {
      const result = await this.executeWithRetry(primaryFn, description);
      return { result, usedFallback: false };
    } catch (error) {
      if (this.enableLogging) {
        console.log(chalk.yellow(`   ⚡ ${description} using fallback after primary failed`));
      }
      
      try {
        const result = await fallbackFn();
        return { result, usedFallback: true };
      } catch (fallbackError) {
        if (this.enableLogging) {
          console.log(chalk.red(`   ❌ ${description} fallback also failed: ${fallbackError.message}`));
        }
        throw fallbackError;
      }
    }
  }

  /**
   * Log error for tracking
   * @private
   */
  _logError(error, description, attempt, maxAttempts) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      description,
      error: {
        message: error.message,
        status: error.status || error.statusCode,
        type: classifyError(error),
        retryable: isRetryableError(error)
      },
      attempt,
      maxAttempts,
      delay: attempt < maxAttempts ? getRetryDelay(error, attempt) : null
    };
    
    this.errorLog.push(logEntry);
  }

  /**
   * Get error log for debugging
   * @returns {Array} Array of error log entries
   */
  getErrorLog() {
    return this.errorLog;
  }

  /**
   * Clear error log
   */
  clearErrorLog() {
    this.errorLog = [];
  }

  /**
   * Get statistics about errors encountered
   * @returns {object} Error statistics
   */
  getErrorStats() {
    const stats = {
      total: this.errorLog.length,
      byType: {},
      rateLimitErrors: 0,
      retriedSuccessfully: this.retriedSuccessCount
    };

    for (const entry of this.errorLog) {
      const type = entry.error.type;
      stats.byType[type] = (stats.byType[type] || 0) + 1;
      
      if (entry.error.type === 'RATE_LIMIT') {
        stats.rateLimitErrors++;
      }
    }

    return stats;
  }
}

// Export singleton instance for convenience
export const rateLimiter = new RateLimiter();

// Export utility functions
export { 
  isRetryableError, 
  isRateLimitError, 
  getRetryDelay, 
  formatDelay, 
  sleep, 
  classifyError 
};
