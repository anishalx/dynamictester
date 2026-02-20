import { isRetryableError, classifyError } from './src/utils/error-handling.js';

const err1 = new Error('Connection error.');
console.log('err1 retryable:', isRetryableError(err1));
console.log('err1 class:', classifyError(err1));

const err2 = new Error('fetch failed');
console.log('err2 retryable:', isRetryableError(err2));
console.log('err2 class:', classifyError(err2));

