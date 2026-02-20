import { OpenAIProvider } from './openai-provider.js';
import { DeepSeekProvider } from './deepseek-provider.js';
import { QwenProvider } from './qwen-provider.js';
import { CopilotProvider } from './copilot-provider.js';
import { GoogleProvider } from './google-provider.js';
import { OpenRouterProvider } from './openrouter-provider.js';
import { NvidiaProvider } from './nvidia-provider.js';
import { getProviderConfig } from '../config/config-manager.js';

/**
 * @typedef {import('./provider-interface.js').BaseProvider} BaseProvider
 */

/**
 * Registry of all supported LLM providers.
 * Maps provider key to provider class.
 * @type {Readonly<Record<string, new () => BaseProvider>>}
 */
const PROVIDER_REGISTRY = Object.freeze({
  openai: OpenAIProvider,
  deepseek: DeepSeekProvider,
  qwen: QwenProvider,
  copilot: CopilotProvider,
  google: GoogleProvider,
  openrouter: OpenRouterProvider,
  nvidia: NvidiaProvider
});

/**
 * Internal cache of provider instances (singleton per provider key).
 * @type {Map<string, BaseProvider>}
 */
const _instances = new Map();

/**
 * Get a provider instance by key.
 * Returns a cached singleton so callers always receive the same instance.
 *
 * @param {string} name - Provider key (e.g. 'openai', 'deepseek')
 * @returns {BaseProvider}
 * @throws {Error} If the provider name is not registered
 */
export function getProvider(name) {
  if (_instances.has(name)) return _instances.get(name);

  const ProviderClass = PROVIDER_REGISTRY[name];
  if (!ProviderClass) {
    throw new Error(`Unknown provider: "${name}". Available: ${Object.keys(PROVIDER_REGISTRY).join(', ')}`);
  }

  const instance = new ProviderClass();
  _instances.set(name, instance);
  return instance;
}

/**
 * Get all registered provider instances.
 * @returns {BaseProvider[]}
 */
export function getAllProviders() {
  return Object.keys(PROVIDER_REGISTRY).map(getProvider);
}

/**
 * Get only the providers that the user has configured (authenticated).
 * Also includes providers that have matching environment variables
 * (e.g. OPENAI_API_KEY for OpenAI).
 *
 * @returns {Promise<BaseProvider[]>}
 */
export async function getConfiguredProviders() {
  const all = getAllProviders();
  const results = [];

  for (const provider of all) {
    const isValid = await provider.validateAuth();
    if (isValid) results.push(provider);
  }

  return results;
}

/**
 * Get the list of all registered provider keys.
 * @returns {string[]}
 */
export function getProviderNames() {
  return Object.keys(PROVIDER_REGISTRY);
}

/**
 * Check whether a provider key is registered.
 * @param {string} name
 * @returns {boolean}
 */
export function isValidProvider(name) {
  return name in PROVIDER_REGISTRY;
}

/**
 * Create an OpenAI SDK client for a specific provider.
 * Loads the stored config and delegates to the provider's `createClient()`.
 *
 * For Google Antigravity, uses `createClientAsync()` to handle token refresh.
 *
 * @param {string} providerName - Provider key
 * @returns {Promise<import('openai').default>} Configured OpenAI SDK instance
 */
export async function createClientForProvider(providerName) {
  const provider = getProvider(providerName);
  const config = await getProviderConfig(providerName);

  // Google Antigravity needs async token refresh
  if (providerName === 'google' && config?.authMode === 'antigravity') {
    if (typeof provider.createClientAsync !== 'function') {
      throw new Error(`Provider "${providerName}" does not support async client creation`);
    }
    return provider.createClientAsync(config);
  }

  return provider.createClient(config);
}
