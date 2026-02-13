import { fs, path } from 'zx';
import { homedir } from 'os';

/**
 * Configuration file version — increment on schema changes.
 * @type {number}
 */
const CONFIG_VERSION = 1;

/**
 * Default config directory path.
 * @type {string}
 */
const CONFIG_DIR = path.join(homedir(), '.config', 'dynamictester');

/**
 * Default config file path.
 * @type {string}
 */
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

/**
 * Default config structure for a fresh installation.
 * @returns {object}
 */
function createDefaultConfig() {
  return {
    version: CONFIG_VERSION,
    defaultProvider: null,
    defaultModel: null,
    providers: {}
  };
}

/**
 * Load the config from disk. Creates a default if not found.
 * @returns {Promise<object>} The configuration object
 */
export async function loadConfig() {
  try {
    await fs.ensureDir(CONFIG_DIR);
    if (await fs.pathExists(CONFIG_PATH)) {
      const config = await fs.readJSON(CONFIG_PATH);
      // Migrate older versions if needed
      if (!config.version) {
        config.version = CONFIG_VERSION;
      }
      if (!config.providers) {
        config.providers = {};
      }
      return config;
    }
  } catch (e) { /* Config file corrupt or unreadable — start fresh */ }

  return createDefaultConfig();
}

/**
 * Save the config to disk.
 * @param {object} config - The full configuration object
 * @returns {Promise<void>}
 */
export async function saveConfig(config) {
  await fs.ensureDir(CONFIG_DIR);
  await fs.writeJSON(CONFIG_PATH, config, { spaces: 2 });
}

/**
 * Get the stored configuration for a single provider.
 * @param {string} name - Provider key (e.g. 'openai', 'deepseek')
 * @returns {Promise<object|null>}
 */
export async function getProviderConfig(name) {
  const config = await loadConfig();
  return config.providers[name] || null;
}

/**
 * Update or create the configuration for a single provider.
 * @param {string} name - Provider key
 * @param {object} providerConfig - Provider-specific configuration
 * @returns {Promise<void>}
 */
export async function setProviderConfig(name, providerConfig) {
  const config = await loadConfig();
  config.providers[name] = { ...providerConfig, configured: true };
  await saveConfig(config);
}

/**
 * Remove a provider's stored credentials / configuration.
 * @param {string} name - Provider key
 * @returns {Promise<void>}
 */
export async function clearProviderConfig(name) {
  const config = await loadConfig();
  delete config.providers[name];
  await saveConfig(config);
}

/**
 * Set the default provider and model.
 * @param {string} provider - Provider key
 * @param {string} model - Model identifier
 * @returns {Promise<void>}
 */
export async function setDefaults(provider, model) {
  const config = await loadConfig();
  config.defaultProvider = provider;
  config.defaultModel = model;
  await saveConfig(config);
}

/**
 * Get a list of all configured (authenticated) provider names.
 * @returns {Promise<string[]>}
 */
export async function getConfiguredProviders() {
  const config = await loadConfig();
  return Object.entries(config.providers)
    .filter(([, v]) => v.configured)
    .map(([k]) => k);
}

/**
 * Get the config directory path (useful for logging / troubleshooting).
 * @returns {string}
 */
export function getConfigDir() {
  return CONFIG_DIR;
}

/**
 * Get the config file path.
 * @returns {string}
 */
export function getConfigPath() {
  return CONFIG_PATH;
}
