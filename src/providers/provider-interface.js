/**
 * @typedef {object} ModelInfo
 * @property {string} id - Model identifier sent to the API (e.g. 'gpt-4o')
 * @property {string} name - Human-readable display name
 * @property {string} [description] - Short description of capabilities
 */

/**
 * Abstract base class that every LLM provider must extend.
 *
 * A provider is responsible for:
 * 1. Declaring the models it supports (`getModels`)
 * 2. Running an interactive auth flow (`authenticate`)
 * 3. Checking whether stored credentials are valid (`validateAuth`)
 * 4. Creating an OpenAI-SDK-compatible client (`createClient`)
 *
 * All providers return an `OpenAI` SDK instance from `createClient()` because
 * DeepSeek, Qwen, GitHub Models, and Google Gemini all expose OpenAI-compatible
 * chat completion endpoints. The executor only needs to swap the client instance.
 */
export class BaseProvider {
  /**
   * @returns {string} Internal provider key (e.g. 'openai', 'deepseek')
   */
  get name() {
    throw new Error('BaseProvider.name must be overridden');
  }

  /**
   * @returns {string} Human-readable display name (e.g. 'OpenAI', 'DeepSeek')
   */
  get displayName() {
    throw new Error('BaseProvider.displayName must be overridden');
  }

  /**
   * Return the list of models this provider supports.
   * @returns {ModelInfo[]}
   */
  getModels() {
    throw new Error('BaseProvider.getModels() must be overridden');
  }

  /**
   * Return the default model identifier for this provider.
   * @returns {string}
   */
  getDefaultModel() {
    throw new Error('BaseProvider.getDefaultModel() must be overridden');
  }

  /**
   * Run the interactive authentication flow (prompt for API key, OAuth, etc.).
   * Should persist credentials via `config-manager.js`.
   * @returns {Promise<boolean>} true if auth succeeded
   */
  async authenticate() {
    throw new Error('BaseProvider.authenticate() must be overridden');
  }

  /**
   * Check whether valid credentials exist for this provider.
   * May optionally make a lightweight API call to verify them.
   * @returns {Promise<boolean>}
   */
  async validateAuth() {
    throw new Error('BaseProvider.validateAuth() must be overridden');
  }

  /**
   * Create an OpenAI-SDK-compatible client configured for this provider.
   * @param {object} providerConfig - The stored config from config-manager
   * @returns {import('openai').default} An OpenAI SDK instance
   */
  createClient(providerConfig) {
    throw new Error('BaseProvider.createClient() must be overridden');
  }
}
