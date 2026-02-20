import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * OpenRouter API base URL.
 * @type {string}
 */
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';

/**
 * OpenRouter provider — unified gateway to hundreds of AI models.
 * Fully OpenAI-compatible: uses the OpenAI SDK with a custom baseURL.
 *
 * Models use a `provider/model` naming convention (e.g. `openai/gpt-4o`).
 * Free-tier models are available with a `:free` suffix.
 * All listed models support tool/function calling.
 */
export class OpenRouterProvider extends BaseProvider {
  get name() {
    return 'openrouter';
  }

  get displayName() {
    return 'OpenRouter';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      // --- Popular paid models ---
      { id: 'openai/gpt-4o', name: 'GPT-4o', description: 'Most capable OpenAI model, multimodal' },
      { id: 'anthropic/claude-sonnet-4-20250514', name: 'Claude Sonnet 4', description: 'Anthropic reasoning model' },
      { id: 'google/gemini-2.5-flash-preview', name: 'Gemini 2.5 Flash', description: 'Google fast + capable' },
      { id: 'deepseek/deepseek-chat-v3-0324', name: 'DeepSeek V3', description: 'DeepSeek general purpose' },
      { id: 'meta-llama/llama-4-maverick', name: 'Llama 4 Maverick', description: 'Meta open-weight model' },
      // --- Free models (all support tool calling) ---
      { id: 'openrouter/free', name: 'Free Router (auto)', description: 'Auto-selects best free model' },
      { id: 'qwen/qwen3-coder:free', name: 'Qwen3 Coder 480B (free)', description: '262K context, MoE 35B active' },
      { id: 'openai/gpt-oss-120b:free', name: 'GPT-OSS 120B (free)', description: '131K context, open-source' },
      { id: 'meta-llama/llama-3.3-70b-instruct:free', name: 'Llama 3.3 70B (free)', description: '128K context, reliable tool use' },
      { id: 'mistralai/mistral-small-3.1-24b-instruct:free', name: 'Mistral Small 3.1 (free)', description: '128K context, strong tool fidelity' },
      { id: 'google/gemma-3-27b-it:free', name: 'Gemma 3 27B (free)', description: '131K context, Google open model' }
    ];
  }

  getDefaultModel() {
    return 'openai/gpt-4o';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- OpenRouter Authentication ---'));
    console.log(chalk.gray('Get your API key from: https://openrouter.ai/keys\n'));
    console.log(chalk.gray('OpenRouter provides access to 200+ models (OpenAI, Anthropic, Google, Meta, etc.)'));
    console.log(chalk.gray('Free-tier models available with :free suffix (e.g. meta-llama/llama-3.3-70b-instruct:free)\n'));

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your OpenRouter API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          if (!input.startsWith('sk-or-')) {
            return 'OpenRouter API keys typically start with "sk-or-"';
          }
          return true;
        }
      }
    ]);

    await setProviderConfig('openrouter', { apiKey: apiKey.trim() });
    console.log(chalk.green('OpenRouter credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('openrouter');
    if (!config?.apiKey) {
      if (process.env.OPENROUTER_API_KEY) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey || process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      throw new Error('OpenRouter API key not found. Run "node src/main.js auth login" or set OPENROUTER_API_KEY.');
    }
    // Disable SDK built-in retries — our RateLimiter handles retry with proper backoff
    return new OpenAI({
      apiKey,
      baseURL: OPENROUTER_BASE_URL,
      maxRetries: 0,
      defaultHeaders: {
        'HTTP-Referer': 'https://github.com/anishalx/dynamictester',
        'X-Title': 'Dynamic Security Tester'
      }
    });
  }
}
