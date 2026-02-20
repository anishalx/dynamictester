import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * NVIDIA NIM API base URL.
 * @type {string}
 */
const NVIDIA_BASE_URL = 'https://integrate.api.nvidia.com/v1';

/**
 * NVIDIA NIM provider — access Kimi K2, DeepSeek, Qwen, Llama, Nemotron, and
 * other models hosted on NVIDIA's inference microservices platform.
 * Fully OpenAI-compatible: uses the OpenAI SDK with a custom baseURL.
 *
 * API keys start with `nvapi-` and are obtained from https://build.nvidia.com.
 */
export class NvidiaProvider extends BaseProvider {
  get name() {
    return 'nvidia';
  }

  get displayName() {
    return 'NVIDIA NIM';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      // --- Kimi K2 family (Moonshot AI) ---
      { id: 'moonshotai/kimi-k2-instruct', name: 'Kimi K2 Instruct', description: '1T MoE, 32B active, tool calling, 128K context' },
      { id: 'moonshotai/kimi-k2-instruct-0905', name: 'Kimi K2 Instruct 0905', description: 'Updated Kimi K2 variant, tool calling' },
      { id: 'moonshotai/kimi-k2-thinking', name: 'Kimi K2 Thinking', description: 'Chain-of-thought reasoning mode' },
      // Note: kimi-k2.5 is a multimodal model on NVIDIA NIM that does NOT support
      // tool calling and hangs indefinitely. Use kimi-k2-instruct instead.
      // --- Other popular models ---
      { id: 'deepseek-ai/deepseek-v3.2', name: 'DeepSeek V3.2', description: 'General purpose, 128K context' },
      { id: 'qwen/qwen3-235b-a22b', name: 'Qwen3 235B', description: 'MoE 22B active, 128K context' },
      { id: 'meta/llama-3.3-70b-instruct', name: 'Llama 3.3 70B', description: 'Meta open-weight, 128K context' },
      { id: 'nvidia/llama-3.1-nemotron-ultra-253b-v1', name: 'Nemotron Ultra 253B', description: 'NVIDIA flagship reasoning model' },
      { id: 'mistralai/mistral-2-large-instruct', name: 'Mistral Large 2', description: '123B params, 128K context' }
    ];
  }

  getDefaultModel() {
    return 'moonshotai/kimi-k2-instruct';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- NVIDIA NIM Authentication ---'));
    console.log(chalk.gray('Get your API key from: https://build.nvidia.com\n'));
    console.log(chalk.gray('NVIDIA NIM hosts Kimi K2, DeepSeek, Qwen, Llama, Nemotron, and more.'));
    console.log(chalk.gray('Many models are available on the free tier.\n'));

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your NVIDIA API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          if (!input.startsWith('nvapi-')) {
            return 'NVIDIA API keys start with "nvapi-"';
          }
          return true;
        }
      }
    ]);

    await setProviderConfig('nvidia', { apiKey: apiKey.trim() });
    console.log(chalk.green('NVIDIA NIM credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('nvidia');
    if (!config?.apiKey) {
      if (process.env.NVIDIA_API_KEY) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey || process.env.NVIDIA_API_KEY;
    if (!apiKey) {
      throw new Error('NVIDIA API key not found. Run "node src/main.js auth login" or set NVIDIA_API_KEY.');
    }
    // Disable SDK built-in retries — our RateLimiter handles retry with proper backoff
    return new OpenAI({ apiKey, baseURL: NVIDIA_BASE_URL, timeout: 180000, maxRetries: 0 });
  }
}
