import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * Qwen / DashScope region endpoints (OpenAI-compatible mode).
 * @type {Record<string, string>}
 */
const QWEN_ENDPOINTS = Object.freeze({
  international: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
  us: 'https://dashscope-us.aliyuncs.com/compatible-mode/v1',
  china: 'https://dashscope.aliyuncs.com/compatible-mode/v1'
});

/**
 * Qwen provider — Alibaba Cloud Model Studio (DashScope).
 * Fully OpenAI-compatible: uses the OpenAI SDK with a custom baseURL.
 */
export class QwenProvider extends BaseProvider {
  get name() {
    return 'qwen';
  }

  get displayName() {
    return 'Qwen (Alibaba Cloud)';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      { id: 'qwen-max', name: 'Qwen Max', description: 'Most capable, complex tasks' },
      { id: 'qwen-plus', name: 'Qwen Plus', description: 'Balanced performance/cost' },
      { id: 'qwen-coder-plus', name: 'Qwen Coder Plus', description: 'Code generation and tool calling' },
      { id: 'qwen-flash', name: 'Qwen Flash', description: 'Fast and cheap' },
      { id: 'qwen-turbo', name: 'Qwen Turbo', description: 'Ultra-fast responses' }
    ];
  }

  getDefaultModel() {
    return 'qwen-max';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- Qwen (Alibaba Cloud) Authentication ---'));
    console.log(chalk.gray('Get your API key from: https://bailian.console.alibabacloud.com/\n'));

    const { region } = await inquirer.prompt([
      {
        type: 'list',
        name: 'region',
        message: 'Select your region:',
        choices: [
          { name: 'International (Singapore)', value: 'international' },
          { name: 'US (Virginia)', value: 'us' },
          { name: 'China (Beijing)', value: 'china' }
        ],
        default: 'international'
      }
    ]);

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your DashScope API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          return true;
        }
      }
    ]);

    // Validate
    try {
      console.log(chalk.gray('Validating API key...'));
      const client = new OpenAI({
        apiKey: apiKey.trim(),
        baseURL: QWEN_ENDPOINTS[region]
      });
      // Qwen's /models endpoint may not be available; try a lightweight completion
      await client.chat.completions.create({
        model: 'qwen-turbo',
        messages: [{ role: 'user', content: 'hi' }],
        max_tokens: 1
      });
      console.log(chalk.green('API key validated successfully.'));
    } catch (e) {
      console.log(chalk.red(`Validation failed: ${e.message}`));
      const { proceed } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'proceed',
          message: 'Save the key anyway?',
          default: false
        }
      ]);
      if (!proceed) return false;
    }

    await setProviderConfig('qwen', { apiKey: apiKey.trim(), region });
    console.log(chalk.green('Qwen credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('qwen');
    if (!config?.apiKey) {
      if (process.env.DASHSCOPE_API_KEY) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey || process.env.DASHSCOPE_API_KEY;
    if (!apiKey) {
      throw new Error('Qwen API key not found. Run "node src/main.js auth login" or set DASHSCOPE_API_KEY.');
    }
    const region = providerConfig?.region || 'international';
    const baseURL = QWEN_ENDPOINTS[region] || QWEN_ENDPOINTS.international;
    return new OpenAI({ apiKey, baseURL });
  }
}
