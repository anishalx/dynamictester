import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * DeepSeek API base URL.
 * @type {string}
 */
const DEEPSEEK_BASE_URL = 'https://api.deepseek.com';

/**
 * DeepSeek provider — deepseek-chat (V3), deepseek-reasoner (R1).
 * Fully OpenAI-compatible: uses the OpenAI SDK with a custom baseURL.
 */
export class DeepSeekProvider extends BaseProvider {
  get name() {
    return 'deepseek';
  }

  get displayName() {
    return 'DeepSeek';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      { id: 'deepseek-chat', name: 'DeepSeek Chat (V3)', description: 'General purpose, 128K context' },
      { id: 'deepseek-reasoner', name: 'DeepSeek Reasoner (R1)', description: 'Chain-of-thought reasoning, 128K context' }
    ];
  }

  getDefaultModel() {
    return 'deepseek-chat';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- DeepSeek Authentication ---'));
    console.log(chalk.gray('Get your API key from: https://platform.deepseek.com/api_keys\n'));

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your DeepSeek API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          return true;
        }
      }
    ]);

    await setProviderConfig('deepseek', { apiKey: apiKey.trim() });
    console.log(chalk.green('DeepSeek credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('deepseek');
    if (!config?.apiKey) {
      if (process.env.DEEPSEEK_API_KEY) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey || process.env.DEEPSEEK_API_KEY;
    if (!apiKey) {
      throw new Error('DeepSeek API key not found. Run "node src/main.js auth login" or set DEEPSEEK_API_KEY.');
    }
    return new OpenAI({ apiKey, baseURL: DEEPSEEK_BASE_URL });
  }
}
