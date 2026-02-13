import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * OpenAI provider — GPT-4o, GPT-4-turbo, o1, o1-mini, o3-mini.
 * Uses the OpenAI SDK directly (default baseURL).
 */
export class OpenAIProvider extends BaseProvider {
  get name() {
    return 'openai';
  }

  get displayName() {
    return 'OpenAI';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      { id: 'gpt-4o', name: 'GPT-4o', description: 'Most capable, multimodal' },
      { id: 'gpt-4o-mini', name: 'GPT-4o Mini', description: 'Fast and cheap' },
      { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', description: '128K context' },
      { id: 'o1', name: 'o1', description: 'Reasoning model' },
      { id: 'o1-mini', name: 'o1 Mini', description: 'Compact reasoning' },
      { id: 'o3-mini', name: 'o3 Mini', description: 'Latest compact reasoning' }
    ];
  }

  getDefaultModel() {
    return 'gpt-4o';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- OpenAI Authentication ---'));
    console.log(chalk.gray('Get your API key from: https://platform.openai.com/api-keys\n'));

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your OpenAI API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          if (!input.startsWith('sk-')) {
            return 'OpenAI API keys typically start with "sk-"';
          }
          return true;
        }
      }
    ]);

    await setProviderConfig('openai', { apiKey: apiKey.trim() });
    console.log(chalk.green('OpenAI credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('openai');
    if (!config?.apiKey) {
      // Fall back to environment variable
      if (process.env.OPENAI_API_KEY) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.apiKey || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error('OpenAI API key not found. Run "node src/main.js auth login" or set OPENAI_API_KEY.');
    }
    return new OpenAI({ apiKey });
  }
}
