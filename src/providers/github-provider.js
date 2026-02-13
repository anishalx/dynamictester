import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';

/**
 * GitHub Models inference endpoint (backed by Azure AI).
 * @type {string}
 */
const GITHUB_MODELS_BASE_URL = 'https://models.inference.ai.azure.com';

/**
 * GitHub Models provider — access GPT-4o, DeepSeek-R1, Llama, Mistral,
 * and many more models via your GitHub account.
 *
 * Authentication uses a GitHub Personal Access Token (PAT) with `models:read` scope.
 */
export class GitHubProvider extends BaseProvider {
  get name() {
    return 'github';
  }

  get displayName() {
    return 'GitHub Models (Copilot)';
  }

  /**
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModels() {
    return [
      { id: 'gpt-4o', name: 'GPT-4o (GitHub)', description: 'OpenAI GPT-4o via GitHub Models' },
      { id: 'gpt-4o-mini', name: 'GPT-4o Mini (GitHub)', description: 'Fast and cheap via GitHub' },
      { id: 'o3-mini', name: 'o3 Mini (GitHub)', description: 'Reasoning model via GitHub' },
      { id: 'DeepSeek-R1', name: 'DeepSeek R1 (GitHub)', description: 'DeepSeek reasoning via GitHub' },
      { id: 'Llama-4-Scout-17B-16E-Instruct', name: 'Llama 4 Scout (GitHub)', description: 'Meta Llama 4 via GitHub' },
      { id: 'Mistral-large-2411', name: 'Mistral Large (GitHub)', description: 'Mistral Large via GitHub' },
      { id: 'Codestral-2501', name: 'Codestral (GitHub)', description: 'Mistral code model via GitHub' }
    ];
  }

  getDefaultModel() {
    return 'gpt-4o';
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- GitHub Models Authentication ---'));
    console.log(chalk.gray('Create a Personal Access Token (PAT) at: https://github.com/settings/tokens'));
    console.log(chalk.gray('Required scope: models:read\n'));

    const { token } = await inquirer.prompt([
      {
        type: 'password',
        name: 'token',
        message: 'Enter your GitHub Personal Access Token:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'Token is required';
          }
          if (!input.startsWith('ghp_') && !input.startsWith('github_pat_') && !input.startsWith('gho_')) {
            return 'GitHub PATs typically start with "ghp_", "github_pat_", or "gho_"';
          }
          return true;
        }
      }
    ]);

    // Validate with a lightweight models list
    try {
      console.log(chalk.gray('Validating token...'));
      const client = new OpenAI({
        apiKey: token.trim(),
        baseURL: GITHUB_MODELS_BASE_URL
      });
      await client.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'hi' }],
        max_tokens: 1
      });
      console.log(chalk.green('Token validated successfully.'));
    } catch (e) {
      console.log(chalk.red(`Validation failed: ${e.message}`));
      const { proceed } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'proceed',
          message: 'Save the token anyway?',
          default: false
        }
      ]);
      if (!proceed) return false;
    }

    await setProviderConfig('github', { token: token.trim() });
    console.log(chalk.green('GitHub Models credentials saved.'));
    return true;
  }

  async validateAuth() {
    const config = await getProviderConfig('github');
    if (!config?.token) {
      if (process.env.GITHUB_TOKEN) return true;
      return false;
    }
    return true;
  }

  /**
   * @param {object} providerConfig
   * @returns {OpenAI}
   */
  createClient(providerConfig) {
    const apiKey = providerConfig?.token || process.env.GITHUB_TOKEN;
    if (!apiKey) {
      throw new Error('GitHub token not found. Run "node src/main.js auth login" or set GITHUB_TOKEN.');
    }
    return new OpenAI({ apiKey, baseURL: GITHUB_MODELS_BASE_URL });
  }
}
