import OpenAI from 'openai';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { BaseProvider } from './provider-interface.js';
import { getProviderConfig, setProviderConfig } from '../config/config-manager.js';
import {
  runAntigravityOAuthFlow,
  ensureFreshToken
} from './google-oauth.js';
import { AntigravityClient } from './antigravity-client.js';

/**
 * Google Gemini API base URL (standard API-key access via AI Studio).
 * @type {string}
 */
const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/openai/';

/**
 * Google provider — two authentication modes:
 *
 * 1. **Gemini API Key** — standard key from aistudio.google.com
 *    Uses the OpenAI-compatible endpoint at generativelanguage.googleapis.com.
 *
 * 2. **Antigravity OAuth** — full Google Cloud OAuth (PKCE) flow
 *    Proxied through Google's sandbox endpoint at
 *    daily-cloudcode-pa.sandbox.googleapis.com.
 *    Provides access to Claude Sonnet/Opus, Gemini 3, and other models
 *    available through Google's infrastructure.
 */
export class GoogleProvider extends BaseProvider {
  get name() {
    return 'google';
  }

  get displayName() {
    return 'Google (Gemini / Antigravity)';
  }

  /**
   * Standard Gemini models available via API key.
   * @returns {import('./provider-interface.js').ModelInfo[]}
   * @private
   */
  _getGeminiModels() {
    return [
      { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', description: 'Fast, multimodal, 1M context' },
      { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Best Gemini model, 1M context' },
      { id: 'gemini-2.0-flash', name: 'Gemini 2.0 Flash', description: 'Previous gen fast model' }
    ];
  }

  /**
   * Models available through Antigravity OAuth (Claude, Gemini 3, GPT-OSS).
   * These use dashes in version numbers (e.g. claude-sonnet-4-5, NOT claude-sonnet-4.5).
   * @returns {import('./provider-interface.js').ModelInfo[]}
   * @private
   */
  _getAntigravityModels() {
    return [
      { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5', description: 'Anthropic Sonnet via Google (fast, capable)' },
      { id: 'claude-sonnet-4-5-thinking', name: 'Claude Sonnet 4.5 Thinking', description: 'Sonnet 4.5 with extended thinking' },
      { id: 'claude-opus-4-5-thinking', name: 'Claude Opus 4.5 Thinking', description: 'Anthropic Opus via Google (strongest)' },
      { id: 'claude-opus-4-6-thinking', name: 'Claude Opus 4.6 Thinking', description: 'Latest Opus with extended thinking' },
      { id: 'gemini-3-pro-high', name: 'Gemini 3 Pro High', description: 'Gemini 3 Pro, high quality setting' },
      { id: 'gemini-3-pro-low', name: 'Gemini 3 Pro Low', description: 'Gemini 3 Pro, low latency setting' },
      { id: 'gpt-oss-120b-medium', name: 'GPT-OSS 120B Medium', description: 'Open-source GPT 120B via Google' }
    ];
  }

  /**
   * Return models based on the current auth mode.
   * Antigravity mode shows both Gemini and Antigravity-exclusive models.
   * API key mode shows only standard Gemini models.
   *
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  async getModels() {
    const config = await getProviderConfig('google');
    if (config?.authMode === 'antigravity') {
      return [...this._getAntigravityModels(), ...this._getGeminiModels()];
    }
    return this._getGeminiModels();
  }

  /**
   * Synchronous model list for contexts where async is not available.
   * Returns the full combined list (safe superset).
   * @returns {import('./provider-interface.js').ModelInfo[]}
   */
  getModelsSync() {
    return [...this._getAntigravityModels(), ...this._getGeminiModels()];
  }

  /**
   * Check if a model ID is valid for this provider.
   * @param {string} modelId
   * @returns {boolean}
   */
  isValidModel(modelId) {
    const allModels = this.getModelsSync();
    return allModels.some(m => m.id === modelId);
  }

  getDefaultModel() {
    return 'gemini-2.5-flash';
  }

  /**
   * Determine which models require Antigravity auth.
   * Claude models, Gemini 3, and GPT-OSS are only available through Antigravity.
   * @param {string} modelId
   * @returns {boolean}
   */
  _requiresAntigravity(modelId) {
    return modelId.startsWith('claude-') ||
           modelId.startsWith('gemini-3') ||
           modelId.startsWith('gpt-oss');
  }

  async authenticate() {
    console.log(chalk.cyan('\n--- Google Authentication ---'));
    console.log(chalk.gray('Choose how you want to authenticate:\n'));

    const { authMode } = await inquirer.prompt([
      {
        type: 'list',
        name: 'authMode',
        message: 'Authentication mode:',
        choices: [
          {
            name: 'Gemini API Key (simple — for Gemini models)',
            value: 'apikey'
          },
          {
            name: 'Antigravity OAuth (advanced — for Gemini + Claude models)',
            value: 'antigravity'
          }
        ]
      }
    ]);

    if (authMode === 'apikey') {
      return this._authenticateApiKey();
    }
    return this._authenticateAntigravity();
  }

  /**
   * API key authentication flow.
   * @returns {Promise<boolean>}
   * @private
   */
  async _authenticateApiKey() {
    console.log(chalk.gray('Get your API key from: https://aistudio.google.com/apikey\n'));

    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your Gemini API key:',
        mask: '*',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'API key is required';
          }
          return true;
        }
      }
    ]);

    await setProviderConfig('google', {
      authMode: 'apikey',
      apiKey: apiKey.trim()
    });
    console.log(chalk.green('Google Gemini API key saved.'));
    return true;
  }

  /**
   * Antigravity OAuth authentication flow.
   * @returns {Promise<boolean>}
   * @private
   */
  async _authenticateAntigravity() {
    console.log(chalk.gray('Starting Antigravity OAuth flow...\n'));

    try {
      const tokenData = await runAntigravityOAuthFlow();

      await setProviderConfig('google', {
        authMode: 'antigravity',
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresAt: tokenData.expiresAt,
        projectId: tokenData.projectId
      });

      console.log(chalk.green('Google Antigravity credentials saved.'));
      return true;
    } catch (e) {
      console.log(chalk.red(`Antigravity OAuth failed: ${e.message}`));
      return false;
    }
  }

  async validateAuth() {
    const config = await getProviderConfig('google');
    if (!config) {
      if (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY) return true;
      return false;
    }

    if (config.authMode === 'apikey') {
      return !!config.apiKey;
    }

    if (config.authMode === 'antigravity') {
      // Check if we have a refresh token (can always get a fresh access token)
      return !!config.refreshToken;
    }

    return false;
  }

  /**
   * Create an LLM client for the stored provider config.
   *
   * Returns an OpenAI SDK instance for API-key mode, or an AntigravityClient
   * adapter for Antigravity OAuth mode.
   *
   * @param {object} providerConfig
   * @returns {OpenAI|AntigravityClient}
   */
  createClient(providerConfig) {
    if (!providerConfig) {
      // Fall back to environment variables
      const envKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
      if (envKey) {
        return new OpenAI({ apiKey: envKey, baseURL: GEMINI_BASE_URL });
      }
      throw new Error('Google credentials not found. Run "node src/main.js auth login".');
    }

    if (providerConfig.authMode === 'apikey') {
      return new OpenAI({
        apiKey: providerConfig.apiKey,
        baseURL: GEMINI_BASE_URL
      });
    }

    if (providerConfig.authMode === 'antigravity') {
      return new AntigravityClient({
        accessToken: providerConfig.accessToken,
        projectId: providerConfig.projectId
      });
    }

    throw new Error('Unknown Google auth mode. Re-authenticate with "node src/main.js auth login".');
  }

  /**
   * Create an Antigravity client with a fresh access token.
   * Refreshes the token if expired and persists the updated token.
   *
   * @param {object} providerConfig - Stored provider config
   * @returns {Promise<OpenAI|AntigravityClient>} Client with fresh credentials
   */
  async createClientAsync(providerConfig) {
    if (!providerConfig || providerConfig.authMode !== 'antigravity') {
      return this.createClient(providerConfig);
    }

    // Ensure token is fresh
    const freshTokenData = await ensureFreshToken({
      accessToken: providerConfig.accessToken,
      refreshToken: providerConfig.refreshToken,
      expiresAt: providerConfig.expiresAt
    });

    // Persist refreshed token if it changed
    if (freshTokenData.accessToken !== providerConfig.accessToken) {
      await setProviderConfig('google', {
        ...providerConfig,
        accessToken: freshTokenData.accessToken,
        expiresAt: freshTokenData.expiresAt
      });
    }

    return new AntigravityClient({
      accessToken: freshTokenData.accessToken,
      projectId: providerConfig.projectId
    });
  }
}
