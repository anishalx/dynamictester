import { Stagehand } from '@browserbasehq/stagehand';

/**
 * Default timeout for Stagehand act() operations (ms)
 */
const ACT_TIMEOUT_MS = 30000;

/**
 * Default max steps for agent() operations
 */
const DEFAULT_AGENT_MAX_STEPS = 10;

/**
 * Manages the Stagehand AI browser automation instance and exposes
 * 4 high-level tools for the LLM agent: act, extract, observe, agent.
 *
 * Stagehand owns the browser lifecycle. BrowserManager receives
 * the Playwright page/context from Stagehand instead of launching its own.
 *
 * @example
 * const mgr = new StagehandManager();
 * await mgr.init();
 * const page = mgr.getPage();       // Playwright Page
 * const context = mgr.getContext();  // Playwright BrowserContext-like
 * // ... pass page/context to BrowserManager
 * await mgr.close();
 */
export class StagehandManager {
  constructor() {
    /** @type {import('@browserbasehq/stagehand').Stagehand|null} */
    this.stagehand = null;
    this._initialized = false;
  }

  /**
   * Initialize Stagehand in LOCAL mode with Chromium.
   * Must be called before any other method.
   */
  async init() {
    this.stagehand = new Stagehand({
      env: 'LOCAL',
      model: 'openai/gpt-4o',
      localBrowserLaunchOptions: {
        headless: true,
        viewport: { width: 1280, height: 720 },
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      },
      selfHeal: true,
      verbose: 0,
      disablePino: true,
      disableAPI: true
    });
    await this.stagehand.init();
    this._initialized = true;
  }

  /**
   * Get the active Playwright-compatible Page from Stagehand's context.
   * @returns {import('playwright-core').Page|null}
   */
  getPage() {
    if (!this._initialized || !this.stagehand) return null;
    try {
      const pages = this.stagehand.context.pages();
      return pages[0] || null;
    } catch {
      return null;
    }
  }

  /**
   * Get the Stagehand context (V3Context).
   * Note: this is NOT a standard Playwright BrowserContext — it wraps CDP.
   * BrowserManager will use it for cookie extraction.
   * @returns {import('@browserbasehq/stagehand').V3Context|null}
   */
  getContext() {
    if (!this._initialized || !this.stagehand) return null;
    try {
      return this.stagehand.context;
    } catch {
      return null;
    }
  }

  /**
   * Get the raw Stagehand instance.
   * @returns {import('@browserbasehq/stagehand').Stagehand|null}
   */
  getStagehand() {
    return this.stagehand;
  }

  /**
   * Close the Stagehand browser and clean up.
   */
  async close() {
    if (this.stagehand) {
      try {
        await this.stagehand.close();
      } catch (e) { /* Best-effort cleanup */ }
      this.stagehand = null;
      this._initialized = false;
    }
  }

  /**
   * Returns the 4 Stagehand tool definitions with handlers,
   * matching the same shape as BrowserManager.getTools().
   *
   * @returns {Array<{name: string, description: string, parameters: object, handler: Function}>}
   */
  getTools() {
    return [
      {
        name: 'stagehand_act',
        description: 'Execute a browser action using AI natural language. Self-healing: handles dynamic UI, overlays, SPAs without exact selectors. Use when you do not have a CSS selector or when browser_click/browser_fill fails. Examples: "click the Login button", "fill the email field with test@test.com".',
        parameters: {
          type: 'object',
          properties: {
            instruction: {
              type: 'string',
              description: 'Natural language instruction for the action (e.g., "click the Submit button", "type admin into the username field")'
            }
          },
          required: ['instruction']
        },
        handler: this._handleAct.bind(this)
      },
      {
        name: 'stagehand_extract',
        description: 'Extract structured data from the current page using AI. Better than regex/DOM scraping for complex pages. Use to extract error messages, form structures, table data, API responses displayed on page.',
        parameters: {
          type: 'object',
          properties: {
            instruction: {
              type: 'string',
              description: 'What to extract (e.g., "all form field names and types", "the error message displayed", "all API endpoints listed on this page")'
            },
            selector: {
              type: 'string',
              description: 'Optional CSS selector to scope extraction to a specific element'
            }
          },
          required: ['instruction']
        },
        handler: this._handleExtract.bind(this)
      },
      {
        name: 'stagehand_observe',
        description: 'Discover available actions and interactive elements on the current page using AI. Returns a list of possible actions with their selectors. Use to map attack surface on unfamiliar pages, find injection points, or discover hidden interactive elements.',
        parameters: {
          type: 'object',
          properties: {
            instruction: {
              type: 'string',
              description: 'What to observe (e.g., "all form inputs and buttons", "all links to API endpoints", "interactive elements that accept user input")'
            }
          },
          required: ['instruction']
        },
        handler: this._handleObserve.bind(this)
      },
      {
        name: 'stagehand_agent',
        description: 'Execute a complex multi-step browser workflow autonomously using AI. Use for login sequences, multi-page navigation, CSRF token harvesting, or any task requiring multiple coordinated browser actions. The agent will plan and execute steps to accomplish the goal.',
        parameters: {
          type: 'object',
          properties: {
            instruction: {
              type: 'string',
              description: 'High-level goal to accomplish (e.g., "log in with email admin@juice.sh and password admin123", "navigate to the user profile page and extract all personal data fields")'
            },
            maxSteps: {
              type: 'number',
              description: 'Maximum number of steps the agent can take (default: 10, max: 20)'
            }
          },
          required: ['instruction']
        },
        handler: this._handleAgent.bind(this)
      }
    ];
  }

  /**
   * Handle stagehand_act tool call.
   * @param {object} params
   * @param {string} params.instruction
   * @returns {Promise<object>} Status object
   * @private
   */
  async _handleAct({ instruction }) {
    if (!this._initialized || !this.stagehand) {
      return { status: 'error', message: 'Stagehand not initialized' };
    }
    try {
      const result = await this.stagehand.act(instruction, {
        timeoutMs: ACT_TIMEOUT_MS
      });
      return {
        status: 'success',
        action: instruction,
        success: result.success,
        message: result.message || null,
        action_taken: result.action || null
      };
    } catch (e) {
      return {
        status: 'error',
        action: instruction,
        message: e.message
      };
    }
  }

  /**
   * Handle stagehand_extract tool call.
   * @param {object} params
   * @param {string} params.instruction
   * @param {string} [params.selector]
   * @returns {Promise<object>} Status object
   * @private
   */
  async _handleExtract({ instruction, selector }) {
    if (!this._initialized || !this.stagehand) {
      return { status: 'error', message: 'Stagehand not initialized' };
    }
    try {
      const options = {};
      if (selector) {
        options.selector = selector;
      }
      const result = await this.stagehand.extract(instruction, options);
      return {
        status: 'success',
        instruction,
        data: result
      };
    } catch (e) {
      return {
        status: 'error',
        instruction,
        message: e.message
      };
    }
  }

  /**
   * Handle stagehand_observe tool call.
   * @param {object} params
   * @param {string} params.instruction
   * @returns {Promise<object>} Status object
   * @private
   */
  async _handleObserve({ instruction }) {
    if (!this._initialized || !this.stagehand) {
      return { status: 'error', message: 'Stagehand not initialized' };
    }
    try {
      const actions = await this.stagehand.observe(instruction);
      return {
        status: 'success',
        instruction,
        actions: actions.slice(0, 25),
        totalFound: actions.length
      };
    } catch (e) {
      return {
        status: 'error',
        instruction,
        message: e.message
      };
    }
  }

  /**
   * Handle stagehand_agent tool call.
   * @param {object} params
   * @param {string} params.instruction
   * @param {number} [params.maxSteps=10]
   * @returns {Promise<object>} Status object
   * @private
   */
  async _handleAgent({ instruction, maxSteps }) {
    if (!this._initialized || !this.stagehand) {
      return { status: 'error', message: 'Stagehand not initialized' };
    }
    const steps = Math.min(maxSteps || DEFAULT_AGENT_MAX_STEPS, 20);
    try {
      const agent = this.stagehand.agent({ model: 'openai/gpt-4o' });
      const result = await agent.execute(instruction, {
        maxSteps: steps
      });
      return {
        status: 'success',
        instruction,
        completed: result.completed,
        message: result.message || null,
        steps: result.actions?.length || 0,
        actions: result.actions?.slice(0, 10).map(a => ({
          text: a.text || a.action || String(a),
          result: a.result || null
        })) || []
      };
    } catch (e) {
      return {
        status: 'error',
        instruction,
        message: e.message
      };
    }
  }
}
