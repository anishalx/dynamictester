import { Stagehand } from '@browserbasehq/stagehand';
import { chromium } from 'playwright';
import { z } from 'zod';

/**
 * Default timeout for Stagehand act() operations (ms)
 */
const ACT_TIMEOUT_MS = 30000;

/**
 * Default max steps for agent() operations
 */
const DEFAULT_AGENT_MAX_STEPS = 10;

// ---------------------------------------------------------------------------
// Predefined Zod schemas for structured extraction in security testing
// ---------------------------------------------------------------------------

/**
 * Schema for extracting form field information
 */
const FORM_FIELDS_SCHEMA = z.array(z.object({
  name: z.string().describe('Form field name attribute'),
  type: z.string().describe('Input type (text, password, email, hidden, etc.)'),
  id: z.string().optional().describe('Element ID'),
  selector: z.string().optional().describe('CSS selector to target this field'),
  placeholder: z.string().optional().describe('Placeholder text'),
  required: z.boolean().optional().describe('Whether the field is required'),
  value: z.string().optional().describe('Current value if visible')
})).describe('All form fields on the page');

/**
 * Schema for extracting error messages (useful for detecting injection success)
 */
const ERROR_MESSAGES_SCHEMA = z.array(z.object({
  text: z.string().describe('The error message text'),
  type: z.string().optional().describe('Error type (validation, server, database, auth, etc.)'),
  selector: z.string().optional().describe('CSS selector of the error element')
})).describe('Error messages displayed on the page');

/**
 * Schema for extracting links / navigation
 */
const LINKS_SCHEMA = z.array(z.object({
  text: z.string().describe('Link text'),
  href: z.string().describe('Link URL'),
  selector: z.string().optional().describe('CSS selector for the link')
})).describe('Links on the page');

/**
 * Schema for extracting API endpoints (from docs, swagger, network tables, etc.)
 */
const API_ENDPOINTS_SCHEMA = z.array(z.object({
  path: z.string().describe('API endpoint path (e.g. /api/users)'),
  method: z.string().optional().describe('HTTP method (GET, POST, etc.)'),
  description: z.string().optional().describe('Endpoint description')
})).describe('API endpoints listed on the page');

/**
 * Schema for extracting page text content
 */
const TEXT_SCHEMA = z.object({
  text: z.string().describe('The main text content of the page')
}).describe('Visible text on the page');

/**
 * Schema for extracting table data
 */
const TABLE_DATA_SCHEMA = z.object({
  headers: z.array(z.string()).describe('Table column headers'),
  rows: z.array(z.array(z.string())).describe('Table rows (each row is an array of cell values)')
}).describe('Table data on the page');

/**
 * Registry of predefined schemas keyed by name.
 * @type {Record<string, import('zod').ZodType>}
 */
const EXTRACT_SCHEMAS = Object.freeze({
  form_fields: FORM_FIELDS_SCHEMA,
  error_messages: ERROR_MESSAGES_SCHEMA,
  links: LINKS_SCHEMA,
  api_endpoints: API_ENDPOINTS_SCHEMA,
  text: TEXT_SCHEMA,
  table_data: TABLE_DATA_SCHEMA
});

/**
 * Manages the Stagehand AI browser automation instance and exposes
 * high-level tools for the LLM agent: act, extract, observe, agent.
 *
 * Architecture:
 * - Stagehand owns the browser lifecycle and AI methods (act/extract/observe/agent).
 * - A real Playwright Browser is connected via CDP (stagehand.connectURL()).
 * - BrowserManager receives the Playwright Page/BrowserContext for low-level tools.
 * - This avoids V3Context compatibility issues with standard Playwright methods.
 *
 * @example
 * const mgr = new StagehandManager();
 * await mgr.init();
 * const page = mgr.getPage();       // real Playwright Page (via CDP)
 * const context = mgr.getContext();  // real Playwright BrowserContext
 * const browser = mgr.getBrowser();  // real Playwright Browser
 * await mgr.close();
 */
export class StagehandManager {
  /**
   * @param {object} [options]
   * @param {string} [options.stagehandModel='openai/gpt-4o'] - Model for Stagehand AI operations (provider/model format).
   *   Stagehand uses its own OPENAI_API_KEY from env — this only affects which model is called.
   */
  constructor(options = {}) {
    /** @type {string} */
    this._stagehandModel = options.stagehandModel || 'openai/gpt-4o';
    /** @type {import('@browserbasehq/stagehand').Stagehand|null} */
    this.stagehand = null;
    /** @type {import('playwright').Browser|null} */
    this._cdpBrowser = null;
    /** @type {import('playwright').BrowserContext|null} */
    this._cdpContext = null;
    /** @type {import('playwright').Page|null} */
    this._cdpPage = null;
    this._initialized = false;
  }

  /**
   * Initialize Stagehand in LOCAL mode with Chromium, then connect Playwright
   * to the same browser via CDP for full Playwright API compatibility.
   *
   * Must be called before any other method.
   */
  async init() {
    this.stagehand = new Stagehand({
      env: 'LOCAL',
      model: this._stagehandModel,
      localBrowserLaunchOptions: {
        headless: true,
        viewport: { width: 1280, height: 720 },
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      },
      selfHeal: true,
      verbose: 0,
      disablePino: true
    });
    await this.stagehand.init();

    // Connect Playwright to Stagehand's browser via Chrome DevTools Protocol.
    // This gives us a real Playwright Browser/BrowserContext/Page that works
    // with all standard Playwright methods (cookies(), waitForSelector(), etc.)
    const cdpUrl = this.stagehand.connectURL();
    this._cdpBrowser = await chromium.connectOverCDP(cdpUrl);
    const contexts = this._cdpBrowser.contexts();
    this._cdpContext = contexts[0] || await this._cdpBrowser.newContext();
    const pages = this._cdpContext.pages();
    this._cdpPage = pages[0] || await this._cdpContext.newPage();

    this._initialized = true;
  }

  /**
   * Get the active Playwright Page connected via CDP.
   * This is a real Playwright Page — fully compatible with BrowserManager.
   * @returns {import('playwright').Page|null}
   */
  getPage() {
    if (!this._initialized) return null;
    return this._cdpPage || null;
  }

  /**
   * Get the Playwright BrowserContext connected via CDP.
   * @returns {import('playwright').BrowserContext|null}
   */
  getContext() {
    if (!this._initialized) return null;
    return this._cdpContext || null;
  }

  /**
   * Get the Playwright Browser connected via CDP.
   * @returns {import('playwright').Browser|null}
   */
  getBrowser() {
    if (!this._initialized) return null;
    return this._cdpBrowser || null;
  }

  /**
   * Get the raw Stagehand instance.
   * @returns {import('@browserbasehq/stagehand').Stagehand|null}
   */
  getStagehand() {
    return this.stagehand;
  }

  /**
   * Close the CDP Playwright browser and Stagehand, clean up.
   */
  async close() {
    // Disconnect the CDP Playwright browser first (it doesn't own the browser process)
    if (this._cdpBrowser) {
      try {
        await this._cdpBrowser.close();
      } catch (e) { /* Best-effort cleanup */ }
      this._cdpBrowser = null;
      this._cdpContext = null;
      this._cdpPage = null;
    }
    // Then close Stagehand (which owns the actual browser process)
    if (this.stagehand) {
      try {
        await this.stagehand.close();
      } catch (e) { /* Best-effort cleanup */ }
      this.stagehand = null;
    }
    this._initialized = false;
  }

  /**
   * Returns the Stagehand tool definitions with handlers,
   * matching the same shape as BrowserManager.getTools().
   *
   * Tools: stagehand_act, stagehand_extract, stagehand_observe, stagehand_agent
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
        description: 'Extract structured data from the current page using AI. Supports predefined schemas for common patterns (form_fields, error_messages, links, api_endpoints, text, table_data) or free-form extraction. Better than regex/DOM scraping for complex pages.',
        parameters: {
          type: 'object',
          properties: {
            instruction: {
              type: 'string',
              description: 'What to extract (e.g., "all form field names and types", "the error message displayed", "all API endpoints")'
            },
            schemaType: {
              type: 'string',
              enum: ['form_fields', 'error_messages', 'links', 'api_endpoints', 'text', 'table_data'],
              description: 'Predefined schema for structured extraction. Use form_fields for input discovery, error_messages for injection detection, links for navigation mapping, api_endpoints for API surface discovery, text for page content, table_data for tabular data. Omit for free-form extraction.'
            },
            selector: {
              type: 'string',
              description: 'Optional CSS/XPath selector to scope extraction to a specific element (reduces tokens and improves accuracy)'
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
        timeout: ACT_TIMEOUT_MS
      });
      return {
        status: 'success',
        action: instruction,
        success: result.success,
        message: result.message || null,
        action_taken: result.actionDescription || null
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
   * Supports predefined Zod schemas via schemaType or free-form extraction.
   *
   * V3 API signatures:
   * - stagehand.extract()                              → { pageText: string }
   * - stagehand.extract(instruction)                   → { extraction: string }
   * - stagehand.extract(instruction, schema, options?)  → z.infer<schema>
   *
   * @param {object} params
   * @param {string} params.instruction
   * @param {string} [params.schemaType]
   * @param {string} [params.selector]
   * @returns {Promise<object>} Status object
   * @private
   */
  async _handleExtract({ instruction, schemaType, selector }) {
    if (!this._initialized || !this.stagehand) {
      return { status: 'error', message: 'Stagehand not initialized' };
    }
    try {
      const options = {};
      if (selector) {
        options.selector = selector;
      }

      let result;
      const schema = schemaType ? EXTRACT_SCHEMAS[schemaType] : null;

      if (schema) {
        // Structured extraction with Zod schema — returns typed data
        result = await this.stagehand.extract(instruction, schema, options);
      } else {
        // Free-form extraction — returns { extraction: string }
        const hasOptions = Object.keys(options).length > 0;
        result = await this.stagehand.extract(instruction, hasOptions ? options : undefined);
      }

      return {
        status: 'success',
        instruction,
        schemaType: schemaType || 'free_form',
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
   * V3 agent API: stagehand.agent(config) → agent instance, then agent.execute(instruction).
   *
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
      const agent = this.stagehand.agent({
        model: this._stagehandModel
      });
      const result = await agent.execute({
        instruction,
        maxSteps: steps
      });

      const completed = result?.completed ?? false;
      const message = result?.message ?? null;
      const actionsList = result?.actions ?? [];

      return {
        status: 'success',
        instruction,
        completed,
        message,
        steps: actionsList.length,
        actions: actionsList.slice(0, 10).map(a => ({
          type: a?.type || null,
          action: a?.action || a?.instruction || a?.reasoning || String(a),
          pageUrl: a?.pageUrl || null
        }))
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
