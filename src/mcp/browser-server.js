import { chromium } from 'playwright';

const MAX_CONTENT_LENGTH = 15000; // Max chars to return to avoid token limits

/**
 * Browser automation tools for the LLM
 */
export class BrowserManager {
  constructor() {
    this.browser = null;
    this.context = null;
    this.page = null;
  }

  async ensureBrowser() {
    if (!this.browser) {
      this.browser = await chromium.launch({ headless: true });
      this.context = await this.browser.newContext();
      this.page = await this.context.newPage();
    }
  }

  async navigate({ url }) {
    await this.ensureBrowser();
    await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    return { status: 'success', url, title: await this.page.title() };
  }

  async fill({ selector, value }) {
    if (!this.page) throw new Error('No page open');
    await this.page.waitForSelector(selector, { timeout: 10000 });
    await this.page.fill(selector, value);
    return { status: 'success', selector, value };
  }

  async click({ selector }) {
    if (!this.page) throw new Error('No page open');
    await this.page.waitForSelector(selector, { timeout: 10000 });
    await this.page.click(selector);
    return { status: 'success', selector };
  }

  /**
   * Get a summarized/truncated response instead of full HTML
   */
  async getResponse({ extract = 'summary' }) {
    if (!this.page) throw new Error('No page open');
    
    let result = {
      status: 'success',
      url: this.page.url(),
      title: await this.page.title()
    };

    if (extract === 'full') {
      // Return truncated full content
      const content = await this.page.content();
      result.content = content.slice(0, MAX_CONTENT_LENGTH);
      if (content.length > MAX_CONTENT_LENGTH) {
        result.truncated = true;
        result.originalLength = content.length;
      }
    } else {
      // Extract only relevant parts for security testing
      result.forms = await this.extractForms();
      result.inputs = await this.extractInputs();
      result.links = await this.extractLinks();
      result.scripts = await this.extractScriptSources();
      result.text = await this.extractVisibleText();
    }

    return result;
  }

  async extractForms() {
    try {
      return await this.page.evaluate(() => {
        const forms = Array.from(document.querySelectorAll('form'));
        return forms.slice(0, 10).map(form => ({
          action: form.action,
          method: form.method,
          id: form.id,
          inputs: Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 20).map(input => ({
            name: input.name,
            type: input.type,
            id: input.id,
            placeholder: input.placeholder
          }))
        }));
      });
    } catch { return []; }
  }

  async extractInputs() {
    try {
      return await this.page.evaluate(() => {
        const inputs = Array.from(document.querySelectorAll('input, textarea, select'));
        return inputs.slice(0, 30).map(input => ({
          name: input.name,
          type: input.type,
          id: input.id,
          placeholder: input.placeholder,
          selector: input.id ? `#${input.id}` : (input.name ? `[name="${input.name}"]` : null)
        })).filter(i => i.selector);
      });
    } catch { return []; }
  }

  async extractLinks() {
    try {
      return await this.page.evaluate(() => {
        const links = Array.from(document.querySelectorAll('a[href]'));
        return links.slice(0, 20).map(a => ({
          href: a.href,
          text: a.textContent?.trim().slice(0, 50)
        }));
      });
    } catch { return []; }
  }

  async extractScriptSources() {
    try {
      return await this.page.evaluate(() => {
        const scripts = Array.from(document.querySelectorAll('script[src]'));
        return scripts.slice(0, 10).map(s => s.src);
      });
    } catch { return []; }
  }

  async extractVisibleText() {
    try {
      const text = await this.page.evaluate(() => {
        return document.body?.innerText?.slice(0, 5000) || '';
      });
      return text;
    } catch { return ''; }
  }

  /**
   * Type text and press Enter (useful for search boxes)
   */
  async typeAndSubmit({ selector, value }) {
    if (!this.page) throw new Error('No page open');
    await this.page.waitForSelector(selector, { timeout: 10000 });
    await this.page.fill(selector, value);
    await this.page.press(selector, 'Enter');
    await this.page.waitForLoadState('domcontentloaded');
    return { status: 'success', selector, value };
  }

  /**
   * Wait for navigation after an action
   */
  async waitForNavigation({ timeout = 5000 } = {}) {
    if (!this.page) throw new Error('No page open');
    try {
      await this.page.waitForLoadState('domcontentloaded', { timeout });
      return { status: 'success', url: this.page.url() };
    } catch {
      return { status: 'timeout', url: this.page.url() };
    }
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
    }
    return { status: 'success' };
  }

  getTools() {
    return [
      {
        name: 'browser_navigate',
        description: 'Navigate to a URL',
        parameters: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'URL to navigate to' }
          },
          required: ['url']
        },
        handler: this.navigate.bind(this)
      },
      {
        name: 'browser_fill',
        description: 'Fill a form field with a value',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector for the input field' },
            value: { type: 'string', description: 'Value to fill' }
          },
          required: ['selector', 'value']
        },
        handler: this.fill.bind(this)
      },
      {
        name: 'browser_click',
        description: 'Click an element',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector for the element to click' }
          },
          required: ['selector']
        },
        handler: this.click.bind(this)
      },
      {
        name: 'browser_type_and_submit',
        description: 'Type text into an input and press Enter to submit',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector for the input field' },
            value: { type: 'string', description: 'Value to type' }
          },
          required: ['selector', 'value']
        },
        handler: this.typeAndSubmit.bind(this)
      },
      {
        name: 'browser_get_response',
        description: 'Get page information. Returns forms, inputs, links, and visible text by default. Use extract="full" for truncated HTML.',
        parameters: {
          type: 'object',
          properties: {
            extract: { 
              type: 'string', 
              enum: ['summary', 'full'],
              description: 'What to extract: "summary" (default, returns forms/inputs/links) or "full" (truncated HTML)'
            }
          }
        },
        handler: this.getResponse.bind(this)
      },
      {
        name: 'browser_close',
        description: 'Close the browser',
        parameters: {
          type: 'object',
          properties: {}
        },
        handler: this.close.bind(this)
      }
    ];
  }
}
