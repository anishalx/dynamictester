import { chromium } from 'playwright';
import { AuthManager, getAuthManager } from '../auth/auth-manager.js';

const MAX_CONTENT_LENGTH = 15000; // Max chars to return to avoid token limits
const DEFAULT_TIMEOUT = 5000; // 5 seconds default timeout (reduced from 8s)

/**
 * Browser automation tools for the LLM
 * Enhanced with better error handling, element visibility checks, and auth propagation.
 *
 * Supports two modes:
 * 1. Self-managed: Launches its own Chromium browser (default, original behavior).
 * 2. Externally-managed: Receives page/context from Stagehand (or any external source).
 *    In this mode, ensureBrowser() is a no-op and close() does NOT close the browser.
 *
 * @param {object} [options]
 * @param {import('playwright-core').Page} [options.page] - External Playwright page
 * @param {object} [options.context] - External browser context (Playwright or V3Context)
 * @param {import('playwright-core').Browser} [options.browser] - External browser instance
 */
export class BrowserManager {
  constructor(options = {}) {
    this.browser = options.browser || null;
    this.context = options.context || null;
    this.page = options.page || null;
    this._externallyManaged = !!(options.page || options.context);
    this.authManager = getAuthManager();
    this._initPromise = null; // Guard against concurrent ensureBrowser() calls

    // Store the user-specified target URL so SSRF checks can whitelist it.
    // Without this, requests to localhost / private IPs are blocked even when
    // the user explicitly chose that host as the testing target.
    this._allowedTargetHost = null;
    if (options.targetUrl) {
      try {
        const parsed = new URL(options.targetUrl);
        this._allowedTargetHost = parsed.host; // includes port, e.g. "localhost:3000"
      } catch (e) { /* invalid targetUrl — ignore, SSRF checks remain strict */ }
    }
  }

  async ensureBrowser() {
    // If externally managed (e.g. Stagehand), skip browser launch
    if (this._externallyManaged && this.page) {
      return;
    }
    if (this.browser) return;

    // Prevent concurrent initialization — return the same promise if init is in progress
    if (this._initPromise) {
      return this._initPromise;
    }

    this._initPromise = (async () => {
      try {
        this.browser = await chromium.launch({ headless: true });
        this.context = await this.browser.newContext({
          viewport: { width: 1280, height: 720 },
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        });
        this.page = await this.context.newPage();
      } catch (err) {
        // Clean up partial state on failure so next call can retry
        if (this.browser) {
          try { await this.browser.close(); } catch (_) { /* best effort */ }
        }
        this.browser = null;
        this.context = null;
        this.page = null;
        throw err;
      } finally {
        this._initPromise = null;
      }
    })();
    return this._initPromise;
  }

  /**
   * Check if a selector points to a visible, enabled element
   */
  async isElementInteractable(selector) {
    try {
      const element = await this.page.$(selector);
      if (!element) return { interactable: false, reason: 'Element not found' };
      
      const isVisible = await element.isVisible();
      const isEnabled = await element.isEnabled();
      
      if (!isVisible) return { interactable: false, reason: 'Element is hidden' };
      if (!isEnabled) return { interactable: false, reason: 'Element is disabled' };
      
      return { interactable: true };
    } catch (e) {
      return { interactable: false, reason: e.message };
    }
  }

  /**
   * Find an alternative selector if the primary one doesn't work
   */
  async findAlternativeSelector(originalSelector, elementType = 'input') {
    try {
      // Try common alternative selectors
      const alternatives = await this.page.evaluate((type) => {
        const elements = document.querySelectorAll(type);
        const interactable = [];
        
        for (const el of elements) {
          // Check if visible and enabled
          const style = window.getComputedStyle(el);
          const isVisible = style.display !== 'none' && 
                           style.visibility !== 'hidden' && 
                           el.offsetParent !== null;
          const isEnabled = !el.disabled;
          
          if (isVisible && isEnabled) {
            let selector = null;
            if (el.id) selector = `#${el.id}`;
            else if (el.name) selector = `[name="${el.name}"]`;
            else if (el.placeholder) selector = `[placeholder="${el.placeholder}"]`;
            else if (el.type && el.className && el.className.trim()) selector = `${type}[type="${el.type}"].${el.className.trim().split(' ')[0]}`;
            
            if (selector) {
              interactable.push({
                selector,
                type: el.type || 'text',
                placeholder: el.placeholder,
                name: el.name,
                id: el.id
              });
            }
          }
        }
        return interactable;
      }, elementType);
      
      return alternatives;
    } catch {
      return [];
    }
  }

  async navigate({ url }) {
    await this.ensureBrowser();
    try {
      await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      // Wait a bit for SPA content to render
      await this.page.waitForTimeout(1000);
      return { status: 'success', url, title: await this.page.title() };
    } catch (e) {
      return { status: 'error', message: e.message, url };
    }
  }

  async fill({ selector, value }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    
    // First check if element is interactable
    const check = await this.isElementInteractable(selector);
    if (!check.interactable) {
      // Try to find alternatives
      const alternatives = await this.findAlternativeSelector(selector, 'input, textarea');
      if (alternatives.length > 0) {
        return {
          status: 'error',
          message: `Selector "${selector}" - ${check.reason}. Try these instead:`,
          alternatives: alternatives.slice(0, 5)
        };
      }
      return { 
        status: 'error', 
        message: `Selector "${selector}" - ${check.reason}. No alternative selectors found.`,
        suggestion: 'Use browser_get_response to find valid selectors'
      };
    }

    try {
      await this.page.waitForSelector(selector, { state: 'visible', timeout: DEFAULT_TIMEOUT });
      await this.page.fill(selector, value);
      return { status: 'success', selector, value };
    } catch (e) {
      return { status: 'error', message: e.message.split('\n')[0], selector };
    }
  }

  async click({ selector }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    
    // First check if element is interactable
    const check = await this.isElementInteractable(selector);
    if (!check.interactable) {
      // Try common button selectors
      const buttonAlternatives = await this.findAlternativeSelector(selector, 'button, [type="submit"], a');
      if (buttonAlternatives.length > 0) {
        return {
          status: 'error',
          message: `Selector "${selector}" - ${check.reason}. Try these instead:`,
          alternatives: buttonAlternatives.slice(0, 5)
        };
      }
      return { 
        status: 'error', 
        message: `Selector "${selector}" - ${check.reason}`,
        suggestion: 'Use browser_get_response to find clickable elements'
      };
    }

    try {
      await this.page.waitForSelector(selector, { state: 'visible', timeout: DEFAULT_TIMEOUT });
      await this.page.click(selector);
      // Wait for any navigation or updates
      await this.page.waitForTimeout(500);
      return { status: 'success', selector };
    } catch (e) {
      return { status: 'error', message: e.message.split('\n')[0], selector };
    }
  }

  /**
   * Get a summarized/truncated response instead of full HTML
   */
  async getResponse({ extract = 'summary' }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    
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
      result.inputs = await this.extractInteractableInputs();
      result.buttons = await this.extractButtons();
      result.links = await this.extractLinks();
      result.scripts = await this.extractScriptSources();
      result.text = await this.extractVisibleText();
      result.errors = await this.extractErrorMessages();
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
          inputs: Array.from(form.querySelectorAll('input:not([type="hidden"]), textarea, select'))
            .filter(input => {
              const style = window.getComputedStyle(input);
              return style.display !== 'none' && !input.disabled;
            })
            .slice(0, 20)
            .map(input => ({
              name: input.name,
              type: input.type,
              id: input.id,
              placeholder: input.placeholder,
              selector: input.id ? `#${input.id}` : (input.name ? `[name="${input.name}"]` : null)
            }))
        }));
      });
    } catch { return []; }
  }

  /**
   * Extract only visible, enabled inputs
   */
  async extractInteractableInputs() {
    try {
      return await this.page.evaluate(() => {
        const inputs = Array.from(document.querySelectorAll('input, textarea, select'));
        return inputs
          .filter(input => {
            const style = window.getComputedStyle(input);
            const isVisible = style.display !== 'none' && 
                             style.visibility !== 'hidden' && 
                             input.offsetParent !== null &&
                             input.type !== 'hidden';
            const isEnabled = !input.disabled;
            return isVisible && isEnabled;
          })
          .slice(0, 30)
          .map(input => ({
            name: input.name || null,
            type: input.type || 'text',
            id: input.id || null,
            placeholder: input.placeholder || null,
            selector: input.id ? `#${input.id}` : (input.name ? `[name="${input.name}"]` : null),
            value: input.value ? '(has value)' : '(empty)'
          }))
          .filter(i => i.selector);
      });
    } catch { return []; }
  }

  /**
   * Extract clickable buttons
   */
  async extractButtons() {
    try {
      return await this.page.evaluate(() => {
        const buttons = Array.from(document.querySelectorAll('button, [type="submit"], [role="button"]'));
        return buttons
          .filter(btn => {
            const style = window.getComputedStyle(btn);
            return style.display !== 'none' && !btn.disabled;
          })
          .slice(0, 15)
          .map(btn => ({
            text: btn.textContent?.trim().slice(0, 50) || '',
            type: btn.type || 'button',
            id: btn.id || null,
            selector: btn.id ? `#${btn.id}` : 
                      btn.type === 'submit' ? '[type="submit"]' :
                      btn.className ? `${btn.tagName.toLowerCase()}.${btn.className.split(' ')[0]}` : null
          }))
          .filter(b => b.selector);
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
   * Extract error messages (useful for detecting successful injections)
   */
  async extractErrorMessages() {
    try {
      return await this.page.evaluate(() => {
        // Look for common error message patterns
        const errorSelectors = [
          '.error', '.alert-error', '.alert-danger', '[role="alert"]',
          '.message-error', '.error-message', '.validation-error',
          '.mat-error', '.ng-invalid', '.has-error'
        ];
        
        const errors = [];
        for (const selector of errorSelectors) {
          const elements = document.querySelectorAll(selector);
          for (const el of elements) {
            const text = el.textContent?.trim();
            if (text && text.length > 0 && text.length < 500) {
              errors.push(text);
            }
          }
        }
        return errors.slice(0, 10);
      });
    } catch { return []; }
  }

  /**
   * Type text and press Enter (useful for search boxes)
   */
  async typeAndSubmit({ selector, value }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    
    const check = await this.isElementInteractable(selector);
    if (!check.interactable) {
      return { status: 'error', message: check.reason, selector };
    }

    try {
      await this.page.waitForSelector(selector, { state: 'visible', timeout: DEFAULT_TIMEOUT });
      await this.page.fill(selector, value);
      await this.page.press(selector, 'Enter');
      await this.page.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => {});
      return { status: 'success', selector, value };
    } catch (e) {
      return { status: 'error', message: e.message.split('\n')[0], selector };
    }
  }

  /**
   * Wait for navigation after an action
   */
  async waitForNavigation({ timeout = 5000 } = {}) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    try {
      await this.page.waitForLoadState('domcontentloaded', { timeout });
      return { status: 'success', url: this.page.url() };
    } catch {
      return { status: 'timeout', url: this.page.url() };
    }
  }

  /**
   * Take a screenshot for evidence
   */
  async screenshot({ path: screenshotPath, fullPage = false }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };

    // Validate path to prevent path traversal — screenshots must stay in cwd or below
    try {
      const { resolve, relative } = await import('path');
      const resolved = resolve(screenshotPath);
      const rel = relative(process.cwd(), resolved);
      if (rel.startsWith('..')) {
        return { status: 'error', message: `Path traversal blocked: "${screenshotPath}" resolves outside the working directory` };
      }
    } catch (e) {
      return { status: 'error', message: `Invalid screenshot path: ${e.message}` };
    }

    try {
      const buffer = await this.page.screenshot({ path: screenshotPath, fullPage });
      return { status: 'success', path: screenshotPath, size: buffer.length };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Force click an element using JavaScript (bypasses visibility checks)
   */
  async forceClick({ selector }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    try {
      const result = await this.page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return { success: false, error: 'Element not found' };
        el.click();
        return { success: true };
      }, selector);
      
      if (!result.success) {
        return { status: 'error', message: result.error, selector };
      }
      await this.page.waitForTimeout(500);
      return { status: 'success', selector, method: 'force_click' };
    } catch (e) {
      return { status: 'error', message: e.message, selector };
    }
  }

  /**
   * Scroll the page to reveal hidden elements
   */
  async scroll({ direction = 'down', amount = 500 }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    try {
      await this.page.evaluate((dir, amt) => {
        if (dir === 'down') window.scrollBy(0, amt);
        else if (dir === 'up') window.scrollBy(0, -amt);
        else if (dir === 'top') window.scrollTo(0, 0);
        else if (dir === 'bottom') window.scrollTo(0, document.body.scrollHeight);
      }, direction, amount);
      await this.page.waitForTimeout(300);
      return { status: 'success', direction, amount };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Wait for an element to appear (useful for SPAs)
   */
  async waitForElement({ selector, timeout = 5000, state = 'visible' }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    try {
      await this.page.waitForSelector(selector, { state, timeout });
      return { status: 'success', selector, found: true };
    } catch (e) {
      return { status: 'timeout', selector, found: false, message: `Element not found within ${timeout}ms` };
    }
  }

  /**
   * Capture authentication tokens from browser storage and cookies
   * Call this AFTER successful login to capture JWT/session tokens
   */
  async captureAuth() {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    
    try {
      // Extract tokens from localStorage and sessionStorage
      const storageTokens = await this.page.evaluate((keys) => {
        const tokens = {};
        
        // Check localStorage
        for (const key of keys) {
          const value = localStorage.getItem(key);
          if (value) {
            tokens[`localStorage:${key}`] = value;
          }
        }
        
        // Check sessionStorage
        for (const key of keys) {
          const value = sessionStorage.getItem(key);
          if (value) {
            tokens[`sessionStorage:${key}`] = value;
          }
        }
        
        // Also check all localStorage keys for JWT-like values
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          // Check if value looks like a JWT (3 dot-separated parts)
          if (value && value.split('.').length === 3 && value.length > 50) {
            tokens[`localStorage:${key}`] = value;
          }
        }
        
        return tokens;
      }, AuthManager.JWT_STORAGE_KEYS);

      // Extract cookies from browser context
      let cookies = [];
      try {
        if (typeof this.context.cookies === 'function') {
          cookies = await this.context.cookies();
        } else if (this.page) {
          // Fallback: parse document.cookie for Stagehand/V3Context
          const cookieStr = await this.page.evaluate(() => document.cookie).catch(() => '');
          if (cookieStr) {
            cookies = cookieStr.split(';').map(c => {
              const [name, ...rest] = c.trim().split('=');
              return { name: name.trim(), value: rest.join('=').trim() };
            }).filter(c => c.name);
          }
        }
      } catch (e) { /* Context not ready */ }
      
      // Store tokens in AuthManager
      let jwtFound = false;
      for (const [key, value] of Object.entries(storageTokens)) {
        const result = this.authManager.setJwtToken(value, key);
        if (result.success) {
          jwtFound = true;
          break; // Use first valid token found
        }
      }

      // Store cookies
      this.authManager.setCookies(cookies);

      const status = this.authManager.getStatus();
      
      return {
        status: 'success',
        message: jwtFound ? 'JWT token captured' : 'Session cookies captured',
        authStatus: status,
        tokensFound: Object.keys(storageTokens).length,
        cookiesFound: cookies.length
      };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  /**
   * Get current authentication status
   */
  getAuthStatus() {
    return { status: 'success', ...this.authManager.getStatus() };
  }

  /**
   * Clear stored authentication
   */
  clearAuth() {
    this.authManager.clear();
    return { status: 'success', message: 'Authentication cleared' };
  }

  /**
   * Make a direct HTTP request using Node.js native fetch (bypasses CORS).
   * Essential for API testing — works without navigating the browser first.
   * ENHANCED: Auto-injects stored auth tokens from AuthManager and browser cookies.
   *
   * @param {object} params
   * @param {string} params.url - Request URL
   * @param {string} [params.method='GET'] - HTTP method
   * @param {object} [params.headers={}] - Additional headers
   * @param {string|object|null} [params.body=null] - Request body
   * @param {string} [params.contentType='application/json'] - Content-Type header
   * @param {boolean} [params.useAuth=true] - Whether to inject stored auth
   * @returns {Promise<object>} Status object with response data
   */
  async httpRequest({ url, method = 'GET', headers = {}, body = null, contentType = 'application/json', useAuth = true }) {
    try {
      // Validate URL to prevent SSRF against internal/private networks
      const ssrfCheck = BrowserManager._validateUrlForSSRF(url, this._allowedTargetHost);
      if (!ssrfCheck.safe) {
        return { status: 'error', message: `SSRF protection: ${ssrfCheck.reason}`, url };
      }

      // Auto-inject auth headers if available and useAuth is true
      const authHeaders = useAuth ? this.authManager.getAuthHeaders() : {};

      // Extract cookies from browser context if it exists
      let cookieHeader = '';
      if (this.context) {
        try {
          // Playwright BrowserContext has .cookies(); Stagehand V3Context does not.
          if (typeof this.context.cookies === 'function') {
            const cookies = await this.context.cookies();
            if (cookies.length > 0) {
              cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');
            }
          } else if (this.page) {
            // Fallback: extract via CDP through the page
            const cdpCookies = await this.page.evaluate(() => document.cookie).catch(() => '');
            if (cdpCookies) {
              cookieHeader = cdpCookies;
            }
          }
        } catch (e) { /* Browser context not ready yet */ }
      }

      const mergedHeaders = {
        'Content-Type': contentType,
        ...authHeaders,
        ...headers
      };

      // Add cookies if we have them and no Cookie header was explicitly set
      if (cookieHeader && !mergedHeaders['Cookie'] && !mergedHeaders['cookie']) {
        mergedHeaders['Cookie'] = cookieHeader;
      }

      const fetchOptions = {
        method,
        headers: mergedHeaders,
        redirect: 'follow'
      };

      if (body && method !== 'GET') {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
      }

      // Use Node.js native fetch — no CORS restrictions, no page navigation required
      // Add abort controller with 30s timeout to prevent hanging requests
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      fetchOptions.signal = controller.signal;

      const startTime = Date.now();
      let response;
      try {
        response = await fetch(url, fetchOptions);
      } finally {
        clearTimeout(timeoutId);
      }
      const endTime = Date.now();
      const responseTimeMs = endTime - startTime;
      const text = await response.text();

      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) { /* Not JSON */ }

      return {
        status: 'success',
        url,
        method,
        httpStatus: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: text.slice(0, 5000),
        json,
        responseSuccess: response.ok,
        authInjected: useAuth && this.authManager.hasAuth(),
        responseTimeMs,
        responseTimeSec: (responseTimeMs / 1000).toFixed(3)
      };
    } catch (e) {
      return { status: 'error', message: e.message, url };
    }
  }

  /**
   * Execute JavaScript in the page context
   */
  async executeScript({ script }) {
    if (!this.page) return { status: 'error', message: 'No page open. Call browser_navigate first.' };
    try {
      const result = await this.page.evaluate((code) => {
        try {
          return { success: true, result: eval(code) };
        } catch (e) {
          return { success: false, error: e.message };
        }
      }, script);
      
      return {
        status: result.success ? 'success' : 'error',
        result: result.result,
        error: result.error
      };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async close() {
    if (this._externallyManaged) {
      // Do NOT close the browser — Stagehand owns the lifecycle
      this.page = null;
      this.context = null;
      this.browser = null;
      return { status: 'success', note: 'externally managed — browser not closed' };
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
    }
    return { status: 'success' };
  }

  /**
   * Validate a URL to prevent SSRF attacks against internal/private networks.
   * Blocks requests to private IPs, loopback, link-local, and metadata endpoints.
   * If allowedHost is provided (from the user-specified target URL), requests to
   * that exact host:port are permitted even if they resolve to a private address.
   *
   * @param {string} urlStr - URL to validate
   * @param {string|null} [allowedHost=null] - Whitelisted host (e.g. "localhost:3000")
   * @returns {{ safe: boolean, reason?: string }}
   * @private
   */
  static _validateUrlForSSRF(urlStr, allowedHost = null) {
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (e) {
      return { safe: false, reason: 'Invalid URL' };
    }

    // Only allow http and https protocols
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { safe: false, reason: `Protocol "${parsed.protocol}" is not allowed` };
    }

    // If this host matches the user-specified target, allow it through.
    // parsed.host includes the port (e.g. "localhost:3000"), so this is strict.
    if (allowedHost && parsed.host === allowedHost) {
      return { safe: true };
    }

    const hostname = parsed.hostname;

    // Block obvious private/internal hostnames
    const blockedPatterns = [
      /^localhost$/i,
      /^127\.\d+\.\d+\.\d+$/,            // IPv4 loopback
      /^10\.\d+\.\d+\.\d+$/,              // RFC1918 Class A
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/, // RFC1918 Class B
      /^192\.168\.\d+\.\d+$/,             // RFC1918 Class C
      /^169\.254\.\d+\.\d+$/,             // Link-local / cloud metadata
      /^0\.0\.0\.0$/,                      // Unspecified
      /^\[?::1\]?$/,                       // IPv6 loopback
      /^\[?fe80:/i,                        // IPv6 link-local
      /^\[?fc/i,                           // IPv6 unique local
      /^\[?fd/i,                           // IPv6 unique local
      /^metadata\.google\.internal$/i,     // GCP metadata
      /^metadata\.internal$/i              // Generic cloud metadata
    ];

    for (const pattern of blockedPatterns) {
      if (pattern.test(hostname)) {
        return { safe: false, reason: `Hostname "${hostname}" resolves to a private/internal address` };
      }
    }

    return { safe: true };
  }

  getTools() {
    return [
      {
        name: 'browser_navigate',
        description: 'Navigate to a URL. Waits for page to load.',
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
        description: 'Fill a form field. Returns alternatives if selector is hidden/disabled. Use browser_get_response first to find valid selectors.',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector for the input field (e.g., #email, [name="username"])' },
            value: { type: 'string', description: 'Value to fill' }
          },
          required: ['selector', 'value']
        },
        handler: this.fill.bind(this)
      },
      {
        name: 'browser_click',
        description: 'Click an element. Returns alternatives if selector is hidden/disabled.',
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
        description: 'Get page info with ONLY visible/interactable elements. Returns forms, inputs (visible only), buttons, links, errors. Use this FIRST before trying to interact.',
        parameters: {
          type: 'object',
          properties: {
            extract: { 
              type: 'string', 
              enum: ['summary', 'full'],
              description: 'What to extract: "summary" (default, returns visible forms/inputs/buttons) or "full" (truncated HTML)'
            }
          }
        },
        handler: this.getResponse.bind(this)
      },
      {
        name: 'browser_screenshot',
        description: 'Take a screenshot for evidence',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Path to save screenshot' },
            fullPage: { type: 'boolean', description: 'Capture full page (default: false)' }
          },
          required: ['path']
        },
        handler: this.screenshot.bind(this)
      },
      {
        name: 'browser_close',
        description: 'Close the browser',
        parameters: {
          type: 'object',
          properties: {}
        },
        handler: this.close.bind(this)
      },
      {
        name: 'browser_force_click',
        description: 'Force click an element using JavaScript. Use when browser_click fails due to overlays or hidden elements.',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector for the element to click' }
          },
          required: ['selector']
        },
        handler: this.forceClick.bind(this)
      },
      {
        name: 'browser_scroll',
        description: 'Scroll the page to reveal hidden elements',
        parameters: {
          type: 'object',
          properties: {
            direction: { type: 'string', enum: ['up', 'down', 'top', 'bottom'], description: 'Scroll direction' },
            amount: { type: 'number', description: 'Pixels to scroll (default: 500)' }
          }
        },
        handler: this.scroll.bind(this)
      },
      {
        name: 'browser_wait_for_element',
        description: 'Wait for an element to appear on page (useful for SPA content loading)',
        parameters: {
          type: 'object',
          properties: {
            selector: { type: 'string', description: 'CSS selector to wait for' },
            timeout: { type: 'number', description: 'Max time to wait in ms (default: 5000)' },
            state: { type: 'string', enum: ['visible', 'attached', 'hidden'], description: 'Element state to wait for' }
          },
          required: ['selector']
        },
        handler: this.waitForElement.bind(this)
      },
      {
        name: 'browser_http_request',
        description: 'Make a direct HTTP request to an API endpoint. CRITICAL for testing injection in REST APIs without browser UI. Use for /rest/*, /api/* endpoints.',
        parameters: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'Full URL to request' },
            method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], description: 'HTTP method' },
            headers: { type: 'object', description: 'Additional headers' },
            body: { type: 'string', description: 'Request body (for POST/PUT/PATCH)' },
            contentType: { type: 'string', description: 'Content-Type header (default: application/json)' }
          },
          required: ['url']
        },
        handler: this.httpRequest.bind(this)
      },
      {
        name: 'browser_execute_script',
        description: 'Execute JavaScript in page context. Use for DOM-based XSS detection or complex interactions.',
        parameters: {
          type: 'object',
          properties: {
            script: { type: 'string', description: 'JavaScript code to execute' }
          },
          required: ['script']
        },
        handler: this.executeScript.bind(this)
      },
      {
        name: 'browser_capture_auth',
        description: 'Capture authentication tokens (JWT/cookies) from browser storage AFTER successful login. Call this immediately after login to enable auth propagation for subsequent API requests.',
        parameters: {
          type: 'object',
          properties: {}
        },
        handler: this.captureAuth.bind(this)
      },
      {
        name: 'browser_get_auth_status',
        description: 'Get the current authentication status - shows what tokens/cookies are stored and will be injected into requests.',
        parameters: {
          type: 'object',
          properties: {}
        },
        handler: this.getAuthStatus.bind(this)
      },
      {
        name: 'browser_clear_auth',
        description: 'Clear all stored authentication tokens and cookies.',
        parameters: {
          type: 'object',
          properties: {}
        },
        handler: this.clearAuth.bind(this)
      }
    ];
  }
}
