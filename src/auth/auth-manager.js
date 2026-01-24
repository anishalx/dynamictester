/**
 * Authentication Manager
 * Stores and manages JWT tokens and cookies captured from browser sessions
 * Provides auth headers for injection into HTTP requests
 */

export class AuthManager {
  constructor() {
    this.jwtToken = null;
    this.bearerToken = null;
    this.cookies = {};
    this.customHeaders = {};
    this.authType = null; // 'jwt', 'bearer', 'cookie', 'custom'
  }

  /**
   * Store JWT token extracted from localStorage/sessionStorage
   * @param {string} token - The JWT token
   * @param {string} source - Where the token was found ('localStorage', 'sessionStorage', 'header')
   */
  setJwtToken(token, source = 'localStorage') {
    if (!token || typeof token !== 'string') {
      return { success: false, error: 'Invalid token provided' };
    }
    
    // Basic JWT validation (3 parts separated by dots)
    const parts = token.split('.');
    if (parts.length !== 3) {
      // Might be a Bearer token without JWT structure
      this.bearerToken = token;
      this.authType = 'bearer';
      return { success: true, type: 'bearer', source };
    }
    
    this.jwtToken = token;
    this.authType = 'jwt';
    return { success: true, type: 'jwt', source };
  }

  /**
   * Store cookies from browser context
   * @param {Array|Object} cookies - Cookies from Playwright context
   */
  setCookies(cookies) {
    if (Array.isArray(cookies)) {
      cookies.forEach(cookie => {
        this.cookies[cookie.name] = cookie.value;
      });
    } else if (typeof cookies === 'object') {
      Object.assign(this.cookies, cookies);
    }
    
    if (Object.keys(this.cookies).length > 0 && !this.authType) {
      this.authType = 'cookie';
    }
    
    return { success: true, cookieCount: Object.keys(this.cookies).length };
  }

  /**
   * Set custom auth header
   * @param {string} headerName - Header name (e.g., 'X-Auth-Token')
   * @param {string} headerValue - Header value
   */
  setCustomHeader(headerName, headerValue) {
    this.customHeaders[headerName] = headerValue;
    if (!this.authType) {
      this.authType = 'custom';
    }
    return { success: true, header: headerName };
  }

  /**
   * Get all authentication headers for HTTP requests
   * @returns {Object} Headers object to merge with request headers
   */
  getAuthHeaders() {
    const headers = {};

    // Add JWT/Bearer token
    if (this.jwtToken) {
      headers['Authorization'] = `Bearer ${this.jwtToken}`;
    } else if (this.bearerToken) {
      headers['Authorization'] = `Bearer ${this.bearerToken}`;
    }

    // Add cookies as Cookie header
    if (Object.keys(this.cookies).length > 0) {
      const cookieString = Object.entries(this.cookies)
        .map(([name, value]) => `${name}=${value}`)
        .join('; ');
      headers['Cookie'] = cookieString;
    }

    // Add custom headers
    Object.assign(headers, this.customHeaders);

    return headers;
  }

  /**
   * Check if authentication is available
   * @returns {boolean}
   */
  hasAuth() {
    return !!(
      this.jwtToken ||
      this.bearerToken ||
      Object.keys(this.cookies).length > 0 ||
      Object.keys(this.customHeaders).length > 0
    );
  }

  /**
   * Get authentication status summary
   * @returns {Object} Auth status
   */
  getStatus() {
    return {
      hasAuth: this.hasAuth(),
      authType: this.authType,
      hasJwt: !!this.jwtToken,
      hasBearer: !!this.bearerToken,
      cookieCount: Object.keys(this.cookies).length,
      customHeaderCount: Object.keys(this.customHeaders).length,
      cookies: Object.keys(this.cookies),
      customHeaders: Object.keys(this.customHeaders)
    };
  }

  /**
   * Clear all stored authentication
   */
  clear() {
    this.jwtToken = null;
    this.bearerToken = null;
    this.cookies = {};
    this.customHeaders = {};
    this.authType = null;
    return { success: true, message: 'Authentication cleared' };
  }

  /**
   * Common JWT storage key patterns to search for
   */
  static get JWT_STORAGE_KEYS() {
    return [
      'token',
      'jwt',
      'jwtToken',
      'jwt_token',
      'accessToken',
      'access_token',
      'authToken',
      'auth_token',
      'id_token',
      'idToken',
      'Authorization',
      'authorization',
      'bearer',
      'Bearer'
    ];
  }

  /**
   * Common cookie names that indicate auth
   */
  static get AUTH_COOKIE_NAMES() {
    return [
      'session',
      'sid',
      'connect.sid',
      'JSESSIONID',
      'PHPSESSID',
      'auth',
      'token',
      'jwt',
      '_session',
      'X-Auth-Token'
    ];
  }
}

/**
 * Create a singleton AuthManager instance
 * @returns {AuthManager}
 */
let authManagerInstance = null;

export function getAuthManager() {
  if (!authManagerInstance) {
    authManagerInstance = new AuthManager();
  }
  return authManagerInstance;
}

export function resetAuthManager() {
  if (authManagerInstance) {
    authManagerInstance.clear();
  }
  authManagerInstance = new AuthManager();
  return authManagerInstance;
}
