/**
 * Analyzes HTTP responses to detect vulnerability indicators.
 * Distinguishes real vulnerabilities from false positives with
 * comprehensive pattern matching for SQL, NoSQL, SSRF, XXE, and more.
 */

export class ResponseAnalyzer {
  /**
   * Safely extract body text from a response object.
   * Handles null, undefined, string, and object bodies.
   * @param {object} response - HTTP response object
   * @returns {string} Body text (empty string if unavailable)
   * @private
   */
  static _getBodyText(response) {
    if (response?.body == null) return '';
    if (typeof response.body === 'string') return response.body;
    try {
      return JSON.stringify(response.body);
    } catch {
      return String(response.body);
    }
  }

  /**
   * Detect database-specific error messages in response.
   * Covers MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, CouchDB, and Cassandra.
   *
   * @param {object} response - HTTP response object
   * @returns {object} Detection result
   */
  static detectDatabaseErrors(response) {
    const errorPatterns = {
      mysql: [
        /you have an error in your sql syntax/i,
        /warning.*mysql/i,
        /valid mysql result/i,
        /mysqlclient\./i,
        /mysql_fetch/i,
        /mysql_query/i,
        /mysql_num_rows/i,
        /com\.mysql\.jdbc/i,
        /mariadb/i
      ],
      postgresql: [
        /postgresql.*error/i,
        /pg_query\(\)/i,
        /pg_exec\(\)/i,
        /syntax error at or near/i,
        /unterminated quoted string/i,
        /invalid input syntax/i,
        /current transaction is aborted/i,
        /PSQLException/i
      ],
      mssql: [
        /microsoft sql server/i,
        /odbc sql server driver/i,
        /unclosed quotation mark/i,
        /\[sql server\]/i,
        /\[sql server\].*line \d+/i,
        /incorrect syntax near/i,
        /SqlException/i,
        /nvarchar.*value/i
      ],
      oracle: [
        /ora-\d{5}/i,
        /oracle error/i,
        /oracle.*driver/i,
        /warning.*oci_/i,
        /quoted string not properly terminated/i
      ],
      sqlite: [
        /sqlite.*error/i,
        /sqlite3::/i,
        /unrecognized token/i,
        /SQLITE_ERROR/i,
        /near ".*": syntax error/i
      ],
      mongodb: [
        /MongoError/i,
        /MongoServerError/i,
        /mongo.*exception/i,
        /\$where.*not.*allowed/i,
        /bad query/i,
        /BSONObj.*valid/i,
        /can't canonicalize query/i,
        /FieldPath.*doesn't start with/i
      ],
      couchdb: [
        /couchdb/i,
        /bad_request.*invalid/i,
        /doc_validation/i
      ],
      cassandra: [
        /cassandra.*error/i,
        /SyntaxException/i,
        /InvalidQueryException/i
      ]
    };

    const bodyText = this._getBodyText(response);

    for (const [db, patterns] of Object.entries(errorPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(bodyText)) {
          return { 
            detected: true, 
            database: db, 
            pattern: pattern.source,
            confidence: 'HIGH'
          };
        }
      }
    }

    return { detected: false, database: null, confidence: 'NONE' };
  }

  /**
   * Compare responses for boolean-based blind injection
   * @param {object} trueResponse - Response with true condition
   * @param {object} falseResponse - Response with false condition
   * @returns {object} Comparison result
   */
  static compareBooleanResponses(trueResponse, falseResponse) {
    const trueBody = this._getBodyText(trueResponse);
    const falseBody = this._getBodyText(falseResponse);

    // Compare response lengths
    const lengthDiff = Math.abs(trueBody.length - falseBody.length);
    
    // Compare content
    const contentDiff = trueBody !== falseBody;
    
    // Compare status codes
    const statusDiff = trueResponse.status !== falseResponse.status;

    // Calculate confidence
    const confidence = this.calculateBooleanConfidence(lengthDiff, contentDiff, statusDiff);

    return {
      different: contentDiff || statusDiff || lengthDiff > 10,
      lengthDifference: lengthDiff,
      contentDifference: contentDiff,
      statusDifference: statusDiff,
      confidence,
      details: {
        trueLength: trueBody.length,
        falseLength: falseBody.length,
        trueStatus: trueResponse.status,
        falseStatus: falseResponse.status
      }
    };
  }

  /**
   * Measure timing differences for time-based blind injection
   * @param {number} normalTime - Normal response time (seconds)
   * @param {number} delayedTime - Delayed response time (seconds)
   * @param {number} expectedDelay - Expected delay in seconds
   * @returns {object} Timing analysis result
   */
  static measureTimingDifference(normalTime, delayedTime, expectedDelay) {
    const actualDelay = delayedTime - normalTime;
    const tolerance = expectedDelay * 0.2; // 20% tolerance
    const confirmed = actualDelay >= (expectedDelay - tolerance);
    
    let confidence = 'LOW';
    if (actualDelay >= expectedDelay * 0.9) {
      confidence = 'HIGH';
    } else if (actualDelay >= expectedDelay * 0.7) {
      confidence = 'MEDIUM';
    }

    return {
      confirmed,
      actualDelay: parseFloat(actualDelay.toFixed(2)),
      expectedDelay,
      tolerance: parseFloat(tolerance.toFixed(2)),
      confidence,
      details: {
        normalTime: parseFloat(normalTime.toFixed(2)),
        delayedTime: parseFloat(delayedTime.toFixed(2)),
        difference: parseFloat(actualDelay.toFixed(2))
      }
    };
  }

  /**
   * Detect input validation errors (false positive indicator).
   * A validation error means the app properly rejected malicious input —
   * this is NOT a vulnerability indicator.
   *
   * NOTE: HTTP 400 alone is NOT treated as validation. Many injection
   * payloads trigger 400 from the framework while the injection still
   * reaches the backend. We only flag 400 when the body also contains
   * explicit validation language.
   *
   * @param {object} response - HTTP response
   * @returns {boolean} True if validation error detected
   */
  static isValidationError(response) {
    const bodyText = this._getBodyText(response);

    const validationPatterns = [
      /invalid input/i,
      /validation failed/i,
      /malformed request/i,
      /invalid parameter/i,
      /parameter.*invalid/i,
      /input.*rejected/i,
      /field.*required/i,
      /must be a valid/i,
      /does not match.*pattern/i,
      /failed.*constraint/i,
      /expected.*but got/i,
      /not a valid.*format/i
    ];

    const hasValidationBody = validationPatterns.some(pattern => pattern.test(bodyText));

    // HTTP 400 is only a validation indicator when the body confirms it.
    // A bare 400 without validation language could still be an injection vector.
    if (response.status === 400 && hasValidationBody) {
      return true;
    }

    // HTTP 422 (Unprocessable Entity) is a strong validation signal
    if (response.status === 422) {
      return true;
    }

    // Body-only patterns (any status code)
    return hasValidationBody;
  }

  /**
   * Detect WAF/firewall blocking (false positive indicator).
   * Extended with AWS WAF, Azure Front Door, F5 BIG-IP, Sucuri, and more.
   *
   * @param {object} response - HTTP response
   * @returns {object} WAF detection result
   */
  static detectWAFBlocking(response) {
    const bodyText = this._getBodyText(response);

    const headerText = response.headers
      ? (typeof response.headers === 'string'
        ? response.headers
        : Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join(' '))
      : '';

    const combined = bodyText + ' ' + headerText;

    const wafPatterns = {
      cloudflare: [/cloudflare/i, /cf-ray/i, /cf-chl-bypass/i],
      akamai: [/akamai/i, /akamai.*ghost/i, /x-akamai-transformed/i],
      imperva: [/imperva/i, /incapsula/i, /visid_incap/i],
      modsecurity: [/mod_security/i, /modsec/i, /NOYB/i],
      awswaf: [/aws.*waf/i, /awselb/i, /x-amzn-requestid/i, /request blocked.*aws/i],
      azureFrontDoor: [/azure.*front.*door/i, /afd-/i],
      f5BigIP: [/big-?ip/i, /f5.*network/i, /TS[0-9a-f]{8}/i],
      sucuri: [/sucuri/i, /x-sucuri/i],
      barracuda: [/barracuda/i, /barra_counter_session/i],
      fortinet: [/fortiweb/i, /fortigate/i],
      generic: [
        /blocked.*security/i,
        /request.*blocked/i,
        /request.*has been.*blocked/i,
        /security.*violation/i,
        /your request has been blocked/i,
        /suspicious.*activity/i,
        /web application firewall/i,
        /blocked by.*(?:security|firewall|protection)/i
      ]
    };

    for (const [waf, patterns] of Object.entries(wafPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(combined)) {
          return {
            detected: true,
            waf,
            confidence: 'HIGH'
          };
        }
      }
    }

    // Check status codes
    if (response.status === 403 || response.status === 406) {
      return {
        detected: true,
        waf: 'unknown',
        confidence: 'MEDIUM',
        reason: `HTTP ${response.status} suggests WAF blocking`
      };
    }

    return { detected: false, waf: null };
  }

  /**
   * Detect SSRF indicators in a response.
   * Checks for internal IP/metadata responses that indicate successful SSRF.
   *
   * @param {object} response - HTTP response
   * @returns {object} SSRF detection result
   */
  static detectSSRFIndicators(response) {
    const bodyText = this._getBodyText(response);

    const ssrfPatterns = {
      awsMetadata: [
        /ami-id/i,
        /instance-id.*i-[0-9a-f]/i,
        /security-credentials/i,
        /iam\/info/i,
        /meta-data\//i
      ],
      gcpMetadata: [
        /computeMetadata/i,
        /v1\/project/i,
        /service-accounts.*default/i
      ],
      azureMetadata: [
        /Metadata.*true/i,
        /Microsoft\.Compute/i,
        /azureenvironment/i
      ],
      internalServices: [
        /root:.*:0:0/i      // /etc/passwd content — strong SSRF indicator
      ],
      internalNetwork: [
        /localhost/i,
        /127\.0\.0\.1/i,
        /0\.0\.0\.0/i,
        /10\.\d+\.\d+\.\d+/,
        /172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+/,
        /192\.168\.\d+\.\d+/
      ]
    };

    for (const [source, patterns] of Object.entries(ssrfPatterns)) {
      // Bare internal IP/hostname matches get LOW confidence — they appear
      // in normal API responses (e.g. {"server": "localhost:3000"}).
      // Cloud metadata and /etc/passwd patterns get HIGH confidence.
      const confidence = source === 'internalNetwork' ? 'LOW' : 'HIGH';
      for (const pattern of patterns) {
        if (pattern.test(bodyText)) {
          return {
            detected: true,
            source,
            pattern: pattern.source,
            confidence
          };
        }
      }
    }

    return { detected: false, source: null, confidence: 'NONE' };
  }

  /**
   * Detect XXE indicators in a response.
   * Checks for file content disclosure or out-of-band DNS interactions.
   *
   * @param {object} response - HTTP response
   * @returns {object} XXE detection result
   */
  static detectXXEIndicators(response) {
    const bodyText = this._getBodyText(response);

    const xxePatterns = [
      /root:.*:0:0/i,                     // /etc/passwd
      /\[boot loader\]/i,                 // win.ini
      /\[extensions\]/i,                  // win.ini
      /ENTITY.*SYSTEM/i,                  // XXE entity reflected
      /DOCTYPE.*\[/i,                     // DTD reflected
      /java\.io\.FileNotFoundException/i, // Java file error
      /javax\.xml/i                       // Java XML parser error
    ];

    for (const pattern of xxePatterns) {
      if (pattern.test(bodyText)) {
        return {
          detected: true,
          pattern: pattern.source,
          confidence: 'HIGH'
        };
      }
    }

    return { detected: false, confidence: 'NONE' };
  }

  /**
   * Detect XSS reflection in response body.
   * Checks if common XSS payloads appear unescaped in the response.
   *
   * @param {object} response - HTTP response
   * @param {string} [payload] - The specific payload that was sent
   * @returns {object} XSS detection result
   */
  static detectXSSReflection(response, payload) {
    const bodyText = this._getBodyText(response);

    // Check if the exact payload is reflected unescaped
    if (payload && bodyText.includes(payload)) {
      return {
        detected: true,
        type: 'reflected',
        confidence: 'HIGH',
        detail: 'Payload reflected unescaped in response body'
      };
    }

    // Check for common XSS indicators
    const xssPatterns = [
      /<script[^>]*>.*?alert/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /onmouseover\s*=/i,
      /javascript:/i,
      /<svg[^>]*onload/i,
      /<img[^>]*onerror/i
    ];

    for (const pattern of xssPatterns) {
      if (pattern.test(bodyText)) {
        return {
          detected: true,
          type: 'reflected',
          pattern: pattern.source,
          confidence: 'MEDIUM'
        };
      }
    }

    return { detected: false, confidence: 'NONE' };
  }

  /**
   * Extract data from SQL injection response
   * @param {object} response - HTTP response
   * @param {string} expectedPattern - Pattern to match extracted data
   * @returns {Array} Extracted data
   */
  static extractData(response, expectedPattern) {
    const bodyText = this._getBodyText(response);

    const data = [];
    
    // Try to parse as JSON first
    try {
      const json = (typeof response.body === 'object' && response.body !== null)
        ? response.body
        : JSON.parse(bodyText);

      if (Array.isArray(json)) {
        return json;
      }
      if (json != null && (json.results || json.data)) {
        return json.results || json.data;
      }
    } catch (e) {
      // Not JSON, continue with pattern matching
    }

    // Pattern-based extraction
    if (expectedPattern) {
      try {
        const regex = new RegExp(expectedPattern, 'gi');
        const matches = bodyText.matchAll(regex);
        for (const match of matches) {
          data.push(match[1] || match[0]);
        }
      } catch (e) {
        // Invalid regex pattern — fall back to literal string search
        const idx = bodyText.indexOf(expectedPattern);
        if (idx !== -1) {
          data.push(bodyText.substring(idx, idx + expectedPattern.length + 100));
        }
      }
    }

    return data;
  }

  /**
   * Calculate confidence for boolean-based testing
   * @private
   */
  static calculateBooleanConfidence(lengthDiff, contentDiff, statusDiff) {
    if (contentDiff && statusDiff) return 'HIGH';
    if (contentDiff && lengthDiff > 100) return 'HIGH';
    if (contentDiff || lengthDiff > 50) return 'MEDIUM';
    if (lengthDiff > 10) return 'LOW';
    return 'NONE';
  }
}
