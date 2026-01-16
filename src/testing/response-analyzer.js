/**
 * Analyzes HTTP responses to detect vulnerability indicators
 * Distinguishes real vulnerabilities from false positives
 */

export class ResponseAnalyzer {
  /**
   * Detect database-specific error messages in response
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
        /mysql_num_rows/i
      ],
      postgresql: [
        /postgresql.*error/i,
        /pg_query\(\)/i,
        /pg_exec\(\)/i,
        /syntax error at or near/i,
        /unterminated quoted string/i,
        /invalid input syntax/i
      ],
      mssql: [
        /microsoft sql server/i,
        /odbc sql server driver/i,
        /unclosed quotation mark/i,
        /\[sql server\]/i,
        /line \d+:/i,
        /incorrect syntax near/i
      ],
      oracle: [
        /ora-\d{5}/i,
        /oracle error/i,
        /oracle.*driver/i,
        /warning.*oci_/i
      ],
      sqlite: [
        /sqlite.*error/i,
        /sqlite3::/i,
        /unrecognized token/i
      ]
    };

    const bodyText = typeof response.body === 'string' 
      ? response.body 
      : JSON.stringify(response.body);

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
    const trueBody = typeof trueResponse.body === 'string' 
      ? trueResponse.body 
      : JSON.stringify(trueResponse.body);
    
    const falseBody = typeof falseResponse.body === 'string'
      ? falseResponse.body
      : JSON.stringify(falseResponse.body);

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
        trueLeng: trueBody.length,
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
      actualDelay: actualDelay.toFixed(2),
      expectedDelay,
      tolerance: tolerance.toFixed(2),
      confidence,
      details: {
        normalTime: normalTime.toFixed(2),
        delayedTime: delayedTime.toFixed(2),
        difference: actualDelay.toFixed(2)
      }
    };
  }

  /**
   * Detect input validation errors (false positive indicator)
   * @param {object} response - HTTP response
   * @returns {boolean} True if validation error detected
   */
  static isValidationError(response) {
    const bodyText = typeof response.body === 'string'
      ? response.body
      : JSON.stringify(response.body);

    const validationPatterns = [
      /invalid input/i,
      /validation failed/i,
      /bad request/i,
      /malformed/i,
      /invalid parameter/i,
      /parameter.*invalid/i,
      /input.*rejected/i,
      /not allowed/i
    ];

    // HTTP 400 is often validation error
    if (response.status === 400) {
      return true;
    }

    return validationPatterns.some(pattern => pattern.test(bodyText));
  }

  /**
   * Detect WAF/firewall blocking (false positive indicator)
   * @param {object} response - HTTP response
   * @returns {object} WAF detection result
   */
  static detectWAFBlocking(response) {
    const bodyText = typeof response.body === 'string'
      ? response.body
      : JSON.stringify(response.body);

    const wafPatterns = {
      cloudflare: [/cloudflare/i, /cf-ray/i],
      akamai: [/akamai/i],
      imperva: [/imperva/i, /incapsula/i],
      modsecurity: [/mod_security/i, /modsec/i],
      generic: [
        /blocked.*security/i,
        /request.*blocked/i,
        /access denied/i,
        /forbidden/i
      ]
    };

    for (const [waf, patterns] of Object.entries(wafPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(bodyText) || pattern.test(response.headers?.toString() || '')) {
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
   * Extract data from SQL injection response
   * @param {object} response - HTTP response
   * @param {string} expectedPattern - Pattern to match extracted data
   * @returns {Array} Extracted data
   */
  static extractData(response, expectedPattern) {
    const bodyText = typeof response.body === 'string'
      ? response.body
      : JSON.stringify(response.body);

    const data = [];
    
    // Try to parse as JSON first
    try {
      const json = typeof response.body === 'object' 
        ? response.body 
        : JSON.parse(bodyText);
      
      if (Array.isArray(json)) {
        return json;
      }
      if (json.results || json.data) {
        return json.results || json.data;
      }
    } catch (e) {
      // Not JSON, continue with pattern matching
    }

    // Pattern-based extraction
    if (expectedPattern) {
      const regex = new RegExp(expectedPattern, 'gi');
      const matches = bodyText.matchAll(regex);
      for (const match of matches) {
        data.push(match[1] || match[0]);
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
