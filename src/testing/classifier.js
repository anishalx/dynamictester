import { determineLevel, getLevelDetails } from './exploitation-levels.js';

/**
 * Classify vulnerability based on testing evidence
 * Implements Shannon's classification decision framework
 */
export class VulnerabilityClassifier {
  /**
   * Classify a tested vulnerability as EXPLOITED, POTENTIAL, or FALSE_POSITIVE
   * 
   * Classification Rules:
   * - Level 3+: Data extracted → EXPLOITED
   * - Level 1-2 + External blocker → POTENTIAL
   * - Level 1-2 + Security blocker → FALSE_POSITIVE
   * - Level 0 → FALSE_POSITIVE
   * 
   * @param {object} testResult - Complete test result with evidence
   * @returns {object} Classification decision
   */
  static classify(testResult) {
    const level = determineLevel(testResult.evidence);
    const levelDetails = getLevelDetails(level);
    
    // Level 3+: Data extracted = EXPLOITED
    if (level >= 3) {
      return {
        classification: 'EXPLOITED',
        level,
        levelName: levelDetails.name,
        confidence: levelDetails.confidence,
        reason: 'Successfully extracted data from target system',
        evidence: testResult.evidence,
        includeInReport: true,
        requiresAction: true
      };
    }

    // Level 1-2: Partial confirmation, check blockers
    if (level > 0) {
      // External blocker (auth, network, server issues) = POTENTIAL
      if (testResult.externalBlocker) {
        return {
          classification: 'POTENTIAL',
          level,
          levelName: levelDetails.name,
          confidence: levelDetails.confidence,
          reason: testResult.blockerReason || 'External constraint prevents full exploitation',
          blocker: testResult.externalBlocker,
          evidence: testResult.evidence,
          includeInReport: true,
          requiresAction: true,
          note: 'Vulnerability may be exploitable if blocker is removed'
        };
      }

      // Security blocker (prepared statements, WAF, validation) = FALSE POSITIVE
      if (testResult.securityBlocker) {
        return {
          classification: 'FALSE_POSITIVE',
          level,
          levelName: levelDetails.name,
          confidence: 'N/A',
          reason: testResult.securityReason || 'Security controls prevent exploitation',
          securityControl: testResult.securityBlocker,
          evidence: testResult.evidence,
          includeInReport: false,
          requiresAction: false,
          note: 'Static analysis finding contradicted by dynamic testing'
        };
      }

      // No blocker specified but partial confirmation
      // Use blocker analysis to determine
      const analysis = this.analyzeBlocker(testResult);
      if (analysis.isSecurityControl) {
        return {
          classification: 'FALSE_POSITIVE',
          level,
          levelName: levelDetails.name,
          confidence: 'N/A',
          reason: 'Security implementation blocks exploitation',
          securityControl: analysis.details,
          evidence: testResult.evidence,
          includeInReport: false,
          requiresAction: false
        };
      }

      // Default for Level 1-2 without clear blocker = POTENTIAL (low confidence)
      return {
        classification: 'POTENTIAL',
        level,
        levelName: levelDetails.name,
        confidence: 'LOW',
        reason: 'Partial confirmation but unable to extract data',
        evidence: testResult.evidence,
        includeInReport: true,
        requiresAction: true,
        note: 'Further investigation recommended'
      };
    }

    // Level 0: No evidence = FALSE POSITIVE
    return {
      classification: 'FALSE_POSITIVE',
      level: 0,
      levelName: levelDetails.name,
      confidence: 'N/A',
      reason: 'No evidence of exploitability after exhaustive testing',
      attemptsExhausted: testResult.bypassAttempts || 0,
      totalAttempts: testResult.attempts?.length || 0,
      evidence: testResult.evidence,
      includeInReport: false,
      requiresAction: false,
      note: 'Static analysis appears to be incorrect'
    };
  }

  /**
   * Determine if blocker is security control or external constraint
   * 
   * Security Control Indicators:
   * - Prepared statements, parameter binding
   * - Input validation, sanitization
   * - WAF blocking
   * - Authorization checks
   * 
   * External Constraint Indicators:
   * - Authentication required (can't obtain creds)
   * - Server unavailable
   * - Network errors
   * - Rate limiting
   * 
   * @param {object} testResult - Test result
   * @returns {object} Analysis result
   */
  static analyzeBlocker(testResult) {
    const securityIndicators = [
      'prepared statement',
      'parameter binding',
      'input validation',
      'validation error',
      'waf block',
      'firewall',
      'sanitization',
      'sanitize',
      'escaping',
      'escape',
      'authorization check',
      'permission denied',
      'filtered',
      'blacklist'
    ];

    const externalIndicators = [
      'authentication required',
      'login required',
      'credentials needed',
      'server unavailable',
      'server down',
      'network error',
      'connection refused',
      'timeout',
      'timed out',
      'rate limit',
      'too many requests',
      'application crashed',
      'service unavailable'
    ];

    const blockerText = (
      (testResult.blockerDescription || '') +
      ' ' +
      (testResult.blockerReason || '') +
      ' ' +
      (testResult.securityReason || '') +
      ' ' +
      (testResult.error || '')
    ).toLowerCase();

    const isSecurityControl = securityIndicators.some(indicator => 
      blockerText.includes(indicator)
    );

    const isExternalConstraint = externalIndicators.some(indicator =>
      blockerText.includes(indicator)
    );

    let classification = 'UNKNOWN';
    let details = 'Unable to determine blocker type';

    if (isSecurityControl && !isExternalConstraint) {
      classification = 'FALSE_POSITIVE';
      details = 'Security controls preventing exploitation';
    } else if (isExternalConstraint && !isSecurityControl) {
      classification = 'POTENTIAL';
      details = 'External constraints blocking testing';
    } else if (isSecurityControl && isExternalConstraint) {
      // Both detected, prioritize security control
      classification = 'FALSE_POSITIVE';
      details = 'Security controls detected (external constraints also present)';
    }

    return {
      isSecurityControl,
      isExternalConstraint,
      classification,
      details,
      blockerText: blockerText.substring(0, 200) // First 200 chars for debugging
    };
  }

  /**
   * Generate classification summary report
   * @param {Array} classifications - Array of classification results
   * @returns {object} Summary statistics
   */
  static summarize(classifications) {
    const summary = {
      total: classifications.length,
      exploited: 0,
      potential: 0,
      falsePositive: 0,
      byLevel: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 },
      criticalImpact: 0,
      requiresAction: 0
    };

    for (const result of classifications) {
      summary.byLevel[result.level] = (summary.byLevel[result.level] || 0) + 1;

      if (result.classification === 'EXPLOITED') {
        summary.exploited++;
        if (result.level === 4) summary.criticalImpact++;
      } else if (result.classification === 'POTENTIAL') {
        summary.potential++;
      } else {
        summary.falsePositive++;
      }

      if (result.requiresAction) {
        summary.requiresAction++;
      }
    }

    summary.accuracyRate = summary.total > 0
      ? ((summary.exploited + summary.potential) / summary.total * 100).toFixed(1) + '%'
      : '0%';

    return summary;
  }
}
