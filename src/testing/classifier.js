import { determineLevel, getLevelDetails } from './exploitation-levels.js';

/**
 * Classify vulnerability based on testing evidence
 * Implements the classification decision framework
 * 
 * Classifications:
 * - CONFIRMED: Exploitation proven with data extraction (Level 3-4)
 * - LIKELY: Partial evidence, could be exploitable (Level 1-2)
 * - BLOCKED: External factors prevent testing (auth, network, rate limit)
 * - NOT_REPRODUCIBLE: Security controls prevent exploitation
 */
export class VulnerabilityClassifier {
  /**
   * Classify a tested vulnerability
   * 
   * Classification Rules:
   * - Level 3+: Data extracted → CONFIRMED
   * - Level 1-2 + External blocker → BLOCKED
   * - Level 1-2 + Security blocker → NOT_REPRODUCIBLE
   * - Level 1-2 + No blocker → LIKELY
   * - Level 0 → NOT_REPRODUCIBLE
   * 
   * @param {object} testResult - Complete test result with evidence
   * @returns {object} Classification decision
   */
  static classify(testResult) {
    if (!testResult || !testResult.evidence) {
      return {
        classification: 'NOT_REPRODUCIBLE',
        level: 0,
        levelName: 'No Exploitation',
        confidence: 'N/A',
        reason: 'No test result or evidence provided',
        evidence: testResult?.evidence || {},
        includeInReport: false,
        requiresAction: false,
        ciExitCode: 0
      };
    }

    const level = determineLevel(testResult.evidence);
    const levelDetails = getLevelDetails(level);
    
    // Level 3+: Data extracted = CONFIRMED
    if (level >= 3) {
      return {
        classification: 'CONFIRMED',
        level,
        levelName: levelDetails.name,
        confidence: levelDetails.confidence,
        reason: 'Successfully extracted data from target system',
        evidence: testResult.evidence,
        includeInReport: true,
        requiresAction: true,
        ciExitCode: 1  // Fail CI on confirmed exploits
      };
    }

    // Level 1-2: Partial confirmation, check blockers
    if (level > 0) {
      // External blocker (auth, network, server issues) = BLOCKED
      if (testResult.externalBlocker) {
        return {
          classification: 'BLOCKED',
          level,
          levelName: levelDetails.name,
          confidence: levelDetails.confidence,
          reason: testResult.blockerReason || 'External constraint prevents full exploitation',
          blocker: testResult.externalBlocker,
          evidence: testResult.evidence,
          includeInReport: true,
          requiresAction: true,
          ciExitCode: 0,  // Don't fail CI on blocked tests
          note: 'Vulnerability may be exploitable if blocker is removed'
        };
      }

      // Security blocker (prepared statements, WAF, validation) = NOT_REPRODUCIBLE
      if (testResult.securityBlocker) {
        return {
          classification: 'NOT_REPRODUCIBLE',
          level,
          levelName: levelDetails.name,
          confidence: 'N/A',
          reason: testResult.securityReason || 'Security controls prevent exploitation',
          securityControl: testResult.securityBlocker,
          evidence: testResult.evidence,
          includeInReport: false,
          requiresAction: false,
          ciExitCode: 0,
          note: 'Static analysis finding contradicted by dynamic testing'
        };
      }

      // No blocker specified but partial confirmation
      // Use blocker analysis to determine
      const analysis = this.analyzeBlocker(testResult);
      if (analysis.isSecurityControl) {
        return {
          classification: 'NOT_REPRODUCIBLE',
          level,
          levelName: levelDetails.name,
          confidence: 'N/A',
          reason: 'Security implementation blocks exploitation',
          securityControl: analysis.details,
          evidence: testResult.evidence,
          includeInReport: false,
          requiresAction: false,
          ciExitCode: 0
        };
      }

      if (analysis.isExternalConstraint) {
        return {
          classification: 'BLOCKED',
          level,
          levelName: levelDetails.name,
          confidence: 'LOW',
          reason: analysis.details,
          evidence: testResult.evidence,
          includeInReport: true,
          requiresAction: true,
          ciExitCode: 0,
          note: 'Testing blocked by external constraint'
        };
      }

      // Default for Level 1-2 without clear blocker = LIKELY
      return {
        classification: 'LIKELY',
        level,
        levelName: levelDetails.name,
        confidence: 'LOW',
        reason: 'Partial confirmation but unable to extract data',
        evidence: testResult.evidence,
        includeInReport: true,
        requiresAction: true,
        ciExitCode: 0,  // Don't fail CI on LIKELY (use --fail-on-likely flag to change)
        note: 'Further investigation recommended'
      };
    }

    // Level 0: No evidence = NOT_REPRODUCIBLE
    return {
      classification: 'NOT_REPRODUCIBLE',
      level: 0,
      levelName: levelDetails.name,
      confidence: 'N/A',
      reason: 'No evidence of exploitability after exhaustive testing',
      attemptsExhausted: testResult.bypassAttempts ?? 0,
      totalAttempts: testResult.attempts?.length || 0,
      evidence: testResult.evidence,
      includeInReport: false,
      requiresAction: false,
      ciExitCode: 0,
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
      confirmed: 0,
      likely: 0,
      blocked: 0,
      notReproducible: 0,
      byLevel: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 },
      criticalImpact: 0,
      requiresAction: 0,
      ciExitCode: 0
    };

    for (const result of classifications) {
      summary.byLevel[result.level] = (summary.byLevel[result.level] || 0) + 1;

      switch (result.classification) {
        case 'CONFIRMED':
          summary.confirmed++;
          if (result.level === 4) summary.criticalImpact++;
          summary.ciExitCode = 1; // Fail CI if any confirmed
          break;
        case 'LIKELY':
          summary.likely++;
          break;
        case 'BLOCKED':
          summary.blocked++;
          break;
        case 'NOT_REPRODUCIBLE':
          summary.notReproducible++;
          break;
      }

      if (result.requiresAction) {
        summary.requiresAction++;
      }
    }

    summary.exploitableRate = summary.total > 0
      ? ((summary.confirmed + summary.likely) / summary.total * 100).toFixed(1) + '%'
      : '0%';

    return summary;
  }
}
