/**
 * Validation utilities for normalized vulnerability data
 */

/**
 * Validate a single normalized vulnerability structure
 * @param {object} vuln - Normalized vulnerability object
 * @returns {{valid: boolean, errors: string[]}}
 */
export function validateVulnerability(vuln) {
  const errors = [];

  if (!vuln || typeof vuln !== 'object') {
    return { valid: false, errors: ['Vulnerability must be a non-null object'] };
  }

  // Check required fields
  const required = ['id', 'source', 'type', 'severity', 'location', 'description'];
  for (const field of required) {
    if (!vuln[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // Validate location object
  if (vuln.location) {
    if (!vuln.location.file) {
      errors.push('location.file is required');
    }
    if (typeof vuln.location.line !== 'number') {
      errors.push('location.line must be a number');
    }
  }

  // Validate severity
  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  if (vuln.severity && !validSeverities.includes(vuln.severity)) {
    errors.push(`Invalid severity: ${vuln.severity}. Must be one of: ${validSeverities.join(', ')}`);
  }

  // Validate confidence
  const validConfidences = ['HIGH', 'MEDIUM', 'LOW'];
  if (vuln.confidence && !validConfidences.includes(vuln.confidence)) {
    errors.push(`Invalid confidence: ${vuln.confidence}. Must be one of: ${validConfidences.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate an array of vulnerabilities
 * @param {object[]} vulnerabilities - Array of normalized vulnerabilities
 * @returns {{valid: boolean, totalCount: number, validCount: number, invalidCount: number, errors: object[]}}
 */
export function validateVulnerabilities(vulnerabilities) {
  if (!Array.isArray(vulnerabilities)) {
    return {
      valid: false,
      totalCount: 0,
      validCount: 0,
      invalidCount: 0,
      errors: [{ index: -1, errors: ['vulnerabilities must be an array'] }]
    };
  }

  const results = vulnerabilities.map((v, i) => ({
    index: i,
    ...validateVulnerability(v)
  }));

  const invalid = results.filter(r => !r.valid);
  
  return {
    valid: invalid.length === 0,
    totalCount: vulnerabilities.length,
    validCount: results.filter(r => r.valid).length,
    invalidCount: invalid.length,
    errors: invalid
  };
}

/**
 * Check for duplicate vulnerability IDs
 * @param {object[]} vulnerabilities - Array of vulnerabilities
 * @returns {{hasDuplicates: boolean, duplicates: object[]}}
 */
export function checkDuplicates(vulnerabilities) {
  const idMap = new Map();
  const duplicates = [];

  for (let i = 0; i < vulnerabilities.length; i++) {
    const vuln = vulnerabilities[i];
    const id = vuln.id;

    if (idMap.has(id)) {
      duplicates.push({
        id,
        indices: [idMap.get(id), i],
        sources: [vulnerabilities[idMap.get(id)].source, vuln.source]
      });
    } else {
      idMap.set(id, i);
    }
  }

  return {
    hasDuplicates: duplicates.length > 0,
    duplicates
  };
}
