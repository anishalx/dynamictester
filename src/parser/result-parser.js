import { fs } from 'zx';
import chalk from 'chalk';
import { detectAnalyzerType, createParser } from './parser-factory.js';
import { validateVulnerabilities } from './validator.js';

/**
 * Parse static analyzer result file(s) - supports multiple formats
 * @param {string|string[]} resultPath - Single path or array of paths to analyzer outputs
 * @returns {Promise<{vulnerabilities: Array, summary: object}>}
 */
export async function parseStaticAnalysisResults(resultPath) {
  const paths = Array.isArray(resultPath) ? resultPath : [resultPath];
  
  const allVulnerabilities = [];
  const summary = {
    bySource: {},
    byType: {},
    total: 0,
    errors: []
  };

  console.log(chalk.blue(`\n📊 Processing ${paths.length} analyzer result file(s)...\n`));

  const existingIds = new Set();

  for (const filePath of paths) {
    console.log(chalk.blue(`📄 Processing: ${filePath}`));
    
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const data = JSON.parse(content);
      
      // Auto-detect analyzer type
      const analyzerType = detectAnalyzerType(data);
      if (!analyzerType) {
        const error = `Could not detect analyzer type for ${filePath}`;
        console.log(chalk.yellow(`⚠️  ${error}, skipping...`));
        summary.errors.push({ file: filePath, error: 'Unknown analyzer type' });
        continue;
      }

      console.log(chalk.cyan(`   ✓ Detected: ${analyzerType}`));

      // Create appropriate parser and parse with error handling
      const parser = createParser(analyzerType);
      let vulnerabilities;
      try {
        vulnerabilities = await parser.parse(data);
      } catch (parseError) {
        console.error(chalk.red(`   ❌ Parser error: ${parseError.message}`));
        summary.errors.push({ file: filePath, error: `Parser error: ${parseError.message}` });
        continue;
      }

      // Validate
      const validation = validateVulnerabilities(vulnerabilities);
      if (!validation.valid) {
        console.log(chalk.yellow(`⚠️  Validation warnings in ${filePath}:`));
        validation.errors.slice(0, 5).forEach(err => {
          console.log(chalk.yellow(`   - Index ${err.index}: ${err.errors.join(', ')}`));
        });
        if (validation.errors.length > 5) {
          console.log(chalk.yellow(`   ... and ${validation.errors.length - 5} more errors`));
        }
      }

      // Deduplicate before adding to results (incremental Set, not rebuilt each file)
      const uniqueVulns = [];
      let duplicateCount = 0;
      for (const vuln of vulnerabilities) {
        const rawId = vuln?.id;
        const id = typeof rawId === 'string' ? rawId.trim() : rawId;
        const hasId = id !== undefined && id !== null && id !== '';
        if (!hasId) {
          uniqueVulns.push(vuln);
          continue;
        }
        if (existingIds.has(id)) {
          duplicateCount++;
          continue;
        }
        existingIds.add(id);
        uniqueVulns.push(vuln);
      }
      
      if (duplicateCount > 0) {
        console.log(chalk.yellow(`   ⚠️  Skipped ${duplicateCount} duplicate(s)`));
      }

      allVulnerabilities.push(...uniqueVulns);

      // Update summary
      summary.bySource[analyzerType] = (summary.bySource[analyzerType] || 0) + uniqueVulns.length;
      
      console.log(chalk.green(`   ✓ Parsed ${uniqueVulns.length} vulnerabilities\n`));

    } catch (error) {
      const errorMsg = `Failed to parse ${filePath}: ${error.message}`;
      console.error(chalk.red(`❌ ${errorMsg}`));
      summary.errors.push({ file: filePath, error: error.message });
    }
  }

  // Calculate type summary
  for (const vuln of allVulnerabilities) {
    summary.byType[vuln.type] = (summary.byType[vuln.type] || 0) + 1;
  }
  summary.total = allVulnerabilities.length;

  // Print summary
  console.log(chalk.green(`\n✅ Total vulnerabilities parsed: ${summary.total}`));
  
  if (Object.keys(summary.bySource).length > 0) {
    console.log(chalk.cyan('\n📊 By Source Analyzer:'));
    for (const [source, count] of Object.entries(summary.bySource)) {
      console.log(chalk.cyan(`   - ${source}: ${count}`));
    }
  }
  
  if (Object.keys(summary.byType).length > 0) {
    console.log(chalk.cyan('\n📊 By Vulnerability Type:'));
    for (const [type, count] of Object.entries(summary.byType)) {
      console.log(chalk.cyan(`   - ${type}: ${count}`));
    }
  }

  if (summary.errors.length > 0) {
    console.log(chalk.yellow(`\n⚠️  ${summary.errors.length} file(s) had errors`));
  }

  return { vulnerabilities: allVulnerabilities, summary };
}

/**
 * Backward compatibility: Parse a single static analysis result
 * @deprecated Not imported anywhere — use parseStaticAnalysisResults instead.
 * @param {string} resultJsonPath - Path to a single result file
 * @returns {Promise<Array>} Array of vulnerabilities
 */
export async function parseStaticAnalysisResult(resultJsonPath) {
  const result = await parseStaticAnalysisResults(resultJsonPath);
  return result.vulnerabilities;
}
