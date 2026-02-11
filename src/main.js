#!/usr/bin/env node

import chalk from 'chalk';
import inquirer from 'inquirer';
import { parseStaticAnalysisResults } from './parser/result-parser.js';
import { generateExploitationQueue } from './queue/queue-generator.js';
import { executeExploitationAgent } from './agents/executor.js';
import { path, fs } from 'zx';
import { getSupportedAnalyzers } from './parser/parser-factory.js';
import { generateSarifReport, generateHtmlReport, generateDeveloperSummary } from './reporting/report-generator.js';

async function main() {
  console.log(chalk.cyan.bold('\n🔍 Dynamic Security Tester (OpenAI Powered)'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log(chalk.gray(`Supported analyzers: ${getSupportedAnalyzers().join(', ')}`));
  console.log(chalk.gray('─'.repeat(60)));

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'resultJsonPath',
      message: 'Path to analyzer result file(s) (comma-separated for multiple):',
      validate: async (input) => {
        const paths = input.split(',').map(p => p.trim());
        for (const p of paths) {
          if (!(await fs.pathExists(p))) {
            return `File does not exist: ${p}`;
          }
        }
        return true;
      }
    },
    {
      type: 'input',
      name: 'targetUrl',
      message: 'Target URL for dynamic testing:',
      default: 'http://localhost:3000',
      validate: (input) => {
        try {
          new URL(input);
          return true;
        } catch {
          return 'Please enter a valid URL.';
        }
      }
    },
    {
      type: 'input',
      name: 'outputDir',
      message: 'Output directory for results and evidence:',
      default: './output'
    }
  ]);

  const { resultJsonPath, targetUrl, outputDir } = answers;
  
  // Parse comma-separated paths
  const resultPaths = resultJsonPath.split(',').map(p => p.trim());

  console.log(chalk.gray(`\nProcessing:`));
  console.log(chalk.gray(`- Result files: ${resultPaths.length}`));
  resultPaths.forEach(p => console.log(chalk.gray(`  • ${p}`)));
  console.log(chalk.gray(`- Target: ${targetUrl}`));
  console.log(chalk.gray(`- Output: ${outputDir}`));
  console.log(chalk.gray('─'.repeat(40)));

  try {
    // Ensure output directory exists
    await fs.ensureDir(outputDir);

    // Step 1: Parse static analysis results (supports multiple files)
    console.log(chalk.blue('\n📋 Step 1: Parsing static analysis results...'));
    const { vulnerabilities, summary } = await parseStaticAnalysisResults(resultPaths);
    
    if (vulnerabilities.length === 0) {
      console.log(chalk.yellow('⚠️ No vulnerabilities found. Exiting.'));
      process.exit(0);
    }

    // Step 2: Generate exploitation queues
    console.log(chalk.blue('\n📋 Step 2: Generating exploitation queues...'));
    const queues = await generateExploitationQueue(vulnerabilities, outputDir);
    
    // Step 3: Execute exploitation agents
    console.log(chalk.blue('\n📋 Step 3: Reviewing vulnerabilities...'));
    
    // Map prompt files to vulnerability types
    const promptMapping = {
      injection: 'exploit-injection.txt',
      xss: 'exploit-xss.txt',
      ssrf: 'exploit-ssrf.txt',
      secrets: 'exploit-secrets.txt',
      auth: 'exploit-auth.txt',
      traversal: 'exploit-traversal.txt',
      xxe: 'exploit-xxe.txt',
      redirect: 'exploit-redirect.txt',
      dependency: 'exploit-generic.txt',  // Dependencies typically don't need dynamic testing
      config: 'exploit-generic.txt',
      other: 'exploit-generic.txt'
    };

    for (const [type, queue] of Object.entries(queues)) {
      if (queue.length > 0) {
        console.log(chalk.cyan(`\n🎯 Found ${queue.length} ${type.toUpperCase()} vulnerabilities:`));
        
        // Show vulnerability summary
        for (let i = 0; i < Math.min(queue.length, 5); i++) {
          const v = queue[i];
          console.log(chalk.gray(`   ${i + 1}. ${v.vulnerabilityType} in ${v.location}`));
        }
        if (queue.length > 5) {
          console.log(chalk.gray(`   ... and ${queue.length - 5} more`));
        }

        const { runTests } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'runTests',
            message: `Run dynamic exploitation tests for ${type}?`,
            default: true
          }
        ]);

        if (runTests) {
          const queuePath = path.resolve(outputDir, 'deliverables', `${type}_exploitation_queue.json`);
          const promptFile = promptMapping[type] || 'exploit-generic.txt';
          const promptPath = path.resolve(process.cwd(), 'prompts', promptFile);
          
          if (!(await fs.pathExists(promptPath))) {
            console.log(chalk.yellow(`⚠️ Prompt template not found: ${promptFile}. Using generic prompt.`));
            // Create a generic prompt if it doesn't exist
            const genericPromptPath = path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt');
            if (!(await fs.pathExists(genericPromptPath))) {
              await createGenericPrompt(genericPromptPath);
            }
          }

          const result = await executeExploitationAgent(
            await fs.pathExists(promptPath) ? promptPath : path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt'),
            queuePath,
            targetUrl,
            outputDir
          );
          
          if (result.success) {
            console.log(chalk.green(`✅ ${type} exploitation completed in ${result.turns} turns`));
          } else {
            console.log(chalk.red(`❌ ${type} exploitation failed: ${result.error}`));
          }
        }
      }
    }
    
    // Generate reports
    console.log(chalk.blue('\n📋 Generating reports...'));
    const evidenceDir = path.join(outputDir, 'evidence');
    await fs.ensureDir(evidenceDir);
    
    try {
      await generateDeveloperSummary(evidenceDir, path.join(outputDir, 'developer_summary.json'));
    } catch (reportError) {
      console.log(chalk.yellow(`⚠️ Developer summary warning: ${reportError.message}`));
    }
    
    try {
      await generateSarifReport(evidenceDir, path.join(outputDir, 'report.sarif.json'), { targetUrl });
    } catch (reportError) {
      console.log(chalk.yellow(`⚠️ SARIF report warning: ${reportError.message}`));
    }
    
    try {
      await generateHtmlReport(evidenceDir, path.join(outputDir, 'report.html'), { targetUrl });
    } catch (reportError) {
      console.log(chalk.yellow(`⚠️ HTML report warning: ${reportError.message}`));
    }
    
    console.log(chalk.green.bold('\n🎉 Dynamic testing session complete!'));
    console.log(chalk.gray(`Results saved to: ${outputDir}`));
    console.log(chalk.gray(`\nOutput files:`));
    console.log(chalk.gray(`  • evidence/           - Individual finding details`));
    console.log(chalk.gray(`  • findings_summary.json - Quick summary for developers`));
    console.log(chalk.gray(`  • developer_summary.json - Categorized findings`));
    console.log(chalk.gray(`  • report.sarif.json   - SARIF for IDE integration`));
    console.log(chalk.gray(`  • report.html         - Visual HTML report`));
    
  } catch (error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}`));
    console.error(error.stack);
    process.exit(1);
  }
}

async function createGenericPrompt(promptPath) {
  const genericPrompt = `<role>
You are a Security Exploitation Specialist. Your goal is to test vulnerabilities identified by static analysis.
</role>

<objective>
Test every vulnerability in the queue file: {{QUEUE_PATH}}
For each vulnerability, generate appropriate payloads and test them against: {{WEB_URL}}
Document successful exploits with proof.
</objective>

<instructions>
1. Read and understand each vulnerability in the queue
2. Navigate to the target application
3. Identify the vulnerable endpoint or parameter
4. Generate and test appropriate payloads
5. Document evidence of successful exploitation
</instructions>

<available_tools>
- browser_navigate: Navigate to a URL
- browser_fill: Fill form fields with payloads
- browser_click: Click buttons/submit forms
- browser_get_response: Get page content after action
- save_evidence: Save exploitation evidence
</available_tools>
`;
  await fs.ensureDir(path.dirname(promptPath));
  await fs.writeFile(promptPath, genericPrompt);
}

main();
