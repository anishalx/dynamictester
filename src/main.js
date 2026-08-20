#!/usr/bin/env node

import dotenv from 'dotenv';
dotenv.config();

import chalk from 'chalk';
import inquirer from 'inquirer';
import { parseStaticAnalysisResults } from './parser/result-parser.js';
import { generateExploitationQueue } from './queue/queue-generator.js';
import { createRouteParser, enrichWithRouteInfo } from './parser/route-parser.js';
import { executeExploitationAgent, executeAgentsInParallel } from './agents/executor.js';
import { path, fs } from 'zx';
import { getSupportedAnalyzers } from './parser/parser-factory.js';
import { generateSarifReport, generateHtmlReport, generateDeveloperSummary, generateAllReports } from './reporting/report-generator.js';
import { runCIMode } from './reporting/ci-reporter.js';
import {
  getProvider,
  getAllProviders,
  getConfiguredProviders,
  createClientForProvider,
  isValidProvider
} from './providers/provider-registry.js';
import {
  loadConfig,
  setDefaults,
  getProviderConfig,
  clearProviderConfig,
  getConfigPath
} from './config/config-manager.js';

// ---------------------------------------------------------------------------
// Subcommand routing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
// Determine subcommand: first positional arg that doesn't start with --
const subcommand = args.find(a => !a.startsWith('--')) || null;

// Parse --provider and --model CLI flags (e.g. --provider=google --model=gemini-2.5-pro)
const cliProvider = args.find(a => a.startsWith('--provider='))?.split('=')[1];
const cliModel = args.find(a => a.startsWith('--model='))?.split('=')[1];

// Parse CI mode flags
const isCIMode = args.includes('--ci');
const ciFailOnLikely = args.includes('--fail-on-likely');
const ciFailOnBlocked = args.includes('--fail-on-blocked');

// Parse --dry-run flag (preview queues without running exploitation)
const isDryRun = args.includes('--dry-run');

// Parse --types flag (filter which vulnerability types to test, comma-separated)
const cliTypesRaw = args.find(a => a.startsWith('--types='))?.split('=')[1]?.trim();
const cliTypes = cliTypesRaw ? cliTypesRaw.split(',').map(t => t.trim().toLowerCase()) : null;

// Parse --scan-summary flag (show summary of past scan results)
const isScanSummary = args.includes('--scan-summary');

// Parse CI-compatible CLI args for non-interactive mode
const cliTarget = args.find(a => a.startsWith('--target='))?.split('=')[1]?.trim();
const cliResults = args.find(a => a.startsWith('--results='))?.split('=')[1]?.trim();
const cliOutput = args.find(a => a.startsWith('--output='))?.split('=')[1]?.trim();

// Parse --help flag
const isHelp = args.includes('--help') || args.includes('-h');

if (isHelp && !subcommand) {
  console.log(chalk.cyan.bold('\n🔍 Dynamic Security Tester — CLI Reference\n'));
  console.log(chalk.white('Usage:'));
  console.log(chalk.gray('  node src/main.js [flags]                   Interactive mode'));
  console.log(chalk.gray('  node src/main.js auth login|status|logout   Manage LLM provider credentials'));
  console.log(chalk.gray('  node src/main.js --scan-summary [output=DIR] Show summary of past scan results\n'));
  console.log(chalk.white('CLI Flags:'));
  console.log(chalk.gray('  --provider=<name>       Override LLM provider (openai, deepseek, qwen, copilot, google, openrouter, nvidia)'));
  console.log(chalk.gray('  --model=<name>          Override LLM model (e.g., gpt-4o, gemini-2.5-pro)'));
  console.log(chalk.gray('  --types=<types>         Filter vuln types to test (comma-separated, e.g., injection,xss)'));
  console.log(chalk.gray('  --dry-run               Preview exploitation queues without running tests'));
  console.log(chalk.gray('  --scan-summary          Show summary of past scan results'));
  console.log(chalk.gray('  --ci                    Enable CI/CD mode with exit codes'));
  console.log(chalk.gray('  --target=<url>          Target URL (required in CI mode)'));
  console.log(chalk.gray('  --results=<paths>       Analyzer result files, comma-separated (required in CI mode)'));
  console.log(chalk.gray('  --output=<dir>          Output directory for reports'));
  console.log(chalk.gray('  --fail-on-likely        In CI mode, also fail for LIKELY findings'));
  console.log(chalk.gray('  --fail-on-blocked       In CI mode, also fail for BLOCKED findings'));
  console.log(chalk.gray('  -h, --help              Show this help message\n'));
  console.log(chalk.white('Examples:'));
  console.log(chalk.gray('  node src/main.js'));
  console.log(chalk.gray('  node src/main.js --provider=google --model=gemini-2.5-pro'));
  console.log(chalk.gray('  node src/main.js --types=injection,xss --dry-run'));
  console.log(chalk.gray('  node src/main.js --ci --target=http://localhost:3000 --results=semgrep.json'));
  console.log(chalk.gray('  node src/main.js --scan-summary --output=./output\n'));
  process.exit(0);
}

if (subcommand === 'auth') {
  const action = args[1]; // login | status | logout
  try {
    if (action === 'login') {
      await authLogin();
    } else if (action === 'status') {
      await authStatus();
    } else if (action === 'logout') {
      await authLogout();
    } else {
      console.log(chalk.cyan('Usage:'));
      console.log(chalk.gray('  node src/main.js auth login    - Configure LLM provider credentials'));
      console.log(chalk.gray('  node src/main.js auth status   - Show configured providers'));
      console.log(chalk.gray('  node src/main.js auth logout   - Remove stored credentials'));
      process.exit(0);
    }
  } catch (authError) {
    console.error(chalk.red(`\nAuth error: ${authError.message}`));
    process.exit(1);
  }
} else if (isScanSummary) {
  await scanSummary();
} else {
  await main();
}

// ---------------------------------------------------------------------------
// Auth subcommands
// ---------------------------------------------------------------------------

/**
 * Interactive provider authentication flow.
 * Lists all available providers and lets the user pick one to configure.
 */
async function authLogin() {
  console.log(chalk.cyan.bold('\n🔐 Provider Authentication'));
  console.log(chalk.gray('─'.repeat(60)));

  const providers = getAllProviders();
  const configuredNames = (await getConfiguredProviders()).map(p => p.name);

  const { providerName } = await inquirer.prompt([
    {
      type: 'list',
      name: 'providerName',
      message: 'Select a provider to configure:',
      choices: providers.map(p => ({
        name: `${p.displayName}${configuredNames.includes(p.name) ? chalk.green(' [configured]') : ''}`,
        value: p.name
      }))
    }
  ]);

  const provider = getProvider(providerName);
  const success = await provider.authenticate();

  if (success) {
    // Ask if this should be the default
    const { setAsDefault } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'setAsDefault',
        message: `Set ${provider.displayName} as your default provider?`,
        default: true
      }
    ]);

    if (setAsDefault) {
      const models = await provider.getModels();
      const { modelId } = await inquirer.prompt([
        {
          type: 'list',
          name: 'modelId',
          message: 'Select default model:',
          choices: models.map(m => ({
            name: `${m.name} — ${m.description}`,
            value: m.id
          })),
          default: provider.getDefaultModel()
        }
      ]);
      await setDefaults(providerName, modelId);
      console.log(chalk.green(`\nDefault set: ${provider.displayName} / ${modelId}`));
    }
  }

  console.log('');
  process.exit(0);
}

/**
 * Show which providers are configured and their status.
 */
async function authStatus() {
  console.log(chalk.cyan.bold('\n📋 Provider Status'));
  console.log(chalk.gray('─'.repeat(60)));

  const config = await loadConfig();
  const providers = getAllProviders();

  for (const provider of providers) {
    const isValid = await provider.validateAuth();
    const icon = isValid ? chalk.green('✓') : chalk.gray('○');
    const status = isValid ? chalk.green('configured') : chalk.gray('not configured');
    const isDefault = config.defaultProvider === provider.name ? chalk.cyan(' (default)') : '';
    console.log(`  ${icon} ${provider.displayName}: ${status}${isDefault}`);
  }

  if (config.defaultProvider && config.defaultModel) {
    console.log(chalk.gray(`\nDefault: ${config.defaultProvider} / ${config.defaultModel}`));
  }
  console.log(chalk.gray(`Config: ${getConfigPath()}\n`));
  process.exit(0);
}

/**
 * Remove stored credentials for a provider.
 */
async function authLogout() {
  console.log(chalk.cyan.bold('\n🗑️  Remove Credentials'));
  console.log(chalk.gray('─'.repeat(60)));

  const configured = await getConfiguredProviders();

  if (configured.length === 0) {
    console.log(chalk.gray('No providers configured.\n'));
    process.exit(0);
  }

  const { providerName } = await inquirer.prompt([
    {
      type: 'list',
      name: 'providerName',
      message: 'Select a provider to remove:',
      choices: [
        ...configured.map(p => ({
          name: p.displayName,
          value: p.name
        })),
        { name: chalk.red('Remove ALL providers'), value: '__all__' }
      ]
    }
  ]);

  if (providerName === '__all__') {
    for (const p of configured) {
      await clearProviderConfig(p.name);
    }
    console.log(chalk.green('All credentials removed.'));
  } else {
    await clearProviderConfig(providerName);
    console.log(chalk.green(`${providerName} credentials removed.`));
  }

  console.log('');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main testing flow
// ---------------------------------------------------------------------------

async function main() {
  console.log(chalk.cyan.bold('\n🔍 Dynamic Security Tester'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log(chalk.gray(`Supported analyzers: ${getSupportedAnalyzers().join(', ')}`));
  console.log(chalk.gray('─'.repeat(60)));

  // ------------------------------------------------------------------
  // Prompt 1-3: Analyzer results, target URL, output directory
  // In CI mode, use --results=, --target=, --output= CLI args instead
  // ------------------------------------------------------------------
  let resultJsonPath;
  let targetUrl;
  let outputDir;

  if (isCIMode) {
    // CI mode: require CLI args, no interactive prompts
    if (!cliResults) {
      console.error(chalk.red('CI mode requires --results=<path> argument (comma-separated for multiple files).'));
      process.exit(2);
    }
    if (!cliTarget) {
      console.error(chalk.red('CI mode requires --target=<url> argument.'));
      process.exit(2);
    }
    resultJsonPath = cliResults;
    targetUrl = cliTarget;
    outputDir = cliOutput || './output';

    // Validate paths exist
    const paths = resultJsonPath.split(',').map(p => p.trim());
    for (const p of paths) {
      if (!(await fs.pathExists(p))) {
        console.error(chalk.red(`Result file does not exist: ${p}`));
        process.exit(2);
      }
    }
    // Validate URL
    try {
      new URL(targetUrl);
    } catch {
      console.error(chalk.red(`Invalid target URL: ${targetUrl}`));
      process.exit(2);
    }
  } else {
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
    resultJsonPath = answers.resultJsonPath;
    targetUrl = answers.targetUrl;
    outputDir = answers.outputDir;
  }

  // ------------------------------------------------------------------
  // Prompt 4: Provider and model selection
  // ------------------------------------------------------------------
  const { providerName, modelId, client, providerConfig, fallbackProviders } = await selectProviderAndModel();

  // Parse comma-separated paths
  const resultPaths = resultJsonPath.split(',').map(p => p.trim());

  console.log(chalk.gray(`\nProcessing:`));
  console.log(chalk.gray(`- Result files: ${resultPaths.length}`));
  resultPaths.forEach(p => console.log(chalk.gray(`  • ${p}`)));
  console.log(chalk.gray(`- Target: ${targetUrl}`));
  console.log(chalk.gray(`- Output: ${outputDir}`));
  console.log(chalk.gray(`- Provider: ${providerName}`));
  console.log(chalk.gray(`- Model: ${modelId}`));
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
    // Step 1.5: Enrich vulnerabilities with route/endpoint information
    let enrichedVulns = vulnerabilities;
    try {
      const repoPath = resultPaths[0] ? path.dirname(path.resolve(resultPaths[0])) : process.cwd();
      const routeSourceDir = process.env.DYNAMIC_TESTER_REPO_PATH || repoPath;
      console.log(chalk.blue(`\n📋 Step 1.5: Discovering API routes from source code...`));
      const routeParser = createRouteParser();
      const routeMapping = await routeParser.parseDirectory(routeSourceDir);
      if (routeMapping.routes.length > 0) {
        console.log(chalk.green(`   ✓ Discovered ${routeMapping.routes.length} routes across ${routeMapping.summary.files.length} files`));
        enrichedVulns = enrichWithRouteInfo(vulnerabilities, routeMapping);
        const withEndpoints = enrichedVulns.filter(v => v.suggestedEndpoint || (v.derivedEndpoints && v.derivedEndpoints.length > 0));
        console.log(chalk.green(`   ✓ Matched endpoints for ${withEndpoints.length}/${vulnerabilities.length} vulnerabilities`));
      } else {
        console.log(chalk.yellow(`   ⚠️ No Express routes found in ${routeSourceDir}. Agent will derive endpoints from file paths.`));
      }
    } catch (routeError) {
      console.log(chalk.yellow(`   ⚠️ Route discovery failed: ${routeError.message}. Agent will derive endpoints from file paths.`));
    }

    const queues = await generateExploitationQueue(enrichedVulns, outputDir);
    
    // Step 3: Execute exploitation agents
    console.log(chalk.blue('\n📋 Step 3: Reviewing vulnerabilities...'));
    
    // Map prompt files to vulnerability types
    const promptMapping = {
      injection: 'exploit-injection.txt',
      xss: 'exploit-xss.txt',
      ssrf: 'exploit-ssrf.txt',
      xxe: 'exploit-xxe.txt',
      traversal: 'exploit-traversal.txt',
      redirect: 'exploit-redirect.txt',
      secrets: 'exploit-secrets.txt',
      auth: 'exploit-auth.txt',
      csrf: 'exploit-generic.txt',
      deserialization: 'exploit-generic.txt',
      upload: 'exploit-generic.txt',
      access: 'exploit-generic.txt',
      crypto: 'exploit-generic.txt',
      config: 'exploit-generic.txt',
      dependency: 'exploit-generic.txt',
      other: 'exploit-generic.txt'
    };

    const plannedAgents = [];
    const warnings = [];

    for (const [type, queue] of Object.entries(queues)) {
      // --types flag: skip types not in the filter list
      if (cliTypes && !cliTypes.includes(type)) {
        if (queue.length > 0) {
          console.log(chalk.gray(`\n⏭️  Skipping ${type.toUpperCase()} (${queue.length} vulns) — not in --types filter`));
        }
        continue;
      }
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

        // In CI mode, auto-run all tests without prompting
        let runTests = true;
        if (!isCIMode) {
          const confirmation = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'runTests',
              message: `Run dynamic exploitation tests for ${type}?`,
              default: true
            }
          ]);
          runTests = confirmation.runTests;
        }

        if (runTests && isDryRun) {
          // Dry run mode: just show the queue summary without running exploitation
          console.log(chalk.gray(`   📋 [DRY RUN] Would test ${queue.length} ${type.toUpperCase()} vulnerabilities`));
          console.log(chalk.gray(`   Queue: ${path.resolve(outputDir, 'deliverables', `${type}_exploitation_queue.json`)}`));
          console.log(chalk.gray(`   Prompt: ${promptMapping[type] || 'exploit-generic.txt'}`));
          continue;
        }

        if (runTests) {
          const queuePath = path.resolve(outputDir, 'deliverables', `${type}_exploitation_queue.json`);
          const promptFile = promptMapping[type] || 'exploit-generic.txt';
          const promptPath = path.resolve(process.cwd(), 'prompts', promptFile);

          if (!(await fs.pathExists(promptPath))) {
            console.log(chalk.yellow(`⚠️ Prompt template not found: ${promptFile}. Using generic prompt.`));
            const genericPromptPath = path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt');
            if (!(await fs.pathExists(genericPromptPath))) {
              await createGenericPrompt(genericPromptPath);
            }
          }

          plannedAgents.push({
            promptTemplate: await fs.pathExists(promptPath)
              ? promptPath
              : path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt'),
            queuePath,
            targetUrl,
            outputDir,
            name: `${type}-agent`,
            model: modelId
          });
        }
      }
    }

    if (isDryRun) {
      // Dry run mode: show summary of what would be tested
      console.log(chalk.cyan.bold('\n📋 Dry Run Summary'));
      console.log(chalk.gray('─'.repeat(60)));
      let totalWouldTest = 0;
      for (const [type, queue] of Object.entries(queues)) {
        if (cliTypes && !cliTypes.includes(type)) continue;
        if (queue.length > 0) {
          console.log(chalk.gray(`   ${type}: ${queue.length} vulnerabilities`));
          totalWouldTest += queue.length;
        }
      }
      console.log(chalk.cyan(`\n   Total to test: ${totalWouldTest} vulnerabilities`));
      console.log(chalk.gray(`   Provider: ${providerName}/${modelId}`));
      console.log(chalk.gray(`   Target: ${targetUrl}`));
      console.log(chalk.gray('\n   Remove --dry-run to execute the exploitation.'));
      console.log('');
      process.exit(0);
    }

    if (plannedAgents.length > 0) {
      const maxParallelAgents = Number(process.env.DYNAMIC_TESTER_MAX_PARALLEL_AGENTS || 3);
      const parallelLimit = Number.isFinite(maxParallelAgents) && maxParallelAgents > 0
        ? Math.floor(maxParallelAgents)
        : 3;

      console.log(chalk.cyan(`\n🚀 Running ${plannedAgents.length} exploitation agent(s) with parallel limit ${parallelLimit}...`));

      for (let i = 0; i < plannedAgents.length; i += parallelLimit) {
        const batch = plannedAgents.slice(i, i + parallelLimit);
        const results = await executeAgentsInParallel(batch, {
          model: modelId,
          client,
          providerName,
          providerConfig,
          fallbackProviders
        });
        if (results.failed > 0) {
          warnings.push(`${results.failed} exploitation agent(s) failed`);
        }
      }
    }
    
    // Generate reports
    console.log(chalk.blue('\n📋 Generating reports...'));
    const evidenceDir = path.join(outputDir, 'evidence');
    await fs.ensureDir(evidenceDir);
    
    try {
      await generateAllReports(evidenceDir, outputDir, { targetUrl });
    } catch (reportError) {
      console.log(chalk.yellow(`⚠️ Report generation warning: ${reportError.message}`));
      // Fall back to individual report generation
      try {
        await generateDeveloperSummary(evidenceDir, path.join(outputDir, 'developer_summary.json'));
      } catch (e) {
        console.log(chalk.yellow(`⚠️ Developer summary warning: ${e.message}`));
      }
      try {
        await generateSarifReport(evidenceDir, path.join(outputDir, 'report.sarif.json'), { targetUrl });
      } catch (e) {
        console.log(chalk.yellow(`⚠️ SARIF report warning: ${e.message}`));
      }
      try {
        await generateHtmlReport(evidenceDir, path.join(outputDir, 'report.html'), { targetUrl });
      } catch (e) {
        console.log(chalk.yellow(`⚠️ HTML report warning: ${e.message}`));
      }
    }

    // CI mode: generate CI report and exit with appropriate code
    if (isCIMode) {
      console.log(chalk.blue('\n📋 Generating CI report...'));
      try {
        const exitCode = await runCIMode({
          evidenceDir,
          outputDir,
          failOnLikely: ciFailOnLikely,
          failOnBlocked: ciFailOnBlocked
        });
        console.log(chalk.gray(`\nResults saved to: ${outputDir}`));
        process.exit(exitCode);
      } catch (ciError) {
        console.error(chalk.red(`CI report error: ${ciError.message}`));
        process.exit(2);
      }
    }
    
      if (warnings.length > 0) {
        console.log(chalk.yellow(`\n⚠️ Completed with warnings:`));
        warnings.forEach(w => console.log(chalk.yellow(`  • ${w}`)));
      }
      console.log(chalk.green.bold('\n🎉 Dynamic testing session complete!'));
    console.log(chalk.gray(`Results saved to: ${outputDir}`));
    console.log(chalk.gray(`\nOutput files:`));
    console.log(chalk.gray(`  • evidence/              - Individual finding details`));
    console.log(chalk.gray(`  • findings_summary.json  - Quick summary for developers`));
    console.log(chalk.gray(`  • developer_summary.json - Categorized findings`));
    console.log(chalk.gray(`  • report.sarif.json      - SARIF for IDE integration`));
    console.log(chalk.gray(`  • report.html            - Visual HTML report`));
    console.log(chalk.gray(`\nTip: Use --ci flag for CI/CD integration with exit codes`));
    
  } catch (error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}`));
    console.error(error.stack);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Provider / model selection
// ---------------------------------------------------------------------------

/**
 * Prompt the user to select an LLM provider and model.
 * Handles auto-selection when only one provider is available,
 * backward-compatible env-var fallback, CLI flag overrides,
 * and validates stored default models.
 *
 * @returns {Promise<{providerName: string, modelId: string, client: import('openai').default, providerConfig: object, fallbackProviders: Array<{name: string, model: string}>}>}
 */
async function selectProviderAndModel() {
  const config = await loadConfig();
  const configured = await getConfiguredProviders();

  /**
   * Build a fallback list from all configured providers except the chosen one.
   * @param {string} chosenName - Provider being used as primary
   * @returns {Array<{name: string, model: string}>}
   */
  function buildFallbacks(chosenName) {
    return configured
      .filter(p => p.name !== chosenName)
      .map(p => ({ name: p.name, model: p.getDefaultModel() }));
  }

  // If nothing configured and OPENAI_API_KEY is set, auto-use OpenAI
  if (configured.length === 0 && process.env.OPENAI_API_KEY) {
    console.log(chalk.gray('\nUsing OpenAI from OPENAI_API_KEY environment variable.'));
    const provider = getProvider('openai');
    const providerConfig = { apiKey: process.env.OPENAI_API_KEY };
    const client = provider.createClient(providerConfig);
    return { providerName: 'openai', modelId: cliModel || 'gpt-4o', client, providerConfig, fallbackProviders: buildFallbacks('openai') };
  }

  if (configured.length === 0) {
    console.log(chalk.yellow('\nNo LLM providers configured.'));
    console.log(chalk.gray('Run: node src/main.js auth login'));
    console.log(chalk.gray('Or set OPENAI_API_KEY environment variable.'));
    process.exit(1);
  }

  // CLI flag override: --provider=xxx --model=xxx
  if (cliProvider) {
    const providerExists = configured.some(p => p.name === cliProvider);
    if (!providerExists) {
      console.log(chalk.red(`\nProvider "${cliProvider}" is not configured.`));
      console.log(chalk.gray('Configured providers: ' + configured.map(p => p.name).join(', ')));
      process.exit(1);
    }
    const provider = getProvider(cliProvider);
    const providerConfig = await getProviderConfig(cliProvider);
    const client = await createClientForProvider(cliProvider);
    const modelId = cliModel || provider.getDefaultModel();
    console.log(chalk.gray(`\nUsing CLI override: ${cliProvider}/${modelId}`));
    return { providerName: cliProvider, modelId, client, providerConfig, fallbackProviders: buildFallbacks(cliProvider) };
  }

  // CI mode: use stored default or first available provider, no interactive prompts
  if (isCIMode) {
    let providerName;
    let modelId;

    if (config.defaultProvider && config.defaultModel) {
      providerName = config.defaultProvider;
      modelId = config.defaultModel;
    } else {
      // Use first configured provider
      providerName = configured[0].name;
      const provider = getProvider(providerName);
      modelId = provider.getDefaultModel();
    }

    console.log(chalk.gray(`\nCI mode: using ${providerName}/${modelId}`));
    const providerConfig = await getProviderConfig(providerName);
    const client = await createClientForProvider(providerName);
    return { providerName, modelId, client, providerConfig, fallbackProviders: buildFallbacks(providerName) };
  }

  let providerName;
  let modelId;

  // If only one provider is configured, skip the provider selection
  if (configured.length === 1) {
    providerName = configured[0].name;
    console.log(chalk.gray(`\nUsing ${configured[0].displayName} (only configured provider).`));
  } else {
    // Check for stored default
    if (config.defaultProvider && config.defaultModel) {
      if (!isValidProvider(config.defaultProvider)) {
        console.log(chalk.yellow(`\nStored default provider "${config.defaultProvider}" is no longer available.`));
        console.log(chalk.gray('Available providers: ' + getAllProviders().map(p => p.name).join(', ')));
        console.log(chalk.gray('Please select a new provider.\n'));
      } else {
        // Validate that the stored default model is still valid
        const defaultProvider = getProvider(config.defaultProvider);
        const isValid = defaultProvider.isValidModel
          ? defaultProvider.isValidModel(config.defaultModel)
          : true; // Providers without isValidModel are assumed valid

        if (isValid) {
          const { useDefault } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'useDefault',
              message: `Use default provider ${config.defaultProvider}/${config.defaultModel}?`,
              default: true
            }
          ]);
          if (useDefault) {
            const providerConfig = await getProviderConfig(config.defaultProvider);
            const client = await createClientForProvider(config.defaultProvider);
            return { providerName: config.defaultProvider, modelId: config.defaultModel, client, providerConfig, fallbackProviders: buildFallbacks(config.defaultProvider) };
          }
        } else {
          console.log(chalk.yellow(`\nStored default model "${config.defaultModel}" is no longer valid for ${config.defaultProvider}.`));
          console.log(chalk.gray('Please select a new model.\n'));
        }
      }
    }

    // Step 1: Select provider
    const { selectedProvider } = await inquirer.prompt([
      {
        type: 'list',
        name: 'selectedProvider',
        message: 'Select LLM provider:',
        choices: configured.map(p => ({
          name: p.displayName,
          value: p.name
        }))
      }
    ]);
    providerName = selectedProvider;
  }

  // Step 2: Select model (await since getModels() may be async for Google)
  const provider = getProvider(providerName);
  const models = await provider.getModels();

  // If --model flag was provided, use it directly
  if (cliModel) {
    modelId = cliModel;
  } else {
    const { selectedModel } = await inquirer.prompt([
      {
        type: 'list',
        name: 'selectedModel',
        message: 'Select model:',
        choices: models.map(m => ({
          name: `${m.name} — ${m.description}`,
          value: m.id
        })),
        default: provider.getDefaultModel()
      }
    ]);
    modelId = selectedModel;
  }

  const providerConfig = await getProviderConfig(providerName);
  const client = await createClientForProvider(providerName);
  return { providerName, modelId, client, providerConfig, fallbackProviders: buildFallbacks(providerName) };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scan Summary command
// ---------------------------------------------------------------------------

/**
 * Show a quick summary of past scan results from the output directory.
 * Reads findings_summary.json, evidence files, and CI report.
 */
async function scanSummary() {
  const outputDir = cliOutput || './output';
  
  console.log(chalk.cyan.bold('\n📊 Scan Summary'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log(chalk.gray(`Output directory: ${outputDir}`));
  console.log(chalk.gray('─'.repeat(60)));

  const summaryPath = path.join(outputDir, 'findings_summary.json');
  const evidenceDir = path.join(outputDir, 'evidence');
  const ciReportPath = path.join(outputDir, 'ci-report.json');
  
  let findings = [];

  // Try reading findings_summary.json
  try {
    findings = await fs.readJSON(summaryPath);
    if (!Array.isArray(findings)) findings = [];
  } catch (e) {
    // Fall back to reading evidence files
    try {
      if (await fs.pathExists(evidenceDir)) {
        const files = await fs.readdir(evidenceDir);
        for (const file of files) {
          if (file.endsWith('.json') && file.startsWith('evidence-')) {
            try {
              const data = await fs.readJSON(path.join(evidenceDir, file));
              findings.push(data);
            } catch (e) { /* skip corrupt files */ }
          }
        }
      }
    } catch (e) { /* directory doesn't exist */ }
  }

  if (findings.length === 0) {
    console.log(chalk.yellow('\n⚠️  No findings found. Run a scan first.'));
    console.log(chalk.gray(`  Looked for: ${summaryPath}`));
    console.log(chalk.gray(`  Looked for: ${evidenceDir}`));
    process.exit(0);
  }

  // Classify findings
  const confirmed = findings.filter(f => (f.classification || f.status) === 'CONFIRMED');
  const likely = findings.filter(f => (f.classification || f.status) === 'LIKELY');
  const blocked = findings.filter(f => (f.classification || f.status) === 'BLOCKED');
  const notReproducible = findings.filter(f => {
    const c = f.classification || f.status;
    return c === 'NOT_REPRODUCIBLE' || c === 'TESTED_NOT_EXPLOITABLE';
  });

  // Group by type
  const byType = {};
  for (const f of findings) {
    const t = f.type || f.vulnerability?.type || 'Unknown';
    byType[t] = (byType[t] || 0) + 1;
  }

  console.log(chalk.green(`\n✅ Total findings: ${findings.length}`));
  console.log(chalk.red(`   🔴 CONFIRMED:        ${confirmed.length}`));
  console.log(chalk.yellow(`   🟡 LIKELY:           ${likely.length}`));
  console.log(chalk.magenta(`   🟠 BLOCKED:          ${blocked.length}`));
  console.log(chalk.green(`   🟢 NOT REPRODUCIBLE: ${notReproducible.length}`));

  if (confirmed.length > 0) {
    console.log(chalk.red('\n🔴 Confirmed Exploits:'));
    for (const f of confirmed) {
      const loc = f.sourceLocation || {};
      console.log(chalk.red(`   • ${loc.file || f.file || 'unknown'}:${loc.line || f.line || '?'} — ${f.vulnerability?.type || f.type || 'Unknown'} (Level ${f.level ?? '?'})`));
      if (f.exploitation?.endpoint) {
        console.log(chalk.gray(`     Endpoint: ${f.exploitation.endpoint}`));
      }
    }
  }

  if (likely.length > 0) {
    console.log(chalk.yellow('\n🟡 Likely Exploits:'));
    for (const f of likely.slice(0, 10)) {
      const loc = f.sourceLocation || {};
      console.log(chalk.yellow(`   • ${loc.file || f.file || 'unknown'}:${loc.line || f.line || '?'} — ${f.vulnerability?.type || f.type || 'Unknown'}`));
    }
    if (likely.length > 10) {
      console.log(chalk.yellow(`   ... and ${likely.length - 10} more`));
    }
  }

  // Type breakdown
  if (Object.keys(byType).length > 0) {
    console.log(chalk.cyan('\n📊 By Vulnerability Type:'));
    const sorted = Object.entries(byType).sort(([, a], [, b]) => b - a);
    for (const [type, count] of sorted) {
      console.log(chalk.cyan(`   ${type}: ${count}`));
    }
  }

  // CI report if available
  try {
    const ciReport = await fs.readJSON(ciReportPath);
    console.log(chalk.gray(`\n📋 Last CI Report: ${ciReport.exitReason || 'N/A'}`));
    console.log(chalk.gray(`   Exit code: ${ciReport.exitCode}`));
    console.log(chalk.gray(`   Generated: ${ciReport.timestamp || 'N/A'}`));
  } catch (e) { /* no CI report */ }

  console.log('');
  process.exit(0);
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
- browser_http_request: Send HTTP requests and get responses
- save_evidence: Save exploitation evidence
</available_tools>
`;
  await fs.ensureDir(path.dirname(promptPath));
  await fs.writeFile(promptPath, genericPrompt);
}
