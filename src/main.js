#!/usr/bin/env node

import dotenv from 'dotenv';
dotenv.config({ quiet: true });

import chalk from 'chalk';
import inquirer from 'inquirer';
import { parseStaticAnalysisResults } from './parser/result-parser.js';
import { generateExploitationQueue } from './queue/queue-generator.js';
import { executeExploitationAgent } from './agents/executor.js';
import { path, fs } from 'zx';
import { getSupportedAnalyzers } from './parser/parser-factory.js';
import { generateSarifReport, generateHtmlReport, generateDeveloperSummary } from './reporting/report-generator.js';
import {
  getProvider,
  getAllProviders,
  getConfiguredProviders,
  createClientForProvider
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
const subcommand = args[0];

// Parse --provider and --model CLI flags (e.g. --provider=copilot --model=gpt-4o)
const cliProvider = args.find(a => a.startsWith('--provider='))?.split('=')[1];
const cliModel = args.find(a => a.startsWith('--model='))?.split('=')[1];

if (subcommand === 'auth') {
  const action = args[1]; // login | status | logout
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
  // ------------------------------------------------------------------
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

  // ------------------------------------------------------------------
  // Prompt 4: Provider and model selection
  // ------------------------------------------------------------------
  const { providerName, modelId, client, providerConfig } = await selectProviderAndModel();

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
      dependency: 'exploit-generic.txt',
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
            const genericPromptPath = path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt');
            if (!(await fs.pathExists(genericPromptPath))) {
              await createGenericPrompt(genericPromptPath);
            }
          }

          const result = await executeExploitationAgent(
            await fs.pathExists(promptPath) ? promptPath : path.resolve(process.cwd(), 'prompts', 'exploit-generic.txt'),
            queuePath,
            targetUrl,
            outputDir,
            { model: modelId, client, providerName, providerConfig }
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

// ---------------------------------------------------------------------------
// Provider / model selection
// ---------------------------------------------------------------------------

/**
 * Prompt the user to select an LLM provider and model.
 * Handles auto-selection when only one provider is available,
 * backward-compatible env-var fallback, CLI flag overrides,
 * and validates stored default models.
 *
 * @returns {Promise<{providerName: string, modelId: string, client: import('openai').default, providerConfig: object}>}
 */
async function selectProviderAndModel() {
  const config = await loadConfig();
  const configured = await getConfiguredProviders();

  // If nothing configured and OPENAI_API_KEY is set, auto-use OpenAI
  if (configured.length === 0 && process.env.OPENAI_API_KEY) {
    console.log(chalk.gray('\nUsing OpenAI from OPENAI_API_KEY environment variable.'));
    const provider = getProvider('openai');
    const providerConfig = { apiKey: process.env.OPENAI_API_KEY };
    const client = provider.createClient(providerConfig);
    return { providerName: 'openai', modelId: cliModel || 'gpt-4o', client, providerConfig };
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
    return { providerName: cliProvider, modelId, client, providerConfig };
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
          return { providerName: config.defaultProvider, modelId: config.defaultModel, client, providerConfig };
        }
      } else {
        console.log(chalk.yellow(`\nStored default model "${config.defaultModel}" is no longer valid for ${config.defaultProvider}.`));
        console.log(chalk.gray('Please select a new model.\n'));
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
  return { providerName, modelId, client, providerConfig };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
