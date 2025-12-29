# Dynamic Security Tester

**An AI-powered dynamic security testing tool that bridges static analysis with automated exploitation testing.**

This tool takes vulnerability findings from static analysis tools (like Semgrep) and uses OpenAI's GPT models combined with Playwright browser automation to dynamically test and validate those vulnerabilities against a running web application.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [How It Works](#how-it-works)
- [Module Reference](#module-reference)
- [Prompt Templates](#prompt-templates)
- [Available Browser Tools](#available-browser-tools)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Structure](#output-structure)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)

---

## Overview

The **Dynamic Security Tester** automates the process of validating security vulnerabilities discovered during static analysis. Instead of manually testing each finding, this tool:

1. **Parses** static analysis results (Semgrep JSON format)
2. **Categorizes** vulnerabilities by type (XSS, Injection, SSRF, Secrets, etc.)
3. **Generates** exploitation queues for each category
4. **Deploys** AI agents that use browser automation to test vulnerabilities
5. **Documents** evidence of successful exploits

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   Static Analysis   │────▶│  Dynamic Security    │────▶│   Exploitation      │
│   (Semgrep)         │     │  Tester              │     │   Evidence          │
│   result.json       │     │                      │     │   & Reports         │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           DYNAMIC SECURITY TESTER                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────┐                                                       │
│  │    main.js      │  CLI Entry Point - Interactive prompts                │
│  │    (CLI)        │  Orchestrates the entire workflow                     │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           ▼                                                                │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐      │
│  │  result-parser  │────▶│ queue-generator │────▶│    executor     │      │
│  │                 │     │                 │     │                 │      │
│  │  Parses Semgrep │     │ Groups vulns by │     │ OpenAI Agent    │      │
│  │  JSON output    │     │ type & creates  │     │ with browser    │      │
│  │                 │     │ queue files     │     │ tools           │      │
│  └─────────────────┘     └─────────────────┘     └────────┬────────┘      │
│                                                           │                │
│                                                           ▼                │
│                                              ┌─────────────────┐           │
│                                              │ browser-server  │           │
│                                              │                 │           │
│                                              │ Playwright      │           │
│                                              │ automation      │           │
│                                              │ tools           │           │
│                                              └─────────────────┘           │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
dynamictest/
├── src/
│   ├── main.js                    # CLI entry point and workflow orchestrator
│   ├── agents/
│   │   └── executor.js            # OpenAI agent execution engine
│   ├── mcp/
│   │   └── browser-server.js      # Playwright browser automation tools
│   ├── parser/
│   │   └── result-parser.js       # Semgrep result JSON parser
│   ├── queue/
│   │   └── queue-generator.js     # Vulnerability queue generator
│   └── reporter/                  # (Future) Report generation module
├── prompts/
│   ├── exploit-xss.txt            # XSS exploitation prompt template
│   ├── exploit-injection.txt      # SQL/Command injection prompt
│   ├── exploit-secrets.txt        # Secrets/credentials analysis prompt
│   └── exploit-generic.txt        # Generic vulnerability testing prompt
├── static-analyzer-results/
│   └── result.json                # Semgrep output (input to this tool)
├── output/
│   └── deliverables/              # Generated exploitation queue files
│       ├── xss_exploitation_queue.json
│       ├── injection_exploitation_queue.json
│       ├── secrets_exploitation_queue.json
│       └── crypto_exploitation_queue.json
├── package.json
└── README.md
```

---

## How It Works

### Step 1: Parse Static Analysis Results (`result-parser.js`)

The parser reads a Semgrep JSON result file and extracts vulnerability information:

```javascript
// Input: Semgrep result.json
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss.mustache-escape...",
      "path": "src/routes/search.js",
      "start": { "line": 42, "col": 5 },
      "extra": {
        "message": "Detected user input...",
        "metadata": {
          "cwe": ["CWE-79"],
          "vulnerability_class": ["Cross-Site-Scripting"]
        }
      }
    }
  ]
}
```

The parser maps Semgrep findings to internal vulnerability types:

| Vulnerability Class | Internal Type |
|---------------------|---------------|
| SQL Injection, Command Injection, Code Injection | `injection` |
| Cross-Site Scripting (XSS) | `xss` |
| Server-Side Request Forgery | `ssrf` |
| Hardcoded Secrets, Credentials | `secrets` |
| Cryptographic Issues | `crypto` |
| Authentication Issues | `auth` |
| Everything else | `other` |

### Step 2: Generate Exploitation Queues (`queue-generator.js`)

Groups vulnerabilities by type and creates JSON queue files:

```javascript
// Output: xss_exploitation_queue.json
{
  "vulnerabilities": [
    {
      "id": "javascript.express.security.audit.xss...",
      "checkId": "xss-reflected-input",
      "verdict": "vulnerable",
      "confidence": "MEDIUM",
      "vulnerabilityType": "ReflectedXSS",
      "source": "src/routes/search.js:42",
      "file": "src/routes/search.js",
      "line": 42,
      "description": "User input directly rendered...",
      "cwe": ["CWE-79"],
      "witnessPayload": "<img src=x onerror=alert(1)>"
    }
  ]
}
```

**Witness Payloads**: The queue generator creates initial test payloads:

| Vulnerability Type | Witness Payload |
|--------------------|-----------------|
| SQLi | `' OR '1'='1' --` |
| Command Injection | `; whoami` |
| Eval Injection | `require('child_process').execSync('id')` |
| SSTI | `{{7*7}}` |
| XSS (all types) | `<img src=x onerror=alert(1)>` |

### Step 3: Execute AI Agent (`executor.js`)

The executor creates an OpenAI-powered agent loop:

```
┌─────────────────────────────────────────────────────────────────────┐
│                       AGENT EXECUTION LOOP                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Load prompt template + interpolate variables                    │
│     ({{WEB_URL}}, {{QUEUE_PATH}})                                  │
│                                                                     │
│  2. Send to OpenAI with tool definitions                           │
│     ┌──────────────────────────────────────────────────────────┐   │
│     │  System: You are an XSS Exploitation Specialist...       │   │
│     │  User: Target: http://localhost:3000                     │   │
│     │        Vulnerabilities to test: ...                      │   │
│     └──────────────────────────────────────────────────────────┘   │
│                                                                     │
│  3. Agent calls tools (browser_navigate, browser_fill, etc.)       │
│                                                                     │
│  4. Execute tool, return result to agent                           │
│                                                                     │
│  5. Repeat until agent finishes or max_turns (30) reached          │
│                                                                     │
│  6. Evidence saved to output/evidence/                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

### `src/main.js` - CLI Entry Point

**Purpose**: Interactive command-line interface that orchestrates the entire workflow.

**Key Functions**:
- `main()` - Main entry point, prompts user for:
  - Path to static analyzer result.json
  - Target URL for dynamic testing
  - Output directory
- `createGenericPrompt()` - Creates fallback prompt template if missing

**Prompt Mapping**:
```javascript
const promptMapping = {
  injection: 'exploit-injection.txt',
  xss: 'exploit-xss.txt',
  ssrf: 'exploit-ssrf.txt',
  secrets: 'exploit-secrets.txt',
  auth: 'exploit-auth.txt',
  other: 'exploit-generic.txt'
};
```

---

### `src/parser/result-parser.js` - Static Analysis Parser

**Purpose**: Parse Semgrep JSON output and normalize vulnerabilities.

**Exports**:
```javascript
export async function parseStaticAnalysisResult(resultJsonPath)
```

**Returns**: Array of normalized vulnerability objects:
```javascript
{
  id: string,              // Unique identifier
  type: string,            // Internal type (injection, xss, etc.)
  severity: string,        // ERROR, WARNING, INFO
  confidence: string,      // HIGH, MEDIUM, LOW
  location: {
    file: string,
    line: number,
    column: number,
    endLine: number,
    endColumn: number
  },
  description: string,     // Vulnerability message
  cwe: string[],           // CWE identifiers
  owasp: string[],         // OWASP categories
  vulnerabilityClass: string[],
  checkId: string,         // Original Semgrep check ID
  shortlink: string        // Reference URL
}
```

**Mapping Logic** (in `mapVulnerabilityType()`):
1. Check `vulnerability_class` metadata
2. Check CWE codes
3. Check `check_id` patterns
4. Default to `'other'`

---

### `src/queue/queue-generator.js` - Queue Generator

**Purpose**: Group vulnerabilities by type and generate exploitation queue files.

**Exports**:
```javascript
export async function generateExploitationQueue(vulnerabilities, outputDir)
```

**Queue Categories**:
- `injection` - SQL, Command, Code injection
- `xss` - Cross-Site Scripting
- `ssrf` - Server-Side Request Forgery
- `auth` - Authentication issues
- `secrets` - Hardcoded credentials
- `crypto` - Cryptographic issues
- `other` - Everything else

**Helper Functions**:
- `getVulnerabilitySubType(vuln)` - Determines specific subtype (SQLi, DOMXSS, etc.)
- `generateWitnessPayload(vuln)` - Creates initial test payload

---

### `src/agents/executor.js` - AI Agent Executor

**Purpose**: Execute OpenAI-powered agent for dynamic testing.

**Exports**:
```javascript
export async function executeExploitationAgent(
  promptTemplate,  // Path to prompt .txt file
  queuePath,       // Path to vulnerability queue JSON
  targetUrl,       // Target web application URL
  outputDir,       // Output directory for evidence
  options = {}     // { model: 'gpt-4o-mini' }
)
```

**Returns**:
```javascript
{
  success: boolean,
  turns: number,      // Number of agent turns
  error?: string      // Error message if failed
}
```

**Key Configuration**:
- `MAX_TOOL_RESULT_LENGTH = 8000` - Truncate tool results to avoid token limits
- `maxTurns = 30` - Maximum agent conversation turns
- `max_tokens = 1000` - Limit response size per turn

**Built-in Tools**:
- `save_evidence({ id, type, evidence, payload, success })` - Save exploitation evidence
- `read_queue_file({ filePath })` - Read vulnerability queue (limited to first 5)

---

### `src/mcp/browser-server.js` - Browser Automation

**Purpose**: Playwright-based browser automation tools for the AI agent.

**Class**: `BrowserManager`

**Configuration**:
- `MAX_CONTENT_LENGTH = 15000` - Max chars to return from page
- Headless Chromium browser
- 30-second navigation timeout
- 10-second selector timeout

---

## Available Browser Tools

The AI agent has access to these browser automation tools:

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `browser_navigate` | Navigate to a URL | `url: string` |
| `browser_fill` | Fill a form field | `selector: string, value: string` |
| `browser_click` | Click an element | `selector: string` |
| `browser_type_and_submit` | Type text and press Enter | `selector: string, value: string` |
| `browser_get_response` | Get page information | `extract?: 'summary' \| 'full'` |
| `browser_close` | Close the browser | - |

### `browser_get_response` Details

By default (`extract: 'summary'`), returns:
```javascript
{
  status: 'success',
  url: string,
  title: string,
  forms: [{
    action: string,
    method: string,
    id: string,
    inputs: [{ name, type, id, placeholder }]
  }],
  inputs: [{ name, type, id, placeholder, selector }],
  links: [{ href, text }],
  scripts: [string],  // Script sources
  text: string        // Visible text (first 5000 chars)
}
```

With `extract: 'full'`, returns truncated HTML content.

---

## Prompt Templates

Prompt templates are located in `prompts/` and use placeholder variables:

| Variable | Description |
|----------|-------------|
| `{{WEB_URL}}` | Target web application URL |
| `{{QUEUE_PATH}}` | Path to the vulnerability queue JSON file |

### Template Structure

```xml
<role>
You are an [Specialist Type]. Your goal is to...
</role>

<objective>
Test every vulnerability in the queue file: {{QUEUE_PATH}}
For each vulnerability, generate appropriate payloads...
</objective>

<starting_context>
1. Read the exploitation queue
2. For each vulnerability: [specific steps]
3. Test payloads using browser automation
4. Save findings using save_evidence
</starting_context>

<available_tools>
- browser_navigate: Navigate to a URL
- browser_fill: Fill form fields
- browser_click: Click buttons
- browser_get_response: Get page content
- save_evidence: Save exploitation evidence
</available_tools>

<methodology>
[Specific testing methodology for this vulnerability type]
</methodology>

<deliverable>
Create an evidence file documenting:
- Each vulnerability tested
- Payloads used
- Results (success/failure)
- Proof of exploitation
</deliverable>
```

---

## Installation

### Prerequisites

- Node.js 18+ 
- npm
- OpenAI API key

### Setup

```bash
# Clone or navigate to the project
cd dynamictest

# Install dependencies
npm install

# Set OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Install Playwright browsers
npx playwright install chromium
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `openai` | OpenAI API client |
| `playwright` | Browser automation |
| `chalk` | Terminal colors |
| `inquirer` | Interactive CLI prompts |
| `zx` | Shell scripting utilities |
| `js-yaml` | YAML parsing (if needed) |

---

## Usage

### Basic Usage

```bash
# Run the tool
node src/main.js
```

The interactive CLI will prompt for:
1. **Path to static analyzer result.json** - Semgrep output file
2. **Target URL** - Web application to test (default: http://localhost:3000)
3. **Output directory** - Where to save results (default: ./output)

### Example Session

```
🔍 Dynamic Security Tester (OpenAI Powered)
────────────────────────────────────────────────────────────────

? Path to static analyzer result.json: ./static-analyzer-results/result.json
? Target URL for dynamic testing: http://localhost:3000
? Output directory for results: ./output

Processing:
- Result: ./static-analyzer-results/result.json
- Target: http://localhost:3000
- Output: ./output
────────────────────────────────────────────────

📋 Step 1: Parsing static analysis results...
✅ Parsed 15 vulnerabilities from 20 total findings
   - injection: 5
   - xss: 4
   - secrets: 3
   - crypto: 3

📋 Step 2: Generating exploitation queues...
✅ Created injection_exploitation_queue.json with 5 vulnerabilities
✅ Created xss_exploitation_queue.json with 4 vulnerabilities
✅ Created secrets_exploitation_queue.json with 3 vulnerabilities
✅ Created crypto_exploitation_queue.json with 3 vulnerabilities

📋 Step 3: Reviewing vulnerabilities...

🎯 Found 5 INJECTION vulnerabilities:
   1. SQLi in src/routes/users.js
   2. CommandInjection in src/utils/shell.js
   ... and 3 more

? Run dynamic exploitation tests for injection? (Y/n)
```

---

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENAI_API_KEY` | Your OpenAI API key | Yes |

### Model Selection

The default model is `gpt-4o-mini`. To use a different model, modify `executor.js`:

```javascript
const model = options.model || 'gpt-4o-mini';
```

### Timeouts

Adjust in `browser-server.js`:
```javascript
// Navigation timeout
await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

// Selector timeout
await this.page.waitForSelector(selector, { timeout: 10000 });
```

---

## Output Structure

```
output/
├── deliverables/                      # Exploitation queue files
│   ├── injection_exploitation_queue.json
│   ├── xss_exploitation_queue.json
│   ├── secrets_exploitation_queue.json
│   └── crypto_exploitation_queue.json
└── evidence/                          # Exploitation evidence
    ├── evidence-vuln-001-1703773456.json
    ├── evidence-vuln-002-1703773489.json
    └── ...
```

### Evidence File Format

```javascript
{
  "id": "vuln-001",
  "type": "xss",
  "evidence": "XSS payload executed successfully. Alert box appeared.",
  "payload": "<img src=x onerror=alert(1)>",
  "success": true,
  "timestamp": "2024-12-28T10:30:00.000Z"
}
```

---

## Extending the Tool

### Adding New Vulnerability Types

1. **Update the parser** (`result-parser.js`):
```javascript
// In mapVulnerabilityType()
if (vcLower.includes('your-new-type')) return 'newtype';
```

2. **Add queue category** (`queue-generator.js`):
```javascript
const queues = {
  // ... existing
  newtype: []
};
```

3. **Create prompt template** (`prompts/exploit-newtype.txt`)

4. **Update prompt mapping** (`main.js`):
```javascript
const promptMapping = {
  // ... existing
  newtype: 'exploit-newtype.txt'
};
```

### Adding New Browser Tools

Add to `BrowserManager.getTools()` in `browser-server.js`:

```javascript
{
  name: 'browser_custom_action',
  description: 'Description of what this tool does',
  parameters: {
    type: 'object',
    properties: {
      param1: { type: 'string', description: 'Parameter description' }
    },
    required: ['param1']
  },
  handler: this.customAction.bind(this)
}
```

Then implement the handler method:
```javascript
async customAction({ param1 }) {
  // Implementation
  return { status: 'success', /* ... */ };
}
```

### Adding Custom Evidence Tools

Add to `executor.js` in the `toolHandlers` object:

```javascript
async function custom_tool({ arg1, arg2 }) {
  // Your custom logic
  return { status: 'success', data: result };
}

// Add to tool definitions and toolHandlers
```

---

## Troubleshooting

### Common Issues

**1. "No vulnerabilities found in result.json"**
- Ensure Semgrep output uses `results` or `findings` array
- Check that findings have valid `check_id` and metadata

**2. "Rate limit exceeded"**
- Using `gpt-4o-mini` helps avoid rate limits
- Reduce `maxTurns` in executor.js

**3. "Selector timeout"**
- The target page may be slow or the selector doesn't exist
- Increase timeout in `browser-server.js`
- Use `browser_get_response` to find correct selectors

**4. "Tool result truncated"**
- This is expected behavior to avoid token limits
- Important data should be at the start of responses

### Debug Mode

Add console logging in `executor.js`:
```javascript
console.log('Full response:', JSON.stringify(assistantMessage, null, 2));
```

---

## License

ISC

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

When adding new features:
- Follow existing code patterns
- Update this README
- Add appropriate prompt templates
- Test with real static analysis output
