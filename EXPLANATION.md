# 📚 Complete Project Explanation - Dynamic Security Tester

> **Author's Note**: This document explains every aspect of the Dynamic Security Tester tool in elaborate detail. It's designed for someone with zero knowledge about this project to understand exactly how it works.

---

## 📋 Table of Contents

1. [What is This Tool? (Executive Summary)](#1-what-is-this-tool-executive-summary)
2. [Why Does This Tool Exist? (Problem Statement)](#2-why-does-this-tool-exist-problem-statement)
3. [How Does It Work? (High-Level Overview)](#3-how-does-it-work-high-level-overview)
4. [Project Architecture (Visual Diagrams)](#4-project-architecture-visual-diagrams)
5. [File-by-File Explanation](#5-file-by-file-explanation)
6. [Data Flow - Complete Journey](#6-data-flow---complete-journey)
7. [Key Concepts Explained](#7-key-concepts-explained)
8. [Practical Examples with Sample Data](#8-practical-examples-with-sample-data)
9. [Technology Stack Explanation](#9-technology-stack-explanation)
10. [Professor Q&A Section](#10-professor-qa-section)
11. [Glossary of Terms](#11-glossary-of-terms)

---

# 1. What is This Tool? (Executive Summary)

## One-Line Definition
**Dynamic Security Tester** is an AI-powered tool that automatically tests if security vulnerabilities found by static code analyzers are actually exploitable in a running web application.

## Simple Explanation (Non-Technical)

Imagine you have a security scanner that reads your code and says: *"Hey, there might be a problem on line 42 of your login file - someone could potentially steal data."*

But here's the problem: **These scanners often cry wolf!** They find 100 "potential" problems, but maybe only 10 are real issues. Developers waste time fixing things that were never actually dangerous.

**This tool solves that problem by:**
1. Taking those "potential" problems
2. Actually TRYING to exploit them on your running website
3. Telling you: "Yes, this one is REAL and dangerous!" or "No, this one is fine - your security controls blocked it."

## Technical Definition

This is a **Dynamic Application Security Testing (DAST)** tool that:
- **Parses** output from static analysis tools (Semgrep, Trivy, CodeQL, etc.)
- **Uses AI (GPT-4)** to generate intelligent attack payloads
- **Automates browser testing** with Playwright
- **Produces evidence** and reports showing which vulnerabilities are confirmed

---

# 2. Why Does This Tool Exist? (Problem Statement)

## The Gap Between Static and Dynamic Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    THE SECURITY TESTING GAP                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STATIC ANALYSIS (SAST)              DYNAMIC ANALYSIS (DAST)                │
│  ──────────────────────              ───────────────────────                │
│                                                                              │
│  ✓ Scans source code                 ✓ Tests running application            │
│  ✓ Finds potential vulns             ✓ Confirms actual exploits             │
│  ✓ Fast - no app needed              ✓ Proves real impact                   │
│                                                                              │
│  ✗ High false positive rate          ✗ Slow manual process                  │
│  ✗ Can't prove exploitability        ✗ Requires security expertise          │
│  ✗ No runtime context                ✗ May miss code-level issues           │
│                                                                              │
│                          ┌─────────────────┐                                │
│                          │                 │                                │
│                          │   THIS TOOL     │                                │
│                          │   BRIDGES THE   │                                │
│                          │      GAP        │                                │
│                          │                 │                                │
│                          └─────────────────┘                                │
│                                                                              │
│  Takes SAST output ────────────────────────▶ Produces DAST proof            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Real-World Problem Example

A static analyzer (Semgrep) might report:

```
⚠️ WARNING: SQL Injection vulnerability detected
   File: routes/users.js
   Line: 42
   Code: db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
```

But is this ACTUALLY exploitable? Maybe:
- The application has input validation elsewhere
- A Web Application Firewall (WAF) blocks attacks
- The database user has limited permissions

**This tool answers that question definitively.**

---

# 3. How Does It Work? (High-Level Overview)

## The 5-Step Process

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         HOW THE TOOL WORKS                                │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  STEP 1: PARSE                                                            │
│  ─────────────────                                                        │
│  Read JSON files from security scanners (Semgrep, Trivy, etc.)           │
│  Convert to unified format                                                │
│                                                                           │
│           ▼                                                               │
│                                                                           │
│  STEP 2: CATEGORIZE                                                       │
│  ─────────────────────                                                    │
│  Group vulnerabilities by type:                                           │
│  • SQL Injection → injection queue                                        │
│  • XSS → xss queue                                                        │
│  • Hardcoded secrets → secrets queue                                      │
│                                                                           │
│           ▼                                                               │
│                                                                           │
│  STEP 3: TEST WITH AI                                                     │
│  ────────────────────────                                                 │
│  For each vulnerability:                                                  │
│  • GPT-4 analyzes the code context                                        │
│  • Generates smart attack payloads                                        │
│  • Uses Playwright browser to test them                                   │
│                                                                           │
│           ▼                                                               │
│                                                                           │
│  STEP 4: COLLECT EVIDENCE                                                 │
│  ──────────────────────────                                               │
│  Save detailed proof for each test:                                       │
│  • What payload was used                                                  │
│  • What response was received                                             │
│  • Was it exploitable? YES/NO                                             │
│                                                                           │
│           ▼                                                               │
│                                                                           │
│  STEP 5: GENERATE REPORTS                                                 │
│  ─────────────────────────                                                │
│  Create output files:                                                     │
│  • SARIF (for IDEs like VS Code)                                          │
│  • HTML (for human review)                                                │
│  • JSON summary (for developers)                                          │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# 4. Project Architecture (Visual Diagrams)

## 4.1 Overall System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DYNAMIC SECURITY TESTER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐  │
│  │   Parser    │──▶│   Queue     │──▶│  Executor   │──▶│    Reports      │  │
│  │             │   │  Generator  │   │             │   │                 │  │
│  │ Semgrep     │   │             │   │ OpenAI GPT  │   │ • SARIF         │  │
│  │ Trivy       │   │ Groups by   │   │ LLM Agent   │   │ • HTML          │  │
│  │ CodeQL      │   │ vuln type   │   │ + Browser   │   │ • JSON Summary  │  │
│  │ Syft/OSV    │   │             │   │             │   │                 │  │
│  │ Gitleaks    │   │             │   │             │   │                 │  │
│  │ Noir        │   │             │   │             │   │                 │  │
│  └─────────────┘   └─────────────┘   └──────┬──────┘   └─────────────────┘  │
│                                             │                                │
│                                             ▼                                │
│                                    ┌────────────────┐                        │
│                                    │ Browser Manager│                        │
│                                    │                │                        │
│                                    │ • Navigate     │                        │
│                                    │ • Fill forms   │                        │
│                                    │ • HTTP requests│                        │
│                                    │ • Screenshots  │                        │
│                                    └───────┬────────┘                        │
│                                            │                                 │
│                                            ▼                                 │
│                                    ┌────────────────┐                        │
│                                    │  Auth Manager  │                        │
│                                    │                │                        │
│                                    │ • JWT tokens   │                        │
│                                    │ • Cookies      │                        │
│                                    │ • Headers      │                        │
│                                    └────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.2 Directory Structure Explained

```
dynamictester/
│
├── src/                              # 📁 SOURCE CODE (Main application)
│   ├── main.js                       # 🚀 Entry point - orchestrates everything
│   │
│   ├── agents/                       # 🤖 AI Agent Components
│   │   └── executor.js               # GPT-4 agent that tests vulnerabilities
│   │
│   ├── auth/                         # 🔐 Authentication Management
│   │   └── auth-manager.js           # Stores JWT tokens and cookies
│   │
│   ├── mcp/                          # 🌐 Browser Automation
│   │   └── browser-server.js         # Playwright browser tools (13 functions)
│   │
│   ├── parser/                       # 📄 Input Parsing System
│   │   ├── parser-factory.js         # Detects which scanner produced input
│   │   ├── result-parser.js          # Main parser coordinator
│   │   ├── normalizer.js             # Converts to standard format
│   │   ├── validator.js              # Validates input data
│   │   └── parsers/                  # Individual parser implementations
│   │       ├── semgrep-parser.js     # Parses Semgrep output
│   │       ├── trivy-parser.js       # Parses Trivy output
│   │       ├── codeql-parser.js      # Parses CodeQL output
│   │       └── ... (more parsers)
│   │
│   ├── queue/                        # 📋 Queue Management
│   │   └── queue-generator.js        # Groups vulns by type
│   │
│   ├── reporting/                    # 📊 Report Generation
│   │   ├── report-generator.js       # Creates SARIF, HTML, JSON reports
│   │   └── ci-reporter.js            # CI/CD integration (exit codes)
│   │
│   ├── testing/                      # 🧪 Testing Logic
│   │   ├── exploitation-levels.js    # 4-level proof system (L0-L4)
│   │   ├── classifier.js             # CONFIRMED/LIKELY/BLOCKED classification
│   │   ├── payload-generator.js      # AI payload generation
│   │   ├── bypass-engine.js          # WAF bypass generation
│   │   └── response-analyzer.js      # Detects DB errors, WAF blocks
│   │
│   └── utils/                        # 🔧 Utility Functions
│       ├── rate-limiter.js           # API rate limit handling
│       └── error-handling.js         # Error management
│
├── prompts/                          # 📝 AI PROMPT TEMPLATES
│   ├── exploit-injection.txt         # Instructions for SQL/Command injection
│   ├── exploit-xss.txt               # Instructions for XSS testing
│   ├── exploit-traversal.txt         # Instructions for path traversal
│   ├── exploit-xxe.txt               # Instructions for XXE testing
│   ├── exploit-redirect.txt          # Instructions for open redirect
│   ├── exploit-secrets.txt           # Instructions for secrets validation
│   └── exploit-generic.txt           # Generic testing template
│
├── [output directories]/             # 📦 OUTPUT DATA (generated)
│   ├── deliverables/                 # Exploitation queues
│   │   ├── injection_exploitation_queue.json
│   │   ├── xss_exploitation_queue.json
│   │   └── ...
│   └── evidence/                     # Test evidence files
│       └── evidence-*.json
│
├── package.json                      # 📦 NPM dependencies
├── README.md                         # 📖 Project documentation
└── MULTI_ANALYZER_USAGE.md           # 📖 Multi-analyzer guide
```

---

# 5. File-by-File Explanation

## 5.1 Entry Point: `src/main.js`

### What It Does
This is the **starting point** of the application. When you run `node src/main.js`, this file executes first.

### Step-by-Step Breakdown

```javascript
#!/usr/bin/env node    // ← This tells Linux/Mac this is a Node.js script

// STEP 1: Import Dependencies
import chalk from 'chalk';           // For colored console output
import inquirer from 'inquirer';     // For interactive prompts
import { parseStaticAnalysisResults } from './parser/result-parser.js';
import { generateExploitationQueue } from './queue/queue-generator.js';
import { executeExploitationAgent } from './agents/executor.js';
// ... more imports
```

### Main Function Flow

```javascript
async function main() {
    // 1. Show welcome message
    console.log('🔍 Dynamic Security Tester');
    
    // 2. Ask user for input (interactive prompts)
    const answers = await inquirer.prompt([
        {
            name: 'resultJsonPath',
            message: 'Path to analyzer result file(s):',
            // Example: "./semgrep-results.json"
        },
        {
            name: 'targetUrl', 
            message: 'Target URL for testing:',
            default: 'http://localhost:3000'
        },
        {
            name: 'outputDir',
            message: 'Output directory:',
            default: './output'
        }
    ]);
    
    // 3. Parse the static analysis results
    const { vulnerabilities, summary } = await parseStaticAnalysisResults(resultPaths);
    
    // 4. Group vulnerabilities by type (SQL injection, XSS, etc.)
    const queues = await generateExploitationQueue(vulnerabilities, outputDir);
    
    // 5. For each vulnerability type, run AI-powered tests
    for (const [type, queue] of Object.entries(queues)) {
        if (queue.length > 0) {
            // Ask user: "Run tests for SQL injection?"
            const { runTests } = await inquirer.prompt([...]);
            
            if (runTests) {
                // Execute the AI agent to test these vulnerabilities
                await executeExploitationAgent(promptPath, queuePath, targetUrl, outputDir);
            }
        }
    }
    
    // 6. Generate final reports
    await generateSarifReport(evidenceDir, outputPath);
    await generateHtmlReport(evidenceDir, outputPath);
    await generateDeveloperSummary(evidenceDir, outputPath);
}
```

### Real Example of Running the Tool

```bash
$ node src/main.js

🔍 Dynamic Security Tester (OpenAI Powered)
────────────────────────────────────────────────────────────────
Supported analyzers: semgrep, gitleaks, trivy, osv, syft, noir, codeql
────────────────────────────────────────────────────────────────

? Path to analyzer result file(s): ./semgrep-results.json
? Target URL for dynamic testing: http://localhost:3000
? Output directory for results: ./output

📋 Step 1: Parsing static analysis results...
   ✓ Detected: semgrep
   ✓ Parsed 15 vulnerabilities

📋 Step 2: Generating exploitation queues...
✅ Created injection_exploitation_queue.json with 5 vulnerabilities
✅ Created xss_exploitation_queue.json with 4 vulnerabilities

📋 Step 3: Reviewing vulnerabilities...

🎯 Found 5 INJECTION vulnerabilities:
   1. SQLi in semgrep
   2. SQLi in semgrep
   ...

? Run dynamic exploitation tests for injection? Yes

🚀 Starting OpenAI exploitation agent (gpt-4o)...
```

---

## 5.2 AI Agent: `src/agents/executor.js`

### What It Does
This is the **brain** of the tool. It uses OpenAI's GPT-4 model to:
1. Read vulnerability information
2. Decide what payloads to try
3. Control a browser to test them
4. Save evidence of results

### How the AI Agent Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI AGENT WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SYSTEM PROMPT                                                               │
│  ─────────────                                                               │
│  "You are a security expert. Test vulnerabilities at {{WEB_URL}}            │
│   Read the queue file at {{QUEUE_PATH}} and test each one."                 │
│                                                                              │
│         ▼                                                                    │
│  ┌──────────────┐                                                            │
│  │   GPT-4      │ ←────── "I need to test SQLi at /api/users"               │
│  │   Model      │                                                            │
│  └──────┬───────┘                                                            │
│         │                                                                    │
│         │ Tool Call: browser_http_request                                    │
│         │ {url: "/api/users?id=' OR '1'='1'--", method: "GET"}              │
│         ▼                                                                    │
│  ┌──────────────┐                                                            │
│  │  Playwright  │ ────────▶ Makes actual HTTP request                       │
│  │   Browser    │                                                            │
│  └──────┬───────┘                                                            │
│         │                                                                    │
│         │ Response: {"users": [...all users...]}                            │
│         ▼                                                                    │
│  ┌──────────────┐                                                            │
│  │   GPT-4      │ ←────── "Payload worked! All users returned."             │
│  │   Analyzes   │                                                            │
│  └──────┬───────┘                                                            │
│         │                                                                    │
│         │ Tool Call: save_evidence                                           │
│         │ {id: "sqli-123", success: true, proof: "Returned all users"}      │
│         ▼                                                                    │
│  ┌──────────────┐                                                            │
│  │   Evidence   │ ────────▶ evidence-sqli-123-1706012345.json               │
│  │   Saved      │                                                            │
│  └──────────────┘                                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Code Sections Explained

#### 1. Setting Up the AI Agent

```javascript
export async function executeExploitationAgent(promptTemplate, queuePath, targetUrl, outputDir) {
    const model = 'gpt-4o';  // Use GPT-4 model
    
    // Load the prompt template (e.g., exploit-injection.txt)
    let systemPrompt = await fs.readFile(promptTemplate, 'utf8');
    
    // Replace placeholders with actual values
    systemPrompt = systemPrompt
        .replace(/{{WEB_URL}}/g, targetUrl)       // http://localhost:3000
        .replace(/{{QUEUE_PATH}}/g, queuePath);   // ./output/injection_queue.json
```

#### 2. Available Tools for GPT-4

The AI has access to these **tools** (functions it can call):

| Tool Name | What It Does | Example Use |
|-----------|--------------|-------------|
| `browser_navigate` | Go to a URL | Navigate to login page |
| `browser_fill` | Fill form fields | Enter username/password |
| `browser_click` | Click buttons | Click "Submit" button |
| `browser_http_request` | Make HTTP requests | Test API endpoints directly |
| `browser_capture_auth` | Capture JWT tokens | Store authentication for later use |
| `save_evidence` | Save test results | Record if exploit worked |
| `read_queue_file` | Read vulnerability queue | Get list of vulns to test |

#### 3. The Conversation Loop

```javascript
const messages = [
    { role: 'system', content: systemPrompt },      // Instructions
    { role: 'user', content: 'Start testing...' }  // Initial command
];

let turnCount = 0;
const maxTurns = 50;  // Maximum iterations

while (turnCount < maxTurns) {
    // Ask GPT-4 what to do next
    const response = await openai.chat.completions.create({
        model: model,
        messages: messages,
        tools: tools,           // Available browser tools
        tool_choice: 'auto',    // Let GPT-4 decide which tool to use
    });
    
    // If GPT-4 wants to use a tool
    if (response.tool_calls) {
        for (const toolCall of response.tool_calls) {
            // Execute the tool (e.g., browser_http_request)
            const result = await toolHandlers[toolCall.name](toolCall.arguments);
            
            // Send the result back to GPT-4
            messages.push({ role: 'tool', content: result });
        }
    }
    
    // Check if GPT-4 is done
    if (response.finish_reason === 'stop') break;
}
```

---

## 5.3 Browser Automation: `src/mcp/browser-server.js`

### What It Does
This file provides **browser automation** using Playwright. It's like a remote control for a web browser that the AI can use.

### The BrowserManager Class

```javascript
export class BrowserManager {
    constructor() {
        this.browser = null;   // Chromium browser instance
        this.page = null;      // Current page
        this.authManager = getAuthManager();  // For storing authentication
    }
    
    // Start the browser when needed
    async ensureBrowser() {
        if (!this.browser) {
            this.browser = await chromium.launch({ headless: true });
            this.page = await this.browser.newPage();
        }
    }
}
```

### 13 Available Browser Tools

Here's every tool the AI can use:

#### Navigation Tools
```javascript
// 1. Navigate to URL
async navigate({ url }) {
    await this.page.goto(url);
    return { status: 'success', url, title: await this.page.title() };
}

// Example: navigate({ url: 'http://localhost:3000/login' })
```

#### Form Interaction Tools
```javascript
// 2. Fill a form field
async fill({ selector, value }) {
    await this.page.fill(selector, value);
    return { status: 'success', selector, value };
}
// Example: fill({ selector: '#username', value: 'admin' })

// 3. Click an element
async click({ selector }) {
    await this.page.click(selector);
    return { status: 'success', selector };
}
// Example: click({ selector: '#submit-button' })

// 4. Force click (using JavaScript, bypasses visibility checks)
async forceClick({ selector }) {
    await this.page.evaluate((sel) => document.querySelector(sel).click(), selector);
    return { status: 'success' };
}

// 5. Type and press Enter
async typeAndSubmit({ selector, value }) {
    await this.page.fill(selector, value);
    await this.page.press(selector, 'Enter');
    return { status: 'success' };
}
```

#### Information Extraction Tools
```javascript
// 6. Get page response (forms, inputs, buttons)
async getResponse() {
    return {
        url: this.page.url(),
        title: await this.page.title(),
        forms: await this.extractForms(),
        inputs: await this.extractInteractableInputs(),
        buttons: await this.extractButtons(),
        errors: await this.extractErrorMessages()  // Important for detecting SQL errors!
    };
}
```

#### HTTP Request Tool (Most Important!)
```javascript
// 7. Make direct HTTP request (bypasses browser UI)
async httpRequest({ url, method, headers, body, useAuth }) {
    const authHeaders = useAuth ? this.authManager.getAuthHeaders() : {};
    
    const response = await fetch(url, {
        method: method || 'GET',
        headers: { ...headers, ...authHeaders },
        body: body ? JSON.stringify(body) : undefined
    });
    
    return {
        status: response.status,
        body: await response.text()
    };
}

// Example: Testing SQL injection directly
// httpRequest({ 
//     url: "http://localhost:3000/api/users?id=' OR '1'='1'--",
//     method: 'GET',
//     useAuth: true
// })
```

#### Authentication Tools
```javascript
// 8. Capture authentication tokens
async captureAuth() {
    // Get JWT from localStorage
    const jwt = await this.page.evaluate(() => {
        return localStorage.getItem('token') || 
               localStorage.getItem('jwt') ||
               localStorage.getItem('accessToken');
    });
    
    // Get cookies
    const cookies = await this.context.cookies();
    
    // Store in AuthManager for later use
    this.authManager.setJwtToken(jwt);
    this.authManager.setCookies(cookies);
    
    return { status: 'success', hasAuth: this.authManager.hasAuth() };
}
```

### Smart Features

#### Auto-Detecting Alternative Selectors
If a selector doesn't work, the tool suggests alternatives:

```javascript
async findAlternativeSelector(originalSelector) {
    // Find all visible, enabled inputs on the page
    const alternatives = await this.page.evaluate(() => {
        const inputs = document.querySelectorAll('input');
        return inputs
            .filter(input => input.offsetParent !== null && !input.disabled)
            .map(input => ({
                selector: input.id ? `#${input.id}` : `[name="${input.name}"]`,
                type: input.type,
                placeholder: input.placeholder
            }));
    });
    return alternatives;
}

// If AI tries: fill({ selector: '#email' })
// But #email doesn't exist, it returns:
// "Try these instead: [name='user_email'], [placeholder='Enter email']"
```

---

## 5.4 Parser System: `src/parser/`

### What It Does
The parser system converts output from different security scanners into a **unified format** that the rest of the tool can understand.

### Why Do We Need This?

Different scanners output different JSON formats:

```
Semgrep Output:              Trivy Output:               Gitleaks Output:
{                            {                           [
  "results": [                 "Results": [                {
    "check_id": "...",           "Vulnerabilities": [        "Secret": "...",
    "path": "...",               { "VulnerabilityID":        "File": "...",
    "start": { "line": 1 }       }]                          "Line": 1
  }]                           }]                          }
}                            }                           ]
```

We need to convert all of these to ONE format!

### Parser Factory: `parser-factory.js`

```javascript
// Automatically detect which scanner produced the output
export function detectAnalyzerType(data) {
    // Semgrep: has 'results' array and 'version' field
    if (data.results && data.version) {
        return 'semgrep';
    }
    
    // Gitleaks: has 'Findings' array or array with 'Secret'
    if (data.Findings || (Array.isArray(data) && data[0]?.Secret !== undefined)) {
        return 'gitleaks';
    }
    
    // Trivy: has 'Results' with 'Vulnerabilities'
    if (data.Results && Array.isArray(data.Results)) {
        return 'trivy';
    }
    
    // ... more detections
    
    return null;  // Unknown format
}

// Create the right parser for the detected type
export function createParser(analyzerType) {
    const parsers = {
        semgrep: SemgrepParser,
        gitleaks: GitleaksParser,
        trivy: TrivyParser,
        osv: OsvParser,
        syft: SyftParser,
        noir: NoirParser,
        codeql: CodeQLParser
    };
    
    return new parsers[analyzerType]();
}
```

### Normalizer: `normalizer.js`

Converts raw data to standard values:

```javascript
// Standardize severity levels
export function normalizeSeverity(severity) {
    const s = String(severity).toUpperCase();
    
    if (['CRITICAL', 'BLOCKER'].includes(s)) return 'CRITICAL';
    if (['HIGH', 'ERROR'].includes(s)) return 'HIGH';
    if (['MEDIUM', 'WARNING'].includes(s)) return 'MEDIUM';
    if (['LOW', 'MINOR'].includes(s)) return 'LOW';
    if (['INFO', 'NOTE'].includes(s)) return 'INFO';
    
    return 'MEDIUM';  // Default
}

// Categorize vulnerabilities by type
export function categorizeVulnerability(vuln) {
    const text = vuln.description.toLowerCase();
    
    // Check for SQL injection indicators
    if (/sql.*injection|cwe-89/.test(text)) {
        return { type: 'injection', subType: 'SQLi' };
    }
    
    // Check for XSS indicators
    if (/xss|cross.*site.*script|cwe-79/.test(text)) {
        return { type: 'xss', subType: 'ReflectedXSS' };
    }
    
    // Check for hardcoded secrets
    if (/secret|password|api[_-]?key|token/.test(text)) {
        return { type: 'secrets', subType: 'HardcodedSecret' };
    }
    
    // ... more categories
    
    return { type: 'other', subType: 'Unknown' };
}
```

### Semgrep Parser Example: `parsers/semgrep-parser.js`

```javascript
export class SemgrepParser extends BaseParser {
    constructor() {
        super('semgrep');
    }
    
    async parse(data) {
        const findings = data.results || [];
        const vulnerabilities = [];
        
        for (const finding of findings) {
            // Determine vulnerability type
            const { type, subType } = categorizeVulnerability({
                checkId: finding.check_id,
                description: finding.extra?.message,
                cwe: finding.extra?.metadata?.cwe
            });
            
            // Create normalized vulnerability object
            vulnerabilities.push({
                id: finding.check_id,
                source: 'semgrep',
                type: type,                    // e.g., 'injection'
                subType: subType,              // e.g., 'SQLi'
                severity: normalizeSeverity(finding.extra?.severity),
                location: {
                    file: finding.path,        // e.g., 'routes/users.js'
                    line: finding.start?.line, // e.g., 42
                    column: finding.start?.col,
                    snippet: finding.extra?.lines
                },
                description: finding.extra?.message,
                cwe: finding.extra?.metadata?.cwe || [],
                owasp: finding.extra?.metadata?.owasp || []
            });
        }
        
        return vulnerabilities;
    }
}
```

---

## 5.5 Queue Generator: `src/queue/queue-generator.js`

### What It Does
Takes all parsed vulnerabilities and **groups them by type**, creating separate queue files for each category.

```javascript
export async function generateExploitationQueue(vulnerabilities, outputDir) {
    // Initialize empty queues for each type
    const queues = {
        injection: [],   // SQL injection, command injection
        xss: [],         // Cross-site scripting
        ssrf: [],        // Server-side request forgery
        secrets: [],     // Hardcoded credentials
        traversal: [],   // Path traversal
        xxe: [],         // XML external entity
        redirect: [],    // Open redirect
        other: []        // Everything else
    };
    
    // Sort each vulnerability into the right queue
    for (const vuln of vulnerabilities) {
        const queueType = vuln.type || 'other';
        
        queues[queueType].push({
            id: vuln.id,
            source: vuln.source,           // 'semgrep'
            vulnerabilityType: vuln.subType, // 'SQLi'
            file: vuln.location.file,       // 'routes/users.js'
            line: vuln.location.line,       // 42
            column: vuln.location.column,   // 5
            snippet: vuln.location.snippet, // 'db.query(...)'
            description: vuln.description,
            cwe: vuln.cwe,                  // ['CWE-89']
            witnessPayload: generateWitnessPayload(vuln)  // "' OR '1'='1' --"
        });
    }
    
    // Save each queue to a file
    for (const [type, queue] of Object.entries(queues)) {
        if (queue.length > 0) {
            const filePath = `${outputDir}/deliverables/${type}_exploitation_queue.json`;
            await fs.writeJSON(filePath, { vulnerabilities: queue });
            console.log(`✅ Created ${type}_exploitation_queue.json with ${queue.length} vulns`);
        }
    }
    
    return queues;
}
```

### Generating Witness Payloads

```javascript
// Create initial test payloads based on vulnerability type
function generateWitnessPayload(vuln) {
    const subType = vuln.subType;
    
    // SQL Injection payloads
    if (subType === 'SQLi') {
        return "' OR '1'='1' --";
    }
    
    // Command Injection payloads
    if (subType === 'CommandInjection') {
        return "; whoami";
    }
    
    // XSS payloads
    if (vuln.type === 'xss') {
        return "<img src=x onerror=alert(1)>";
    }
    
    // Server-Side Template Injection
    if (subType === 'SSTI') {
        return "{{7*7}}";  // If vulnerable, will return 49
    }
    
    // SSRF payloads
    if (vuln.type === 'ssrf') {
        return "http://169.254.169.254/latest/meta-data/";  // AWS metadata endpoint
    }
    
    return "test_payload";  // Default
}
```

---

## 5.6 Authentication Manager: `src/auth/auth-manager.js`

### What It Does
Stores and manages authentication tokens (JWT, cookies) captured from browser sessions. These are then automatically included in subsequent HTTP requests.

### Why Is This Important?

Most real-world applications require login. Without capturing authentication:
- The tool would get "401 Unauthorized" errors
- It couldn't test protected endpoints
- Most vulnerabilities would appear unexploitable

### The AuthManager Class

```javascript
export class AuthManager {
    constructor() {
        this.jwtToken = null;      // JWT token (e.g., "eyJhbGciOiJI...")
        this.bearerToken = null;   // Bearer token
        this.cookies = {};         // Session cookies
        this.customHeaders = {};   // Custom auth headers
    }
    
    // Store a JWT token
    setJwtToken(token, source = 'localStorage') {
        // Validate JWT format (3 parts separated by dots)
        const parts = token.split('.');
        if (parts.length !== 3) {
            // Not a JWT, might be a simple bearer token
            this.bearerToken = token;
            return { success: true, type: 'bearer' };
        }
        
        this.jwtToken = token;
        return { success: true, type: 'jwt', source };
    }
    
    // Store cookies
    setCookies(cookies) {
        if (Array.isArray(cookies)) {
            cookies.forEach(cookie => {
                this.cookies[cookie.name] = cookie.value;
            });
        }
        return { success: true, cookieCount: Object.keys(this.cookies).length };
    }
    
    // Get all auth headers for HTTP requests
    getAuthHeaders() {
        const headers = {};
        
        // Add Authorization header
        if (this.jwtToken) {
            headers['Authorization'] = `Bearer ${this.jwtToken}`;
        }
        
        // Add Cookie header
        if (Object.keys(this.cookies).length > 0) {
            headers['Cookie'] = Object.entries(this.cookies)
                .map(([name, value]) => `${name}=${value}`)
                .join('; ');
        }
        
        return headers;
    }
}
```

### Common JWT Storage Keys

```javascript
// The tool looks for tokens in these common locations
static get JWT_STORAGE_KEYS() {
    return [
        'token',        // Most common
        'jwt',
        'jwtToken',
        'jwt_token',
        'accessToken',
        'access_token',
        'authToken',
        'auth_token',
        'id_token',
        'Authorization'
    ];
}
```

---

## 5.7 Report Generator: `src/reporting/report-generator.js`

### What It Does
Creates **three types of reports** from the evidence files:
1. **SARIF** - For IDE integration (VS Code, GitHub)
2. **HTML** - For human review
3. **JSON** - For developers

### SARIF Report Generation

SARIF (Static Analysis Results Interchange Format) is an industry-standard format that IDEs understand.

```javascript
export async function generateSarifReport(evidenceDir, outputPath) {
    // Collect all evidence files
    const evidenceFiles = await fs.readdir(evidenceDir);
    const findings = [];
    
    for (const file of evidenceFiles) {
        if (file.endsWith('.json') && file.startsWith('evidence-')) {
            const data = await fs.readJSON(path.join(evidenceDir, file));
            findings.push(data);
        }
    }
    
    // Build SARIF structure
    const sarif = {
        "$schema": "https://sarif-schema...",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DynamicSecurityTester",
                    "version": "1.0.0"
                }
            },
            "results": findings.map(finding => ({
                "ruleId": finding.vulnerability?.cwe || "UNKNOWN",
                "level": finding.exploitation?.success ? "error" : "warning",
                "message": {
                    "text": `${finding.vulnerability?.type} at ${finding.sourceLocation?.file}:${finding.sourceLocation?.line}`
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.sourceLocation?.file
                        },
                        "region": {
                            "startLine": finding.sourceLocation?.line
                        }
                    }
                }]
            }))
        }]
    };
    
    await fs.writeJSON(outputPath, sarif);
}
```

### HTML Report Generation

Creates a visual report with:
- Summary statistics
- Confirmed vs not exploitable counts
- Details of each finding

```javascript
export async function generateHtmlReport(evidenceDir, outputPath, metadata) {
    const findings = await collectFindings(evidenceDir);
    
    // Sort by status (confirmed first)
    findings.sort((a, b) => {
        if (a.status === 'CONFIRMED' && b.status !== 'CONFIRMED') return -1;
        if (b.status === 'CONFIRMED' && a.status !== 'CONFIRMED') return 1;
        return 0;
    });
    
    const confirmedCount = findings.filter(f => f.status === 'CONFIRMED').length;
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Test Report</title>
        <style>
            /* Dark theme, modern styling */
            body { background: #0f172a; color: #e2e8f0; }
            .stat-value.confirmed { color: #ef4444; }  /* Red for confirmed */
            .finding.confirmed { border-left: 4px solid #ef4444; }
        </style>
    </head>
    <body>
        <h1>🔒 Dynamic Security Test Report</h1>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value confirmed">${confirmedCount}</div>
                <div class="stat-label">Confirmed Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-value">${findings.length}</div>
                <div class="stat-label">Total Tested</div>
            </div>
        </div>
        
        <!-- Individual findings -->
        ${findings.map(f => `
            <div class="finding ${f.status === 'CONFIRMED' ? 'confirmed' : ''}">
                <h3>${f.vulnerability?.type}</h3>
                <p>File: ${f.sourceLocation?.file}:${f.sourceLocation?.line}</p>
                <p>Payload: ${f.exploitation?.payload}</p>
                <p>Status: ${f.status}</p>
            </div>
        `).join('')}
    </body>
    </html>
    `;
    
    await fs.writeFile(outputPath, html);
}
```

---

## 5.8 Exploitation Levels: `src/testing/exploitation-levels.js`

### What It Does
Defines a **4-level classification system** for measuring how successful an exploitation attempt was.

### The 5 Levels (0-4)

```javascript
export const ExploitationLevels = {
    LEVEL_0: {
        level: 0,
        name: 'No Exploitation',
        classification: 'NOT_REPRODUCIBLE',
        description: 'No vulnerability found - security controls working'
    },
    
    LEVEL_1: {
        level: 1,
        name: 'Injection Point Confirmed',
        classification: 'LIKELY',
        description: 'Errors observed, but no data extracted yet'
    },
    
    LEVEL_2: {
        level: 2,
        name: 'Query Structure Manipulated',
        classification: 'LIKELY',
        description: 'Can modify query structure (UNION, ORDER BY work)'
    },
    
    LEVEL_3: {
        level: 3,
        name: 'Data Extraction Proven',
        classification: 'CONFIRMED',
        description: 'Actual data retrieved from database'
    },
    
    LEVEL_4: {
        level: 4,
        name: 'Critical Impact Demonstrated',
        classification: 'CONFIRMED',
        description: 'Admin credentials obtained or command execution achieved'
    }
};
```

### Visual Representation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       EXPLOITATION LEVEL CLASSIFICATION                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Level 0: NOT_REPRODUCIBLE                                                   │
│  ─────────────────────────                                                   │
│  • No injection point found                                                  │
│  • Security controls blocked the attack                                      │
│  • False positive from static analysis                                       │
│                                                                              │
│  Level 1: LIKELY (Low Confidence)                                            │
│  ─────────────────────────────────                                           │
│  • Error messages observed (e.g., "SQL syntax error")                        │
│  • Timing differences detected                                               │
│  • Response variations confirmed                                             │
│                                                                              │
│  Level 2: LIKELY (Medium Confidence)                                         │
│  ────────────────────────────────────                                        │
│  • Boolean logic working (true vs false conditions)                          │
│  • UNION SELECT succeeds                                                     │
│  • ORDER BY confirms column count                                            │
│                                                                              │
│  Level 3: CONFIRMED ✓                                                        │
│  ────────────────────                                                        │
│  • Actual data retrieved from database                                       │
│  • Database version extracted                                                │
│  • Table/column names enumerated                                             │
│                                                                              │
│  Level 4: CONFIRMED (Critical) ⚠️                                            │
│  ──────────────────────────────                                              │
│  • Admin credentials obtained                                                │
│  • System commands executed                                                  │
│  • Sensitive data dumped                                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5.9 Prompt Templates: `prompts/`

### What They Are
These are **instruction files** that tell GPT-4 how to test each type of vulnerability.

### Example: `exploit-injection.txt`

```xml
<role>
You are an expert Injection Exploitation Specialist performing dynamic 
security testing. Your task is to validate SQL Injection and Command 
Injection vulnerabilities identified by static analysis.
</role>

<objective>
For EACH vulnerability in {{QUEUE_PATH}}:
1. Analyze the static analysis context (file, line, technology, code snippet)
2. Derive the likely web endpoint from the source file path
3. Craft targeted payloads based on the technology stack
4. Test and document results with source code mapping
Target: {{WEB_URL}}
</objective>

<endpoint_discovery>
Derive endpoints from source file paths:
- routes/login.ts      → /login, /api/login
- routes/users.ts      → /users, /api/users
- controllers/auth.js  → /auth, /api/auth
</endpoint_discovery>

<payload_crafting>
For SQLi - Check technology:
- Sequelize/TypeORM: ' OR '1'='1'--
- MySQL: ' UNION SELECT NULL,NULL,NULL--
- PostgreSQL: '; SELECT pg_sleep(5)--

For Command Injection:
- Linux: ; id, | whoami
- Windows: & whoami
</payload_crafting>

<anti_hallucination>
CRITICAL RULES:
1. NEVER fabricate success - if the test fails, mark as NOT_REPRODUCIBLE
2. Report actual HTTP status codes and response contents
3. Do not claim data extraction without showing the actual data
</anti_hallucination>
```

---

# 6. Data Flow - Complete Journey

Let's trace how data flows through the entire system:

## 6.1 Input: Semgrep JSON File

```json
{
  "version": "1.147.0",
  "results": [
    {
      "check_id": "javascript.sequelize.security.audit.express-sequelize-injection",
      "path": "routes/users.ts",
      "start": { "line": 42, "col": 5 },
      "extra": {
        "message": "SQL injection vulnerability detected",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-89"],
          "owasp": ["A03:2021"]
        }
      }
    }
  ]
}
```

## 6.2 After Parsing (Normalized Format)

```json
{
  "id": "javascript.sequelize.security.audit.express-sequelize-injection",
  "source": "semgrep",
  "type": "injection",
  "subType": "SQLi",
  "severity": "HIGH",
  "location": {
    "file": "routes/users.ts",
    "line": 42,
    "column": 5
  },
  "description": "SQL injection vulnerability detected",
  "cwe": ["CWE-89"],
  "owasp": ["A03:2021"]
}
```

## 6.3 Exploitation Queue File

```json
{
  "vulnerabilities": [
    {
      "id": "javascript.sequelize.security.audit.express-sequelize-injection",
      "source": "semgrep",
      "vulnerabilityType": "SQLi",
      "file": "routes/users.ts",
      "line": 42,
      "column": 5,
      "description": "SQL injection vulnerability detected",
      "cwe": ["CWE-89"],
      "witnessPayload": "' OR '1'='1' --"
    }
  ]
}
```

## 6.4 Evidence File (After Testing)

```json
{
  "findingId": "javascript.sequelize.security.audit.express-sequelize-injection",
  "timestamp": "2026-01-26T10:30:00.000Z",
  "sourceLocation": {
    "file": "routes/users.ts",
    "line": 42,
    "column": 5
  },
  "vulnerability": {
    "type": "SQLi",
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  },
  "exploitation": {
    "endpoint": "/api/users?id=' OR '1'='1'--",
    "method": "GET",
    "payload": "' OR '1'='1'--",
    "response": "Returned 50 users instead of 1",
    "success": true,
    "proof": "Query returned all users due to always-true condition"
  },
  "status": "CONFIRMED"
}
```

## 6.5 Final Reports

### Developer Summary (JSON)
```json
{
  "generated": "2026-01-26T10:35:00.000Z",
  "totals": {
    "confirmed": 3,
    "notExploitable": 7,
    "total": 10
  },
  "confirmed": [
    {
      "file": "routes/users.ts",
      "line": 42,
      "cwe": "CWE-89",
      "endpoint": "/api/users"
    }
  ]
}
```

### SARIF (For IDEs)
```json
{
  "$schema": "https://sarif-schema...",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "DynamicSecurityTester" } },
    "results": [{
      "ruleId": "CWE-89",
      "level": "error",
      "message": { "text": "[CONFIRMED] SQLi at routes/users.ts:42" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "routes/users.ts" },
          "region": { "startLine": 42 }
        }
      }]
    }]
  }]
}
```

---

# 7. Key Concepts Explained

## 7.1 Static vs Dynamic Analysis

| Aspect | Static Analysis (SAST) | Dynamic Analysis (DAST) |
|--------|----------------------|------------------------|
| **What it scans** | Source code | Running application |
| **When it runs** | Before deployment | After deployment |
| **Speed** | Fast (no app needed) | Slower (needs running app) |
| **False positives** | High (30-70%) | Low (proves exploitability) |
| **Coverage** | All code paths | Only tested paths |
| **Example tools** | Semgrep, CodeQL | OWASP ZAP, Burp Suite |

## 7.2 Why AI/LLM?

Traditional DAST tools use **fixed playbooks** - predefined attack sequences. But:

1. **Context Matters**: A SQLi payload for MySQL differs from PostgreSQL
2. **Intelligence Required**: Understanding response patterns needs reasoning
3. **Adaptive Testing**: When blocked, AI can try bypass techniques

GPT-4 can:
- Read code snippets and understand the technology
- Generate context-aware payloads
- Interpret complex responses
- Make decisions about what to try next

## 7.3 What is CWE?

**CWE (Common Weakness Enumeration)** is a standardized list of software vulnerabilities.

| CWE ID | Name | Example |
|--------|------|---------|
| CWE-89 | SQL Injection | `db.query("SELECT * FROM users WHERE id=" + id)` |
| CWE-79 | Cross-Site Scripting (XSS) | `innerHTML = userInput` |
| CWE-22 | Path Traversal | `readFile(basePath + userInput)` |
| CWE-78 | OS Command Injection | `exec("ping " + userInput)` |
| CWE-798 | Hardcoded Credentials | `password = "admin123"` |

## 7.4 What is OWASP?

**OWASP (Open Web Application Security Project)** maintains the famous "OWASP Top 10" - the most critical web security risks.

| OWASP 2021 | Risk |
|------------|------|
| A01:2021 | Broken Access Control |
| A02:2021 | Cryptographic Failures |
| A03:2021 | Injection (SQL, Command, etc.) |
| A07:2021 | Identification and Authentication Failures |

## 7.5 What is SARIF?

**SARIF (Static Analysis Results Interchange Format)** is a standard JSON format for security tool output.

Benefits:
- VS Code can read it and show warnings in the editor
- GitHub Advanced Security integrates with it
- All security tools can share results in one format

---

# 8. Practical Examples with Sample Data

## 8.1 Example: Testing SQL Injection

### Step 1: Static Analyzer Finds Potential SQLi
```javascript
// File: routes/users.js, Line 42
app.get('/api/users', (req, res) => {
    const id = req.query.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);  // VULNERABLE!
});
```

Semgrep reports:
```
⚠️ SQL Injection: User input directly concatenated into SQL query
   File: routes/users.js:42
   CWE: CWE-89
```

### Step 2: Tool Creates Exploitation Queue
```json
{
  "vulnerabilities": [{
    "id": "sqli-users-42",
    "file": "routes/users.js",
    "line": 42,
    "vulnerabilityType": "SQLi",
    "witnessPayload": "' OR '1'='1' --"
  }]
}
```

### Step 3: AI Agent Tests
The AI reads the queue and thinks:
> "This is SQLi in an Express route at /api/users. The parameter is 'id' in the query string. I'll test with a payload."

```
Tool Call: browser_http_request
{
  "url": "http://localhost:3000/api/users?id=' OR '1'='1'--",
  "method": "GET"
}

Response: {
  "status": 200,
  "body": "[{\"id\":1,\"name\":\"Alice\"},{\"id\":2,\"name\":\"Bob\"},...]"
}
```

AI analyzes:
> "The query returned ALL users instead of just one. This confirms the SQL injection works!"

### Step 4: Evidence Saved
```json
{
  "findingId": "sqli-users-42",
  "sourceLocation": {
    "file": "routes/users.js",
    "line": 42
  },
  "exploitation": {
    "endpoint": "/api/users?id=' OR '1'='1'--",
    "payload": "' OR '1'='1'--",
    "success": true,
    "proof": "Query returned 50 users instead of 1"
  },
  "status": "CONFIRMED"
}
```

---

## 8.2 Example: Testing XSS (Cross-Site Scripting)

### Vulnerable Code
```javascript
// File: routes/search.js, Line 15
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results for: ${query}</h1>`);  // VULNERABLE!
});
```

### AI Testing Process
```
1. Navigate to: http://localhost:3000/search?q=<script>alert(1)</script>
2. Check page response for script execution
3. Try variations if blocked:
   - <img src=x onerror=alert(1)>
   - <svg onload=alert(1)>
   
Result: Page contains unescaped <script> tag
Status: CONFIRMED
```

---

## 8.3 Example: False Positive

### "Vulnerable" Code
```javascript
// routes/users.js - Semgrep flags this as SQLi
app.get('/api/users', (req, res) => {
    const id = parseInt(req.query.id);  // parseInt sanitizes input!
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
```

### Testing
```
Payload: ' OR '1'='1'--
Response: {"error": "Invalid ID format"}

AI Analysis: The parseInt() function converts the payload to NaN, 
which fails validation. The vulnerability is NOT exploitable.

Status: NOT_REPRODUCIBLE
```

---

# 9. Technology Stack Explanation

## 9.1 Node.js (Runtime)

**What**: JavaScript runtime for running code outside browsers
**Why Used**: Modern, async-friendly, great for I/O operations

## 9.2 OpenAI API (GPT-4)

**What**: AI language model API
**Why Used**: 
- Understands code context
- Generates intelligent payloads
- Makes testing decisions
- Adapts when attacks fail

```javascript
import OpenAI from 'openai';
const openai = new OpenAI();

const response = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: 'Test this SQLi...' }],
    tools: browserTools  // GPT-4 can call browser functions!
});
```

## 9.3 Playwright (Browser Automation)

**What**: Headless browser automation library
**Why Used**:
- Controls Chrome/Firefox programmatically
- Fills forms, clicks buttons
- Makes authenticated requests
- Captures cookies/tokens

```javascript
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.goto('http://localhost:3000');
await page.fill('#username', "admin' OR '1'='1'--");
await page.click('#submit');
```

## 9.4 Chalk (Console Styling)

**What**: Library for colored terminal output
**Why Used**: Makes output readable with colors

```javascript
import chalk from 'chalk';

console.log(chalk.green('✅ Test passed'));
console.log(chalk.red('❌ Vulnerability CONFIRMED'));
console.log(chalk.yellow('⚠️ Warning'));
```

## 9.5 Inquirer (Interactive Prompts)

**What**: Library for command-line user input
**Why Used**: Clean interactive prompts

```javascript
import inquirer from 'inquirer';

const answers = await inquirer.prompt([
    {
        type: 'input',
        name: 'targetUrl',
        message: 'Enter target URL:',
        default: 'http://localhost:3000'
    },
    {
        type: 'confirm',
        name: 'runTests',
        message: 'Run SQL injection tests?',
        default: true
    }
]);
```

## 9.6 zx (Shell Utilities)

**What**: Google's library for shell scripting in JavaScript
**Why Used**: Easy file system operations

```javascript
import { fs, path } from 'zx';

await fs.ensureDir('./output');
await fs.writeJSON('./output/report.json', data);
const exists = await fs.pathExists('./input.json');
```

---

# 10. Professor Q&A Section

## Q1: What is the main purpose of this tool?

**Answer**: This tool bridges the gap between static and dynamic security analysis. Static analyzers find *potential* vulnerabilities in source code, but have high false positive rates (30-70%). This tool takes those findings and *actually tests them* against a running application to confirm which ones are real, exploitable vulnerabilities. It uses AI (GPT-4) to generate intelligent attack payloads and Playwright for browser automation.

---

## Q2: How does the tool use AI/LLM?

**Answer**: The tool uses OpenAI's GPT-4 model as an intelligent testing agent. Here's how:

1. **System Prompt**: We give GPT-4 a detailed prompt explaining it's a security testing expert
2. **Tool Access**: GPT-4 can call browser automation functions (navigate, fill forms, make HTTP requests)
3. **Decision Making**: GPT-4 analyzes vulnerability context (file, line, technology) and decides what payloads to try
4. **Response Analysis**: GPT-4 interprets responses to determine if attacks succeeded
5. **Evidence Collection**: GPT-4 saves detailed proof of findings

The key advantage is that GPT-4 understands context - it knows a SQL injection payload for MySQL differs from PostgreSQL, and can adapt when initial attempts fail.

---

## Q3: What types of vulnerabilities can this tool test?

**Answer**: The tool supports testing these vulnerability types:

| Type | CWE | Example |
|------|-----|---------|
| SQL Injection | CWE-89 | `' OR '1'='1'--` |
| Command Injection | CWE-78 | `; whoami` |
| Cross-Site Scripting (XSS) | CWE-79 | `<script>alert(1)</script>` |
| Path Traversal | CWE-22 | `../../etc/passwd` |
| XML External Entity (XXE) | CWE-611 | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| Server-Side Request Forgery (SSRF) | CWE-918 | `http://169.254.169.254/` |
| Open Redirect | CWE-601 | `?redirect=http://evil.com` |
| Hardcoded Secrets | CWE-798 | API keys, passwords in code |

---

## Q4: How does the parser system work?

**Answer**: The parser system uses a **Factory Pattern** to handle multiple input formats:

1. **Detection**: `parser-factory.js` examines JSON structure to identify the source (Semgrep, Trivy, etc.)
   - Semgrep: Has `results` array and `version` field
   - Trivy: Has `Results` with `Vulnerabilities`
   - Gitleaks: Has `Findings` or array with `Secret` field

2. **Parsing**: Creates appropriate parser instance (`SemgrepParser`, `TrivyParser`, etc.)

3. **Normalization**: Converts all formats to a unified structure:
   ```javascript
   {
     id, source, type, subType, severity,
     location: { file, line, column },
     cwe, owasp, description
   }
   ```

4. **Validation**: Ensures all required fields exist

This design follows **Open/Closed Principle** - we can add new parsers without modifying existing code.

---

## Q5: What is the exploitation level classification?

**Answer**: We use a 5-level (0-4) classification system:

| Level | Name | Classification | Meaning |
|-------|------|----------------|---------|
| 0 | No Exploitation | NOT_REPRODUCIBLE | Security controls working |
| 1 | Injection Point Confirmed | LIKELY | Errors/timing differences seen |
| 2 | Query Structure Manipulated | LIKELY | Boolean/UNION logic works |
| 3 | Data Extraction Proven | CONFIRMED | Actual data retrieved |
| 4 | Critical Impact | CONFIRMED | Admin access/RCE achieved |

Levels 0-2 are "likely" or "not reproducible" - more investigation needed.
Levels 3-4 are "confirmed" - definitive proof of exploitability.

---

## Q6: How does authentication propagation work?

**Answer**: The `AuthManager` class handles this:

1. **Capture Phase**: After user logs in via browser, we call `browser_capture_auth`
   - Extracts JWT from localStorage/sessionStorage
   - Captures cookies from browser context
   - Stores in `AuthManager` singleton

2. **Injection Phase**: Subsequent HTTP requests automatically include auth
   ```javascript
   const headers = authManager.getAuthHeaders();
   // Returns: { 'Authorization': 'Bearer eyJ...', 'Cookie': 'session=abc123' }
   ```

3. **Common Locations Checked**:
   - `localStorage.token`, `localStorage.jwt`, `localStorage.accessToken`
   - Session cookies like `connect.sid`, `JSESSIONID`

This ensures we can test protected endpoints that require authentication.

---

## Q7: What output formats does the tool generate?

**Answer**: Three output formats:

1. **SARIF (Static Analysis Results Interchange Format)**
   - Industry standard for security tool output
   - VS Code and GitHub can read it
   - Shows vulnerabilities directly in IDE with line numbers

2. **HTML Report**
   - Visual report for human review
   - Dark theme, modern design
   - Shows confirmed vs not exploitable counts
   - Good for presenting to stakeholders

3. **Developer Summary (JSON)**
   - Quick reference for developers
   - Lists confirmed exploits with file/line/endpoint
   - Easy to parse programmatically
   - Good for CI/CD integration

---

## Q8: How does the tool prevent false positives?

**Answer**: Multiple anti-hallucination mechanisms:

1. **Prompt Engineering**: The AI prompt includes strict rules:
   ```
   NEVER fabricate success - if the test fails, mark as NOT_REPRODUCIBLE
   Report actual HTTP status codes and response contents
   Do not claim data extraction without showing actual data
   ```

2. **Evidence Requirements**: Must save concrete proof:
   - Actual payload used
   - Actual response received
   - Specific proof of exploitation

3. **Multi-Level Classification**: We distinguish between:
   - CONFIRMED (Level 3-4): Actual data extracted
   - LIKELY (Level 1-2): Indicators seen but not proven
   - NOT_REPRODUCIBLE (Level 0): No evidence

4. **Source Mapping**: Every finding links back to original file:line:column

---

## Q9: What is the role of Playwright?

**Answer**: Playwright is a browser automation library that:

1. **Controls Chromium**: Runs a headless Chrome browser programmatically

2. **Form Interaction**: 
   ```javascript
   await page.fill('#username', 'admin');
   await page.click('#login-button');
   ```

3. **HTTP Requests**: Direct API testing without browser UI
   ```javascript
   await page.request.get('/api/users?id=1');
   ```

4. **Element Detection**: Finds forms, inputs, buttons on page

5. **Response Capture**: Gets page content, detects error messages

It's the "hands" that execute what the AI "brain" decides.

---

## Q10: How does the queue generator work?

**Answer**: The queue generator groups vulnerabilities by type:

```javascript
const queues = {
  injection: [],  // SQL injection, command injection
  xss: [],        // Cross-site scripting
  secrets: [],    // Hardcoded credentials
  traversal: [],  // Path traversal
  // ... more types
};

for (const vuln of vulnerabilities) {
  queues[vuln.type].push(vuln);
}
```

Each queue gets a separate file: `injection_exploitation_queue.json`, `xss_exploitation_queue.json`, etc.

This allows:
- Testing one type at a time
- Using type-specific prompts (SQL injection prompt knows MySQL vs PostgreSQL)
- Parallel testing of different types

---

## Q11: What security analyzers are supported?

**Answer**: The tool supports 7 analyzers:

| Analyzer | Purpose | Output Format |
|----------|---------|---------------|
| **Semgrep** | Static code analysis (SAST) | JSON with `results` array |
| **Trivy** | Container/dependency scanning | JSON with `Results` array |
| **CodeQL** | Deep semantic analysis (GitHub) | SARIF format |
| **Gitleaks** | Secret detection in repos | JSON with `Findings` |
| **Syft** | Software Bill of Materials (SBOM) | JSON with `artifacts` |
| **OSV** | Open Source Vulnerability database | JSON with `vulns` |
| **OWASP Noir** | API security scanning | JSON with `endpoints` |

---

## Q12: How does rate limiting work?

**Answer**: The `RateLimiter` class handles OpenAI API limits:

```javascript
class RateLimiter {
  async executeWithRetry(fn, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        if (isRateLimitError(error)) {
          // Wait longer for rate limits
          const delay = getRetryDelay(error, attempt);
          // delay increases: 30s → 40s → 50s
          await sleep(delay);
        }
      }
    }
  }
}
```

Features:
- Exponential backoff (longer delays on repeated failures)
- Rate limit-specific delays (OpenAI errors get 30+ second waits)
- Graceful degradation (falls back to predefined payloads if API fails)

---

## Q13: What design patterns are used in this project?

**Answer**: Several design patterns:

1. **Factory Pattern** (`parser-factory.js`)
   - `createParser(type)` returns appropriate parser instance
   - Easy to add new parsers

2. **Singleton Pattern** (`auth-manager.js`)
   - `getAuthManager()` returns single instance
   - Shared authentication state

3. **Strategy Pattern** (Prompt templates)
   - Different prompts for different vulnerability types
   - Same executor, different strategies

4. **Observer/Tool Pattern** (AI Agent)
   - GPT-4 calls tools, gets results
   - Decoupled execution

5. **Template Method** (`BaseParser`)
   - Base class defines structure
   - Subclasses implement details

---

## Q14: How would you extend this tool to support a new analyzer?

**Answer**: Follow these steps:

1. **Create Parser** in `src/parser/parsers/`:
   ```javascript
   export class NewAnalyzerParser extends BaseParser {
     constructor() { super('newanalyzer'); }
     
     validate(data) {
       return data && data.specificField;
     }
     
     async parse(data) {
       return data.findings.map(f => ({
         id: f.id,
         type: categorizeVulnerability(f).type,
         location: { file: f.file, line: f.line },
         // ... normalize fields
       }));
     }
   }
   ```

2. **Register in Factory** (`parser-factory.js`):
   ```javascript
   import { NewAnalyzerParser } from './parsers/newanalyzer-parser.js';
   
   const PARSER_REGISTRY = {
     // ... existing
     newanalyzer: NewAnalyzerParser
   };
   ```

3. **Add Detection Logic**:
   ```javascript
   if (data.specificField && data.anotherIndicator) {
     return 'newanalyzer';
   }
   ```

No changes to main.js or executor.js needed!

---

## Q15: What are the limitations of this tool?

**Answer**: 

1. **Requires Running Application**: Can't test without a live target
2. **API Costs**: OpenAI GPT-4 calls cost money
3. **Rate Limits**: OpenAI limits requests per minute
4. **Coverage**: Only tests what AI decides to test
5. **Complex Vulnerabilities**: Some multi-step exploits may be missed
6. **Authentication**: May not handle all auth schemes (OAuth2, MFA)
7. **False Negatives**: AI might miss some valid exploits
8. **Network Dependent**: Needs connectivity to OpenAI API

---

# 11. Glossary of Terms

| Term | Definition |
|------|------------|
| **SAST** | Static Application Security Testing - analyzing source code without running it |
| **DAST** | Dynamic Application Security Testing - testing a running application |
| **SQLi** | SQL Injection - inserting malicious SQL into queries |
| **XSS** | Cross-Site Scripting - injecting malicious scripts into web pages |
| **SSRF** | Server-Side Request Forgery - tricking server to make requests |
| **XXE** | XML External Entity - exploiting XML parsers to read files |
| **CWE** | Common Weakness Enumeration - standardized vulnerability IDs |
| **OWASP** | Open Web Application Security Project - security standards org |
| **SARIF** | Static Analysis Results Interchange Format - report format |
| **JWT** | JSON Web Token - authentication token format |
| **WAF** | Web Application Firewall - security system blocking attacks |
| **LLM** | Large Language Model - AI like GPT-4 |
| **Playwright** | Browser automation library by Microsoft |
| **Payload** | Attack string used to exploit vulnerability |
| **False Positive** | Incorrectly reported vulnerability (not real) |
| **False Negative** | Missed vulnerability (real but not found) |
| **Headless Browser** | Browser running without visible UI |

---

# 📝 Summary

This Dynamic Security Tester is an **AI-powered bridge** between static and dynamic security analysis. It:

1. **Parses** output from 7 different security scanners
2. **Groups** vulnerabilities by type
3. **Tests** each one using GPT-4 + Playwright browser automation
4. **Generates** developer-friendly reports (SARIF, HTML, JSON)

The key innovation is using **AI to make intelligent testing decisions** - understanding code context, crafting appropriate payloads, and analyzing responses - rather than using fixed attack playbooks.

**For your professor**: This project demonstrates knowledge of:
- Security vulnerability types (CWE, OWASP)
- AI/LLM integration (OpenAI API, prompt engineering)
- Browser automation (Playwright)
- Software design patterns (Factory, Singleton, Strategy)
- DevSecOps practices (SARIF, CI/CD integration)
- Modern JavaScript (ES Modules, async/await)

---

*Document generated for educational purposes. Last updated: January 2026*
