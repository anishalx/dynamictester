# Dynamic Security Tester

**AI-powered DAST tool that bridges static analysis with automated exploitation validation.**

Takes vulnerability findings from static analysis tools (Semgrep, Trivy, CodeQL, Gitleaks, OSV, Syft, Noir) and uses OpenAI GPT-4 combined with Playwright browser automation and Stagehand AI to dynamically test, validate, and produce developer-friendly reports.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Analyzer Support** | Parses output from 7 static analyzers with auto-detection |
| **24 Agent Tools** | 15 browser tools, 4 Stagehand AI tools, 5 exploitation workflow tools |
| **LLM-Crafted Payloads** | Context-aware payloads derived from static analysis metadata |
| **Source Code Mapping** | Links every finding to exact `file:line:column` for developers |
| **Industry Reports** | SARIF 2.1.0 for IDE integration, HTML for stakeholders, JSON for CI |
| **Stagehand AI Browser** | Natural-language browser actions, autonomous multi-step workflows |
| **Route Intelligence** | Automatic Express router parsing for endpoint discovery |
| **Auth Propagation** | JWT/cookie capture and injection across tests |
| **WAF Bypass Engine** | Deterministic encoding, technique, and WAF-specific bypass generation |
| **Response Analysis** | Database error detection, WAF detection, boolean/timing analysis |
| **5-Level Proof System** | L0 (no evidence) through L4 (critical impact demonstrated) |
| **4-Class Classification** | CONFIRMED / LIKELY / BLOCKED / NOT_REPRODUCIBLE |
| **CI/CD Mode** | Exit codes (`0`=pass, `1`=confirmed, `2`=error) and machine-readable reports |

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Supported Analyzers](#supported-analyzers)
- [Agent Tools](#agent-tools)
- [Classification System](#classification-system)
- [Output & Reports](#output--reports)
- [Prompt Templates](#prompt-templates)
- [Configuration](#configuration)
- [Testing](#testing)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)
- [Dependencies](#dependencies)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        DYNAMIC SECURITY TESTER                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │    Parser     │──>│    Queue     │──>│   Executor   │──>│   Reports    │  │
│  │              │   │  Generator   │   │              │   │              │  │
│  │ Semgrep      │   │              │   │ OpenAI GPT   │   │ SARIF 2.1.0  │  │
│  │ Trivy        │   │ Groups by    │   │ LLM Agent    │   │ HTML         │  │
│  │ CodeQL       │   │ vuln type    │   │ + Bypass     │   │ JSON Summary │  │
│  │ Syft / OSV   │   │              │   │   Engine     │   │ CI Report    │  │
│  │ Gitleaks     │   │              │   │ + Payload    │   │              │  │
│  │ Noir         │   │              │   │   Generator  │   │              │  │
│  └──────────────┘   └──────────────┘   └──────┬───────┘   └──────────────┘  │
│         │                                     │                              │
│         v                                     v                              │
│  ┌──────────────┐                    ┌─────────────────┐                     │
│  │    Route     │                    │ Browser Manager  │                     │
│  │ Intelligence │                    │  (15 tools)      │                     │
│  │              │                    │                  │                     │
│  │ Express      │                    │ HTTP Requests    │                     │
│  │ Router       │                    │ Form Filling     │                     │
│  │ Parsing      │                    │ Force Click      │                     │
│  └──────┬───────┘                    │ Script Exec      │                     │
│         │                            │ Auth Capture     │                     │
│         v                            └────────┬────────┘                     │
│  ┌──────────────┐                             │                              │
│  │     Auth     │                    ┌────────v────────┐                     │
│  │   Manager    │<──────────────────>│ Stagehand AI    │                     │
│  │              │                    │  (4 tools)       │                     │
│  │ JWT/Cookie   │                    │                  │                     │
│  │ Injection    │                    │ Act / Extract    │                     │
│  └──────────────┘                    │ Observe / Agent  │                     │
│                                      └────────┬────────┘                     │
│                                               │                              │
│                                      ┌────────v────────┐                     │
│                                      │   Response      │                     │
│                                      │   Analyzer      │                     │
│                                      │                  │                     │
│                                      │ DB Errors        │                     │
│                                      │ WAF Detection    │                     │
│                                      │ Boolean/Timing   │                     │
│                                      │ Classification   │                     │
│                                      └─────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Pipeline:** Parse static results -> Queue by vuln type -> Execute via LLM agent with browser tools -> Classify results -> Generate reports

---

## Project Structure

```
dynamictester/
├── src/
│   ├── main.js                          # Entry point — interactive CLI workflow
│   │
│   ├── agents/
│   │   └── executor.js                  # OpenAI GPT agent loop (tool-calling, 50 turns, rate limiting)
│   │
│   ├── auth/
│   │   └── auth-manager.js              # JWT/cookie capture and injection (singleton)
│   │
│   ├── mcp/
│   │   ├── browser-server.js            # BrowserManager — 15 Playwright tools for the LLM
│   │   └── stagehand-manager.js         # StagehandManager — 4 AI browser tools
│   │
│   ├── parser/
│   │   ├── normalizer.js                # Severity/confidence normalization, vuln categorization
│   │   ├── parser-factory.js            # Auto-detect analyzer type + registry of 7 parsers
│   │   ├── parser-interface.js          # BaseParser abstract class
│   │   ├── result-parser.js             # Multi-file parsing coordinator, dedup, validation
│   │   ├── route-parser.js              # Express router file parsing for endpoint discovery
│   │   ├── validator.js                 # Validates normalized vulnerability structure
│   │   └── parsers/
│   │       ├── semgrep-parser.js        # Semgrep JSON output
│   │       ├── trivy-parser.js          # Trivy (vulns, misconfigs, secrets)
│   │       ├── codeql-parser.js         # CodeQL SARIF format
│   │       ├── syft-parser.js           # Syft SBOM
│   │       ├── osv-parser.js            # OSV vulnerability scanner
│   │       ├── gitleaks-parser.js       # Gitleaks secrets scanner (v7 + v8)
│   │       └── noir-parser.js           # OWASP Noir API endpoints
│   │
│   ├── queue/
│   │   └── queue-generator.js           # Group vulnerabilities by type into queue files
│   │
│   ├── reporting/
│   │   ├── report-generator.js          # SARIF 2.1.0, HTML, and developer summary generation
│   │   └── ci-reporter.js              # CI/CD exit codes (0=pass, 1=confirmed, 2=error)
│   │
│   ├── testing/
│   │   ├── bypass-engine.js             # Deterministic WAF/filter bypass generation
│   │   ├── classifier.js               # CONFIRMED/LIKELY/BLOCKED/NOT_REPRODUCIBLE classification
│   │   ├── exploitation-levels.js       # 5-level proof system (L0-L4)
│   │   ├── intelligence-aggregator.js   # Context gathering for payload crafting
│   │   ├── payload-generator.js         # LLM-powered payload generation with anti-hallucination
│   │   ├── response-analyzer.js         # DB error detection, WAF detection, boolean/timing analysis
│   │   ├── test-interface.js            # VulnerabilityTester base class (confirm -> fingerprint -> exploit)
│   │   ├── bypass-engine.test.js        # Tests for bypass engine (18 tests)
│   │   ├── payload-generator.test.js    # Tests for payload generator (88 tests)
│   │   └── response-analyzer.test.js    # Tests for response analyzer (26 tests)
│   │
│   └── utils/
│       ├── error-handling.js            # Error classification, retry eligibility, delay calculation
│       └── rate-limiter.js              # RateLimiter — retry with backoff, parallel stagger
│
├── prompts/                             # LLM prompt templates
│   ├── exploit-injection.txt            # SQL/command injection testing
│   ├── exploit-xss.txt                  # Cross-site scripting testing
│   ├── exploit-traversal.txt            # Path traversal testing
│   ├── exploit-xxe.txt                  # XML external entity testing
│   ├── exploit-redirect.txt             # Open redirect testing
│   ├── exploit-secrets.txt              # Hardcoded secrets validation
│   └── exploit-generic.txt              # General vulnerability testing
│
├── package.json
├── AGENTS.md                            # Coding conventions and guidelines
└── README.md
```

---

## Installation

### Prerequisites

- **Node.js** 18 or later
- **npm**
- **OpenAI API key** with access to GPT-4 or GPT-4o

### Setup

```bash
# Install dependencies
npm install

# Set OpenAI API key
export OPENAI_API_KEY="your-api-key-here"
# Or create a .env file:
# echo 'OPENAI_API_KEY=your-api-key-here' > .env

# Install Playwright browsers
npx playwright install chromium
```

---

## Quick Start

```bash
node src/main.js
```

The interactive CLI prompts for:

1. **Path to analyzer results** -- one or more static analysis output files (comma-separated)
2. **Target URL** -- the running application to test (e.g. `http://localhost:3000`)
3. **Output directory** -- where to save reports and evidence

### Example Session

```
🔍 Dynamic Security Tester (OpenAI Powered)
────────────────────────────────────────────────────────────────
Supported analyzers: semgrep, gitleaks, trivy, osv, syft, noir, codeql
────────────────────────────────────────────────────────────────

? Path to analyzer result file(s): semgrep.json, trivy.json

📋 Step 1: Parsing static analysis results...
✅ Parsed 24 vulnerabilities from 2 files
   - semgrep: 15 findings
   - trivy: 9 findings

📋 Step 2: Generating exploitation queues...
✅ Created injection_exploitation_queue.json with 8 vulnerabilities
   - from semgrep: 5
   - from trivy: 3
✅ Created xss_exploitation_queue.json with 6 vulnerabilities
✅ Created secrets_exploitation_queue.json with 4 vulnerabilities

📋 Step 3: Reviewing vulnerabilities...
🎯 Found 8 INJECTION vulnerabilities:
   1. SQLi in routes/login.ts:34
   2. CommandInjection in utils/exec.js:12
   3. ...

? Run dynamic exploitation tests for injection? (Y/n)

🚀 Starting OpenAI exploitation agent (gpt-4o)...
   Rate limit handling: 3 retries with exponential backoff
   Loaded 8 vulnerabilities from queue

📋 Generating reports...
✅ SARIF report saved: output/report.sarif.json
✅ HTML report saved: output/report.html
✅ Summary saved: output/developer_summary.json

════════════════════════════════════════════════════════
  CI SECURITY SCAN SUMMARY
════════════════════════════════════════════════════════
  Total Findings:      24
  🔴 CONFIRMED:        3
  🟡 LIKELY:           2
  🟠 BLOCKED:          1
  🟢 NOT REPRODUCIBLE: 18
────────────────────────────────────────────────────────
  Exit Code: 1
  Result: FAIL: 3 CONFIRMED exploit(s) found
════════════════════════════════════════════════════════
```

---

## Supported Analyzers

All parsers extend `BaseParser` from `src/parser/parser-interface.js` and implement `validate(data)` and `async parse(data)`.

Analyzer type is auto-detected from the JSON structure by `detectAnalyzerType()` in `parser-factory.js`.

| Analyzer | Format | Parser | What It Finds |
|----------|--------|--------|---------------|
| **Semgrep** | JSON | `semgrep-parser.js` | Code patterns, SAST findings |
| **Trivy** | JSON | `trivy-parser.js` | CVEs, misconfigurations, secrets |
| **CodeQL** | SARIF | `codeql-parser.js` | Data flow, taint analysis |
| **Syft** | JSON | `syft-parser.js` | SBOM, dependency inventory |
| **OSV** | JSON | `osv-parser.js` | Open-source vulnerability database |
| **Gitleaks** | JSON | `gitleaks-parser.js` | Secrets in source/git history (v7 + v8) |
| **Noir** | JSON | `noir-parser.js` | API endpoint discovery |

### Multi-Analyzer Usage

Pass multiple files comma-separated:

```
? Path to analyzer result file(s): semgrep.json, trivy.json, gitleaks.json
```

Results are deduplicated, normalized, and merged into unified exploitation queues.

---

## Agent Tools

The LLM agent has access to **24 tools** across three categories.

### Browser Tools (15)

Playwright-based browser automation exposed to the GPT agent:

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to a URL, wait for page load |
| `browser_fill` | Fill a form field by CSS selector |
| `browser_click` | Click an element by CSS selector |
| `browser_type_and_submit` | Type text and press Enter to submit |
| `browser_get_response` | Get page info (forms, inputs, buttons, links) |
| `browser_screenshot` | Take screenshot for evidence |
| `browser_close` | Close the browser |
| `browser_force_click` | JavaScript click (bypasses overlays/visibility) |
| `browser_scroll` | Scroll page (up/down/top/bottom) |
| `browser_wait_for_element` | Wait for SPA content to appear |
| `browser_http_request` | Direct HTTP/API requests (GET/POST/PUT/DELETE/PATCH) |
| `browser_execute_script` | Execute JavaScript in page context |
| `browser_capture_auth` | Capture JWT/cookies after login |
| `browser_get_auth_status` | Check stored auth tokens |
| `browser_clear_auth` | Clear all stored auth tokens |

### Stagehand AI Tools (4)

AI-powered browser interactions via `@browserbasehq/stagehand`. Use natural language instead of CSS selectors:

| Tool | Description |
|------|-------------|
| `stagehand_act` | Execute browser action in natural language (e.g. "click the Login button") |
| `stagehand_extract` | Extract structured data from page using AI (forms, errors, links, tables) |
| `stagehand_observe` | Discover available actions and interactive elements on a page |
| `stagehand_agent` | Execute multi-step browser workflows autonomously (login sequences, navigation) |

### Exploitation Workflow Tools (5)

Orchestration tools for the exploitation pipeline:

| Tool | Description |
|------|-------------|
| `read_queue_file` | Load the vulnerability queue JSON |
| `generate_payloads` | Generate context-aware payload guidance per vulnerability and stage |
| `analyze_response` | Analyze HTTP response for DB errors, WAF blocking, boolean/timing signals |
| `generate_bypasses` | Generate WAF/filter bypass variations for blocked payloads |
| `save_evidence` | Save exploitation evidence with full source code mapping |

### `browser_http_request` Example

The most important tool for API testing:

```javascript
browser_http_request({
  url: "https://target.com/api/login",
  method: "POST",
  body: '{"email": "\' OR 1=1--", "password": "x"}',
  contentType: "application/json"
})
// Returns:
// { status: "success", httpStatus: 200, body: "...", json: {...} }
```

---

## Classification System

### Exploitation Levels (L0-L4)

| Level | Name | Evidence Required | Classification |
|-------|------|-------------------|----------------|
| **L0** | No Exploitation | All tests failed, security controls working | NOT_REPRODUCIBLE |
| **L1** | Injection Point Confirmed | Error messages, timing differences, response variations | LIKELY |
| **L2** | Query Structure Manipulated | Boolean logic, UNION SELECT, ORDER BY working | LIKELY |
| **L3** | Data Extraction Proven | Actual data retrieved, DB version extracted, tables enumerated | CONFIRMED |
| **L4** | Critical Impact Demonstrated | Sensitive data extracted, admin creds obtained, command execution | CONFIRMED |

### Classification Decision Framework

```
Level 3+ (data extracted)               -> CONFIRMED (CI exit code: 1)
Level 1-2 + external blocker            -> BLOCKED   (CI exit code: 0)
Level 1-2 + security control detected   -> NOT_REPRODUCIBLE (CI exit code: 0)
Level 1-2 + no blocker                  -> LIKELY    (CI exit code: 0)
Level 0                                 -> NOT_REPRODUCIBLE (CI exit code: 0)
```

The classifier (`src/testing/classifier.js`) automatically distinguishes between:
- **Security controls** (prepared statements, WAF, input validation) -- false positive
- **External constraints** (auth required, server down, rate limiting) -- needs investigation

---

## Output & Reports

### Directory Structure

```
output/
├── evidence/                       # Individual finding evidence
│   ├── evidence-vuln-001.json
│   └── evidence-vuln-002.json
├── deliverables/                   # Exploitation queues
│   ├── injection_exploitation_queue.json
│   └── xss_exploitation_queue.json
├── findings_summary.json           # Quick summary
├── developer_summary.json          # Categorized findings for developers
├── report.sarif.json               # SARIF 2.1.0 for IDE integration
├── report.html                     # Visual HTML report
└── ci-report.json                  # CI/CD machine-readable report
```

### Evidence Format

Each finding includes full source code mapping:

```json
{
  "findingId": "javascript.sequelize.sql-injection",
  "timestamp": "2024-01-15T10:30:00.000Z",

  "sourceLocation": {
    "file": "routes/login.ts",
    "line": 34,
    "column": 28
  },

  "vulnerability": {
    "type": "SQL Injection",
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  },

  "exploitation": {
    "endpoint": "/api/login",
    "method": "POST",
    "payload": "' OR '1'='1'--",
    "success": true,
    "proof": "Authenticated as admin without password"
  },

  "remediation": "Use parameterized queries with Sequelize replacements",
  "status": "CONFIRMED"
}
```

### SARIF Report

Integrates with VS Code (SARIF Viewer extension), GitHub Code Scanning, and other IDEs:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "DynamicSecurityTester", "version": "1.0.0" } },
    "results": [{
      "ruleId": "CWE-89",
      "level": "error",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "routes/login.ts" },
          "region": { "startLine": 34, "startColumn": 28 }
        }
      }],
      "properties": {
        "status": "CONFIRMED",
        "endpoint": "/api/login",
        "payload": "' OR '1'='1'--",
        "proof": "Authenticated as admin without password"
      }
    }]
  }]
}
```

### HTML Report

Dark-themed visual report with:
- Confirmed vs Not Exploitable summary with counts
- Source code locations (`file:line:column`)
- Payload details and exploitation proof (HTML-escaped for safety)
- Remediation suggestions
- OWASP and CWE references

### CI Report

Machine-readable JSON with exit code reasoning:

```json
{
  "timestamp": "2024-01-15T10:35:00.000Z",
  "summary": {
    "total": 24,
    "confirmed": 3,
    "likely": 2,
    "blocked": 1,
    "notReproducible": 18
  },
  "exitCode": 1,
  "exitReason": "FAIL: 3 CONFIRMED exploit(s) found",
  "confirmedExploits": [{ "id": "...", "endpoint": "/api/login", "cwe": "CWE-89" }]
}
```

---

## Prompt Templates

All prompts are **universal** -- they work on any application by deriving endpoints from source code paths.

| Prompt | Vulnerability Type | Key Features |
|--------|-------------------|--------------|
| `exploit-injection.txt` | SQLi, Command Injection | Technology-aware (MySQL, PostgreSQL, SQLite, MSSQL) |
| `exploit-xss.txt` | Cross-Site Scripting | Context-aware (HTML, Attribute, JavaScript, DOM) |
| `exploit-traversal.txt` | Path Traversal | OS-aware with encoding variations |
| `exploit-xxe.txt` | XML External Entity | Parser-specific payloads |
| `exploit-redirect.txt` | Open Redirect | Whitelist bypass techniques |
| `exploit-secrets.txt` | Hardcoded Secrets | Credential validation and impact assessment |
| `exploit-generic.txt` | Any vulnerability | General testing methodology |

### Endpoint Discovery

Prompts derive endpoints from source file paths:

```
routes/login.ts      -> /login, /api/login
controllers/users.js -> /users, /api/users
api/v1/products.js   -> /api/v1/products
```

The route parser (`src/parser/route-parser.js`) also statically analyzes Express `app.get()` / `router.post()` patterns to map source locations to HTTP endpoints.

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | OpenAI API key with GPT-4/GPT-4o access |

### Key Settings

**Agent loop** (`src/agents/executor.js`):

```javascript
const maxTurns = 50;                    // Max agent conversation turns
const MAX_TOOL_RESULT_LENGTH = 8000;    // Truncate tool results to avoid token limits
const model = options.model || 'gpt-4o'; // LLM model
```

**Browser timeouts** (`src/mcp/browser-server.js`):

```javascript
const DEFAULT_TIMEOUT = 5000;  // 5 seconds for most operations
const SHORT_TIMEOUT = 2000;    // 2 seconds for quick checks
```

**Rate limiting** (`src/utils/rate-limiter.js`):

```javascript
{
  maxRetries: 3,        // Retry attempts (uses ?? for 0-safe defaults)
  staggerDelay: 2000,   // Delay between parallel task starts (ms)
  retryDelay: 5000      // Base delay between retries (ms)
}
```

---

## Testing

The project uses [Vitest](https://vitest.dev/) for testing.

```bash
# Run all tests
npm test

# Run a specific test file
npx vitest run src/testing/bypass-engine.test.js

# Run tests matching a name pattern
npx vitest run -t "detectDatabaseErrors"
```

### Test Suite

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `src/testing/bypass-engine.test.js` | 18 | Encoding bypasses, technique bypasses, WAF-specific bypasses, attempt tracking |
| `src/testing/payload-generator.test.js` | 88 | Payload generation, anti-hallucination filtering, stage-based payloads |
| `src/testing/response-analyzer.test.js` | 26 | DB error detection, WAF detection, boolean comparison, timing analysis |
| **Total** | **132** | |

---

## Extending the Tool

### Adding a New Static Analyzer Parser

1. **Create the parser** in `src/parser/parsers/<name>-parser.js`:

```javascript
import { BaseParser } from '../parser-interface.js';
import { normalizeSeverity, categorizeVulnerability } from '../normalizer.js';

export class NewParser extends BaseParser {
  constructor() {
    super('newanalyzer');
  }

  validate(data) {
    // Return true if data matches expected format
    return data && Array.isArray(data.findings);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    if (!this.validate(jsonData)) {
      throw new Error('Invalid format');
    }

    return jsonData.findings.map(f => {
      const { type, subType } = categorizeVulnerability({
        description: f.message,
        checkId: f.ruleId,
        cwe: f.cwe
      });

      return {
        id: f.id,
        source: 'newanalyzer',
        sourceVersion: this.analyzerVersion,
        type,
        subType,
        severity: normalizeSeverity(f.severity),
        confidence: 'MEDIUM',
        location: {
          file: f.file || 'unknown',
          line: f.line || 0,
          column: f.column || 0,
          endLine: f.endLine || 0,
          endColumn: f.endColumn || 0,
          snippet: f.snippet || ''
        },
        description: f.message,
        remediation: f.fix || '',
        cwe: f.cwe || [],
        owasp: [],
        cvss: null,
        cve: [],
        metadata: {},
        checkId: f.ruleId,
        reference: f.url || ''
      };
    });
  }
}
```

2. **Register in** `src/parser/parser-factory.js`:

```javascript
import { NewParser } from './parsers/new-parser.js';

const PARSER_REGISTRY = Object.freeze({
  // ... existing parsers
  newanalyzer: NewParser
});
```

3. **Add auto-detection** in `detectAnalyzerType()`:

```javascript
if (data.findings && data.toolName === 'newanalyzer') {
  return 'newanalyzer';
}
```

### Adding a New Browser Tool

In `src/mcp/browser-server.js`:

1. Add the method to `BrowserManager`:

```javascript
async customAction({ param1 }) {
  try {
    // Implementation using this.page (Playwright Page)
    return { status: 'success', data: result };
  } catch (e) {
    return { status: 'error', message: e.message };
  }
}
```

2. Register in `getTools()`:

```javascript
{
  name: 'browser_custom_action',
  description: 'What this tool does',
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

### Adding a New Prompt Template

1. Create `prompts/exploit-<type>.txt` with the system prompt
2. Add mapping in `src/main.js`:

```javascript
const promptMapping = {
  // ... existing mappings
  newtype: 'exploit-newtype.txt'
};
```

### Adding a New Vulnerability Category

Add to the categorization map in `src/parser/normalizer.js`:

```javascript
if (/newpattern|cwe-XXX/.test(indicators)) {
  return { type: 'newtype', subType: 'NewSubType', owasp: ['AXX:2021'] };
}
```

And add the queue bucket in `src/queue/queue-generator.js`:

```javascript
const queues = { /* existing */, newtype: [] };
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "No vulnerabilities found" | Verify analyzer output format matches expected structure. Run with a single file first. |
| "Rate limit exceeded" | Built-in `RateLimiter` handles this automatically with exponential backoff. |
| "Selector timeout" | Use `browser_force_click` or `stagehand_act` with natural language. |
| "Element not found" | Use `browser_get_response` first to discover valid selectors. |
| "Stagehand not initialized" | Stagehand requires a running browser. Call `browser_navigate` first. |
| "Invalid analyzer format" | Check auto-detection in `parser-factory.js`. Pass the correct JSON structure. |

### Rate Limiting

The `RateLimiter` class handles API rate limits automatically:

| Error Type | Retry Strategy |
|------------|---------------|
| Rate Limit (429) | 30s -> 40s -> 50s (max 120s) |
| Server Error (5xx) | 10s -> 20s -> 30s (max 60s) |
| Overloaded / Capacity | Same as server error |
| Network Error | Exponential backoff with jitter |

### Debug Tips

1. Check `evidence/` directory for detailed per-finding agent actions
2. Review `findings_summary.json` for a quick overview
3. Open `report.html` in a browser for visual inspection
4. Install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) VS Code extension to see findings inline
5. Look at `ci-report.json` for classification breakdown

---

## Dependencies

### Runtime

| Package | Version | Purpose |
|---------|---------|---------|
| `openai` | ^6.15.0 | GPT-4/GPT-4o API client |
| `playwright` | ^1.57.0 | Browser automation |
| `@browserbasehq/stagehand` | ^3.0.8 | AI-powered browser interactions |
| `zx` | ^8.8.5 | Shell utilities, `fs` and `path` helpers |
| `inquirer` | ^9.3.8 | Interactive CLI prompts |
| `chalk` | ^4.1.2 | Terminal colors |
| `axios` | ^1.13.2 | HTTP client |
| `js-yaml` | ^4.1.1 | YAML parsing |
| `zod` | ^4.3.6 | Schema validation |

### Development

| Package | Version | Purpose |
|---------|---------|---------|
| `vitest` | ^4.0.18 | Test runner (132 tests) |

---

## License

ISC

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes (follow conventions in `AGENTS.md`)
4. Run `npm test` to verify all 132 tests pass
5. Submit a pull request

Key areas for contribution:
- New static analyzer parsers
- Additional browser/Stagehand tools
- Improved prompt templates
- Report format enhancements
- Test coverage expansion
