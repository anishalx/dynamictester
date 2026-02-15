# Dynamic Security Tester

**AI-powered DAST tool that bridges static analysis with automated exploitation validation.**

Takes vulnerability findings from static analysis tools (Semgrep, Trivy, CodeQL, Gitleaks, OSV, Syft, Noir) and uses LLM agents combined with Playwright browser automation to dynamically test, validate, and produce developer-friendly reports. Supports 6 LLM providers out of the box.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Analyzer Support** | Parses output from 7 static analyzers with auto-detection |
| **6 LLM Providers** | OpenAI, DeepSeek, Qwen, GitHub Models, Google Gemini, GitHub Copilot |
| **20 Agent Tools** | 15 browser tools + 5 exploitation workflow tools |
| **16 Vulnerability Categories** | Injection, XSS, SSRF, XXE, traversal, auth, secrets, and more |
| **Content-Based Deduplication** | SHA-256 hashing eliminates duplicate findings across analyzers |
| **4-Class Classification** | CONFIRMED / LIKELY / BLOCKED / NOT_REPRODUCIBLE |
| **5-Level Proof System** | L0 (no evidence) through L4 (critical impact demonstrated) |
| **Priority Scoring** | Severity + confidence + exploitability bonus, sorted highest-first |
| **Testing Thoroughness Tracking** | HTTP request counting ensures the agent actually tests each vulnerability |
| **Source Code Mapping** | Links every finding to exact `file:line:column` for developers |
| **Industry Reports** | SARIF 2.1.0 for IDE integration, HTML for stakeholders, JSON for CI |
| **Route Intelligence** | Automatic Express router parsing for endpoint discovery |
| **Auth Propagation** | JWT/cookie capture and injection across tests |
| **WAF Bypass Engine** | Deterministic encoding, technique, and WAF-specific bypass generation |
| **Response Analysis** | DB error detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, CouchDB, Cassandra), 11 WAF signatures, boolean/timing analysis |
| **CI/CD Mode** | Exit codes (`0`=pass, `1`=confirmed, `2`=error), `--fail-on-likely`, `--fail-on-blocked` |

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Auth & Providers](#auth--providers)
- [Supported Analyzers](#supported-analyzers)
- [Agent Tools](#agent-tools)
- [Classification System](#classification-system)
- [Output & Reports](#output--reports)
- [Prompt Templates](#prompt-templates)
- [CI/CD Mode](#cicd-mode)
- [Configuration](#configuration)
- [Testing](#testing)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)
- [Dependencies](#dependencies)

---

## Architecture

```
+---------------------------------------------------------------------------+
|                        DYNAMIC SECURITY TESTER                            |
+---------------------------------------------------------------------------+
|                                                                           |
|  +-------------+   +-------------+   +-------------+   +-------------+   |
|  |   Parser    |-->|    Queue    |-->|  Executor   |-->|   Reports   |   |
|  |             |   |  Generator  |   |             |   |             |   |
|  | Semgrep     |   |             |   | LLM Agent   |   | SARIF 2.1.0 |   |
|  | Trivy       |   | 16 category |   | + Bypass    |   | HTML        |   |
|  | CodeQL      |   | buckets w/  |   |   Engine    |   | JSON Summary|   |
|  | Syft / OSV  |   | priority    |   | + Payload   |   | CI Report   |   |
|  | Gitleaks    |   | scoring     |   |   Generator |   |             |   |
|  | Noir        |   |             |   | + Response  |   |             |   |
|  |             |   |             |   |   Analyzer  |   |             |   |
|  +------+------+   +-------------+   +------+------+   +-------------+   |
|         |                                   |                             |
|         v                                   v                             |
|  +-------------+                   +------------------+                   |
|  |    Route    |                   | Browser Manager  |                   |
|  | Intelligence|                   |  (15 tools)      |                   |
|  |             |                   |                  |                   |
|  | Express     |                   | HTTP Requests    |                   |
|  | Router      |                   | Form Filling     |                   |
|  | Parsing     |                   | Force Click      |                   |
|  +------+------+                   | Script Exec      |                   |
|         |                          | Auth Capture     |                   |
|         v                          +--------+---------+                   |
|  +-------------+                            |                             |
|  |    Auth     |                   +--------v---------+                   |
|  |   Manager   |<---------------->| Vuln Classifier  |                   |
|  |             |                   |                  |                   |
|  | JWT/Cookie  |                   | 4-Level Status   |                   |
|  | Injection   |                   | 5-Level Proof    |                   |
|  +-------------+                   +------------------+                   |
|                                                                           |
|  +--------------------------------------------------------------------+  |
|  |                     Provider Registry                              |  |
|  |  OpenAI | DeepSeek | Qwen | GitHub Models | Gemini | Copilot      |  |
|  +--------------------------------------------------------------------+  |
+---------------------------------------------------------------------------+
```

**Pipeline:** Parse static results -> Deduplicate (SHA-256) -> Queue by vuln type with priority scoring -> Execute via LLM agent with browser tools -> Classify results (4-level) -> Generate reports

---

## Project Structure

```
dynamictester/
├── src/
│   ├── main.js                          # Entry point — interactive CLI, auth subcommand, CI mode
│   │
│   ├── agents/
│   │   └── executor.js                  # LLM agent loop (tool-calling, 75 turns, stall detection)
│   │
│   ├── auth/
│   │   └── auth-manager.js              # JWT/cookie capture and injection (singleton)
│   │
│   ├── config/
│   │   └── config-manager.js            # Persistent config at ~/.config/dynamictester/
│   │
│   ├── mcp/
│   │   └── browser-server.js            # BrowserManager — 15 Playwright tools for the LLM
│   │
│   ├── parser/
│   │   ├── normalizer.js                # Severity/confidence normalization, SHA-256 dedup, 18+ categories
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
│   ├── providers/
│   │   ├── provider-interface.js        # BaseProvider abstract class
│   │   ├── provider-registry.js         # Provider registration and client creation
│   │   ├── openai-provider.js           # OpenAI (GPT-4o, o1, o3-mini)
│   │   ├── deepseek-provider.js         # DeepSeek (V3, R1)
│   │   ├── qwen-provider.js             # Qwen / Alibaba Cloud (max, plus, coder, flash, turbo)
│   │   ├── github-provider.js           # GitHub Models (GPT-4o, DeepSeek-R1, Llama, Mistral)
│   │   ├── google-provider.js           # Google Gemini (API key) + Antigravity OAuth
│   │   ├── copilot-provider.js          # GitHub Copilot (Claude, Gemini, GPT via device code)
│   │   ├── antigravity-client.js        # OpenAI-compatible adapter for Antigravity API
│   │   └── google-oauth.js              # Google OAuth 2.0 + PKCE for Antigravity
│   │
│   ├── queue/
│   │   └── queue-generator.js           # 16 category buckets with priority scoring
│   │
│   ├── reporting/
│   │   ├── report-generator.js          # SARIF 2.1.0, HTML with executive summary, developer JSON
│   │   └── ci-reporter.js              # CI/CD exit codes (0=pass, 1=confirmed, 2=error)
│   │
│   ├── testing/
│   │   ├── bypass-engine.js             # Deterministic WAF/filter bypass generation
│   │   ├── classifier.js               # CONFIRMED/LIKELY/BLOCKED/NOT_REPRODUCIBLE classification
│   │   ├── exploitation-levels.js       # 5-level proof system (L0-L4)
│   │   ├── intelligence-aggregator.js   # Context gathering for payload crafting
│   │   ├── payload-generator.js         # LLM-powered payload generation with anti-hallucination
│   │   ├── response-analyzer.js         # DB error detection, WAF detection, SSRF/XXE/XSS analysis
│   │   ├── test-interface.js            # VulnerabilityTester base class (confirm -> fingerprint -> exploit)
│   │   ├── bypass-engine.test.js        # Tests for bypass engine (18 tests)
│   │   ├── payload-generator.test.js    # Tests for payload generator (88 tests)
│   │   └── response-analyzer.test.js    # Tests for response analyzer (27 tests)
│   │
│   └── utils/
│       ├── error-handling.js            # Error classification, retry eligibility, delay calculation
│       └── rate-limiter.js              # RateLimiter — retry with backoff, parallel stagger
│
├── prompts/                             # LLM prompt templates (9 files)
│   ├── exploit-injection.txt            # SQL/command injection
│   ├── exploit-xss.txt                  # Cross-site scripting
│   ├── exploit-ssrf.txt                 # Server-side request forgery
│   ├── exploit-auth.txt                 # Authentication and session security
│   ├── exploit-traversal.txt            # Path traversal
│   ├── exploit-xxe.txt                  # XML external entity
│   ├── exploit-redirect.txt             # Open redirect
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
- At least one LLM provider configured (see [Auth & Providers](#auth--providers))

### Setup

```bash
# Clone and install
git clone https://github.com/anishalx/dynamictester.git
cd dynamictester
npm install

# Install Playwright browsers
npx playwright install chromium

# Configure an LLM provider (interactive)
node src/main.js auth login
```

### Quick Setup with OpenAI

If you just want to get started with OpenAI:

```bash
# Set API key via environment variable (no auth login needed)
export OPENAI_API_KEY="sk-your-key-here"
# Or create a .env file:
echo 'OPENAI_API_KEY=sk-your-key-here' > .env

# Run
node src/main.js
```

---

## Quick Start

```bash
# Interactive mode
node src/main.js

# With provider/model override
node src/main.js --provider=copilot --model=claude-sonnet-4.5

# CI/CD mode
node src/main.js --ci --fail-on-likely
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--provider=<name>` | Override LLM provider (`openai`, `deepseek`, `qwen`, `github`, `google`, `copilot`) |
| `--model=<name>` | Override LLM model (e.g., `gpt-4o`, `claude-sonnet-4.5`, `deepseek-chat`) |
| `--ci` | Enable CI/CD mode -- generate CI report and exit with status code |
| `--fail-on-likely` | In CI mode, also fail for LIKELY-classified findings |
| `--fail-on-blocked` | In CI mode, also fail for BLOCKED-classified findings |

### Auth Subcommand

```bash
node src/main.js auth login     # Configure a new LLM provider
node src/main.js auth status    # Show configured providers and defaults
node src/main.js auth logout    # Remove provider credentials
```

### Example Session

```
🔍 Dynamic Security Tester
────────────────────────────────────────────────────────────────
Supported analyzers: semgrep, gitleaks, trivy, osv, syft, noir, codeql
────────────────────────────────────────────────────────────────

? Path to analyzer result file(s): semgrep.json, trivy.json, gitleaks.json

📋 Step 1: Parsing static analysis results...
✅ Parsed 91 vulnerabilities from 3 files
   - semgrep: 41 findings
   - gitleaks: 47 findings
   - trivy: 3 findings

📋 Step 2: Generating exploitation queues...
✅ Created 7 queues:
   - injection: 11 vulnerabilities (priority-sorted)
   - xss: 10 vulnerabilities
   - traversal: 4 vulnerabilities
   - redirect: 1 vulnerability
   - deserialization: 1 vulnerability
   - secrets: 57 vulnerabilities
   - other: 7 vulnerabilities

📋 Step 3: Reviewing vulnerabilities...
🎯 Found 11 INJECTION vulnerabilities:
   1. SQLi in routes/login.ts:34
   2. NoSQLi in data/mongodb.js:18
   3. ...

? Run dynamic exploitation tests for injection? (Y/n)

🚀 Starting exploitation agent (claude-sonnet-4.5 via GitHub Copilot)...
   Rate limit handling: 3 retries with exponential backoff
   Loaded 11 vulnerabilities from queue

🤖 Turn 1:
   🔧 read_queue_file
🤖 Turn 2:
   🔧 generate_payloads
🤖 Turn 3:
   🔧 browser_http_request
      📊 Evidence saved: 1/11
      🔴 CONFIRMED — Level 4: Critical Impact Demonstrated
   ...

📋 Generating reports...
✅ SARIF report saved: output/report.sarif.json
✅ HTML report saved: output/report.html
✅ Summary saved: output/developer_summary.json

════════════════════════════════════════════════════════
  CI SECURITY SCAN SUMMARY
════════════════════════════════════════════════════════
  Total Findings:      91
  🔴 CONFIRMED:        3
  🟡 LIKELY:           2
  🟠 BLOCKED:          1
  🟢 NOT REPRODUCIBLE: 85
────────────────────────────────────────────────────────
  Exit Code: 1
  Result: FAIL: 3 CONFIRMED exploit(s) found
════════════════════════════════════════════════════════
```

---

## Auth & Providers

The tool supports 6 LLM providers. All providers expose an OpenAI-compatible client interface, so the exploitation agent works identically regardless of provider.

### Provider Overview

| Provider | Name | Default Model | Auth Method | Env Var Fallback |
|----------|------|---------------|-------------|------------------|
| **OpenAI** | `openai` | `gpt-4o` | API key | `OPENAI_API_KEY` |
| **DeepSeek** | `deepseek` | `deepseek-chat` | API key | `DEEPSEEK_API_KEY` |
| **Qwen** | `qwen` | `qwen-max` | DashScope API key + region | `DASHSCOPE_API_KEY` |
| **GitHub Models** | `github` | `gpt-4o` | GitHub PAT (`ghp_*`) | `GITHUB_TOKEN` |
| **Google Gemini** | `google` | `gemini-2.5-flash` | API key or Antigravity OAuth | `GOOGLE_API_KEY` |
| **GitHub Copilot** | `copilot` | `claude-sonnet-4.5` | Device code OAuth | `GITHUB_COPILOT_TOKEN` |

### Provider Selection Priority

1. **`--provider` / `--model` CLI flags** -- highest priority
2. **Stored defaults** -- set via `auth login` or auto-saved
3. **Single configured provider** -- auto-selected
4. **`OPENAI_API_KEY` env var** -- backward-compatible fallback
5. **Interactive prompt** -- if multiple providers are configured

### Configuration Storage

Provider credentials are stored in `~/.config/dynamictester/config.json`:

```json
{
  "version": 1,
  "defaultProvider": "copilot",
  "defaultModel": "claude-sonnet-4.5",
  "providers": {
    "copilot": { "token": "ghu_...", "configured": true },
    "openai": { "apiKey": "sk-...", "configured": true }
  }
}
```

### Provider-Specific Notes

**GitHub Copilot** authenticates via GitHub Device Code flow (same as VS Code). Run `auth login`, select Copilot, and follow the browser prompt. Models are fetched dynamically from the API.

**Google Gemini** has two modes:
- **API Key** (simple) -- enter a Gemini API key, uses `generativelanguage.googleapis.com`
- **Antigravity OAuth** (advanced) -- full Google Cloud OAuth with PKCE, enables access to additional models (Claude, GPT via Antigravity)

**Qwen** prompts for a region (International/Singapore, US/Virginia, or China/Beijing) which determines the API endpoint.

---

## Supported Analyzers

All parsers extend `BaseParser` and implement `validate(data)` and `async parse(data)`. Analyzer type is auto-detected from JSON structure.

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

Results are deduplicated using content-based SHA-256 hashing (on source, checkId, file, line, column), normalized, and merged into unified exploitation queues.

---

## Agent Tools

The LLM agent has access to **20 tools** across two categories.

### Browser Tools (15)

Playwright-based browser automation exposed to the LLM agent:

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
| `browser_http_request` | Direct HTTP/API requests (GET/POST/PUT/DELETE/PATCH) with response timing |
| `browser_execute_script` | Execute JavaScript in page context |
| `browser_capture_auth` | Capture JWT/cookies after login |
| `browser_get_auth_status` | Check stored auth tokens |
| `browser_clear_auth` | Clear all stored auth tokens |

### Exploitation Workflow Tools (5)

Orchestration tools for the exploitation pipeline:

| Tool | Description |
|------|-------------|
| `read_queue_file` | Load the vulnerability queue JSON with summary stats |
| `generate_payloads` | Generate context-aware payload guidance per vulnerability and stage |
| `analyze_response` | Analyze HTTP response for DB errors, WAF blocking, SSRF/XXE/XSS indicators, boolean/timing signals |
| `generate_bypasses` | Generate WAF/filter bypass variations for blocked payloads |
| `save_evidence` | Save exploitation evidence with full source code mapping and 4-level classification |

### `browser_http_request` Example

The most important tool for API testing. Returns response timing for time-based injection detection:

```javascript
browser_http_request({
  url: "https://target.com/api/login",
  method: "POST",
  body: '{"email": "\' OR 1=1--", "password": "x"}',
  contentType: "application/json"
})
// Returns:
// {
//   status: "success",
//   httpStatus: 200,
//   body: "...",
//   json: {...},
//   responseTimeMs: 1243,
//   responseTimeSec: 1.243
// }
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

### Testing Thoroughness

The agent loop tracks HTTP requests between `save_evidence` calls. If `save_evidence` is called for a web vulnerability without any prior HTTP requests (`browser_http_request`, `browser_navigate`, etc.), the system:
1. Logs a warning in the console
2. Records `httpRequestsMade: 0` in the evidence file for audit trail

This prevents the LLM from shortcutting by saving NOT_REPRODUCIBLE without actually testing.

---

## Output & Reports

### Directory Structure

```
output/
├── evidence/                       # Individual finding evidence
│   ├── evidence-SEMGREP-xxx-1234.json
│   └── evidence-GITLEAKS-xxx-1234.json
├── deliverables/                   # Exploitation queues (priority-sorted)
│   ├── injection_exploitation_queue.json
│   ├── xss_exploitation_queue.json
│   └── secrets_exploitation_queue.json
├── findings_summary.json           # Quick summary with classifications
├── developer_summary.json          # Categorized findings for developers
├── report.sarif.json               # SARIF 2.1.0 for IDE integration
├── report.html                     # Visual HTML report with executive summary
└── ci-report.json                  # CI/CD machine-readable report
```

### Evidence Format

Each finding includes full source code mapping, 4-level classification, and testing audit trail:

```json
{
  "findingId": "SEMGREP-javascript.sequelize.sql-injection-34-28",
  "timestamp": "2025-02-15T10:30:00.000Z",

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

  "classification": "CONFIRMED",
  "status": "CONFIRMED",
  "level": 4,
  "levelName": "Critical Impact Demonstrated",
  "confidence": "HIGH",
  "classificationReason": "Data extraction proven with critical impact",
  "includeInReport": true,
  "requiresAction": true,
  "ciExitCode": 1,
  "httpRequestsMade": 5
}
```

### SARIF Report

Uses tool-scoped rule IDs (DST-001, DST-002, ...) and includes classification metadata. Integrates with VS Code (SARIF Viewer extension), GitHub Code Scanning, and other IDEs:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "DynamicSecurityTester", "version": "1.0.0" } },
    "results": [{
      "ruleId": "DST-001",
      "level": "error",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "routes/login.ts" },
          "region": { "startLine": 34, "startColumn": 28 }
        }
      }],
      "properties": {
        "classification": "CONFIRMED",
        "level": 4,
        "confidence": "HIGH",
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
- Executive summary with risk assessment and false positive rate
- Classification badges (CONFIRMED / LIKELY / BLOCKED / NOT_REPRODUCIBLE)
- Severity-sorted findings
- Source code locations (`file:line:column`)
- Payload details and exploitation proof (HTML-escaped)
- Remediation suggestions
- OWASP and CWE references

---

## Prompt Templates

9 prompt templates cover 16 vulnerability categories. Each prompt is universal and derives endpoints from source code paths.

### Prompt Mapping

| Queue Category | Prompt File | Key Features |
|----------------|-------------|--------------|
| `injection` | `exploit-injection.txt` | Technology-aware (MySQL, PostgreSQL, SQLite, MSSQL, MongoDB) |
| `xss` | `exploit-xss.txt` | Context-aware (HTML, Attribute, JavaScript, DOM) |
| `ssrf` | `exploit-ssrf.txt` | Cloud metadata, internal service discovery, bypass techniques |
| `auth` | `exploit-auth.txt` | JWT, session management, privilege escalation |
| `traversal` | `exploit-traversal.txt` | OS-aware with encoding variations |
| `xxe` | `exploit-xxe.txt` | Parser-specific payloads |
| `redirect` | `exploit-redirect.txt` | Whitelist bypass techniques |
| `secrets` | `exploit-secrets.txt` | Credential validation and impact assessment |
| `csrf` | `exploit-generic.txt` | General testing methodology |
| `deserialization` | `exploit-generic.txt` | General testing methodology |
| `upload` | `exploit-generic.txt` | General testing methodology |
| `access` | `exploit-generic.txt` | General testing methodology |
| `crypto` | `exploit-generic.txt` | General testing methodology |
| `config` | `exploit-generic.txt` | General testing methodology |
| `dependency` | `exploit-generic.txt` | General testing methodology |
| `other` | `exploit-generic.txt` | General testing methodology |

### Endpoint Discovery

Prompts derive endpoints from source file paths:

```
routes/login.ts      -> /login, /api/login
controllers/users.js -> /users, /api/users
api/v1/products.js   -> /api/v1/products
```

The route parser (`src/parser/route-parser.js`) also statically analyzes Express `app.get()` / `router.post()` patterns to map source locations to HTTP endpoints.

---

## CI/CD Mode

Run with `--ci` to get machine-readable output and exit codes:

```bash
# Basic CI mode (fails only on CONFIRMED exploits)
node src/main.js --ci

# Strict mode (fails on CONFIRMED + LIKELY)
node src/main.js --ci --fail-on-likely

# Maximum strictness (fails on CONFIRMED + LIKELY + BLOCKED)
node src/main.js --ci --fail-on-likely --fail-on-blocked
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass -- no actionable findings |
| `1` | Fail -- confirmed exploits found (or LIKELY/BLOCKED if flags set) |
| `2` | Error -- scan failed to complete |

### CI Report

Machine-readable JSON at `output/ci-report.json`:

```json
{
  "timestamp": "2025-02-15T10:35:00.000Z",
  "summary": {
    "total": 91,
    "confirmed": 3,
    "likely": 2,
    "blocked": 1,
    "notReproducible": 85
  },
  "exitCode": 1,
  "exitReason": "FAIL: 3 CONFIRMED exploit(s) found",
  "confirmedExploits": [{ "id": "...", "endpoint": "/api/login", "cwe": "CWE-89" }]
}
```

---

## Configuration

### Key Settings

**Agent loop** (`src/agents/executor.js`):

```javascript
const maxTurns = 75;                    // Max agent conversation turns
const MAX_TOOL_RESULT_LENGTH = 8000;    // Truncate tool results to avoid token limits
const temperature = 0.2;                // Low temperature for consistent exploitation
```

**Browser timeouts** (`src/mcp/browser-server.js`):

```javascript
const DEFAULT_TIMEOUT = 5000;  // 5 seconds for most operations
const SHORT_TIMEOUT = 2000;    // 2 seconds for quick checks
```

**Rate limiting** (`src/utils/rate-limiter.js`):

```javascript
{
  maxRetries: 3,        // Retry attempts
  staggerDelay: 2000,   // Delay between parallel task starts (ms)
  retryDelay: 5000      // Base delay between retries (ms)
}
```

**Retry delays by error type** (`src/utils/error-handling.js`):

| Error Type | Retry Strategy |
|------------|---------------|
| Rate Limit (429) | 30s -> 40s -> 50s (max 120s), respects Retry-After header |
| Server Error (5xx) | 10s -> 20s -> 30s (max 60s) |
| Timeout | Exponential backoff with jitter |
| Network Error | Exponential backoff with jitter |
| Auth Error (401/403) | Not retried (fatal) |

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
| `src/testing/response-analyzer.test.js` | 27 | DB error detection, WAF detection, validation error handling, boolean comparison, timing analysis |
| **Total** | **133** | |

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
    return data && Array.isArray(data.findings);
  }

  async parse(data) {
    const jsonData = typeof data === 'string' ? JSON.parse(data) : data;
    if (!this.validate(jsonData)) throw new Error('Invalid format');

    return jsonData.findings.map(f => {
      const { type, subType } = categorizeVulnerability({
        description: f.message,
        checkId: f.ruleId,
        cwe: f.cwe
      });

      return {
        id: f.id,
        source: 'newanalyzer',
        type,
        subType,
        severity: normalizeSeverity(f.severity),
        confidence: 'MEDIUM',
        location: { file: f.file || 'unknown', line: f.line || 0, column: f.column || 0 },
        description: f.message,
        remediation: f.fix || '',
        cwe: f.cwe || [],
        checkId: f.ruleId
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

### Adding a New LLM Provider

1. **Create** `src/providers/<name>-provider.js` extending `BaseProvider`:

```javascript
import { BaseProvider } from './provider-interface.js';
import OpenAI from 'openai';

export class NewProvider extends BaseProvider {
  get name() { return 'newprovider'; }
  get displayName() { return 'New Provider'; }
  getModels() { return [{ id: 'model-v1', name: 'Model V1', description: '...' }]; }
  getDefaultModel() { return 'model-v1'; }

  async authenticate() { /* prompt for API key, save via config-manager */ }
  async validateAuth() { /* check stored credentials */ }
  createClient(config) { return new OpenAI({ apiKey: config.apiKey, baseURL: '...' }); }
}
```

2. **Register in** `src/providers/provider-registry.js`:

```javascript
import { NewProvider } from './newprovider-provider.js';

const PROVIDER_REGISTRY = Object.freeze({
  // ... existing providers
  newprovider: NewProvider
});
```

### Adding a New Browser Tool

In `src/mcp/browser-server.js`, add the method to `BrowserManager` and register in `getTools()`:

```javascript
async customAction({ param1 }) {
  try {
    return { status: 'success', data: result };
  } catch (e) {
    return { status: 'error', message: e.message };
  }
}
```

### Adding a New Prompt Template

1. Create `prompts/exploit-<type>.txt` with `{{WEB_URL}}` and `{{QUEUE_PATH}}` placeholders
2. Add mapping in `src/main.js` `promptMapping` object

### Adding a New Vulnerability Category

Add to the categorization map in `src/parser/normalizer.js` and the queue bucket in `src/queue/queue-generator.js`.

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "No vulnerabilities found" | Verify analyzer output format matches expected structure. Run with a single file first. |
| "Rate limit exceeded" | Built-in `RateLimiter` handles this automatically with exponential backoff. |
| "Request timed out" | Retried automatically (up to 3 times). If persistent, try a different provider. |
| "Selector timeout" | Use `browser_force_click` instead of `browser_click`. |
| "Element not found" | Use `browser_get_response` first to discover valid selectors. |
| "Invalid analyzer format" | Check auto-detection in `parser-factory.js`. Pass the correct JSON structure. |
| No configured providers | Run `node src/main.js auth login` or set `OPENAI_API_KEY` environment variable. |
| Provider auth expired | Run `node src/main.js auth login` to re-authenticate. Google Antigravity tokens refresh automatically. |

### Debug Tips

1. Check `evidence/` directory for detailed per-finding agent actions
2. Review `findings_summary.json` for a quick overview
3. Open `report.html` in a browser for visual inspection
4. Install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) VS Code extension to see findings inline
5. Look at `ci-report.json` for classification breakdown
6. Check `httpRequestsMade` field in evidence files to verify testing thoroughness

---

## Dependencies

### Runtime

| Package | Version | Purpose |
|---------|---------|---------|
| `openai` | ^6.15.0 | LLM API client (used by all providers) |
| `playwright` | ^1.57.0 | Browser automation |
| `zx` | ^8.8.5 | Shell utilities, `fs` and `path` helpers |
| `inquirer` | ^9.3.8 | Interactive CLI prompts |
| `chalk` | ^4.1.2 | Terminal colors |
| `axios` | ^1.13.2 | HTTP client |
| `dotenv` | ^17.3.1 | Environment variable loading from `.env` |
| `js-yaml` | ^4.1.1 | YAML parsing |
| `zod` | ^4.3.6 | Schema validation |

### Development

| Package | Version | Purpose |
|---------|---------|---------|
| `vitest` | ^4.0.18 | Test runner (133 tests) |

---

## License

ISC

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes (follow conventions in `AGENTS.md`)
4. Run `npm test` to verify all 133 tests pass
5. Submit a pull request

Key areas for contribution:
- New static analyzer parsers
- New LLM providers
- Additional browser tools
- Improved prompt templates
- Report format enhancements
- Test coverage expansion
