# Dynamic Security Tester

**Industry-grade AI-powered dynamic security testing tool that bridges static analysis with automated exploitation validation.**

Takes vulnerability findings from static analysis tools (Semgrep, Trivy, CodeQL, etc.) and uses OpenAI's GPT-4 combined with Playwright browser automation to dynamically test, validate, and generate developer-friendly reports.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Analyzer Support** | Semgrep, Trivy, CodeQL, Syft, OSV, Gitleaks, Noir parsers |
| **Universal Prompts** | Context-aware testing for any web application |
| **LLM-Crafted Payloads** | Technology-specific payloads from static analysis context |
| **Source Code Mapping** | Links findings to exact `file:line:column` for developers |
| **Industry Reports** | SARIF for IDE integration, HTML for stakeholders |
| **Advanced Browser Tools** | HTTP requests, force clicks, scrolling, script execution |
| **Route Intelligence** | Automatic Express router parsing for endpoint discovery |
| **Auth Propagation** | JWT/cookie capture and injection across tests |
| **WAF Bypass Engine** | LLM-powered bypass generation for blocked payloads |
| **Response Analysis** | Intelligent detection of database errors, WAF blocking, validation errors |
| **Confidence Scoring** | CONFIRMED/LIKELY/BLOCKED/NOT_REPRODUCIBLE classification |
| **CI Mode** | Exit codes and reports for CI/CD pipeline integration |

---

## 📋 Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Output & Reports](#output--reports)
- [Browser Tools](#browser-tools)
- [Prompt Templates](#prompt-templates)
- [Configuration](#configuration)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)

---

## Architecture

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
│  │ CodeQL      │   │ vuln type   │   │ + Bypass    │   │ • JSON Summary  │  │
│  │ Syft/OSV    │   │             │   │   Engine    │   │ • CI Report     │  │
│  │ Gitleaks    │   │             │   │             │   │                 │  │
│  │ Noir        │   │             │   │             │   │                 │  │
│  └─────────────┘   └─────────────┘   └──────┬──────┘   └─────────────────┘  │
│         │                                   │                                │
│         ▼                                   ▼                                │
│  ┌─────────────┐                   ┌────────────────┐                        │
│  │   Route     │                   │ Browser Manager│                        │
│  │ Intelligence│                   │                │                        │
│  │             │                   │ • HTTP Requests│                        │
│  │ Express     │                   │ • Form Filling │                        │
│  │ Router      │                   │ • Force Click  │                        │
│  │ Parsing     │                   │ • Script Exec  │                        │
│  └──────┬──────┘                   └───────┬────────┘                        │
│         │                                  │                                 │
│         ▼                                  ▼                                 │
│  ┌─────────────┐                   ┌────────────────┐                        │
│  │    Auth     │                   │    Response    │                        │
│  │   Manager   │◀─────────────────▶│    Analyzer    │                        │
│  │             │                   │                │                        │
│  │ JWT/Cookie  │                   │ DB Errors      │                        │
│  │ Injection   │                   │ WAF Detection  │                        │
│  └─────────────┘                   │ Classification │                        │
│                                    └────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
dynamictester/
├── src/
│   ├── main.js                          # Application entry point
│   │
│   ├── agents/
│   │   └── executor.js                  # OpenAI GPT agent with tool execution
│   │
│   ├── auth/
│   │   └── auth-manager.js              # JWT/cookie capture and injection
│   │
│   ├── mcp/
│   │   └── browser-server.js            # Playwright browser automation (13 tools)
│   │
│   ├── parser/
│   │   ├── normalizer.js                # Normalize findings across analyzers
│   │   ├── parser-factory.js            # Auto-detect and instantiate parsers
│   │   ├── parser-interface.js          # Base parser interface
│   │   ├── result-parser.js             # Main parsing coordinator
│   │   ├── route-parser.js              # Express router intelligence
│   │   ├── validator.js                 # Input validation
│   │   └── parsers/
│   │       ├── semgrep-parser.js        # Semgrep JSON parser
│   │       ├── trivy-parser.js          # Trivy security scanner parser
│   │       ├── codeql-parser.js         # CodeQL SARIF parser
│   │       ├── syft-parser.js           # Syft SBOM parser
│   │       ├── osv-parser.js            # OSV vulnerability scanner parser
│   │       ├── gitleaks-parser.js       # Gitleaks secrets scanner parser
│   │       └── noir-parser.js           # Noir parser
│   │
│   ├── queue/
│   │   └── queue-generator.js           # Group vulnerabilities by type
│   │
│   ├── reporting/
│   │   ├── report-generator.js          # SARIF, HTML, JSON report generation
│   │   └── ci-reporter.js               # CI/CD exit codes and summaries
│   │
│   ├── testing/
│   │   ├── bypass-engine.js             # LLM-powered WAF/filter bypass
│   │   ├── classifier.js                # CONFIRMED/LIKELY/BLOCKED classification
│   │   ├── exploitation-levels.js       # 4-level proof system (L0-L4)
│   │   ├── intelligence-aggregator.js   # Gather context for payload generation
│   │   ├── payload-generator.js         # LLM payload crafting with anti-hallucination
│   │   ├── response-analyzer.js         # DB errors, WAF, validation detection
│   │   └── test-interface.js            # Testing interface
│   │
│   └── utils/
│       ├── error-handling.js            # Global error handlers
│       └── rate-limiter.js              # API rate limiting with backoff
│
├── prompts/
│   ├── exploit-injection.txt            # SQL/Command injection payloads
│   ├── exploit-xss.txt                  # Cross-site scripting payloads
│   ├── exploit-traversal.txt            # Path traversal payloads
│   ├── exploit-xxe.txt                  # XML external entity payloads
│   ├── exploit-redirect.txt             # Open redirect payloads
│   ├── exploit-secrets.txt              # Hardcoded secrets validation
│   └── exploit-generic.txt              # General vulnerability testing
│
├── package.json                         # Dependencies and scripts
├── README.md                            # This file
└── MULTI_ANALYZER_USAGE.md              # Multi-analyzer usage guide
```

---

## Installation

### Prerequisites

- Node.js 18+
- npm
- OpenAI API key

### Setup

```bash
# Install dependencies
npm install

# Set OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Install Playwright browsers
npx playwright install chromium
```

---

## Quick Start

```bash
node src/main.js
```

**Interactive prompts:**
1. Path to static analyzer result.json
2. Target URL for testing (e.g., `http://localhost:3000`)
3. Output directory

### Example Session

```
🔍 Dynamic Security Tester (OpenAI Powered)
────────────────────────────────────────────────────────────────

📋 Step 1: Parsing static analysis results...
✅ Parsed 15 vulnerabilities

📋 Step 2: Generating exploitation queues...
✅ Created injection_exploitation_queue.json (5 vulnerabilities)
✅ Created xss_exploitation_queue.json (4 vulnerabilities)

📋 Step 3: Reviewing vulnerabilities...
🎯 Found 5 INJECTION vulnerabilities:
   1. SQLi in routes/login.ts:34
   2. CommandInjection in utils/exec.js:12

? Run dynamic exploitation tests for injection? (Y/n)

📋 Generating reports...
✅ SARIF report saved: output/report.sarif.json
✅ HTML report saved: output/report.html

🎉 Dynamic testing session complete!

Output files:
  • evidence/           - Individual finding details
  • findings_summary.json - Quick summary for developers
  • report.sarif.json   - SARIF for IDE integration
  • report.html         - Visual HTML report
```

---

## Output & Reports

### Directory Structure

```
output/
├── evidence/                       # Individual findings
│   ├── evidence-vuln-001.json
│   └── evidence-vuln-002.json
├── deliverables/                   # Exploitation queues
│   ├── injection_exploitation_queue.json
│   └── xss_exploitation_queue.json
├── findings_summary.json           # Quick summary
├── developer_summary.json          # Categorized findings
├── report.sarif.json               # SARIF for VS Code
└── report.html                     # Visual HTML report
```

### Evidence Format (Developer-Friendly)

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

Integrates with VS Code, GitHub Code Scanning, and other IDEs:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/...",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "DynamicSecurityTester" } },
    "results": [
      {
        "ruleId": "CWE-89",
        "level": "error",
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "routes/login.ts" },
            "region": { "startLine": 34, "startColumn": 28 }
          }
        }]
      }
    ]
  }]
}
```

### HTML Report

Professional dark-themed report with:
- Confirmed vs Not Exploitable summary
- Source code locations (file:line:column)
- Payload details and exploitation proof
- Remediation suggestions
- OWASP/CWE references

---

## Browser Tools

The AI agent has access to 13 browser automation tools:

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to a URL |
| `browser_fill` | Fill form fields |
| `browser_click` | Click elements |
| `browser_type_and_submit` | Type text + Enter |
| `browser_get_response` | Get page content (forms, inputs, links) |
| `browser_screenshot` | Take screenshot for evidence |
| `browser_close` | Close browser |
| **Advanced Tools** | |
| `browser_force_click` | JavaScript click (bypasses visibility) |
| `browser_scroll` | Scroll page (up/down/top/bottom) |
| `browser_wait_for_element` | Wait for SPA content |
| `browser_http_request` | **Direct HTTP/API requests** |
| `browser_execute_script` | Execute JavaScript in page |

### `browser_http_request` (Most Important)

Enables direct API testing without browser UI:

```javascript
// Test SQL injection on REST API
browser_http_request({
  url: "https://example.com/api/login",
  method: "POST",
  body: '{"email": "\' OR 1=1--", "password": "x"}',
  contentType: "application/json"
})

// Returns
{
  status: "success",
  httpStatus: 200,
  body: "{\"token\": \"admin-jwt-token\"}",
  json: { token: "admin-jwt-token" }
}
```

---

## Prompt Templates

All prompts are **universal** - they work on any application by deriving endpoints from source code paths.

| Prompt | Vulnerability Type | Key Features |
|--------|-------------------|--------------|
| `exploit-injection.txt` | SQLi, Command Injection | Technology-aware payloads (MySQL, PostgreSQL, SQLite) |
| `exploit-xss.txt` | Cross-Site Scripting | Context-aware (HTML, Attribute, JavaScript, DOM) |
| `exploit-traversal.txt` | Path Traversal | OS-aware with encoding variations |
| `exploit-xxe.txt` | XML External Entity | Parser-specific payloads |
| `exploit-redirect.txt` | Open Redirect | Whitelist bypass techniques |
| `exploit-secrets.txt` | Hardcoded Secrets | Credential validation |
| `exploit-ssrf.txt` | Server-Side Request Forgery | Internal network probing |
| `exploit-generic.txt` | Any vulnerability | General testing methodology |

### Endpoint Discovery

Prompts derive endpoints from source file paths:

```
routes/login.ts      → /login, /api/login
controllers/users.js → /users, /api/users
api/v1/products.js   → /api/v1/products
```

### Payload Crafting

Payloads are crafted based on static analysis context:

```
Technology: Sequelize (from metadata)
→ SQLi payloads: ' OR '1'='1'--, ' UNION SELECT...

Technology: PostgreSQL
→ Time-based: '; SELECT pg_sleep(5)--

Context: Linux server
→ Command injection: ; cat /etc/passwd
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | OpenAI API key |

### Key Settings in `executor.js`

```javascript
const maxTurns = 50;              // Max agent conversation turns
const MAX_TOOL_RESULT_LENGTH = 8000;  // Truncate tool results
```

### Timeouts in `browser-server.js`

```javascript
const DEFAULT_TIMEOUT = 5000;  // 5 seconds (reduced for faster feedback)
const SHORT_TIMEOUT = 2000;    // 2 seconds for quick checks
```

### Model Selection

Default is `gpt-4o`. Change in executor.js:

```javascript
const model = options.model || 'gpt-4o';
```

---

## Extending the Tool

### Adding New Vulnerability Types

1. **Update parser** (`src/parser/result-parser.js`):
```javascript
if (vcLower.includes('new-vuln-type')) return 'newtype';
```

2. **Add queue category** (`src/queue/queue-generator.js`):
```javascript
const queues = { /* existing */, newtype: [] };
```

3. **Create prompt** (`prompts/exploit-newtype.txt`)

4. **Add mapping** (`src/main.js`):
```javascript
const promptMapping = { /* existing */, newtype: 'exploit-newtype.txt' };
```

### Adding Browser Tools

In `src/mcp/browser-server.js`:

```javascript
async customAction({ param1 }) {
  // Implementation
  return { status: 'success', data: result };
}

// Add to getTools()
{
  name: 'browser_custom_action',
  description: 'What this tool does',
  parameters: { type: 'object', properties: { param1: { type: 'string' } } },
  handler: this.customAction.bind(this)
}
```

### Adding Static Analyzer Parsers

Create in `src/parser/parsers/`:

```javascript
export function parseNewFormat(data) {
  return data.findings.map(f => ({
    id: f.id,
    type: mapType(f.category),
    location: { file: f.file, line: f.line },
    description: f.message,
    cwe: f.cwe
  }));
}
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "No vulnerabilities found" | Check Semgrep output uses `results` or `findings` array |
| "Rate limit exceeded" | Built-in retry with exponential backoff handles this |
| "Selector timeout" | Use `browser_force_click` or reduce timeout |
| "Element not found" | Use `browser_wait_for_element` for SPAs |

### Debug Tips

1. Check evidence files for detailed agent actions
2. Review `findings_summary.json` for quick overview
3. Open `report.html` for visual inspection
4. Use VS Code with SARIF extension to see findings in-editor

### Rate Limiting

Built-in `RateLimiter` handles API limits automatically:

| Error Type | Retry Strategy |
|------------|---------------|
| Rate Limit (429) | 30s → 40s → 50s (max 120s) |
| Server Error (5xx) | 10s → 20s → 30s (max 60s) |
| Network Error | Exponential backoff with jitter |

---

## Supported Analyzers

| Analyzer | File Format | Parser | Description |
|----------|-------------|--------|-------------|
| Semgrep | JSON | `semgrep-parser.js` | SAST for code patterns |
| Trivy | JSON | `trivy-parser.js` | Container/IaC security |
| CodeQL | SARIF | `codeql-parser.js` | GitHub CodeQL analysis |
| Syft | JSON | `syft-parser.js` | SBOM generation |
| OSV | JSON | `osv-parser.js` | Open-source vulnerabilities |
| Gitleaks | JSON | `gitleaks-parser.js` | Secrets scanner |
| Noir | JSON | `noir-parser.js` | API endpoint discovery |

---

## License

ISC

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Key areas for contribution:
- New static analyzer parsers
- Additional browser tools
- Improved prompt templates
- Report format enhancements
