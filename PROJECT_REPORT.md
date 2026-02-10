# Dynamic Security Tester - Project Report

**Report Generated**: January 28, 2026  
**Version**: 1.0.0  
**Project Type**: AI-Powered Dynamic Application Security Testing (DAST) Tool

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Technical Architecture](#3-technical-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Source Code Structure](#5-source-code-structure)
6. [Component Details](#6-component-details)
7. [Vulnerability Categories](#7-vulnerability-categories)
8. [Data Formats](#8-data-formats)
9. [Prompt Engineering](#9-prompt-engineering)
10. [Output & Reporting](#10-output--reporting)
11. [Usage Guide](#11-usage-guide)
12. [Security Considerations](#12-security-considerations)
13. [Future Enhancements](#13-future-enhancements)

---

## 1. Executive Summary

**Dynamic Security Tester** is an industry-grade AI-powered security validation tool that bridges the gap between Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST). 

The tool takes vulnerability findings from static analysis tools (Semgrep, Trivy, CodeQL, Gitleaks, etc.) and uses **OpenAI GPT-4** combined with **Playwright browser automation** to dynamically test, validate, and generate developer-friendly reports proving whether vulnerabilities are actually exploitable.

### Key Value Propositions

| Benefit | Description |
|---------|-------------|
| **False Positive Reduction** | Validates static findings through actual exploitation attempts |
| **Developer Time Savings** | Eliminates manual investigation of potential vulnerabilities |
| **Proof of Exploitability** | Provides definitive evidence with screenshots and responses |
| **Industry-Standard Output** | SARIF for IDE integration, HTML for stakeholders |
| **Multi-Scanner Support** | Consolidates results from 7+ security tools |

---

## 2. Problem Statement

### The Challenge

Static analysis tools (SAST) like Semgrep, Trivy, and CodeQL are essential for early vulnerability detection, but they suffer from a significant limitation: **high false positive rates**. These tools analyze code patterns without runtime context, leading to:

- Flagging vulnerabilities that are unreachable in practice
- Missing context about input validation and sanitization
- Overwhelming developers with potential issues that may never be exploitable

### The Solution

This tool automates the validation process through a 5-step workflow:

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   PARSE     │──▶│ CATEGORIZE  │──▶│  TEST WITH  │──▶│  COLLECT    │──▶│  GENERATE   │
│             │   │             │   │     AI      │   │  EVIDENCE   │   │   REPORTS   │
│ Read JSON   │   │ Group by    │   │             │   │             │   │             │
│ from SAST   │   │ vuln type   │   │ GPT-4 +     │   │ Save proof  │   │ SARIF/HTML  │
│ tools       │   │             │   │ Playwright  │   │ per finding │   │ JSON        │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

---

## 3. Technical Architecture

### High-Level Architecture Diagram

```
                              ┌────────────────────────────────────────┐
                              │           Dynamic Security Tester       │
                              └────────────────────────────────────────┘
                                                 │
        ┌────────────────────────────────────────┼────────────────────────────────────────┐
        │                                        │                                        │
        ▼                                        ▼                                        ▼
┌───────────────┐                      ┌─────────────────┐                      ┌─────────────────┐
│    PARSER     │                      │    EXECUTOR     │                      │    REPORTER     │
│    LAYER      │                      │     LAYER       │                      │     LAYER       │
├───────────────┤                      ├─────────────────┤                      ├─────────────────┤
│ • Parser      │                      │ • AI Agent      │                      │ • SARIF Gen     │
│   Factory     │                      │   (GPT-4)       │                      │ • HTML Gen      │
│ • Normalizer  │                      │ • Browser       │                      │ • JSON Summary  │
│ • Validator   │                      │   Server        │                      │ • Evidence      │
│ • Route       │                      │ • Auth Manager  │                      │   Collection    │
│   Parser      │                      │ • Bypass Engine │                      │                 │
└───────────────┘                      └─────────────────┘                      └─────────────────┘
        │                                        │                                        │
        ▼                                        ▼                                        ▼
┌───────────────┐                      ┌─────────────────┐                      ┌─────────────────┐
│   INPUTS      │                      │   INTEGRATIONS  │                      │    OUTPUTS      │
├───────────────┤                      ├─────────────────┤                      ├─────────────────┤
│ • Semgrep     │                      │ • OpenAI API    │                      │ • report.sarif  │
│ • Trivy       │                      │ • Playwright    │                      │ • report.html   │
│ • CodeQL      │                      │ • Target App    │                      │ • evidence/*.json│
│ • Gitleaks    │                      │   (HTTP/HTTPS)  │                      │ • summaries     │
│ • Syft/OSV    │                      │                 │                      │                 │
│ • OWASP Noir  │                      │                 │                      │                 │
└───────────────┘                      └─────────────────┘                      └─────────────────┘
```

### Component Interaction Flow

```
User Input (CLI)
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           main.js                                    │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────────────┐   │
│  │ Inquirer│───▶│ Parser  │───▶│ Queue   │───▶│ Executor Loop   │   │
│  │ Prompts │    │ Factory │    │Generator│    │ (per vuln type) │   │
│  └─────────┘    └─────────┘    └─────────┘    └────────┬────────┘   │
└────────────────────────────────────────────────────────┼────────────┘
                                                         │
                    ┌────────────────────────────────────┘
                    ▼
        ┌───────────────────────────────────────────────────────────┐
        │                      executor.js                           │
        │  ┌─────────────────┐    ┌─────────────────────────────┐   │
        │  │   OpenAI API    │◀──▶│   Tool Handler              │   │
        │  │   (gpt-4o)      │    │   ┌─────────────────────┐   │   │
        │  │                 │    │   │ browser_navigate    │   │   │
        │  │ System Prompt   │    │   │ browser_fill        │   │   │
        │  │ from prompts/   │    │   │ browser_click       │   │   │
        │  │                 │    │   │ browser_http_request│   │   │
        │  └─────────────────┘    │   │ save_evidence       │   │   │
        │                         │   │ read_queue          │   │   │
        │                         │   └─────────────────────┘   │   │
        │                         └─────────────────────────────┘   │
        └───────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
        ┌───────────────────┐       ┌───────────────────────────┐
        │  browser-server.js │       │     auth-manager.js       │
        │                    │       │                           │
        │  Playwright        │◀─────▶│  JWT/Cookie Storage       │
        │  Browser Control   │       │  Auto-Injection           │
        └───────────────────┘       └───────────────────────────┘
```

---

## 4. Technology Stack

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `openai` | ^6.15.0 | GPT-4 API for intelligent payload crafting |
| `playwright` | ^1.57.0 | Headless browser automation |
| `inquirer` | ^9.3.8 | Interactive CLI prompts |
| `axios` | ^1.13.2 | HTTP client for direct requests |
| `chalk` | ^4.1.2 | Colored console output |
| `js-yaml` | ^4.1.1 | YAML parsing support |
| `zx` | ^8.8.5 | Shell scripting utilities |

### Runtime Requirements

- **Node.js**: 18+ (ES Modules)
- **OpenAI API Key**: Required for GPT-4 access
- **Network Access**: To target application under test

### Configuration

```json
{
  "name": "dynamictest",
  "version": "1.0.0",
  "type": "module",
  "main": "src/main.js"
}
```

---

## 5. Source Code Structure

```
dynamictester/
├── package.json                    # Dependencies and scripts
├── README.md                       # Quick start guide
├── EXPLANATION.md                  # Detailed architecture explanation
├── MULTI_ANALYZER_USAGE.md         # Multi-scanner usage guide
├── PROJECT_REPORT.md               # This report
│
├── prompts/                        # AI prompt templates
│   ├── exploit-generic.txt         # General vulnerability testing
│   ├── exploit-injection.txt       # SQL/Command injection
│   ├── exploit-xss.txt             # Cross-site scripting
│   ├── exploit-xxe.txt             # XML External Entity
│   ├── exploit-redirect.txt        # Open redirect
│   ├── exploit-secrets.txt         # Hardcoded secrets
│   └── exploit-traversal.txt       # Path traversal
│
├── src/                            # Source code
│   ├── main.js                     # Entry point & orchestration
│   │
│   ├── agents/                     # AI agents
│   │   └── executor.js             # GPT-4 exploitation agent
│   │
│   ├── auth/                       # Authentication
│   │   └── auth-manager.js         # JWT/Cookie management
│   │
│   ├── mcp/                        # Model Context Protocol
│   │   └── browser-server.js       # Playwright browser tools
│   │
│   ├── parser/                     # Input parsing
│   │   ├── parser-factory.js       # Auto-detects analyzer type
│   │   ├── result-parser.js        # Orchestrates parsing
│   │   ├── normalizer.js           # Standardizes fields
│   │   ├── validator.js            # Validates structure
│   │   ├── route-parser.js         # Express route discovery
│   │   ├── parser-interface.js     # Parser base class
│   │   └── parsers/                # Analyzer-specific parsers
│   │
│   ├── queue/                      # Queue management
│   │   └── queue-generator.js      # Groups vulns by type
│   │
│   ├── reporting/                  # Report generation
│   │   └── report-generator.js     # SARIF/HTML/JSON output
│   │
│   ├── testing/                    # Testing utilities
│   │   ├── classifier.js           # Result classification
│   │   ├── proof-classifier.js     # 4-level proof system
│   │   ├── payload-crafter.js      # LLM payload generation
│   │   ├── bypass-engine.js        # WAF bypass techniques
│   │   ├── response-analyzer.js    # Response parsing
│   │   └── intelligence-aggregator.js
│   │
│   └── utils/                      # Utilities
│       ├── rate-limiter.js         # API rate limiting
│       └── error-handler.js        # Global error handling
│
├── cystarevidence/                 # Sample output (project 1)
│   └── deliverables/               # Exploitation queues
│
├── cystartest/                     # Sample output (project 2)
│   └── deliverables/
│
├── semtestoutput/                  # Sample output (project 3)
│   ├── deliverables/               # Exploitation queues
│   └── evidence/                   # Exploitation evidence
│
└── testmainoutputindustries/       # Sample output (project 4)
    ├── deliverables/
    ├── evidence/
    ├── report.sarif.json           # SARIF report
    ├── report.html                 # HTML report
    ├── developer_summary.json      # Developer quick reference
    └── findings_summary.json       # Findings overview
```

---

## 6. Component Details

### 6.1 Main Entry Point (`src/main.js`)

**Purpose**: Orchestrates the complete workflow from input to reports.

**Key Responsibilities**:
- Interactive CLI prompts using Inquirer
- Parses static analysis results (supports multiple comma-separated files)
- Generates exploitation queues grouped by vulnerability type
- Executes AI exploitation agents per category
- Generates final reports (SARIF, HTML, JSON)

**Prompt Type Mapping**:
```javascript
const promptMapping = {
  injection: 'exploit-injection.txt',
  xss: 'exploit-xss.txt',
  xxe: 'exploit-xxe.txt',
  redirect: 'exploit-redirect.txt',
  secrets: 'exploit-secrets.txt',
  traversal: 'exploit-traversal.txt',
  // Others use exploit-generic.txt
};
```

### 6.2 AI Executor (`src/agents/executor.js`)

**Purpose**: The "brain" of the tool - GPT-4 powered exploitation agent.

**Key Features**:
- Uses OpenAI's `gpt-4o` model
- Manages conversation loop with tools (max 50 turns)
- Rate limiting with exponential backoff
- Truncates large tool results (8000 char max) to avoid token limits

**Available Tools for GPT-4**:

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to URL |
| `browser_fill` | Fill form fields |
| `browser_click` | Click elements |
| `browser_http_request` | Direct HTTP requests (preferred for APIs) |
| `browser_capture_auth` | Capture JWT/cookies after login |
| `browser_execute_script` | Execute JavaScript in page |
| `save_evidence` | Save exploitation evidence to file |
| `read_queue` | Read vulnerability queue |

**Evidence Status Values**:
- `CONFIRMED` - Vulnerability successfully exploited
- `TESTED_NOT_EXPLOITABLE` - Tested but not exploitable

### 6.3 Browser Server (`src/mcp/browser-server.js`)

**Purpose**: Playwright-based browser automation with 15 tools for the AI agent.

**Complete Tool Reference**:

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `browser_navigate` | Navigate with page load wait | `url` |
| `browser_fill` | Fill form with visibility check | `selector`, `value` |
| `browser_click` | Click with element validation | `selector` |
| `browser_force_click` | JavaScript click (bypass overlays) | `selector` |
| `browser_type_and_submit` | Type and press Enter | `selector`, `text` |
| `browser_get_response` | Extract forms, inputs, buttons, errors | - |
| `browser_screenshot` | Take screenshot for evidence | `filename` |
| `browser_scroll` | Scroll page | `direction`, `amount` |
| `browser_wait_for_element` | Wait for SPA content | `selector`, `timeout` |
| `browser_http_request` | Direct HTTP with auth injection | `url`, `method`, `body`, `headers` |
| `browser_execute_script` | Execute JS in page context | `script` |
| `browser_capture_auth` | Capture JWT/cookies post-login | - |
| `browser_get_auth_status` | Check stored auth | - |
| `browser_clear_auth` | Clear stored auth | - |

**Smart Features**:
- Auto-finds alternative selectors when primary fails
- Extracts only visible/enabled inputs
- Detects error messages for injection detection
- Auto-injects stored auth tokens into requests

### 6.4 Auth Manager (`src/auth/auth-manager.js`)

**Purpose**: Stores and manages JWT tokens and cookies for authenticated testing.

**Key Features**:
- JWT/Bearer token storage from localStorage/sessionStorage
- Cookie management
- Custom header support
- Auto-injection of auth headers into HTTP requests

**Common Token Keys Detected**:
```javascript
static JWT_KEYS = [
  'token', 'jwt', 'accessToken', 'access_token',
  'authToken', 'auth_token', 'bearerToken', 'bearer_token',
  'idToken', 'id_token', 'refreshToken', 'refresh_token'
];
```

**Common Auth Cookies**:
```javascript
static AUTH_COOKIES = [
  'session', 'sid', 'JSESSIONID', 'connect.sid',
  'PHPSESSID', 'sessionid', 'auth', 'token'
];
```

### 6.5 Parser System

#### Parser Factory (`src/parser/parser-factory.js`)

**Purpose**: Auto-detects analyzer type and creates appropriate parser.

**Supported Analyzers**:

| Analyzer | Detection Pattern | Use Case |
|----------|-------------------|----------|
| Semgrep | `results` + `errors` arrays | Code vulnerabilities |
| Gitleaks | `RuleID` or `rule_id` field | Hardcoded secrets |
| Trivy | `Results` array | Container/dependency CVEs |
| OSV | `osvId` field | Open source vulnerabilities |
| Syft | `artifacts` + `source` | SBOM generation |
| OWASP Noir | `endpoints` field | API security |
| CodeQL | SARIF `$schema` | GitHub Advanced Security |

#### Result Parser (`src/parser/result-parser.js`)

**Purpose**: Coordinates parsing of multiple analyzer result files.

**Key Functions**:
- Auto-detects analyzer type per file
- Deduplicates vulnerabilities across sources
- Provides summary by source and type

#### Normalizer (`src/parser/normalizer.js`)

**Purpose**: Ensures consistent field values across analyzers.

**Severity Levels**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

**Confidence Levels**: `HIGH`, `MEDIUM`, `LOW`

**Vulnerability Type Mapping** (with CWE patterns):
- `injection` → SQLi, CommandInjection, CodeInjection, SSTI, LDAP, XPath
- `xss` → ReflectedXSS, StoredXSS, DOMXSS
- `xxe`, `ssrf`, `csrf`, `redirect`, `traversal`, `auth`, `crypto`, `secrets`, `upload`, `access`

#### Route Parser (`src/parser/route-parser.js`)

**Purpose**: Parses Express router files for endpoint discovery.

**Capabilities**:
- Scans directories recursively for route files
- Detects router variable declarations
- Parses `app.use()` mounts
- Maps routes to source files for intelligent endpoint derivation

### 6.6 Queue Generator (`src/queue/queue-generator.js`)

**Purpose**: Groups vulnerabilities by type for focused testing.

**Queue Categories**:
```
injection, xss, ssrf, auth, secrets, crypto, 
dependency, config, redirect, traversal, xxe, other
```

**Witness Payload Generation**:

| Vulnerability Type | Auto-Generated Payload |
|--------------------|------------------------|
| SQLi | `' OR '1'='1' --` |
| Command Injection | `; whoami` |
| XSS | `<img src=x onerror=alert(1)>` |
| SSRF | `http://169.254.169.254/latest/meta-data/` |
| SSTI | `{{7*7}}` |
| Path Traversal | `../../../etc/passwd` |
| XXE | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |

### 6.7 Reporting System (`src/reporting/report-generator.js`)

**Purpose**: Generates industry-standard reports.

**Output Formats**:

1. **SARIF** (`report.sarif.json`)
   - Standard format for IDE integration (VS Code, GitHub)
   - Contains rule definitions, locations, and results

2. **HTML** (`report.html`)
   - Visual report for stakeholders
   - Includes charts and detailed findings

3. **JSON Developer Summary** (`developer_summary.json`)
   - Quick reference for developers
   - Grouped by severity and status

### 6.8 Testing Utilities

#### Proof Classifier (`src/testing/proof-classifier.js`)

**Purpose**: 4-level classification system for exploitation proof.

| Level | Name | Classification | Confidence |
|-------|------|----------------|------------|
| 0 | No Exploitation | NOT_REPRODUCIBLE | N/A |
| 1 | Injection Point Confirmed | LIKELY | LOW |
| 2 | Query Structure Manipulated | LIKELY | MEDIUM |
| 3 | Data Extraction Proven | CONFIRMED | HIGH |
| 4 | Critical Impact Demonstrated | CONFIRMED | CRITICAL |

#### Bypass Engine (`src/testing/bypass-engine.js`)

**Purpose**: LLM-powered WAF/filter bypass generation.

**Bypass Techniques**:
- Encoding variations (URL, double URL, Unicode)
- Case manipulation
- Comment injection
- Alternative syntax
- Polyglot payloads

#### Response Analyzer (`src/testing/response-analyzer.js`)

**Purpose**: Analyzes HTTP responses for exploitation indicators.

**Detection Patterns**:
- Database error messages
- WAF blocking signatures
- Input validation errors
- Application exceptions

### 6.9 Utilities

#### Rate Limiter (`src/utils/rate-limiter.js`)

**Purpose**: Intelligent retry with exponential backoff.

**Features**:
- Rate limit-specific delays (30s → 40s → 50s)
- Staggered parallel execution
- Error classification and logging

---

## 7. Vulnerability Categories

### Supported Vulnerability Types

| Category | CWE Examples | Prompt File | Description |
|----------|--------------|-------------|-------------|
| **Injection** | CWE-89, CWE-78, CWE-94 | `exploit-injection.txt` | SQL, Command, Code injection |
| **XSS** | CWE-79 | `exploit-xss.txt` | Cross-site scripting (Reflected, Stored, DOM) |
| **XXE** | CWE-611 | `exploit-xxe.txt` | XML External Entity |
| **SSRF** | CWE-918 | `exploit-generic.txt` | Server-side request forgery |
| **CSRF** | CWE-352 | `exploit-generic.txt` | Cross-site request forgery |
| **Redirect** | CWE-601 | `exploit-redirect.txt` | Open redirect |
| **Traversal** | CWE-22 | `exploit-traversal.txt` | Path/directory traversal |
| **Auth** | CWE-287, CWE-306 | `exploit-generic.txt` | Authentication issues |
| **Crypto** | CWE-327, CWE-328 | `exploit-generic.txt` | Weak cryptography |
| **Secrets** | CWE-798 | `exploit-secrets.txt` | Hardcoded credentials |
| **Access** | CWE-284 | `exploit-generic.txt` | Access control |

---

## 8. Data Formats

### 8.1 Exploitation Queue Format

**Location**: `{output}/deliverables/{type}_exploitation_queue.json`

```json
{
  "vulnerabilities": [
    {
      "id": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
      "source": "semgrep",
      "sourceVersion": "1.147.0",
      "checkId": "express-sequelize-injection",
      "verdict": "vulnerable",
      "confidence": "HIGH",
      "vulnerabilityType": "SQLi",
      "file": "routes/users.js",
      "line": 42,
      "column": 28,
      "snippet": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
      "description": "Detected a sequelize statement that is tainted by user input...",
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021"],
      "witnessPayload": "' OR '1'='1' --",
      "metadata": {
        "technology": ["express", "sequelize"],
        "dataflow": {
          "source": "req.params.id",
          "sink": "db.query()"
        }
      }
    }
  ]
}
```

### 8.2 Evidence File Format

**Location**: `{output}/evidence/evidence-{id}-{timestamp}.json`

```json
{
  "findingId": "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection",
  "timestamp": "2026-01-15T18:03:29.081Z",
  "sourceLocation": {
    "file": "routes/users.js",
    "line": 42,
    "column": 28
  },
  "vulnerability": {
    "type": "SQLi",
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  },
  "exploitation": {
    "endpoint": "/api/users/1",
    "method": "GET",
    "payload": "' OR '1'='1",
    "response": "...",
    "success": true,
    "proof": "Database returned all user records instead of single user"
  },
  "remediation": "Use parameterized queries instead of string concatenation",
  "status": "CONFIRMED"
}
```

### 8.3 SARIF Report Format

**Location**: `{output}/report.sarif.json`

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "DynamicSecurityTester",
          "version": "1.0.0",
          "informationUri": "https://example.com/dynamic-tester",
          "rules": [
            {
              "id": "CWE-89",
              "name": "SQL Injection",
              "shortDescription": { "text": "SQL Injection vulnerability" },
              "fullDescription": { "text": "..." },
              "defaultConfiguration": { "level": "error" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": { "text": "Confirmed SQL Injection vulnerability" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "routes/users.js" },
                "region": { "startLine": 42, "startColumn": 28 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 9. Prompt Engineering

### Prompt Template Structure

Each prompt template in `prompts/` follows a structured XML-like format:

```xml
<role>
Expert security researcher persona with specific domain knowledge
</role>

<objective>
Task definition with placeholders:
- {{QUEUE_PATH}} - Path to vulnerability queue
- {{WEB_URL}} - Target application URL
</objective>

<critical_rules>
Must-follow rules for the AI agent:
- Never fabricate results
- Always use real responses
- Test one vulnerability at a time
</critical_rules>

<endpoint_discovery>
How to derive endpoints from source files:
- Parse route patterns
- Handle path parameters
- Consider middleware
</endpoint_discovery>

<payload_crafting>
Technology-specific payload guidance:
- Framework-specific payloads
- Encoding requirements
- Bypass techniques
</payload_crafting>

<evidence_format>
Required fields for save_evidence:
- findingId, endpoint, method
- payload, response, success
- proof, remediation, status
</evidence_format>

<methodology>
Step-by-step testing process:
1. Read queue
2. Derive endpoint
3. Craft payload
4. Execute test
5. Analyze response
6. Save evidence
</methodology>

<available_tools>
Reference to browser tools
</available_tools>

<anti_hallucination>
Rules to prevent fabricated results:
- Only report actual responses
- Include real error messages
- Don't assume success
</anti_hallucination>
```

### Prompt Files Overview

| File | Purpose | Key Focus |
|------|---------|-----------|
| `exploit-injection.txt` | SQL/Command injection | Parameterized query bypass, command chaining |
| `exploit-xss.txt` | Cross-site scripting | DOM manipulation, event handlers, encoding |
| `exploit-xxe.txt` | XML External Entity | DTD injection, entity expansion |
| `exploit-redirect.txt` | Open redirect | URL parsing bypass, parameter pollution |
| `exploit-secrets.txt` | Hardcoded secrets | API key validation, credential testing |
| `exploit-traversal.txt` | Path traversal | Encoding variations, null bytes |
| `exploit-generic.txt` | General vulnerabilities | Flexible testing approach |

---

## 10. Output & Reporting

### Output Directory Structure

```
{output_directory}/
├── deliverables/
│   ├── injection_exploitation_queue.json
│   ├── xss_exploitation_queue.json
│   ├── secrets_exploitation_queue.json
│   ├── redirect_exploitation_queue.json
│   ├── traversal_exploitation_queue.json
│   ├── xxe_exploitation_queue.json
│   └── other_exploitation_queue.json
│
├── evidence/
│   ├── evidence-{finding-id}-{timestamp}.json
│   ├── evidence-{finding-id}-{timestamp}.json
│   └── ...
│
├── developer_summary.json          # Quick reference for developers
├── findings_summary.json           # Statistical overview
├── report.sarif.json               # SARIF for IDE integration
└── report.html                     # Visual report for stakeholders
```

### Report Types

#### 1. SARIF Report
- **Purpose**: IDE integration (VS Code, GitHub Security tab)
- **Use Case**: Developer workflow integration
- **Features**: Clickable file locations, rule definitions

#### 2. HTML Report
- **Purpose**: Stakeholder communication
- **Use Case**: Security reviews, audits
- **Features**: Charts, severity breakdown, evidence links

#### 3. Developer Summary (JSON)
- **Purpose**: Quick developer reference
- **Use Case**: Prioritization, remediation planning
- **Features**: Grouped by severity, actionable items

#### 4. Evidence Files
- **Purpose**: Detailed proof of exploitation
- **Use Case**: Verification, compliance documentation
- **Features**: Full request/response, payloads, timestamps

---

## 11. Usage Guide

### Basic Usage

```bash
# Run the tool
node src/main.js

# Interactive prompts will ask for:
# 1. Path to static analysis results (comma-separated for multiple)
# 2. Target application URL
# 3. Output directory
```

### Single Analyzer Example

```bash
node src/main.js
? Enter path to static analysis results: ./semgrep-results.json
? Enter target application URL: http://localhost:3000
? Enter output directory: ./output
```

### Multi-Analyzer Example

```bash
node src/main.js
? Enter path to static analysis results: ./semgrep.json,./gitleaks.json,./trivy.json
? Enter target application URL: http://localhost:3000
? Enter output directory: ./output
```

### Programmatic Usage

```javascript
import { parseStaticAnalysisResults } from './src/parser/result-parser.js';
import { generateQueues } from './src/queue/queue-generator.js';
import { executeExploitation } from './src/agents/executor.js';

// Parse results from multiple analyzers
const { vulnerabilities, summary } = await parseStaticAnalysisResults([
  './semgrep.json',
  './gitleaks.json'
]);

// Generate categorized queues
const queues = await generateQueues(vulnerabilities, './output/deliverables');

// Execute exploitation for each category
for (const [type, queuePath] of Object.entries(queues)) {
  await executeExploitation(queuePath, 'http://localhost:3000', type);
}
```

### Environment Variables

```bash
export OPENAI_API_KEY="sk-..."  # Required for GPT-4 access
```

---

## 12. Security Considerations

### Safe Usage Guidelines

1. **Authorization**: Only test applications you are authorized to test
2. **Isolation**: Run target applications in isolated environments
3. **Rate Limiting**: The tool includes built-in rate limiting to prevent DoS
4. **Data Handling**: Evidence files may contain sensitive data - handle appropriately
5. **API Keys**: Protect your OpenAI API key

### Known Limitations

| Limitation | Mitigation |
|------------|------------|
| Requires running application | Use with CI/CD staging environments |
| OpenAI API costs | Rate limiting reduces token usage |
| False negatives possible | Use as supplement to manual testing |
| Network-dependent | Ensure stable connectivity |

### Responsible Disclosure

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research on own applications
- ✅ CI/CD security validation
- ❌ NOT for unauthorized testing
- ❌ NOT for production exploitation

---

## 13. Future Enhancements

### Planned Features

| Feature | Priority | Description |
|---------|----------|-------------|
| GraphQL Support | High | Test GraphQL injection and introspection |
| WebSocket Testing | Medium | Real-time protocol security testing |
| API Schema Import | High | OpenAPI/Swagger integration |
| Custom Parsers | Medium | Plugin system for new analyzers |
| Parallel Execution | High | Multi-threaded vulnerability testing |
| Cloud Integration | Low | Direct AWS/Azure/GCP scanner integration |

### Architecture Improvements

- **Plugin System**: Allow custom analyzer parsers
- **Result Caching**: Avoid retesting same endpoints
- **Dashboard**: Real-time testing progress visualization
- **CI/CD Actions**: GitHub Actions / GitLab CI integration

---

## Appendix A: File Reference

### Core Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/main.js` | ~190 | Entry point, orchestration |
| `src/agents/executor.js` | ~476 | GPT-4 exploitation agent |
| `src/mcp/browser-server.js` | ~834 | Playwright browser tools |
| `src/auth/auth-manager.js` | ~170 | JWT/Cookie management |
| `src/parser/parser-factory.js` | ~96 | Analyzer auto-detection |
| `src/parser/result-parser.js` | ~120 | Multi-file parsing |
| `src/parser/normalizer.js` | ~120 | Data standardization |
| `src/parser/validator.js` | ~110 | Structure validation |
| `src/parser/route-parser.js` | ~339 | Express route parsing |
| `src/reporting/report-generator.js` | ~457 | SARIF/HTML/JSON generation |
| `src/testing/proof-classifier.js` | ~142 | Evidence classification |

### Prompt Templates

| File | Target Vulnerabilities |
|------|------------------------|
| `exploit-injection.txt` | SQLi, Command, Code, SSTI, LDAP |
| `exploit-xss.txt` | Reflected, Stored, DOM XSS |
| `exploit-xxe.txt` | XML External Entity |
| `exploit-redirect.txt` | Open Redirect |
| `exploit-secrets.txt` | Hardcoded Secrets |
| `exploit-traversal.txt` | Path Traversal |
| `exploit-generic.txt` | General Vulnerabilities |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **SAST** | Static Application Security Testing |
| **DAST** | Dynamic Application Security Testing |
| **SARIF** | Static Analysis Results Interchange Format |
| **CWE** | Common Weakness Enumeration |
| **OWASP** | Open Web Application Security Project |
| **SQLi** | SQL Injection |
| **XSS** | Cross-Site Scripting |
| **XXE** | XML External Entity |
| **SSRF** | Server-Side Request Forgery |
| **CSRF** | Cross-Site Request Forgery |
| **WAF** | Web Application Firewall |
| **JWT** | JSON Web Token |
| **MCP** | Model Context Protocol |

---

*Report generated by Dynamic Security Tester Project Analysis*
