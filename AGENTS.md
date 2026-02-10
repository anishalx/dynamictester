# AGENTS.md

## Project Overview

Dynamic Security Tester ("dynamictest") — an AI-powered DAST tool that takes vulnerability
findings from static analyzers (Semgrep, Trivy, CodeQL, Gitleaks, OSV, Syft, Noir) and uses
OpenAI GPT-4 + Playwright browser automation to dynamically test whether those vulnerabilities
are exploitable. Produces SARIF reports, HTML reports, and developer-friendly evidence.

**Architecture pipeline:** Parse static results -> Queue by vuln type -> Execute via LLM agent with browser tools -> Generate reports

## Prerequisites

- Node.js 18+
- npm
- `OPENAI_API_KEY` environment variable (set in `.env` or shell)
- Playwright browsers: `npx playwright install chromium`

## Build / Run / Test Commands

This is a pure JavaScript (ES Modules) project. There is no build or transpilation step.

```bash
# Install dependencies
npm install

# Run the tool (interactive CLI)
node src/main.js

# No test framework is currently configured.
# npm test is a placeholder that exits with code 1.
# If tests are added (e.g. with Vitest), run a single test with:
#   npx vitest run path/to/file.test.js
#   npx vitest run -t "test name pattern"
```

There is no linter or formatter configured. No ESLint, Prettier, or editorconfig exists.
Follow the conventions documented below to maintain consistency.

## Project Structure

```
src/
  main.js                  # Entry point — interactive CLI workflow
  agents/
    executor.js            # OpenAI GPT agent loop (tool-calling, max 50 turns, rate limiting)
  auth/
    auth-manager.js        # JWT/cookie/bearer token capture and injection (singleton)
  mcp/
    browser-server.js      # BrowserManager — 15 Playwright tools exposed to the LLM agent
  parser/
    result-parser.js       # Multi-file parsing coordinator, dedup, validation
    parser-factory.js      # Auto-detect analyzer type + registry of 7 parsers
    parser-interface.js    # BaseParser abstract class
    normalizer.js          # Severity/confidence normalization, vuln categorization
    validator.js           # Validates normalized vulnerability structure
    route-parser.js        # Express router file parsing for endpoint discovery
    parsers/               # One parser per supported analyzer (semgrep, trivy, codeql, etc.)
  queue/
    queue-generator.js     # Groups vulns by type into exploitation queue JSON files
  reporting/
    report-generator.js    # SARIF 2.1.0, HTML, and developer summary generation
    ci-reporter.js         # CI/CD exit codes (0=pass, 1=confirmed, 2=error)
  testing/
    test-interface.js      # VulnerabilityTester base class (3-stage: confirm -> fingerprint -> exploit)
    classifier.js          # CONFIRMED/LIKELY/BLOCKED/NOT_REPRODUCIBLE classification
    exploitation-levels.js # 5-level proof system (L0-L4)
    payload-generator.js   # LLM-powered payload generation with anti-hallucination filtering
    bypass-engine.js       # LLM-powered WAF/filter bypass generation
    response-analyzer.js   # DB error detection, WAF detection, boolean/timing analysis
    intelligence-aggregator.js  # Context gathering for payload crafting
  utils/
    error-handling.js      # Error classification, retry eligibility, delay calculation
    rate-limiter.js        # RateLimiter class — retry with backoff, parallel stagger, fallback
prompts/                   # LLM prompt templates (exploit-injection.txt, exploit-xss.txt, etc.)
```

## Code Style Guidelines

### Module System

- ES Modules (`"type": "module"` in package.json). Never use `require()`.
- All relative imports MUST include the `.js` extension: `import { foo } from './bar.js';`

### Imports

- **Default imports** only for third-party packages: `import OpenAI from 'openai';`
- **Named imports** for all internal modules: `import { parseStaticAnalysisResults } from './parser/result-parser.js';`
- Order: third-party packages first, then internal modules. No blank line between groups.
- No barrel files (`index.js`) — import directly from the source file.

### Formatting

- **2-space indentation** (spaces, not tabs)
- **Single quotes** for strings; double quotes only inside HTML template literals
- **Semicolons** always
- **No trailing commas** in objects, arrays, or parameter lists
- **K&R / 1TBS brace style** — opening brace on same line
- **Template literals** for string interpolation: `` `Error: ${error.message}` ``
- Use destructuring: `const { targetUrl, outputDir } = answers;`
- Use optional chaining: `data.results?.[0]?.packages`
- Use object shorthand: `{ result, usedFallback: false }`

### Naming Conventions

| Construct        | Convention         | Example                              |
|------------------|--------------------|--------------------------------------|
| Files            | `kebab-case.js`    | `rate-limiter.js`, `parser-factory.js` |
| Directories      | `kebab-case`       | `parser/parsers/`                    |
| Classes          | `PascalCase`       | `RateLimiter`, `BrowserManager`      |
| Functions        | `camelCase`        | `executeExploitationAgent`, `normalizeSeverity` |
| Variables/Params | `camelCase`        | `targetUrl`, `maxRetries`            |
| Constants        | `UPPER_SNAKE_CASE` | `MAX_TOOL_RESULT_LENGTH`, `DEFAULT_TIMEOUT` |
| Private methods  | `_camelCase`       | `_logError`                          |

### Exports

- **Named exports only** — never use `export default`.
- Export functions: `export function myFunction() { ... }`
- Export classes: `export class MyClass { ... }`
- Singleton instances: `export const rateLimiter = new RateLimiter();`
- Re-exports for convenience are acceptable: `export { isRetryableError, sleep } from './error-handling.js';`

### Functions

- **Function declarations** for top-level exported functions: `export function doSomething() { ... }`
- **Arrow functions** for callbacks and inline handlers: `.map((v) => v.id)`
- **Class methods** use standard syntax (not arrow function class fields).

### Error Handling

- No custom Error subclasses — throw native `Error` with descriptive messages.
- Browser tools and handlers return **status objects**: `{ status: 'success', ...data }` or `{ status: 'error', message: e.message }`. Do not throw from tool handlers.
- Use nested try/catch to isolate optional sub-operations (e.g., report generation) from critical paths.
- Empty catch blocks are acceptable for expected failures (e.g., file not found), but add a comment: `catch (e) { /* File doesn't exist yet */ }`
- Use the `error-handling.js` utilities (`isRetryableError`, `classifyError`, `getRetryDelay`) for retry logic.

### Type Documentation

- This is a pure JavaScript codebase — no TypeScript.
- Use **JSDoc `@typedef`** for complex object shapes (see `parser-interface.js` for examples).
- Use **JSDoc `@param` and `@returns`** on all public/exported functions.
- Mark internal methods with `@private`.

### Async Patterns

- Use `async/await` for all asynchronous operations. Avoid raw `.then()` chains.
- Use `Promise.allSettled` for parallel fault-tolerant execution.
- Use `.catch(() => {})` for optional awaits (fire-and-forget waits, e.g., `page.waitForLoadState`).
- The `sleep()` utility in `error-handling.js` is the only place raw `new Promise` should appear.

### Comments

- **JSDoc blocks** on all classes, exported functions, and public methods.
- **Inline `//` comments** for step annotations: `// Step 1: Parse static analysis results`
- Brief clarifying comments above non-obvious constants or logic.

## Design Patterns

- **Factory:** `parser-factory.js` — `createParser(analyzerType)` selects the right parser from `PARSER_REGISTRY`.
- **Strategy:** Each parser (`SemgrepParser`, `TrivyParser`, etc.) implements `parse()` and `validate()` per the `BaseParser` interface.
- **Template Method:** `VulnerabilityTester` defines a 3-stage workflow (confirm -> fingerprint -> exploit).
- **Singleton:** `AuthManager` via `getAuthManager()`, `rateLimiter` instance in `rate-limiter.js`.
- **Registry:** `PARSER_REGISTRY` is a frozen map of analyzer names to parser classes.
- **Retry with Backoff:** `RateLimiter.executeWithRetry()` — exponential backoff with jitter.
- **Status Objects:** All browser tool methods return `{ status, ...data }` instead of throwing.

## Adding New Components

- **New parser:** Create `src/parser/parsers/<name>-parser.js` extending `BaseParser`, add to `PARSER_REGISTRY` in `parser-factory.js`.
- **New browser tool:** Add method to `BrowserManager` in `src/mcp/browser-server.js`, register in the tools array.
- **New prompt template:** Add `prompts/exploit-<type>.txt`, reference in `queue-generator.js`.
- **New vuln category:** Add to the categorization map in `normalizer.js`.
