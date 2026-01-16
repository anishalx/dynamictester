# Multi-Analyzer Parser Usage Guide

## Quick Start

### Running with Multiple Analyzers

```bash
node src/main.js
```

When prompted:
```
Path to analyzer result file(s) (comma-separated for multiple):
> ./semgrep.json,./gitleaks.json,./trivy.json
```

The tool will:
1. Auto-detect each analyzer type
2. Parse and normalize all vulnerabilities
3. Create combined exploitation queues
4. Show breakdown by source and type

---

## Supported Analyzers

| Analyzer | Type | Detection Key | Typical Use Case |
|----------|------|---------------|------------------|
| **Semgrep** | SAST | `results` + `version` | Code vulnerabilities (XSS, SQLi, etc.) |
| **Gitleaks** | Secret Scanning | `Findings` or `Secret` | Hardcoded secrets, API keys |
| **Trivy** | Vulnerability Scanner | `Results` array | Container/dependency CVEs, misconfigs |
| **OSV** | Vulnerability DB | `results.packages` | Open source dependency vulnerabilities |
| **Syft** | SBOM Generator | `artifacts` + `source` | Software bill of materials |
| **OWASP Noir** | API Security | `endpoints` | API security, missing headers |
| **CodeQL** | SAST | SARIF `runs` | GitHub Advanced Security findings |

---

## Example Workflows

### 1. Comprehensive Security Scan

Scan with multiple tools for complete coverage:

```bash
# Run static analyzers
semgrep --config=auto --json -o semgrep.json ./src
gitleaks detect --report-path gitleaks.json
trivy fs --format json -o trivy.json ./

# Process all results together
node src/main.js
# Input: semgrep.json,gitleaks.json,trivy.json
```

**Result**: Combined exploitation queues with findings from all sources.

---

### 2. Container Security Focus

```bash
# Scan container and dependencies
trivy image --format json -o trivy-image.json myapp:latest
syft packages docker:myapp:latest -o json > syft.json

# Process vulnerability findings
node src/main.js
# Input: trivy-image.json
```

---

### 3. Secret Detection Pipeline

```bash
# Multiple secret scanners
gitleaks detect --report-path gitleaks.json
semgrep --config="p/secrets" --json -o semgrep-secrets.json ./

# Process all secret findings
node src/main.js
# Input: gitleaks.json,semgrep-secrets.json
```

**Output**: `secrets_exploitation_queue.json` with findings from both tools.

---

## Programmatic Usage

### Basic Parsing

```javascript
import { parseStaticAnalysisResults } from './src/parser/result-parser.js';

const { vulnerabilities, summary } = await parseStaticAnalysisResults([
  './semgrep.json',
  './gitleaks.json'
]);

console.log(`Total: ${summary.total} vulnerabilities`);
console.log(`Sources: ${Object.keys(summary.bySource).join(', ')}`);
```

### Using Individual Parsers

```javascript
import { createParser, detectAnalyzerType } from './src/parser/parser-factory.js';
import { fs } from 'zx';

const data = JSON.parse(await fs.readFile('./result.json', 'utf8'));

// Auto-detect
const type = detectAnalyzerType(data);
console.log(`Detected: ${type}`);

// Create parser and parse
const parser = createParser(type);
const vulns = await parser.parse(data);
```

### Validation

```javascript
import { validateVulnerabilities } from './src/parser/validator.js';

const validation = validateVulnerabilities(vulnerabilities);

if (!validation.valid) {
  console.log(`Found ${validation.invalidCount} invalid entries`);
  validation.errors.forEach(err => {
    console.log(`Index ${err.index}: ${err.errors.join(', ')}`);
  });
}
```

---

## Output Format

### Normalized Vulnerability

```json
{
  "id": "SEMGREP-javascript.xss.reflected-42",
  "source": "semgrep",
  "sourceVersion": "1.45.0",
  "type": "xss",
  "subType": "ReflectedXSS",
  "severity": "HIGH",
  "confidence": "HIGH",
  "location": {
    "file": "src/routes/search.js",
    "line": 42,
    "column": 5,
    "endLine": 42,
    "endColumn": 60,
    "snippet": "res.send(query)"
  },
  "description": "Reflected XSS vulnerability",
  "remediation": "Use template escaping",
  "cwe": ["CWE-79"],
  "owasp": ["A03:2021"],
  "cvss": null,
  "cve": [],
  "metadata": {},
  "checkId": "javascript.xss.reflected",
  "reference": "https://..."
}
```

### Exploitation Queue

Queue files include source tracking:

```json
{
  "vulnerabilities": [
    {
      "id": "GITLEAKS-aws-key-123",
      "source": "gitleaks",
      "vulnerabilityType": "AWSKey",
      "file": "config.js",
      "line": 10,
      ...
    },
    {
      "id": "SEMGREP-hardcoded-secret-456",
      "source": "semgrep",
      "vulnerabilityType": "HardcodedSecret",
      "file": "auth.js",
      "line": 25,
      ...
    }
  ]
}
```

---

## Tips & Best Practices

### 1. Tool Selection

- **SAST**: Semgrep or CodeQL for code analysis
- **Secrets**: Gitleaks (fastest) or Semgrep secrets ruleset
- **Dependencies**: Trivy or OSV for CVE detection
- **Containers**: Trivy for images + Syft for SBOM

### 2. Combining Results

```bash
# Best practice: Run complementary tools
semgrep --config=auto --json -o semgrep.json ./    # Code vulns
gitleaks detect --report-path gitleaks.json        # Secrets
trivy fs --scanners vuln,config -o trivy.json ./   # Dependencies + configs
```

This gives comprehensive coverage without overlap.

### 3. Handling Large Outputs

For very large scan results:

```javascript
// Process files individually
for (const file of ['semgrep.json', 'gitleaks.json', 'trivy.json']) {
  const { vulnerabilities } = await parseStaticAnalysisResults(file);
  console.log(`${file}: ${vulnerabilities.length} findings`);
}
```

### 4. Filtering by Severity

```javascript
const { vulnerabilities } = await parseStaticAnalysisResults('./results.json');

const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL');
const highAndCritical = vulnerabilities.filter(v => 
  ['CRITICAL', 'HIGH'].includes(v.severity)
);
```

---

## Troubleshooting

### "Could not detect analyzer type"

**Cause**: JSON format not recognized  
**Solution**: Check the file is valid JSON and matches expected structure

```bash
# Verify JSON is valid
cat result.json | jq .

# Check if it's a supported format
node -e "
import { detectAnalyzerType } from './src/parser/parser-factory.js';
const data = await import('./result.json', { assert: { type: 'json' } });
console.log(detectAnalyzerType(data.default));
"
```

### Validation Errors

**Cause**: Missing required fields  
**Solution**: Check the error messages for specific field names

```javascript
const validation = validateVulnerabilities(vulnerabilities);
validation.errors.forEach(err => console.log(err));
```

### Empty Results

**Cause**: No vulnerabilities found or filtered out  
**Solution**: Check original analyzer output

```bash
# Verify analyzer found issues
jq '.results | length' semgrep.json
jq '.Findings | length' gitleaks.json
```

---

## Testing

### Sample Test Data

Create minimal test files:

**semgrep-test.json:**
```json
{
  "version": "1.0.0",
  "results": [
    {
      "check_id": "test-xss",
      "path": "test.js",
      "start": {"line": 1, "col": 0},
      "end": {"line": 1, "col": 10},
      "extra": {
        "message": "Test XSS",
        "severity": "HIGH",
        "metadata": {
          "cwe": ["CWE-79"],
          "confidence": "HIGH"
        }
      }
    }
  ]
}
```

**gitleaks-test.json:**
```json
[
  {
    "Description": "AWS Access Key",
    "RuleID": "aws-access-token",
    "File": "config.js",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "StartLine": 5,
    "Fingerprint": "abc123"
  }
]
```

Test:
```bash
node src/main.js
# Input: semgrep-test.json,gitleaks-test.json
```

---

## Next Steps

1. **Integration**: Add to CI/CD pipeline
2. **Custom Parsers**: Extend for proprietary tools
3. **Filtering**: Add pre-processing filters
4. **Reporting**: Generate consolidated reports
