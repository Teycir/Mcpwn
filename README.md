# Mcpwn - MCP Security Testing Framework

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--12-orange.svg)](https://modelcontextprotocol.io)
[![Security](https://img.shields.io/badge/security-testing-red.svg)](https://github.com/Teycir/Mcpwn)
[![Tests](https://img.shields.io/badge/tests-45%20passing-brightgreen.svg)](tests_unit/)

**Automated security scanner for Model Context Protocol servers that detects RCE, path traversal, prompt injection, and protocol vulnerabilities.**

## Why Mcpwn?

MCP servers expose powerful capabilities to AI agents. **One vulnerable tool = full system compromise.**

**What Mcpwn Does:**
- ✅ Detects **RCE** via command injection in tool arguments
- ✅ Finds **path traversal** vulnerabilities in file operations  
- ✅ Identifies **prompt injection** risks in LLM-facing tools
- ✅ Tests **protocol fuzzing** and state desync attacks
- ✅ Generates **structured reports** (JSON/SARIF) for AI analysis & CI/CD
- ✅ **Stages findings for AI** - automated baseline → AI deep analysis
- ✅ **Zero dependencies** - pure Python stdlib

**Quick Start:**
```bash
# Scan any MCP server in 5 seconds
python mcpwn.py --quick npx -y @modelcontextprotocol/server-filesystem /tmp

# Get JSON report for AI analysis
python mcpwn.py --output-json report.json npx -y @modelcontextprotocol/server-filesystem /tmp
```

**Real Impact:** Mcpwn found RCE vulnerabilities in production MCP servers by testing tool argument injection patterns that manual code review missed.

## Installation

```bash
# Clone repository
git clone https://github.com/Teycir/Mcpwn.git
cd Mcpwn

# Make executable
chmod +x mcpwn.py

# Run directly (no dependencies needed)
python3 mcpwn.py --help
```

## Prerequisites

- Python 3.8+
- Core framework uses stdlib only (no dependencies)

## Features

- **Semantic Detection**: Pattern-based exploit detection (RCE, file read, timing attacks)
- **Thread-Safe**: Concurrent operations with proper locking
- **Configurable Timeouts**: Per-request timeout control with deadline tracking
- **Payload Deduplication**: Efficient testing without redundant payloads
- **Structured Logging**: Comprehensive logging with severity levels
- **Safe Mode**: Skip destructive tests (protocol fuzzing, subscription flood)
- **Severity Aggregation**: Automatic categorization by CRITICAL/HIGH/MEDIUM/LOW
- **CI/CD Integration**: SARIF output for GitHub Security, GitLab, and other platforms

## Usage

```bash
# Basic scan
python mcpwn.py npx -y @modelcontextprotocol/server-filesystem /tmp

# Quick scan (5s timeout, stops on first tool injection finding)
python mcpwn.py --quick npx -y @modelcontextprotocol/server-filesystem /tmp

# RCE-only mode (skips non-RCE tests)
python mcpwn.py --rce-only npx -y @modelcontextprotocol/server-filesystem /tmp

# Safe mode (skip destructive tests: protocol fuzzing, subscription flood)
python mcpwn.py --safe-mode npx -y @modelcontextprotocol/server-filesystem /tmp

# Custom timeout (default: 10s)
python mcpwn.py --timeout 60 npx -y @modelcontextprotocol/server-filesystem /tmp

# Generate reports with severity breakdown
python mcpwn.py --output-json report.json --output-html report.html npx ...

# Parallel flooding
python mcpwn.py --parallel npx ...

# SARIF output for CI/CD (GitHub Security, GitLab)
python mcpwn.py --output-sarif report.sarif npx ...

# Test against vulnerable server
python mcpwn.py python3 test_data/dvmcp_server.py
```

## Example Output

```
[INFO] Starting Mcpwn
[INFO] Discovery phase...
[INFO] Found 2 tools, 0 resources
[INFO] Testing tool injection...
[WARNING] execute_command: RCE via command
[WARNING]   Detection: uid=1000(user) gid=1000(user)
[INFO] Testing path traversal...
[WARNING] Path traversal: file://../../../etc/passwd
[WARNING]   Detection: root:x:0:0:root
[INFO] Mcpwn complete
[INFO] JSON report: report.json
```

## Attack Surface

**Currently Implemented:**
- State desync (skip/double initialize)
- Capability fuzzing (malformed initialization)
- Tool argument injection (command injection, path traversal)
- Resource path traversal
- Subscription flooding (parallel, skipped in safe mode)
- Prompt injection (indirect LLM jailbreak)
- Protocol fuzzing (malformed JSON-RPC, skipped in safe mode)
- OOB detection (DNS exfiltration)
- Race condition testing
- Resource exhaustion

**Planned (test files exist, not yet integrated):**
- SSRF injection
- Deserialization attacks
- Schema pollution
- Auth bypass

## Detection

Semantic indicators, not crashes:
- `uid=`, `root:x:` → RCE
- `-----BEGIN`, `PRIVATE KEY` → File read
- Statistical timing deviation → Blind injection
- Prompt echo → Indirect prompt injection
- DNS query capture → OOB exfiltration

## Architecture

```
Mcpwn/
├── mcpwn.py              # CLI entry point with logging config
├── payloads.py           # Attack payloads & indicators
├── core/
│   ├── pentester.py      # Main orchestrator (thread-safe, timeout handling)
│   ├── detector.py       # Semantic detection engine
│   └── reporter.py       # JSON/HTML/SARIF reports with severity aggregation
├── tests/
    ├── state_desync.py        # Active
    ├── capability_fuzzing.py  # Active
    ├── tool_injection.py      # Active
    ├── resource_traversal.py  # Active
    ├── subscription_flood.py  # Active
    ├── prompt_injection.py    # Active
    ├── protocol_fuzzing.py    # Active
    ├── oob_detection.py       # Active
    ├── race_condition.py      # Active
    ├── resource_exhaustion.py # Active
    ├── ssrf_injection.py      # Planned
    ├── deserialization.py     # Planned
    ├── schema_pollution.py    # Planned
    └── auth_bypass.py         # Planned
├── tests_unit/           # 45 pytest unit tests
└── test_data/
    └── dvmcp_server.py   # Deliberately vulnerable MCP server for testing
```

## Report Format

JSON reports include:
```json
{
  "summary": {
    "total": 15,
    "by_type": {"RCE": 3, "FILE_READ": 2, "SSRF": 1},
    "by_severity": {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 4, "LOW": 3}
  },
  "findings": [...]
}
```

## Configuration Options

| Flag | Description | Default |
|------|-------------|----------|
| `--safe-mode` | Skip destructive tests | False |
| `--quick` | Fast scan (5s timeout, stops on first tool injection finding) | False |
| `--rce-only` | Skip non-RCE tests | False |
| `--timeout` | Request timeout in seconds (quick mode uses 5s) | 10 |
| `--parallel` | Enable parallel flooding | False |
| `--output-json` | Export JSON report | None |
| `--output-html` | Export HTML report | None |
| `--output-sarif` | Export SARIF report (CI/CD) | None |

## Thread Safety

- Request ID generation protected by lock
- Health checks use dedicated lock
- Send operations protected by transport lock
- Connection pooling with cleanup
- Safe concurrent test execution

## Troubleshooting

**Port conflicts (SSRF/OOB tests)**
```bash
# Check if port 8888 is in use
lsof -i :8888
# Kill conflicting process or wait for cleanup
```

**Timeout errors**
```bash
# Increase timeout for slow servers
python mcpwn.py --timeout 60 ...
```

**Server crashes during tests**
```bash
# Use safe mode to skip destructive tests
python mcpwn.py --safe-mode ...
```

**False positives**
- Resource traversal now requires 2+ markers for detection
- Adjust `LEAK_MARKERS` in `tests/resource_traversal.py` if needed

## Testing

### Running Unit Tests

```bash
# Run all unit tests
python3 -m pytest tests_unit/ -v

# Quick test run
python3 -m pytest tests_unit/ -q

# Run specific test file
python3 -m pytest tests_unit/test_detector.py -v
```

### Integration Testing

Test against the included vulnerable server:
```bash
# Basic integration test
python3 mcpwn.py python3 test_data/dvmcp_server.py

# Quick validation (5s timeout)
python3 mcpwn.py --quick --rce-only python3 test_data/dvmcp_server.py
```

Expected findings:
- RCE via `execute_command` tool
- Path traversal via `read_file` tool

### Coverage Analysis

```bash
# Install coverage tools
pip install pytest-cov

# Run with coverage report
python3 -m pytest tests_unit/ --cov=. --cov-report=term-missing

# Generate HTML coverage report
python3 -m pytest tests_unit/ --cov=. --cov-report=html
# Open htmlcov/index.html in browser
```

### Test Suite Overview

**45 tests covering:**
- **Core Components** (21 tests)
  - Semantic detector (9 tests)
  - Reporter (7 tests)
  - Payloads (5 tests)
- **Edge Cases** (10 tests)
  - Malformed input handling
  - Unicode and special characters
  - Large data processing
  - Concurrent access scenarios
- **Integration** (14 tests)
  - CLI argument validation
  - End-to-end scanning
  - Report generation

**Coverage Requirements:**
- Core modules: >80% coverage
- Critical paths: 100% coverage
- Edge cases: Comprehensive error handling

### Development Testing

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
flake8 . --exclude=.git,.mypy_cache,__pycache__

# Run security checks
bandit -r . -ll --exclude=.git,.mypy_cache,tests_unit
```

## AI Integration

Mcpwn is designed to work seamlessly with AI assistants for enhanced security analysis:

**AI-Assisted Workflow:**
```bash
# 1. Run automated scan
python mcpwn.py --output-json findings.json npx -y @modelcontextprotocol/server-filesystem /tmp

# 2. AI analyzes structured output
# - Parses JSON findings
# - Identifies vulnerability patterns
# - Prioritizes by severity

# 3. AI performs deep analysis
# - Validates findings in context
# - Finds logic flaws Mcpwn missed
# - Generates remediation guidance
```

**Benefits:**
- **Structured Data**: JSON/SARIF output for AI parsing
- **Evidence-Based**: Concrete exploits vs speculation
- **Time Savings**: AI focuses on interpretation, not pattern matching
- **Validation**: Confirm AI-suggested vulnerabilities with automated testing
- **Training**: Mcpwn findings teach AI about MCP vulnerabilities

**Best Practice:** Use Mcpwn for automated baseline → AI for deep contextual analysis → Comprehensive security coverage

## Limitations

**What Mcpwn Detects:**
- Runtime exploits (RCE, path traversal, injection)
- Protocol-level vulnerabilities
- Resource exhaustion and DoS
- Pattern-based security issues

**What Mcpwn Misses:**
- Configuration vulnerabilities (exposed credentials, insecure settings)
- Business logic flaws
- Authorization bypass requiring context
- Complex multi-step attack chains
- Novel vulnerabilities without known patterns

**Recommendation:** Use Mcpwn for automated baseline scanning and CI/CD integration, but complement with manual security review for comprehensive coverage. Automated tools find known patterns; human analysis finds logic flaws.

## FAQ

**Q: How long does a typical scan take?**  
A: Quick mode (`--quick --rce-only`) takes ~5 seconds. Full scan takes 30-60 seconds depending on server complexity.

**Q: Will this crash my MCP server?**  
A: Use `--safe-mode` to skip destructive tests (protocol fuzzing, subscription flood). Tool injection and path traversal tests are non-destructive.

**Q: Does this work with any MCP server?**  
A: Yes, any server implementing the Model Context Protocol (2024-11-05 spec). Works with Python, TypeScript, Go implementations.

**Q: How do I integrate this into CI/CD?**  
A: Use `--output-sarif report.sarif` to generate SARIF format compatible with GitHub Security, GitLab, and other platforms.

**Q: What's the difference between --quick and --rce-only?**  
A: `--quick` reduces timeout to 5s and stops on first finding. `--rce-only` skips non-RCE tests (path traversal, prompt injection, etc). Combine both for fastest scan.

**Q: Can I test my own MCP server?**  
A: Yes! Point Mcpwn at your server command: `python mcpwn.py python3 my_server.py` or `python mcpwn.py node server.js`

**Q: What if I get false positives?**  
A: Check the detection patterns in the JSON report. Path traversal requires 2+ markers. Adjust `LEAK_MARKERS` in `tests/resource_traversal.py` if needed.

**Q: Does this require root/admin privileges?**  
A: No, runs with normal user privileges. Only needs permission to execute the MCP server command.

**Q: How does semantic detection work?**  
A: Instead of looking for crashes, Mcpwn analyzes response content for patterns like `uid=1000`, `root:x:0:0`, `-----BEGIN PRIVATE KEY`, timing deviations, etc.

**Q: Can I use this with AI assistants?**  
A: Yes! Generate JSON output (`--output-json findings.json`) and feed it to AI for deeper analysis. The structured format helps AI understand vulnerabilities in context.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details

## Disclaimer

This tool is for security testing purposes only. Only test systems you have permission to test.

## Author

**Teycir Ben Soltane**
- **Website**: [teycirbensoltane.tn](https://teycirbensoltane.tn)
- **Email**: teycir@pxdmail.net
- **GitHub**: [@Teycir](https://github.com/Teycir)
