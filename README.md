# Mcpwn - MCP Security Testing Framework

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--12-orange.svg)](https://modelcontextprotocol.io)
[![Security](https://img.shields.io/badge/security-testing-red.svg)](https://github.com/Teycir/Mcpwn)

Semantic-focused security testing for Model Context Protocol servers.

## Author

**Teycir Ben Soltane**
- Website: [teycirbensoltane.tn](https://teycirbensoltane.tn)
- Email: teycir@pxdmail.net
- GitHub: [@Teycir](https://github.com/Teycir)

## Prerequisites

- Python 3.8+
- No external dependencies (uses stdlib only)
- Optional: API key for `--llm-generate` mode - Anthropic Claude or Google Gemini

```bash
pip install -r requirements.txt

# For LLM-guided generation (choose one):
pip install openai  # OpenRouter (free models)
# OR
pip install google-generativeai  # Google Gemini (free tier)
# OR
pip install anthropic  # Anthropic Claude (paid)
```

## Architecture

```
Discovery → Attack Generation → Execution → Semantic Detection
```

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

# Quick RCE scan (fast, stops on first finding)
python mcpwn.py --quick npx -y @modelcontextprotocol/server-filesystem /tmp

# RCE-only mode (comprehensive RCE testing)
python mcpwn.py --rce-only npx -y @modelcontextprotocol/server-filesystem /tmp

# Safe mode (skip destructive tests: protocol fuzzing, subscription flood)
python mcpwn.py --safe-mode npx -y @modelcontextprotocol/server-filesystem /tmp

# Custom timeout (default: 10s)
python mcpwn.py --timeout 60 npx -y @modelcontextprotocol/server-filesystem /tmp

# Generate reports with severity breakdown
python mcpwn.py --output-json report.json --output-html report.html npx ...

# Parallel flooding
python mcpwn.py --parallel npx ...

# LLM-guided payload generation (Tier 3)
# Option 1: OpenRouter (free models)
export OPENROUTER_API_KEY=sk-or-v1-...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Option 2: Google Gemini (free tier)
export GEMINI_API_KEY=AIzaSy...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Option 3: Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Or pass API key directly
python mcpwn.py --llm-generate --api-key sk-or-v1-... npx ...

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

**Tier 1 (Implemented)**
- State desync (skip/double initialize)
- Capability fuzzing (malformed initialization)
- Tool argument injection (command injection, path traversal, nested schemas)
- Resource path traversal
- Subscription flooding (parallel, skipped in safe mode)
- SSRF injection (callback listener)
- Deserialization attacks (pickle, YAML, JSON gadgets)

**Tier 2 (Implemented)**
- Prompt injection (indirect LLM jailbreak)
- Protocol fuzzing (malformed JSON-RPC, skipped in safe mode)
- Statistical timing analysis
- Schema pollution
- Auth bypass

**Tier 3 (Implemented)**
- LLM-guided payload generation (context-aware synthesis)
- OOB detection (DNS exfiltration)
- Race condition testing
- Resource exhaustion

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
│   ├── generator.py      # LLM-guided payload generation
│   └── reporter.py       # JSON/HTML reports with severity aggregation
└── tests/
    ├── state_desync.py
    ├── capability_fuzzing.py  # Initialization fuzzing
    ├── tool_injection.py      # Payload deduplication
    ├── resource_traversal.py  # Multi-marker validation
    ├── subscription_flood.py  # Safe mode aware
    ├── prompt_injection.py
    ├── protocol_fuzzing.py    # Connection pooling, safe mode aware
    ├── ssrf_injection.py      # HTTP callback listener with cleanup
    ├── deserialization.py     # Pickle/YAML/JSON gadgets
    ├── schema_pollution.py
    ├── auth_bypass.py
    ├── oob_detection.py       # DNS exfiltration listener
    ├── race_condition.py
    └── resource_exhaustion.py
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
| `--quick` | Stop on first RCE finding | False |
| `--rce-only` | Only test command injection | False |
| `--timeout` | Request timeout in seconds | 10 |
| `--parallel` | Enable parallel flooding | False |
| `--llm-generate` | Enable LLM-guided payloads | False |
| `--api-key` | API key for LLM (or use OPENROUTER_API_KEY/GEMINI_API_KEY/ANTHROPIC_API_KEY env) | None |
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

## Testing Mcpwn

Use the included vulnerable server:
```bash
python mcpwn.py python3 test_data/dvmcp_server.py
```

Expected findings:
- RCE via `execute_command` tool
- Path traversal via `read_file` tool

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## AI Integration

Mcpwn is designed to work seamlessly with AI assistants for enhanced security analysis:

**AI-Assisted Workflow:**
```bash
# 1. Run automated scan
python mcpwn.py --output-json findings.json <server>

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

## Disclaimer

This tool is for security testing purposes only. Only test systems you have permission to test.

## Contact

- **Author**: Teycir Ben Soltane
- **Website**: [teycirbensoltane.tn](https://teycirbensoltane.tn)
- **Email**: teycir@pxdmail.net
- **GitHub**: [@Teycir](https://github.com/Teycir)
