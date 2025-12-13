# Mcpwn - MCP Security Testing Framework

Semantic-focused security testing for Model Context Protocol servers.

## Prerequisites

- Python 3.8+
- No external dependencies (uses stdlib only)
- Optional: API key for `--llm-generate` mode - Anthropic Claude or Google Gemini (see [LLM_GUIDE.md](LLM_GUIDE.md))

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

# Custom timeout (default: 30s)
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
    ├── capability_fuzzing.py  # NEW: Initialization fuzzing
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
| `--timeout` | Request timeout in seconds | 30 |
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
