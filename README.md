# Mcpwn - MCP Security Testing Framework

Semantic-focused security testing for Model Context Protocol servers.

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
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Attack Surface

**Tier 1 (Implemented)**
- State desync (skip/double initialize)
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

**Tier 3 (Planned)**
- OOB detection (DNS exfiltration)
- Race condition testing
- Resource exhaustion

## Detection

Semantic indicators, not crashes:
- `uid=`, `root:x:` → RCE
- `-----BEGIN`, `PRIVATE KEY` → File read
- Statistical timing deviation → Blind injection
- Prompt echo → Indirect prompt injection

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
    ├── tool_injection.py      # Payload deduplication
    ├── resource_traversal.py
    ├── subscription_flood.py  # Safe mode aware
    ├── prompt_injection.py
    ├── protocol_fuzzing.py    # Connection pooling, safe mode aware
    ├── ssrf_injection.py      # HTTP callback listener
    ├── deserialization.py     # Pickle/YAML/JSON gadgets
    ├── schema_pollution.py
    ├── auth_bypass.py
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
| `--output-json` | Export JSON report | None |
| `--output-html` | Export HTML report | None |

## Thread Safety

- Request ID generation protected by lock
- Health checks use dedicated lock
- Connection pooling with cleanup
- Safe concurrent test execution
