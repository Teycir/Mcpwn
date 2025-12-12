# Mcpwn - MCP Security Testing Framework

Semantic-focused security testing for Model Context Protocol servers.

## Architecture

```
Discovery → Attack Generation → Execution → Semantic Detection
```

## Usage

```bash
# Basic scan
python mcpwn.py npx -y @modelcontextprotocol/server-filesystem /tmp

# Quick RCE scan (fast, stops on first finding)
python mcpwn.py --quick npx -y @modelcontextprotocol/server-filesystem /tmp

# RCE-only mode (comprehensive RCE testing)
python mcpwn.py --rce-only npx -y @modelcontextprotocol/server-filesystem /tmp

# Safe mode (skip destructive tests)
python mcpwn.py --safe-mode npx -y @modelcontextprotocol/server-filesystem /tmp

# Generate reports
python mcpwn.py --output-json report.json --output-html report.html npx ...

# Parallel flooding
python mcpwn.py --parallel npx ...
```

## Attack Surface

**Tier 1 (Implemented)**
- State desync (skip/double initialize)
- Tool argument injection (command injection, path traversal, nested schemas)
- Resource path traversal
- Subscription flooding (parallel)

**Tier 2 (Implemented)**
- Prompt injection (indirect LLM jailbreak)
- Protocol fuzzing (malformed JSON-RPC)
- Statistical timing analysis

**Tier 3 (TODO)**
- LLM-guided payload generation
- OOB detection (DNS exfiltration)
- Race condition testing

## Detection

Semantic indicators, not crashes:
- `uid=`, `root:x:` → RCE
- `-----BEGIN`, `PRIVATE KEY` → File read
- Statistical timing deviation → Blind injection
- Prompt echo → Indirect prompt injection

## Architecture

```
Mcpwn/
├── mcpwn.py              # CLI entry point
├── payloads.py           # Attack payloads & indicators
├── core/
│   ├── pentester.py      # Main orchestrator
│   ├── detector.py       # Semantic detection
│   └── reporter.py       # JSON/HTML reports
└── tests/
    ├── state_desync.py
    ├── tool_injection.py
    ├── resource_traversal.py
    ├── subscription_flood.py
    ├── prompt_injection.py
    └── protocol_fuzzing.py
```
