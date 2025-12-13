# Changelog

## [1.1.0] - 2024

### Added
- **API Key Support**: LLM-guided generation now accepts API key via CLI or environment
  - `--api-key` flag for direct key input
  - `ANTHROPIC_API_KEY` environment variable support
  - Automatic fallback to templates if API unavailable
  - Uses Claude 3.5 Sonnet for payload generation

- **Capability Fuzzing Test**: New test module for detecting initialization vulnerabilities
  - Type confusion attacks on capability objects
  - Prototype pollution via capability names
  - DoS detection via oversized capability lists
  - Located in `tests/capability_fuzzing.py`

- **SARIF Report Format**: CI/CD integration support
  - GitHub Security tab compatible
  - GitLab Security Dashboard compatible
  - Severity mapping (CRITICAL/HIGH → error, MEDIUM → warning, LOW → note)
  - Export via `--output-sarif report.sarif`

- **DVMCP Server**: Damn Vulnerable MCP Server for testing
  - Intentionally vulnerable command execution
  - Path traversal vulnerabilities
  - Use: `python mcpwn.py python3 dvmcp_server.py`

- **Documentation Improvements**:
  - Prerequisites section with Python version requirements
  - Example output showing typical findings
  - Troubleshooting guide for common issues
  - Testing instructions using DVMCP

### Fixed
- **Thread Safety**: Added transport-level lock to prevent JSON-RPC message interleaving
  - Fixes race conditions in parallel flooding tests
  - Prevents malformed JSON-RPC responses under concurrent load
  - New `send_lock` in `MCPPentester` class

- **Resource Cleanup**: SSRF listener now properly shuts down
  - Added `cleanup()` method to `SSRFTest`
  - Prevents "Address already in use" errors on rapid restarts
  - Explicit socket closure via `server.shutdown()` and `server.server_close()`

- **False Positive Reduction**: Improved file leak detection
  - Multi-marker validation (requires 2+ indicators from same category)
  - High-confidence single markers (e.g., "root:x:0:0:root")
  - Categorized markers: passwd, shadow, ssh_key, config, windows, error
  - Reduces false positives from innocent text files

### Changed
- Updated `LEAK_MARKERS` from list to categorized dictionary
- SSRF test now includes cleanup in test lifecycle
- Reporter now supports three output formats: JSON, HTML, SARIF

### Technical Details

**Thread Safety Implementation**:
```python
# Before: Race condition possible
self.proc.stdin.write(json.dumps(msg) + '\n')

# After: Protected by lock
with self.send_lock:
    self.proc.stdin.write(json.dumps(msg) + '\n')
```

**False Positive Reduction**:
```python
# Before: Single marker match
return any(marker in content for marker in LEAK_MARKERS)

# After: Multi-marker validation
for category, markers in LEAK_MARKERS.items():
    matches = sum(1 for m in markers if m in content)
    if matches >= 2:
        return True
```

## [1.0.0] - Initial Release

### Features
- Semantic detection engine
- Tool injection testing (RCE, SQLi, path traversal)
- Resource traversal testing
- SSRF detection with callback listener
- Protocol fuzzing
- Prompt injection testing
- OOB detection (DNS exfiltration)
- Race condition testing
- Resource exhaustion testing
- LLM-guided payload generation
- JSON/HTML reporting
- Safe mode for non-destructive testing
- Quick scan mode
- RCE-only mode
