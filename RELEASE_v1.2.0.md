# Mcpwn v1.2.0 - Production Security Features

**Release Date:** 2024-12-15

## What's New

Production-ready side-channel detection and security enforcement for MCP deployments.

### Side-Channel Detection
Detect timing attacks, directory enumeration, and suspicious behavioral patterns.

**Detects:**
- Timing side-channels (>1000ms with low variance)
- Large responses (>1MB indicating directory walks)
- Network activity (af_inet, tcp://, connect patterns)
- Shell execution (subprocess.*, os.system, powershell)
- Root filesystem access (/etc/passwd, /root/, ~/.ssh/)

### Paranoid Security Profile
Production-ready thresholds optimized for serverless environments:
- 1000ms timing threshold (accounts for cold starts)
- 1MB response size limit
- 9 shell execution patterns
- 6 network activity patterns
- 5 sensitive filesystem patterns

### Runtime Allowlist Enforcement
Thread-safe security policy enforcement with SecurityError exception handling.

### CI/CD Integration
Ready-to-use workflows for GitHub Actions, GitLab CI, and deployment pipelines.

## Performance

- 50% I/O reduction: Merged size and behavioral tests
- Memory efficient: Single string conversion per response
- Faster matching: Pre-lowercased indicators cached

## Installation

```bash
git clone https://github.com/Teycir/Mcpwn.git
cd Mcpwn
git checkout v1.2.0
python3 mcpwn.py --help
```

## Usage Examples

### Basic Scan with Paranoid Profile
```bash
python3 mcpwn.py --profile profiles/paranoid.json \
  --output-json report.json \
  npx -y @modelcontextprotocol/server-filesystem /tmp
```

### CI/CD Pre-deployment Check
```bash
python3 mcpwn.py --profile profiles/paranoid.json \
  --allowlist test_data/allowlist.example.json \
  --output-json scan-results.json \
  python3 mcp-server/server.py

CRITICAL=$(jq '.summary.by_severity.CRITICAL // 0' scan-results.json)
[ "$CRITICAL" -gt 0 ] && exit 1
```

## Bug Fixes

- Fixed timing detection false positives with variance check
- Improved exception handling (specific vs unexpected errors)
- Thread-safe caching in AllowlistEnforcer

## New Files

- tests/side_channel.py - Side-channel detection module
- profiles/paranoid.json - Production security profile
- test_data/allowlist.example.json - Allowlist configuration example
- test_data/enforcer.py - Runtime enforcement module
- CI_CD_INTEGRATION.md - Deployment guide

## Future Work (v1.3.0)

- Statistical baseline timing (10-20 samples)
- CIDR subnet matching in allowlist
- Error-based detection (stack trace analysis)
- Regex support in allowlist patterns

## Author

**Teycir Ben Soltane**  
Email: teycir@pxdmail.net  
Website: https://teycirbensoltane.tn

## License

MIT License - See LICENSE file for details
