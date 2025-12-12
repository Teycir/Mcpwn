# Mcpwn Quick Start Guide

## Installation

```bash
git clone <repo>
cd Mcpwn
pip install -r requirements.txt  # No dependencies needed for core
```

## Basic Usage

### 1. Test the Vulnerable Server (Recommended First Step)
```bash
python mcpwn.py python3 dvmcp_server.py
```
Expected: RCE and path traversal findings

### 2. Quick RCE Scan (Fast)
```bash
python mcpwn.py --quick npx -y @modelcontextprotocol/server-filesystem /tmp
```
Stops on first RCE finding

### 3. Full Security Audit
```bash
python mcpwn.py \
  --output-json report.json \
  --output-sarif report.sarif \
  npx -y @modelcontextprotocol/server-filesystem /tmp
```

### 4. Safe Mode (Non-Destructive)
```bash
python mcpwn.py --safe-mode npx -y @modelcontextprotocol/server-filesystem /tmp
```
Skips: protocol fuzzing, subscription flood

## Common Scenarios

### CI/CD Integration
```bash
# GitHub Actions / GitLab CI
python mcpwn.py --output-sarif security-report.sarif <server-command>
# Upload security-report.sarif to Security tab
```

### Development Testing
```bash
# Fast iteration during development
python mcpwn.py --quick --rce-only --timeout 10 <server-command>
```

### Production Pre-Deployment
```bash
# Comprehensive audit
python mcpwn.py \
  --timeout 60 \
  --output-json prod-audit.json \
  --output-html prod-audit.html \
  <server-command>
```

## Understanding Output

### Finding Severity
- **CRITICAL**: RCE, arbitrary file read, SSRF with callback
- **HIGH**: Capability bypass, auth bypass, crash
- **MEDIUM**: DoS, timing anomalies, schema pollution
- **LOW**: Information disclosure, minor misconfigurations

### Common Findings

**RCE Detection**:
```
[WARNING] execute_command: RCE via command
[WARNING]   Detection: uid=1000(user) gid=1000(user)
```

**Path Traversal**:
```
[WARNING] Path traversal: file://../../../etc/passwd
[WARNING]   Detection: root:x:0:0:root
```

**SSRF**:
```
[WARNING] fetch_url: OOB DNS via url
```

## Troubleshooting

### Port Already in Use
```bash
# Kill existing listener
lsof -i :8888 | grep Python | awk '{print $2}' | xargs kill
```

### Timeout Errors
```bash
# Increase timeout for slow servers
python mcpwn.py --timeout 120 <server-command>
```

### Too Many False Positives
Edit `tests/resource_traversal.py`:
```python
# Increase marker threshold
if matches >= 3:  # Was: >= 2
    return True
```

## Report Formats

### JSON (Programmatic)
```json
{
  "summary": {
    "total": 5,
    "by_severity": {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 2}
  },
  "findings": [...]
}
```

### SARIF (CI/CD)
Compatible with:
- GitHub Security tab
- GitLab Security Dashboard
- Azure DevOps
- SonarQube

### HTML (Human-Readable)
Color-coded findings with full details

## Advanced Features

### LLM-Guided Payloads
```bash
# Install anthropic package first
pip install anthropic

# Option 1: Environment variable
export ANTHROPIC_API_KEY=sk-ant-...
python mcpwn.py --llm-generate <server-command>

# Option 2: CLI argument
python mcpwn.py --llm-generate --api-key sk-ant-... <server-command>
```

### Parallel Testing
```bash
python mcpwn.py --parallel <server-command>
```

### Custom Timeout Per Test
Edit `core/pentester.py`:
```python
resp, elapsed = self.send("tools/call", params, timeout=60)
```

## Next Steps

1. Review findings in generated reports
2. Fix vulnerabilities in your MCP server
3. Re-run Mcpwn to verify fixes
4. Integrate into CI/CD pipeline with `--output-sarif`
