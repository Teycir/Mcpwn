# CI/CD Integration Guide

## GitHub Actions Integration

### Basic Workflow

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Mcpwn
        run: |
          git clone https://github.com/teycir/mcpwn.git
          cd mcpwn
      
      - name: Run Security Scan
        run: |
          python3 mcpwn/mcpwn.py --output-sarif report.sarif \
            npx -y @modelcontextprotocol/server-filesystem /tmp
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.sarif
```

### With Trivy and Semgrep

```yaml
name: Comprehensive Security
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
      
      - name: Mcpwn MCP Scan
        run: |
          python3 mcpwn.py --profile paranoid \
            --output-sarif mcpwn-results.sarif \
            npx -y @modelcontextprotocol/server-memory
      
      - name: Upload All Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: |
            trivy-results.sarif
            mcpwn-results.sarif
```

## GitLab CI Integration

```yaml
stages:
  - security

mcp_security_scan:
  stage: security
  image: python:3.11
  script:
    - git clone https://github.com/teycir/mcpwn.git
    - cd mcpwn
    - python3 mcpwn.py --output-json report.json npx -y @modelcontextprotocol/server-filesystem /tmp
  artifacts:
    reports:
      sast: report.json
    paths:
      - report.json
    expire_in: 1 week
```

## Production Deployment Pattern

### With Hasura/DreamFactory Frontend

```yaml
# docker-compose.yml
version: '3.8'
services:
  hasura:
    image: hasura/graphql-engine:latest
    environment:
      HASURA_GRAPHQL_DATABASE_URL: postgres://user:pass@db:5432/mydb
      HASURA_GRAPHQL_ENABLE_CONSOLE: "false"
      HASURA_GRAPHQL_ADMIN_SECRET: ${ADMIN_SECRET}
    ports:
      - "8080:8080"
  
  mcp-server:
    build: ./mcp-server
    environment:
      DATABASE_URL: postgres://readonly:pass@db:5432/mydb
      MCP_ALLOWLIST: /config/allowlist.json
    volumes:
      - ./test_data/allowlist.example.json:/config/allowlist.json:ro
```

### Pre-deployment Security Check

```bash
#!/bin/bash
# pre-deploy-check.sh

echo "Running MCP security scan...
python3 mcpwn.py --profile profiles/paranoid.json \
  --allowlist test_data/allowlist.example.json \
  --output-json scan-results.json \
  python3 mcp-server/server.py

if [ ! -f scan-results.json ]; then
  echo "Scan failed to produce results"
  exit 1
fi

CRITICAL=$(jq '.summary.by_severity.CRITICAL // 0' scan-results.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "CRITICAL vulnerabilities found. Deployment blocked."
  exit 1
fi

echo "Security scan passed. Proceeding with deployment."
```

## Allowlist Enforcement

### Example Configuration

```json
{
  "tools": {
    "query_database": {
      "allowed_capabilities": ["database_read"],
      "forbidden_patterns": ["network", "shell", "filesystem"],
      "max_response_size": 10485760,
      "max_execution_time_ms": 1000,
      "allowed_tables": ["users", "products", "orders"],
      "forbidden_operations": ["DROP", "DELETE", "UPDATE"]
    }
  }
}
```

### Runtime Enforcement

```python
# mcp_server_wrapper.py
import json

class AllowlistEnforcer:
    def __init__(self, allowlist_path):
        with open(allowlist_path) as f:
            self.allowlist = json.load(f)
    
    def check_tool_call(self, tool_name, response):
        rules = self.allowlist.get('tools', {}).get(tool_name, {})
        
        # Check forbidden patterns
        forbidden = rules.get('forbidden_patterns', [])
        response_str = str(response).lower()
        
        for pattern in forbidden:
            if pattern in response_str:
                raise SecurityError(f"Tool {tool_name} violated allowlist: {pattern} detected")
        
        # Check response size
        max_size = rules.get('max_response_size', float('inf'))
        if len(response_str) > max_size:
            raise SecurityError(f"Response size {len(response_str)} exceeds limit {max_size}")
        
        return True
```

## Monitoring Integration

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram

mcp_requests = Counter('mcp_requests_total', 'Total MCP requests', ['tool', 'status'])
mcp_duration = Histogram('mcp_request_duration_seconds', 'Request duration', ['tool'])
mcp_violations = Counter('mcp_allowlist_violations_total', 'Allowlist violations', ['tool', 'pattern'])
```

### Alerting Rules

```yaml
groups:
  - name: mcp_security
    rules:
      - alert: MCPAllowlistViolation
        expr: rate(mcp_allowlist_violations_total[5m]) > 0
        annotations:
          summary: "MCP allowlist violation detected"
      
      - alert: MCPSlowQuery
        expr: histogram_quantile(0.95, mcp_request_duration_seconds) > 1
        annotations:
          summary: "MCP queries are slow (potential directory walk)"
```

## Best Practices

1. **Run Mcpwn in CI/CD** - Block deployments on CRITICAL findings
2. **Use Paranoid Profile** - Enable all side-channel detection
3. **Enforce Allowlists** - Runtime validation of tool behavior
4. **Frontend with RBAC** - Use Hasura/DreamFactory for data tools
5. **Monitor Continuously** - Track violations and anomalies
6. **Regular Scans** - Weekly full scans of all MCP servers
7. **Incident Response** - Automated alerts on security violations

## Author

**Teycir Ben Soltane**  
Email: <teycir@pxdmail.net>  
Website: <https://teycirbensoltane.tn>
