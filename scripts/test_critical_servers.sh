#!/bin/bash
# Test critical MCP servers for security vulnerabilities

echo "=========================================="
echo "Mcpwn Critical Server Testing"
echo "=========================================="

cd /home/teycir/Repos/Mcpwn

# Test 1: Time server (simple, should complete quickly)
echo -e "\n[1/5] Testing time server..."
timeout 20 python3 mcpwn.py --quick --output-json /tmp/time_findings.json uvx mcp-server-time 2>&1 | grep -E "^\[|Found|Testing|WARNING|CRITICAL"

# Test 2: Memory server (medium complexity)
echo -e "\n[2/5] Testing memory server..."
timeout 25 python3 mcpwn.py --quick --output-json /tmp/memory_findings.json npx -y @modelcontextprotocol/server-memory 2>&1 | grep -E "^\[|Found|Testing|WARNING|CRITICAL"

# Test 3: Sequential thinking (simple)
echo -e "\n[3/5] Testing sequential thinking server..."
timeout 20 python3 mcpwn.py --quick --output-json /tmp/sequential_findings.json npx -y @modelcontextprotocol/server-sequential-thinking 2>&1 | grep -E "^\[|Found|Testing|WARNING|CRITICAL"

# Test 4: Filesystem (complex, path traversal focus)
echo -e "\n[4/5] Testing filesystem server (RCE-only mode)..."
timeout 30 python3 mcpwn.py --rce-only --output-json /tmp/filesystem_findings.json npx -y @modelcontextprotocol/server-filesystem /tmp 2>&1 | grep -E "^\[|Found|Testing|WARNING|CRITICAL"

# Test 5: Puppeteer (browser automation)
echo -e "\n[5/5] Testing puppeteer server..."
timeout 25 python3 mcpwn.py --quick --output-json /tmp/puppeteer_findings.json npx -y @modelcontextprotocol/server-puppeteer 2>&1 | grep -E "^\[|Found|Testing|WARNING|CRITICAL"

echo -e "\n=========================================="
echo "Test Summary"
echo "=========================================="

for file in /tmp/*_findings.json; do
    if [ -f "$file" ]; then
        name=$(basename "$file" _findings.json)
        total=$(python3 -c "import json; f=open('$file'); d=json.load(f); print(d.get('summary', {}).get('total', 0))" 2>/dev/null || echo "0")
        echo "✓ $name: $total findings"
    fi
done

echo -e "\nDetailed reports available in /tmp/*_findings.json"
