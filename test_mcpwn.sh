#!/bin/bash
# Quick validation test for Mcpwn improvements

echo "=== Testing Mcpwn against DVMCP ==="
echo ""

echo "[1/4] Testing basic scan..."
if ! python3 mcpwn.py --quick python3 dvmcp_server.py 2>&1 | head -20; then
    echo "✗ Basic scan failed"
    exit 1
fi

echo ""
echo "[2/4] Testing JSON report generation..."
python3 mcpwn.py --quick --output-json /tmp/mcpwn_test.json python3 dvmcp_server.py 2>&1 | grep -E "(JSON report|Found)"

if [ -f /tmp/mcpwn_test.json ]; then
    echo "✓ JSON report created"
    jq '.summary' /tmp/mcpwn_test.json 2>/dev/null || echo "  (jq not installed, skipping preview)"
else
    echo "✗ JSON report failed"
fi

echo ""
echo "[3/4] Testing SARIF report generation..."
python3 mcpwn.py --quick --output-sarif /tmp/mcpwn_test.sarif python3 dvmcp_server.py 2>&1 | grep -E "(SARIF report|Found)"

if [ -f /tmp/mcpwn_test.sarif ]; then
    echo "✓ SARIF report created"
    jq '.runs[0].tool.driver.name' /tmp/mcpwn_test.sarif 2>/dev/null || echo "  (jq not installed, skipping preview)"
else
    echo "✗ SARIF report failed"
fi

echo ""
echo "[4/4] Checking for expected vulnerabilities..."
if [ -f /tmp/mcpwn_test.json ]; then
    if grep -q "RCE\|COMMAND" /tmp/mcpwn_test.json; then
        echo "✓ RCE detection working"
    else
        echo "✗ RCE detection failed"
    fi
fi

echo ""
echo "=== Test complete ==="
rm -f /tmp/mcpwn_test.* 2>/dev/null
echo "✓ Cleanup complete"
