#!/usr/bin/env python3
"""Quick MCP security test runner for multiple servers"""
import subprocess
import json
import os
import tempfile

SERVERS = [
    {
        "name": "time",
        "cmd": "uvx mcp-server-time",
        "timeout": 20
    },
    {
        "name": "memory",
        "cmd": "npx -y @modelcontextprotocol/server-memory",
        "timeout": 25
    },
    {
        "name": "filesystem",
        "cmd": "npx -y @modelcontextprotocol/server-filesystem /tmp",
        "timeout": 25
    },
    {
        "name": "sequentialthinking",
        "cmd": "npx -y @modelcontextprotocol/server-sequential-thinking",
        "timeout": 25
    },
]

def test_server(server_name, cmd, timeout):
    """Test a single MCP server"""
    print(f"\n{'='*60}")
    print(f"Testing: {server_name}")
    print(f"Command: {cmd}")
    print(f"{'='*60}")
    
    report_file = os.path.join(tempfile.gettempdir(), f"{server_name}_report.json")
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mcpwn_script = os.path.join(script_dir, "mcpwn.py")
    cmd_args = ["python3", mcpwn_script, "--quick", "--output-json", report_file] + cmd.split()
    
    try:
        # nosec B603 - cmd is from hardcoded SERVERS list, not user input
        result = subprocess.run(
            cmd_args,
            cwd=script_dir,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr[:500])
        
        # Try to read report
        try:
            with open(report_file) as f:
                report = json.load(f)
                print(f"\n✓ Report generated: {report_file}")
                if 'summary' in report:
                    print(f"  Total findings: {report['summary'].get('total', 0)}")
                    if 'by_severity' in report['summary']:
                        print(f"  By severity: {report['summary']['by_severity']}")
        except (FileNotFoundError, json.JSONDecodeError):
            print("✗ No report generated")
            
    except subprocess.TimeoutExpired:
        print(f"✗ Test timed out after {timeout}s")
    except Exception as e:
        print(f"✗ Test failed: {e}")

if __name__ == "__main__":
    print("Mcpwn Quick Test Suite")
    print(f"Testing {len(SERVERS)} MCP servers...\n")
    
    for server in SERVERS:
        test_server(server["name"], server["cmd"], server["timeout"])
    
    print(f"\n{'='*60}")
    print("Test suite complete")
    print(f"{'='*60}")
