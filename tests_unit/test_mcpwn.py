#!/usr/bin/env python3
"""Pytest test suite for Mcpwn"""
import subprocess
import json
import tempfile
import os
import pytest

def test_help_command():
    """Test --help works without errors"""
    result = subprocess.run(
        ["python3", "mcpwn.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "MCP Security Testing Framework" in result.stdout

def test_no_arguments_shows_error():
    """Test error when no server command provided"""
    result = subprocess.run(
        ["python3", "mcpwn.py"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1
    output = (result.stdout + result.stderr).lower()
    assert "server command required" in output

def test_imports_work():
    """Test core imports are functional"""
    result = subprocess.run(
        ["python3", "-c", "from core import MCPPentester"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0

@pytest.mark.parametrize("file", [
    "mcpwn.py",
    "payloads.py",
    "core/pentester.py",
    "core/detector.py",
    "core/reporter.py",
    "core/generator.py",
])
def test_python_syntax(file):
    """Test Python files have valid syntax"""
    result = subprocess.run(
        ["python3", "-m", "py_compile", file],
        capture_output=True
    )
    assert result.returncode == 0, f"{file} has syntax errors"

def test_vulnerable_server_detection():
    """Test RCE detection against vulnerable test server"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        report_file = f.name
    
    try:
        result = subprocess.run(
            ["python3", "mcpwn.py", "--quick", "--rce-only", 
             "--output-json", report_file,
             "python3", "test_data/dvmcp_server.py"],
            capture_output=True,
            text=True,
            timeout=20
        )
        
        assert result.returncode == 0
        assert os.path.exists(report_file)
        
        with open(report_file) as f:
            report = json.load(f)
        
        assert "findings" in report
        assert len(report["findings"]) > 0, "Should detect RCE vulnerability"
        assert "summary" in report
        
    finally:
        if os.path.exists(report_file):
            os.unlink(report_file)

def test_json_report_format():
    """Test JSON report has correct structure"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        report_file = f.name
    
    try:
        subprocess.run(
            ["python3", "mcpwn.py", "--quick", "--rce-only",
             "--output-json", report_file,
             "python3", "test_data/dvmcp_server.py"],
            capture_output=True,
            timeout=20
        )
        
        with open(report_file) as f:
            report = json.load(f)
        
        assert "tool" in report
        assert "version" in report
        assert "timestamp" in report
        assert "findings" in report
        assert "summary" in report
        assert isinstance(report["findings"], list)
        
    finally:
        if os.path.exists(report_file):
            os.unlink(report_file)

def test_safe_mode_flag():
    """Test --safe-mode flag is accepted"""
    result = subprocess.run(
        ["python3", "mcpwn.py", "--safe-mode", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0

def test_timeout_flag():
    """Test --timeout flag is accepted"""
    result = subprocess.run(
        ["python3", "mcpwn.py", "--timeout", "5", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0

def test_invalid_timeout():
    """Test invalid timeout value is rejected"""
    result = subprocess.run(
        ["python3", "mcpwn.py", "--timeout", "0", "python3", "test_data/dvmcp_server.py"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1
    output = (result.stdout + result.stderr).lower()
    assert "positive" in output
