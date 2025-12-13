"""Unit tests for reporter"""
import pytest
import json
import tempfile
import os
from core.reporter import Reporter

def test_reporter_initialization():
    """Test reporter initializes correctly"""
    reporter = Reporter()
    assert reporter.findings == []

def test_add_findings():
    """Test adding findings"""
    reporter = Reporter()
    findings = [
        {'type': 'RCE', 'severity': 'CRITICAL'},
        {'type': 'FILE_READ', 'severity': 'HIGH'}
    ]
    reporter.add_findings('test', findings)
    
    assert len(reporter.findings) == 2
    assert all('test' in str(f) for f in reporter.findings)

def test_json_export():
    """Test JSON report export"""
    reporter = Reporter()
    reporter.add_findings('test', [{'type': 'RCE', 'severity': 'CRITICAL'}])
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        report_file = f.name
    
    try:
        reporter.to_json(report_file)
        assert os.path.exists(report_file)
        
        with open(report_file) as f:
            report = json.load(f)
        
        assert 'tool' in report
        assert 'findings' in report
        assert 'summary' in report
        assert report['summary']['total'] == 1
    finally:
        os.unlink(report_file)

def test_html_export():
    """Test HTML report export"""
    reporter = Reporter()
    reporter.add_findings('test', [{'type': 'RCE', 'severity': 'CRITICAL'}])
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        report_file = f.name
    
    try:
        reporter.to_html(report_file)
        assert os.path.exists(report_file)
        
        with open(report_file) as f:
            html = f.read()
        
        assert 'Mcpwn' in html
        assert 'RCE' in html
    finally:
        os.unlink(report_file)

def test_sarif_export():
    """Test SARIF report export"""
    reporter = Reporter()
    reporter.add_findings('test', [{'type': 'RCE', 'severity': 'CRITICAL'}])
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        report_file = f.name
    
    try:
        reporter.to_sarif(report_file)
        assert os.path.exists(report_file)
        
        with open(report_file) as f:
            sarif = json.load(f)
        
        assert 'version' in sarif
        assert sarif['version'] == '2.1.0'
        assert 'runs' in sarif
    finally:
        os.unlink(report_file)

def test_severity_summary():
    """Test severity aggregation"""
    reporter = Reporter()
    reporter.add_findings('test', [
        {'type': 'RCE', 'severity': 'CRITICAL'},
        {'type': 'XSS', 'severity': 'HIGH'},
        {'type': 'INFO', 'severity': 'LOW'}
    ])
    
    summary = reporter.summary()
    assert summary['CRITICAL'] == 1
    assert summary['HIGH'] == 1
    assert summary['LOW'] == 1

def test_type_counting():
    """Test finding type counting"""
    reporter = Reporter()
    reporter.add_findings('test', [
        {'type': 'RCE', 'severity': 'CRITICAL'},
        {'type': 'RCE', 'severity': 'HIGH'},
        {'type': 'FILE_READ', 'severity': 'MEDIUM'}
    ])
    
    counts = reporter._count_by_type()
    assert counts['RCE'] == 2
    assert counts['FILE_READ'] == 1
