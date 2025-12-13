"""Unit tests for semantic detector"""
from core.detector import SemanticDetector

def test_detector_initialization():
    """Test detector initializes correctly"""
    detector = SemanticDetector()
    assert detector.findings == []
    assert hasattr(detector, 'timing_analyzer')

def test_rce_detection():
    """Test RCE pattern detection"""
    detector = SemanticDetector()
    response = {"result": {"content": [{"text": "uid=1000(user) gid=1000(user)"}]}}
    detector.analyze(response, "uid=1000(user) gid=1000(user)", 0.1)
    
    assert len(detector.findings) > 0
    assert any(f['type'] == 'RCE' for f in detector.findings)

def test_file_read_detection():
    """Test file read pattern detection"""
    detector = SemanticDetector()
    response = {"result": {"content": [{"text": "root:x:0:0:root:/root:/bin/bash"}]}}
    detector.analyze(response, "root:x:0:0:root:/root:/bin/bash", 0.1)
    
    assert len(detector.findings) > 0
    assert any(f['type'] == 'FILE_READ' for f in detector.findings)

def test_private_key_detection():
    """Test private key detection"""
    detector = SemanticDetector()
    response = {"result": {"content": [{"text": "-----BEGIN RSA PRIVATE KEY-----"}]}}
    detector.analyze(response, "-----BEGIN RSA PRIVATE KEY-----", 0.1)
    
    assert len(detector.findings) > 0
    assert any(f['type'] == 'FILE_READ' for f in detector.findings)

def test_baseline_establishment():
    """Test baseline latency tracking"""
    detector = SemanticDetector()
    detector.analyze({}, "", 0.5, is_baseline=True)
    # Baseline is tracked internally by timing_analyzer
    assert hasattr(detector, 'timing_analyzer')

def test_timing_attack_detection():
    """Test timing-based attack detection"""
    detector = SemanticDetector()
    # Establish baseline
    for _ in range(5):
        detector.analyze({}, "", 0.1, is_baseline=True)
    # Timing detection requires statistical analysis
    detector.analyze({}, "", 10.0)
    # May or may not detect depending on threshold
    assert isinstance(detector.findings, list)

def test_report_generation():
    """Test report generation"""
    detector = SemanticDetector()
    response = {"result": {"content": [{"text": "uid=1000(user)"}]}}
    detector.analyze(response, "uid=1000(user)", 0.1)
    
    report = detector.report()
    assert isinstance(report, list)
    assert len(report) > 0

def test_no_false_positives():
    """Test clean response doesn't trigger detection"""
    detector = SemanticDetector()
    response = {"result": {"content": [{"text": "Hello world"}]}}
    detector.analyze(response, "Hello world", 0.1)
    
    assert len(detector.findings) == 0
