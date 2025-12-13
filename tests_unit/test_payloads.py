"""Unit tests for payloads module"""
import pytest
from payloads import PAYLOADS, PAYLOAD_PRIORITY, INDICATORS

def test_payload_structure():
    """Test payloads dictionary structure"""
    assert isinstance(PAYLOADS, dict)
    assert 'command_injection' in PAYLOADS
    assert 'path_traversal' in PAYLOADS

def test_command_injection_payloads():
    """Test command injection payloads exist"""
    payloads = PAYLOADS['command_injection']
    assert isinstance(payloads, list)
    assert len(payloads) > 0
    assert any('id' in p for p in payloads)

def test_path_traversal_payloads():
    """Test path traversal payloads exist"""
    payloads = PAYLOADS['path_traversal']
    assert isinstance(payloads, list)
    assert len(payloads) > 0
    assert any('../' in p for p in payloads)

def test_payload_priority():
    """Test payload priority list"""
    assert isinstance(PAYLOAD_PRIORITY, list)
    assert 'command_injection' in PAYLOAD_PRIORITY
    assert len(PAYLOAD_PRIORITY) > 0

def test_indicators():
    """Test detection indicators"""
    assert isinstance(INDICATORS, dict)
    assert len(INDICATORS) > 0
    # Check indicators have patterns
    for category, patterns in INDICATORS.items():
        assert len(patterns) > 0

def test_no_empty_payloads():
    """Test no payload category is empty"""
    for category, payloads in PAYLOADS.items():
        assert len(payloads) > 0, f"{category} has no payloads"

def test_payload_uniqueness():
    """Test payloads are mostly unique within categories"""
    for category, payloads in PAYLOADS.items():
        # Allow some duplicates due to variations
        unique_ratio = len(set(payloads)) / len(payloads)
        assert unique_ratio > 0.5, f"{category} has too many duplicate payloads"
