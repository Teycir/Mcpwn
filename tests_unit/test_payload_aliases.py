"""Payload category regression tests."""
from core import MCPPentester
from tests.tool_injection import classify_detections


def test_traversal_alias_returns_real_payloads():
    """Regression: 'traversal' used to resolve to an empty list."""
    pentester = MCPPentester(["unused"], {})
    payloads = pentester.get_payloads({"target_type": "traversal"})
    assert payloads
    assert any("etc/passwd" in payload for payload in payloads)
    assert any(payload.startswith("..") for payload in payloads)


def test_rce_alias_returns_command_payloads():
    pentester = MCPPentester(["unused"], {})
    payloads = pentester.get_payloads({"target_type": "rce"})
    assert "; id" in payloads


def test_unknown_category_falls_back_to_command_injection():
    pentester = MCPPentester(["unused"], {})
    assert pentester.get_payloads({"target_type": "does-not-exist"})


def test_detection_classification_is_unchanged():
    assert classify_detections([{"type": "RCE"}]) == ("RCE", "CRITICAL")
    assert classify_detections([{"type": "FILE_READ"}]) == (
        "FILE_READ", "HIGH")
    assert classify_detections([]) == ("INJECTION_ANOMALY", "MEDIUM")
