"""Evidence model and reporter tests."""
import json

from core.evidence import (
    confidence_label,
    make_finding,
    normalize_finding,
    redact_secret,
)
from core.reporter import Reporter


def test_timing_finding_is_not_promoted_to_rce():
    finding = normalize_finding(
        "side_channel", {"type": "TIMING_SIDE_CHANNEL", "severity": "LOW",
                         "confidence": 25})
    assert finding["type"] == "TIMING_SIDE_CHANNEL"
    assert finding["severity"] == "LOW"
    assert finding["status"] == "informational"
    assert "RCE" not in finding["title"]


def test_blind_timing_is_not_confirmed():
    finding = normalize_finding(
        "tool_injection",
        make_finding("BLIND_RCE_TIMING", severity="MEDIUM", confidence=40))
    assert finding["verified"] is False
    assert finding["status"] in ("possible", "likely")
    assert finding["severity"] == "MEDIUM"


def test_verified_finding_is_confirmed():
    finding = normalize_finding(
        "tool_injection",
        make_finding("RCE", severity="CRITICAL", confidence=95,
                     verified=True, evidence=["uid=1000"]))
    assert finding["verified"] is True
    assert finding["status"] == "confirmed"
    assert finding["confidence"] == 95


def test_unverified_confidence_is_capped():
    finding = normalize_finding(
        "probe", make_finding("SSRF_RESPONSE", confidence=99,
                              verified=False))
    assert finding["confidence"] <= 84
    assert finding["verified"] is False


def test_confidence_labels():
    assert confidence_label(95) == "confirmed"
    assert confidence_label(70) == "likely"
    assert confidence_label(40) == "possible"
    assert confidence_label(10) == "informational"


def test_reporter_deduplicates_and_merges():
    reporter = Reporter()
    reporter.add_findings("tool_injection", [
        {"type": "RCE", "payload": "; id", "severity": "HIGH",
         "confidence": 50, "tool": "exec"},
        {"type": "RCE", "payload": "; id", "severity": "CRITICAL",
         "confidence": 90, "tool": "exec", "verified": True,
         "evidence": ["uid=1000"]},
    ])
    assert len(reporter.findings) == 1
    finding = reporter.findings[0]
    assert finding["severity"] == "CRITICAL"
    assert finding["confidence"] == 90
    assert finding["verified"] is True
    assert finding["occurrences"] == 2


def test_reporter_json_and_sarif_include_confidence(tmp_path):
    reporter = Reporter()
    reporter.add_findings("test", [
        {"type": "RCE", "severity": "CRITICAL", "confidence": 95,
         "verified": True, "tool": "exec", "payload": "; id"},
    ])
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    reporter.to_json(str(json_path))
    reporter.to_sarif(str(sarif_path))

    report = json.loads(json_path.read_text())
    assert report["summary"]["by_confidence"]["confirmed"] == 1
    assert report["summary"]["verified"] == 1
    assert report["findings"][0]["severity"] == "CRITICAL"

    sarif = json.loads(sarif_path.read_text())
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "RCE"
    assert result["properties"]["confidence"] == 95
    assert result["level"] == "error"
    assert sarif["runs"][0]["tool"]["driver"]["rules"]


def test_secret_redaction_never_returns_full_value():
    secret = "AKIAABCDEFGHIJKLMNOP"
    masked = redact_secret(secret)
    assert secret not in masked
    assert masked.startswith("AKIA")
    assert "*" in masked
