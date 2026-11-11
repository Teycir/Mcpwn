"""End-to-end regressions against the deliberately vulnerable demo server."""
import json
import os
import sys

import pytest

from core import MCPPentester
from tests.protocol_fuzzing import ProtocolFuzzingTest
from tests.resource_traversal import ResourceTraversalTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "test_data", "dvmcp_server.py")


@pytest.fixture
def pentester():
    instance = MCPPentester([sys.executable, DEMO], {"timeout": 5})
    instance.start()
    instance.discover()
    yield instance
    instance.stop()


def test_traversal_now_sends_payloads_and_finds_leak(pentester):
    findings = ResourceTraversalTest(pentester).run()
    assert findings, "path traversal test sent no usable payloads"
    assert any(f["type"] == "TOOL_PATH_TRAVERSAL" for f in findings)
    traversal = next(f for f in findings
                     if f["type"] == "TOOL_PATH_TRAVERSAL")
    assert traversal["verified"] is True
    assert traversal["confidence"] >= 85


def test_protocol_fuzzing_does_not_report_false_crashes(pentester):
    findings = ProtocolFuzzingTest(pentester).run()
    crashes = [f for f in findings if f["type"] == "PROTOCOL_CRASH"]
    assert crashes == [], "fake crashes reported for a healthy server"


def test_full_quick_scan_reports_verified_rce(tmp_path):
    report_path = tmp_path / "report.json"
    instance = MCPPentester(
        [sys.executable, DEMO],
        {
            "timeout": 5,
            "quick": True,
            "rce_only": True,
            "output_json": str(report_path),
        },
    )
    instance.run()
    report = json.loads(report_path.read_text())
    findings = report["findings"]
    assert any(f["type"] == "RCE" for f in findings)
    rce = next(f for f in findings if f["type"] == "RCE")
    assert rce["severity"] == "CRITICAL"
    assert rce["verified"] is True
    assert "confidence" in rce and "status" in rce
    assert "by_confidence" in report["summary"]
