"""State desync regression tests (issue #1: missing send_notification)"""
import os
import sys
import logging

from core import MCPPentester
from tests.state_desync import StateDesyncTest

SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_data", "dvmcp_server.py",
)


def test_send_notification_defined():
    """MCPPentester must expose send_notification (JSON-RPC, no id)"""
    assert hasattr(MCPPentester, "send_notification")


def test_state_desync_runs_without_attribute_error():
    """Double-initialize test drives send_notification; must not raise"""
    pentester = MCPPentester([sys.executable, SERVER], {'timeout': 5})
    try:
        findings = StateDesyncTest(pentester).run()
        assert isinstance(findings, list)
    except AttributeError as e:  # pragma: no cover - regression guard
        logging.error("state desync crashed: %s", e)
        raise AssertionError(f"state desync must not raise AttributeError: {e}")
    finally:
        pentester.stop()
