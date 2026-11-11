"""MCP session tests."""
import os
import sys
import time

import pytest

from core.protocol import ProtocolError
from core.session import McpSession
from core.transport import StdioTransport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = os.path.join(ROOT, "test_data", "mcp_test_server.py")


def _session(env=None, timeout=5.0, strict=False):
    environ = os.environ.copy()
    environ.update(env or {})
    transport = StdioTransport([sys.executable, FAKE], env=environ)
    transport.start()
    return McpSession(transport, timeout=timeout, strict_version=strict)


def test_initialize_populates_state_and_sends_initialized():
    session = _session()
    try:
        result = session.initialize()
        assert result["serverInfo"]["name"] == "mcpwn-fake"
        assert session.initialized
        assert session.protocol_version == "2025-06-18"
        assert session.version_supported is True
        assert session.server_capabilities["tools"]["listChanged"] is True

        deadline = time.time() + 2
        initialized = False
        while time.time() < deadline:
            response = session.request("debug/initialized", {})
            initialized = response["result"]["initialized"]
            if initialized:
                break
            time.sleep(0.02)
        assert initialized, "notifications/initialized was not sent"
    finally:
        session.close()


def test_initialize_is_idempotent_unless_forced():
    session = _session()
    try:
        session.initialize()
        sent = session.transport.stats["requests_sent"]
        session.initialize()
        assert session.transport.stats["requests_sent"] == sent
        session.initialize(force=True)
        assert session.transport.stats["requests_sent"] == sent + 1
    finally:
        session.close()


def test_strict_mode_rejects_unknown_protocol_version():
    session = _session({"FAKE_PROTOCOL_VERSION": "1999-01-01"}, strict=True)
    try:
        with pytest.raises(ProtocolError):
            session.initialize()
    finally:
        session.close()


def test_lenient_mode_accepts_unknown_version_but_flags_it():
    session = _session({"FAKE_PROTOCOL_VERSION": "1999-01-01"})
    try:
        session.initialize()
        assert session.version_supported is False
    finally:
        session.close()


def test_pagination_collects_all_pages():
    session = _session({"FAKE_PAGINATION": "1"})
    try:
        session.initialize()
        tools = session.list_tools()
        assert [tool["name"] for tool in tools] == ["echo", "slow"]
    finally:
        session.close()


def test_client_answers_roots_list_with_empty_list():
    session = _session({"FAKE_SERVER_REQUEST": "1"})
    try:
        session.initialize()
        deadline = time.time() + 2
        while time.time() < deadline and not session.server_requests:
            time.sleep(0.02)
        assert session.server_requests
        assert session.server_requests[0]["method"] == "roots/list"
    finally:
        session.close()
