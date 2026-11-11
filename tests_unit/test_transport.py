"""Transport regression tests against the deterministic fake MCP server."""
import os
import sys
import threading
import time

import pytest

from core.protocol import RequestTimeout, result_text
from core.session import McpSession
from core.transport import StdioTransport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = os.path.join(ROOT, "test_data", "mcp_test_server.py")


@pytest.fixture
def session_factory():
    sessions = []

    def make(env=None, init=True, timeout=5.0, strict=False):
        environ = os.environ.copy()
        environ.update(env or {})
        transport = StdioTransport([sys.executable, FAKE], env=environ)
        transport.start()
        session = McpSession(
            transport, timeout=timeout, strict_version=strict)
        if init:
            session.initialize()
        sessions.append(session)
        return session

    yield make
    for session in sessions:
        session.close()


def test_out_of_order_responses_are_correlated(session_factory):
    """A fast response must not satisfy the pending slow request."""
    session = session_factory()
    results = {}

    def call(name, arguments):
        response = session.request(
            "tools/call", {"name": name, "arguments": arguments})
        results[name] = result_text(response)

    slow = threading.Thread(target=call, args=("slow", {"seconds": 0.4}))
    slow.start()
    time.sleep(0.05)
    fast = threading.Thread(target=call, args=("echo", {"text": "fast"}))
    fast.start()
    slow.join(timeout=5)
    fast.join(timeout=5)

    assert results["echo"] == "fast"
    assert results["slow"] == "slept"


def test_requests_actually_run_concurrently(session_factory):
    """Five 0.3s calls must overlap, not serialize behind a pipe lock."""
    session = session_factory()
    started = time.perf_counter()
    threads = [
        threading.Thread(
            target=lambda: session.request(
                "tools/call", {"name": "slow", "arguments": {"seconds": 0.3}}))
        for _ in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.2, "requests serialized ({:.2f}s)".format(elapsed)


def test_notifications_and_server_requests_are_recorded(session_factory):
    session = session_factory({
        "FAKE_NOTIFICATION": "1",
        "FAKE_SERVER_REQUEST": "1",
    })
    deadline = time.time() + 2
    while time.time() < deadline:
        if session.notifications and session.server_requests:
            break
        time.sleep(0.02)
    assert any(
        item["method"] == "notifications/tools/list_changed"
        for item in session.notifications)
    assert any(
        item["method"] == "roots/list" for item in session.server_requests)


def test_timeout_is_reported_and_session_recovers(session_factory):
    session = session_factory()
    with pytest.raises(RequestTimeout):
        session.request(
            "tools/call", {"name": "slow", "arguments": {"seconds": 2}},
            timeout=0.2)
    assert session.ping(timeout=2)
    assert session.transport.stats["timeouts"] == 1


def test_raw_text_probe_does_not_break_the_transport(session_factory):
    """Regression: fuzzing used to write bytes into a text pipe."""
    session = session_factory()
    session.transport.send_raw('{"jsonrpc":"2.0","method":')
    assert session.ping(timeout=2)
    assert session.transport.stats["raw_messages_sent"] == 1


def test_close_is_idempotent(session_factory):
    session = session_factory()
    session.close()
    session.close()
