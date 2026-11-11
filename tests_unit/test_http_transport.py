"""Streamable HTTP transport tests."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.protocol import AuthenticationError, result_text
from core.session import McpSession
from core.transport import StreamableHttpTransport


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw or b"{}")
        except ValueError:
            self._json(400, {"error": {"code": -32700, "message": "bad"}})
            return
        if self.path.endswith("/auth") and not self.headers.get(
                "Authorization"):
            self._json(401, {"error": {"code": -32001,
                                       "message": "unauthorized"}})
            return
        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        request_id = message.get("id")
        method = message.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "http-fake"},
            }
            self._json(200, {"jsonrpc": "2.0", "id": request_id,
                             "result": result},
                       {"Mcp-Session-Id": "sess-123"})
            return
        if method == "sse":
            payload = json.dumps({
                "jsonrpc": "2.0", "id": request_id,
                "result": {"content": [{"type": "text", "text": "sse-ok"}]},
            })
            body = ("event: message\ndata: {}\n\n".format(payload)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json(200, {"jsonrpc": "2.0", "id": request_id,
                         "result": {"tools": []}})

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def http_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:{}/mcp".format(server.server_address[1])
    server.shutdown()
    server.server_close()


def test_http_initialize_captures_session_id(http_url):
    transport = StreamableHttpTransport(http_url, timeout=5)
    transport.start()
    session = McpSession(transport, timeout=5)
    try:
        result = session.initialize()
        assert result["protocolVersion"] == "2025-06-18"
        assert transport.session_id == "sess-123"
        assert session.list_tools() == []
    finally:
        session.close()


def test_http_sse_response_is_parsed(http_url):
    transport = StreamableHttpTransport(http_url, timeout=5)
    transport.start()
    session = McpSession(transport, timeout=5)
    try:
        session.initialize()
        response = session.request("sse", {})
        assert result_text(response) == "sse-ok"
    finally:
        session.close()


def test_http_auth_failure_raises(http_url):
    transport = StreamableHttpTransport(http_url + "/auth", timeout=5)
    transport.start()
    try:
        with pytest.raises(AuthenticationError) as exc:
            transport.request("tools/list", {})
        assert exc.value.status == 401
    finally:
        transport.close()


def test_http_notification_returns_202(http_url):
    transport = StreamableHttpTransport(http_url, timeout=5)
    transport.start()
    try:
        transport.notify("notifications/initialized", {})
        assert transport.stats["notifications_sent"] == 1
    finally:
        transport.close()
