"""MCP capability abuse tests.

These probes look for protocol-level weaknesses that do not require command
execution: unknown methods being accepted, malformed params crashing the
parser, server-initiated requests outside the negotiated capabilities, and
notifications for capabilities the server never declared.
"""
from __future__ import annotations

import json
import logging

from core.evidence import make_finding
from core.protocol import (
    METHOD_NOT_FOUND,
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    error_code,
    result_text,
)

logger = logging.getLogger("mcpwn.capability_abuse")

KNOWN_CLIENT_METHODS = {
    "ping", "roots/list", "sampling/createMessage",
    "elicitation/create", "elicitation/request",
}


class CapabilityAbuseTest:
    """Probe negotiated capability boundaries."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        findings = []
        for probe in (
            self._unknown_method,
            self._malformed_params,
            self._server_requests,
            self._undeclared_notifications,
        ):
            try:
                findings.extend(probe() or [])
            except SafetyLimitExceeded:
                break
            except (TransportError, ProtocolError, RequestTimeout) as exc:
                logger.debug("%s probe failed: %s", probe.__name__, exc)
        return findings

    def _unknown_method(self):
        response, _ = self.pentester.send(
            "mcpwn/does-not-exist", {}, skip_analysis=True)
        code = error_code(response)
        if code is None:
            return [make_finding(
                "CAPABILITY_ABUSE",
                note="server returned a result for an unknown method",
                evidence=[result_text(response, limit=200)],
                severity="MEDIUM",
                confidence=45,
            )]
        if code != METHOD_NOT_FOUND:
            logger.debug("unknown method returned code %s (expected %s)",
                         code, METHOD_NOT_FOUND)
        return []

    def _malformed_params(self):
        """Send params as an array; JSON-RPC requires an object."""
        if not self.pentester.is_alive():
            return []
        packet = json.dumps({
            "jsonrpc": "2.0", "id": 4242, "method": "tools/list",
            "params": [],
        })
        self.pentester.send_raw(packet)
        if not self.pentester.ping(timeout=2.0):
            return [make_finding(
                "CAPABILITY_ABUSE",
                note="server stopped responding after params with wrong type",
                evidence=['params=[] for tools/list'],
                severity="MEDIUM",
                confidence=55,
                verified=True,
            )]
        return []

    def _server_requests(self):
        session = self.pentester.session
        if session is None:
            return []
        findings = []
        for request in list(session.server_requests):
            method = request.get("method", "")
            if method in KNOWN_CLIENT_METHODS:
                if method == "sampling/createMessage":
                    findings.append(make_finding(
                        "CAPABILITY_ABUSE",
                        note="server requested sampling although the client "
                             "did not advertise sampling",
                        evidence=["server request: {}".format(method)],
                        severity="MEDIUM",
                        confidence=60,
                    ))
                continue
            findings.append(make_finding(
                "CAPABILITY_ABUSE",
                note="server sent an unknown client request",
                evidence=["server request: {}".format(method)],
                severity="LOW",
                confidence=35,
            ))
        return findings

    def _undeclared_notifications(self):
        session = self.pentester.session
        if session is None:
            return []
        capabilities = session.server_capabilities or {}
        findings = []
        for notification in list(session.notifications):
            method = notification.get("method", "")
            if method == "notifications/tools/list_changed":
                tools_cap = capabilities.get("tools") or {}
                if not isinstance(tools_cap, dict) or not tools_cap.get(
                        "listChanged"):
                    findings.append(make_finding(
                        "CAPABILITY_ABUSE",
                        note="server sent tools/list_changed without "
                             "declaring the capability",
                        evidence=[method],
                        severity="LOW",
                        confidence=35,
                    ))
            elif method == "notifications/resources/list_changed":
                res_cap = capabilities.get("resources") or {}
                if not isinstance(res_cap, dict) or not res_cap.get(
                        "listChanged"):
                    findings.append(make_finding(
                        "CAPABILITY_ABUSE",
                        note="server sent resources/list_changed without "
                             "declaring the capability",
                        evidence=[method],
                        severity="LOW",
                        confidence=35,
                    ))
        return findings
