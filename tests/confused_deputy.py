"""Confused deputy / object-level authorization tests.

The test compares a deliberately non-existent control identity with privileged
identities.  A finding requires the privileged value to return materially more
data than the control, which is stronger evidence than "the request did not
contain the word forbidden".
"""
from __future__ import annotations

import logging
import uuid

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    error_code,
    result_text,
)

logger = logging.getLogger("mcpwn.confused_deputy")

IDENTITY_HINTS = ("user_id", "userid", "user", "owner", "account", "tenant",
                  "customer", "subject", "sub")
ROLE_HINTS = ("role", "permission", "scope", "admin", "privilege")


class ConfusedDeputyTest:
    """Probe tools for client-controlled privileged identifiers."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, tool):
        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}
        identity_args = [name for name in properties
                         if any(hint in name.lower()
                                for hint in IDENTITY_HINTS)][:2]
        role_args = [name for name in properties
                     if any(hint in name.lower() for hint in ROLE_HINTS)][:2]
        findings = []
        for arg in identity_args:
            findings.extend(self._test_identity(tool, arg, schema))
        for arg in role_args:
            findings.extend(self._test_role(tool, arg, schema))
        return findings

    def _base_args(self, schema):
        args = {}
        properties = schema.get("properties", {}) or {}
        for required in schema.get("required", []) or []:
            spec = properties.get(required, {}) or {}
            args[required] = {
                "string": "test", "integer": 0, "number": 0,
                "boolean": False, "array": [], "object": {},
            }.get(spec.get("type", "string"), "test")
        return args

    def _call(self, tool, args):
        try:
            response, _ = self.pentester.send(
                "tools/call",
                {"name": tool.get("name"), "arguments": args},
                skip_analysis=True,
            )
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None, ""
        if error_code(response) is not None:
            return response, ""
        return response, result_text(response)

    @staticmethod
    def _substantive(text, control_text):
        """Is the response materially larger than the failed control?"""
        return len(text.strip()) > max(10, len(control_text.strip()) + 10)

    def _test_identity(self, tool, arg, schema):
        base = self._base_args(schema)
        control_value = "mcpwn_control_{}".format(uuid.uuid4().hex[:8])
        control_args = dict(base)
        control_args[arg] = control_value
        control_response, control_text = self._call(tool, control_args)
        if control_response is None:
            return []
        control_failed = (
            error_code(control_response) is not None or not control_text.strip())

        findings = []
        for value in ("admin", "root", "0", "1"):
            args = dict(base)
            args[arg] = value
            response, text = self._call(tool, args)
            if response is None or error_code(response) is not None:
                continue
            if not text.strip():
                continue
            materially_more = self._substantive(text, control_text)
            if not (control_failed and materially_more):
                continue
            _, repeat_text = self._call(tool, args)
            verified = self._substantive(repeat_text, control_text)
            findings.append(make_finding(
                "IDOR",
                tool=tool.get("name"),
                arg=arg,
                payload=value,
                severity="HIGH",
                confidence=65 if verified else 45,
                verified=verified,
                evidence=[
                    "control id returned {} bytes".format(len(control_text)),
                    "{} returned {} bytes".format(value, len(text)),
                    content_summary(response, 150),
                ],
                note="privileged identifier returned data while a "
                     "non-existent control did not; confirm authorization model",
            ))
            break
        return findings

    def _test_role(self, tool, arg, schema):
        base = self._base_args(schema)
        for value in ("admin", "root", "superuser"):
            args = dict(base)
            args[arg] = value
            response, text = self._call(tool, args)
            if response is None or error_code(response) is not None:
                continue
            lowered = text.lower()
            reflected = value in lowered and any(
                key in lowered for key in (
                    "role", "permission", "created", "updated"))
            if not reflected:
                continue
            return [make_finding(
                "MASS_ASSIGNMENT",
                tool=tool.get("name"),
                arg=arg,
                payload=value,
                severity="HIGH",
                confidence=45,
                evidence=[
                    "response reflects {}={}".format(arg, value),
                    content_summary(response, 150),
                ],
                note="client-controlled role accepted; verify whether it "
                     "changes authorization",
            )]
        return []
