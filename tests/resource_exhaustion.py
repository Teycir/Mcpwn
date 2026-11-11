"""Resource exhaustion and DoS tests.

Every probe is gated behind ``--allow-destructive`` and bounded by the scan's
payload/request limits.  A crash finding requires the process to be dead or to
fail two consecutive liveness probes; a mere slow response is a low-confidence
observation.
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportClosed,
    TransportError,
    content_summary,
    error_code,
    result_text,
)

logger = logging.getLogger("mcpwn.exhaustion")

BATCH_SIZE = 200


class ResourceExhaustionTest:
    """Test resource exhaustion vulnerabilities."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, tool, quick_mode=False):
        try:
            self.pentester.policy.require_destructive(
                "resource exhaustion tests")
        except SafetyLimitExceeded as exc:
            logger.info("%s", exc)
            return []
        findings = []
        for probe in (self._test_recursive_nesting,
                      self._test_regex_dos):
            findings.extend(self._safe(probe, tool))
        if not quick_mode:
            for probe in (self._test_giant_payload,
                          self._test_array_bomb,
                          self._test_batch_bomb,
                          self._test_parallel_flood):
                findings.extend(self._safe(probe, tool))
        self._recover()
        return findings

    def _safe(self, probe, tool):
        try:
            return probe(tool) or []
        except SafetyLimitExceeded as exc:
            logger.info("%s stopped: %s", probe.__name__, exc)
            return []
        except (TransportError, ProtocolError, RequestTimeout,
                OSError, ValueError, TypeError, KeyError) as exc:
            logger.debug("%s failed: %s", probe.__name__, exc)
            return []

    @staticmethod
    def _string_arg(tool):
        for name, spec in (tool.get("inputSchema", {}) or {}).get(
                "properties", {}).items():
            if isinstance(spec, dict) and spec.get("type") == "string":
                return name
        return None

    @staticmethod
    def _typed_arg(tool, types):
        for name, spec in (tool.get("inputSchema", {}) or {}).get(
                "properties", {}).items():
            if isinstance(spec, dict) and spec.get("type") in types:
                return name, spec.get("type")
        return None, None

    def _test_giant_payload(self, tool):
        arg = self._string_arg(tool)
        if not arg:
            return []
        maximum = self.pentester.policy.limits.max_payload_bytes
        sizes = sorted({min(256 * 1024, maximum), maximum})
        findings = []
        for size in sizes:
            payload = "A" * size
            try:
                response, elapsed = self.pentester.send(
                    "tools/call",
                    {"name": tool.get("name"), "arguments": {arg: payload}},
                    skip_analysis=True, timeout=10,
                )
            except TransportClosed as exc:
                if not self.pentester.is_alive():
                    findings.append(make_finding(
                        "DOS_LARGE_PAYLOAD",
                        tool=tool.get("name"),
                        arg=arg,
                        severity="HIGH",
                        confidence=70,
                        verified=True,
                        evidence=[
                            "{} byte argument".format(size), str(exc)],
                        note="server exited after an oversized argument",
                    ))
                    break
                continue
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                continue
            text = result_text(response).lower()
            if error_code(response) is None and "limit" not in text:
                findings.append(make_finding(
                    "UNBOUNDED_PAYLOAD_SIZE",
                    tool=tool.get("name"),
                    arg=arg,
                    severity="MEDIUM",
                    confidence=55,
                    evidence=[
                        "accepted {} byte argument in {:.2f}s".format(
                            size, elapsed),
                        content_summary(response, 150),
                    ],
                    note="no size limit observed",
                ))
                break
        return findings

    def _test_recursive_nesting(self, tool):
        arg, arg_type = self._typed_arg(tool, ("object", "array"))
        if not arg:
            return []
        depth = 300
        nested: Any = {}
        current = nested
        for _ in range(depth):
            current["a"] = {}
            current = current["a"]
        if arg_type == "array":
            nested = [nested]
        try:
            response, _ = self.pentester.send(
                "tools/call",
                {"name": tool.get("name"), "arguments": {arg: nested}},
                skip_analysis=True,
            )
        except TransportClosed as exc:
            if not self.pentester.is_alive():
                return [make_finding(
                    "DOS_RECURSION_CRASH",
                    tool=tool.get("name"),
                    arg=arg,
                    severity="HIGH",
                    confidence=60,
                    verified=True,
                    evidence=["depth {}".format(depth), str(exc)],
                    note="server exited on deeply nested JSON",
                )]
            return []
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return []
        if "recursion" in result_text(response).lower():
            return [make_finding(
                "STACK_OVERFLOW_EXPOSED",
                tool=tool.get("name"),
                arg=arg,
                severity="MEDIUM",
                confidence=45,
                evidence=[content_summary(response, 200)],
                note="recursion error details exposed",
            )]
        return []

    def _test_array_bomb(self, tool):
        arg, _ = self._typed_arg(tool, ("array",))
        if not arg:
            return []
        wide_array = ["x"] * 20000
        try:
            start = time.perf_counter()
            response, _ = self.pentester.send(
                "tools/call",
                {"name": tool.get("name"), "arguments": {arg: wide_array}},
                skip_analysis=True,
            )
            elapsed = time.perf_counter() - start
        except TransportClosed as exc:
            if not self.pentester.is_alive():
                return [make_finding(
                    "ARRAY_BOMB_CRASH",
                    tool=tool.get("name"),
                    arg=arg,
                    severity="HIGH",
                    confidence=50,
                    verified=True,
                    evidence=[str(exc)],
                    note="server exited on a 20k element array",
                )]
            return []
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return []
        if elapsed > 5:
            return [make_finding(
                "ARRAY_BOMB_SUSCEPTIBLE",
                tool=tool.get("name"),
                arg=arg,
                severity="MEDIUM",
                confidence=40,
                evidence=[
                    "20k element array took {:.2f}s".format(elapsed),
                ],
                note="possible unbounded array processing",
            )]
        return []

    def _test_regex_dos(self, tool):
        arg = self._string_arg(tool)
        if not arg:
            return []
        payloads = [
            "a" * 30 + "!",
            "a" * 30 + "X",
            "0" * 30 + "x",
            "<" + "a" * 30,
            "a" * 25 + "@" * 3,
        ]
        for payload in payloads:
            try:
                start = time.perf_counter()
                self.pentester.send(
                    "tools/call",
                    {"name": tool.get("name"), "arguments": {arg: payload}},
                    skip_analysis=True,
                )
                elapsed = time.perf_counter() - start
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                continue
            if elapsed > 3:
                return [make_finding(
                    "REGEX_DOS",
                    tool=tool.get("name"),
                    arg=arg,
                    payload=payload[:30],
                    severity="MEDIUM",
                    confidence=35,
                    evidence=["probe took {:.2f}s".format(elapsed)],
                    note="single slow probe; confirm with a control input",
                )]
        return []

    def _test_batch_bomb(self, tool):
        batch = [
            {"jsonrpc": "2.0", "method": "tools/list", "id": index}
            for index in range(BATCH_SIZE)
        ]
        start = time.perf_counter()
        try:
            self.pentester.send_raw(json.dumps(batch))
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            if not self.pentester.is_alive():
                return [make_finding(
                    "BATCH_BOMB_CRASH",
                    severity="HIGH",
                    confidence=55,
                    verified=True,
                    evidence=["batch size {}".format(BATCH_SIZE)],
                    note="server exited on a large batch",
                )]
            return []
        elapsed = time.perf_counter() - start
        if not self.pentester.ping(timeout=2.0):
            if not self.pentester.is_alive():
                return [make_finding(
                    "BATCH_BOMB_CRASH",
                    severity="HIGH",
                    confidence=55,
                    verified=True,
                    evidence=["batch size {}".format(BATCH_SIZE)],
                    note="server exited on a large batch",
                )]
            return [make_finding(
                "BATCH_BOMB_CRASH",
                severity="HIGH",
                confidence=50,
                verified=False,
                evidence=[
                    "batch size {}".format(BATCH_SIZE),
                    "no response to liveness ping",
                ],
                note="server unresponsive after a large batch",
            )]
        if elapsed > 3:
            return [make_finding(
                "BATCH_PROCESSING_LAG",
                severity="MEDIUM",
                confidence=35,
                evidence=[
                    "{} requests took {:.2f}s".format(BATCH_SIZE, elapsed),
                ],
                note="batch processing lag",
            )]
        return []

    def _test_parallel_flood(self, tool):
        concurrency = self.pentester.policy.concurrency(8)
        total = concurrency * 2
        payload = {"name": tool.get("name"), "arguments": {}}

        def request():
            try:
                self.pentester.send(
                    "tools/call", payload, skip_analysis=True, timeout=5)
                return True
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                return False

        try:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                results = list(executor.map(
                    lambda _: request(), range(total)))
        except (RuntimeError, OSError) as exc:
            logger.debug("parallel flood executor failed: %s", exc)
            return []
        if not self.pentester.ping(timeout=2.0):
            if not self.pentester.is_alive():
                return [make_finding(
                    "DOS_CONCURRENT_FLOOD",
                    severity="HIGH",
                    confidence=75,
                    verified=True,
                    evidence=["{} concurrent requests".format(total)],
                    note="server exited under concurrent load",
                )]
            return [make_finding(
                "DOS_CONCURRENT_FLOOD",
                severity="HIGH",
                confidence=55,
                verified=False,
                evidence=[
                    "{} concurrent requests".format(total),
                    "no response to liveness ping",
                ],
                note="server unresponsive under concurrent load",
            )]
        success_rate = sum(results) / total if results else 0
        if success_rate < 0.5:
            return [make_finding(
                "CONNECTION_POOL_EXHAUSTION",
                tool=tool.get("name"),
                severity="MEDIUM",
                confidence=40,
                evidence=[
                    "{:.0f}% of requests succeeded".format(
                        success_rate * 100),
                ],
                note="degraded service under bounded concurrency",
            )]
        return []

    def _recover(self):
        if self.pentester.is_alive() and self.pentester.ping(timeout=2.0):
            return
        try:
            self.pentester.restart_server(initialize=True)
        except (TransportError, ProtocolError, RequestTimeout,
                OSError) as exc:
            logger.error("resource exhaustion recovery failed: %s", exc)
