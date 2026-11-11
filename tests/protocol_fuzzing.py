"""JSON-RPC protocol fuzzing.

The previous implementation wrote ``bytes`` into a text-mode pipe.  Every
probe raised ``TypeError`` inside the tester and was reported as a CRITICAL
server crash.  Probes are now sent as text through the transport, and a crash
finding requires the process to be dead (or unresponsive twice) afterwards.
"""
from __future__ import annotations

import json
import logging
import time

from core.evidence import make_finding, redact_secret
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
)

logger = logging.getLogger("mcpwn.protocol_fuzzing")

LEAK_MARKERS = ("Traceback (most recent call last)", "SyntaxError:",
                "at Object.", "File \"", "stack trace")


class ProtocolFuzzingTest:
    """Fuzz JSON-RPC structure for parser crashes and error leaks."""

    def __init__(self, pentester):
        self.pentester = pentester

    def _payloads(self):
        size = min(1024 * 1024, self.pentester.policy.limits.max_payload_bytes)
        large = json.dumps({
            "jsonrpc": "2.0", "id": 9999, "method": "ping",
            "params": {"data": "A" * size},
        })
        return [
            ('{"jsonrpc":"2.0","method":', "TRUNCATED_JSON"),
            ('{"jsonrpc":"2.0","method":12345}', "INVALID_METHOD_TYPE"),
            ('{"jsonrpc":"2.0","result":"unexpected"}', "UNEXPECTED_MESSAGE"),
            ("[]", "EMPTY_BATCH"),
            ('[{"jsonrpc":"2.0","method":"ping"},1]', "INVALID_BATCH_ITEM"),
            ('{"jsonrpc":"2.0","method":"test\\u0000"}',
             "NULL_BYTE_IN_METHOD"),
            ('{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}',
             "INVALID_PARAMS_TYPE"),
            (large, "LARGE_BUFFER"),
        ]

    def run(self):
        findings = []
        for packet, variant in self._payloads():
            try:
                crashed, evidence = self._probe(packet)
            except SafetyLimitExceeded:
                break
            except (TransportError, ProtocolError, RequestTimeout) as exc:
                # A transport failure before/after the probe is not evidence
                # of a server crash unless the process is actually gone.
                crashed = not self.pentester.is_alive()
                evidence = [str(exc)]
            if not crashed:
                for leak in self._error_leaks():
                    findings.append(make_finding(
                        "PROTOCOL_ERROR_LEAK",
                        note="parser detail exposed after {}".format(variant),
                        evidence=[leak],
                        severity="MEDIUM",
                        confidence=45,
                        variant=variant,
                    ))
                continue
            findings.append(make_finding(
                "PROTOCOL_CRASH",
                note="server crashed or stopped responding after {}".format(
                    variant),
                evidence=evidence,
                severity="HIGH",
                confidence=85,
                verified=True,
                variant=variant,
            ))
            self._recover()
        return findings

    def _probe(self, packet):
        if not self.pentester.is_alive():
            self._recover()
        self.pentester.send_raw(packet)
        time.sleep(0.15)
        if not self.pentester.is_alive():
            return True, ["process exited after malformed JSON-RPC"]

        # A zombie server is one that fails two consecutive liveness probes.
        for _ in range(2):
            if self.pentester.ping(timeout=2.0):
                time.sleep(0.05)
                continue
            if not self.pentester.is_alive():
                return True, ["process exited during liveness probe"]
            time.sleep(0.1)
        if not self.pentester.ping(timeout=2.0):
            return True, ["no response to two consecutive ping requests"]
        return False, []

    def _error_leaks(self):
        transport = self.pentester.transport
        if transport is None:
            return []
        candidates = []
        for message in list(transport.late_messages)[-10:]:
            candidates.append(json.dumps(message, ensure_ascii=False))
        for line in list(getattr(transport, "stderr_tail", []))[-10:]:
            candidates.append(line)
        for text in candidates:
            if any(marker in text for marker in LEAK_MARKERS):
                return ["parser details leaked: {}".format(
                    redact_secret(text[:300]))]
        return []

    def _recover(self):
        try:
            self.pentester.restart_server(initialize=True)
        except (TransportError, ProtocolError, RequestTimeout,
                OSError) as exc:
            logger.error("could not recover after protocol fuzz probe: %s", exc)

    def cleanup(self):
        """Compatibility hook; the transport owns all resources."""
        return None
