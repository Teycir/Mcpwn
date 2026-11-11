"""Capability fuzzing during MCP initialization.

A server is allowed to ignore unknown or oddly typed *client* capabilities.
Treating every successful initialize as a validation bypass (the previous
behaviour) produced guaranteed false positives.  This module now reports only
observable failures: a crash, or a timeout severe enough to indicate
unbounded initialization work.
"""
from __future__ import annotations

import logging
import time

from core.evidence import make_finding
from core.protocol import (
    JsonRpcError,
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportClosed,
    TransportError,
    result_of,
)

logger = logging.getLogger("mcpwn.capability_fuzzing")

OVERSIZED_LIST_THRESHOLD = 100


class CapabilityFuzzingTest:
    """Test malformed capabilities during protocol negotiation."""

    FUZZ_CAPABILITIES = [
        {"tools": "invalid_string"},
        {"resources": 123},
        {"prompts": []},
        {"__proto__": {}},
        {"constructor": {}},
        {"../../../etc": {}},
        {"tools": [{"listChanged": True}] * OVERSIZED_LIST_THRESHOLD},
        {"tools": {"subscribe": {"__proto__": {"polluted": True}}}},
        {"tools": None},
        {"logging": {"level": "\x00"}},
    ]

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        if not self.pentester.policy.destructive_allowed:
            logger.info("Capability fuzzing requires --allow-destructive; "
                        "skipping")
            return []
        findings = []
        for capability in self.FUZZ_CAPABILITIES:
            try:
                finding = self._probe(capability)
            except SafetyLimitExceeded:
                break
            finally:
                self._restore()
            if finding:
                findings.append(finding)
        return findings

    def _probe(self, capability):
        if not self.pentester.policy.destructive_allowed:
            # Restarting a server per capability is disruptive; run only when
            # the operator opted into active tests.  Protocol fuzzing still
            # covers malformed messages without restarts.
            return None
        try:
            self.pentester.restart_server(initialize=False)
            session = self.pentester.session
            if session is None:
                return None
            started = time.perf_counter()
            response = session.request(
                "initialize",
                {
                    "protocolVersion": session.preferred_version,
                    "capabilities": capability,
                    "clientInfo": session.client_info,
                },
                timeout=min(5.0, session.timeout),
            )
            elapsed = time.perf_counter() - started
            result = result_of(response)
            if not isinstance(result, dict):
                return None
            # Initialization succeeded: leniency toward unknown client
            # capabilities is spec-compliant, so there is nothing to report.
            # Verify the server still answers requests.
            if not session.ping(timeout=2.0):
                return make_finding(
                    "CAPABILITY_DOS",
                    note="server did not answer ping after malformed "
                         "capabilities",
                    evidence=["capability={!r}".format(capability)],
                    severity="MEDIUM",
                    confidence=50,
                    verified=True,
                )
            logger.debug("accepted malformed capabilities in %.2fs: %r",
                         elapsed, capability)
            return None
        except RequestTimeout as exc:
            return make_finding(
                "CAPABILITY_DOS",
                note="initialize timed out with malformed capabilities",
                evidence=["capability={!r}".format(capability), str(exc)],
                severity="MEDIUM",
                confidence=55,
                verified=False,
            )
        except TransportClosed as exc:
            if not self.pentester.is_alive():
                return make_finding(
                    "CAPABILITY_CRASH",
                    note="server exited while parsing malformed capabilities",
                    evidence=["capability={!r}".format(capability), str(exc)],
                    severity="HIGH",
                    confidence=80,
                    verified=True,
                )
            return None
        except (JsonRpcError, ProtocolError, TransportError, OSError) as exc:
            logger.debug("capability probe rejected (%r): %s", capability, exc)
            return None

    def _restore(self):
        try:
            self.pentester.restart_server(initialize=True)
        except (TransportError, ProtocolError, RequestTimeout,
                OSError) as exc:
            logger.debug("capability fuzzing restore failed: %s", exc)
