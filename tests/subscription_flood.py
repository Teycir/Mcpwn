"""Subscription flooding tests.

Bounded, destructive-gated subscription creation.  The previous version
ignored its ``parallel`` argument and hard-coded 2000 subscriptions; this
version honors configuration and verifies unresponsiveness with two pings.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
)

logger = logging.getLogger("mcpwn.subscription_flood")


class SubscriptionFloodTest:
    """Test resource exhaustion via subscriptions (DoS)."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, count=None, parallel=False):
        try:
            self.pentester.policy.require_destructive(
                "subscription flood")
        except SafetyLimitExceeded as exc:
            logger.info("%s", exc)
            return []
        requested = count if count is not None else self.pentester.config.get(
            "flood_count", 200)
        total = self.pentester.policy.subscription_count(requested)
        baseline = self._measure_latency()
        findings = []

        def subscribe(index):
            try:
                self.pentester.send(
                    "resources/subscribe",
                    {"uri": "file:///tmp/mcpwn_flood_{}.txt".format(index)},
                    skip_analysis=True,
                )
                return True
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                return False

        try:
            if parallel:
                concurrency = self.pentester.policy.concurrency(8)
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    list(executor.map(subscribe, range(total)))
            else:
                for index in range(total):
                    if not subscribe(index):
                        break
                    if index and index % 50 == 0 and \
                            not self.pentester.is_alive():
                        break
        except (RuntimeError, OSError) as exc:
            logger.debug("subscription flood executor failed: %s", exc)

        alive = self._is_alive()
        if not alive:
            findings.append(make_finding(
                "DOS_CRASH",
                severity="HIGH",
                confidence=65,
                verified=True,
                evidence=["server stopped after subscriptions"],
                note="server did not survive the subscription flood",
            ))
        else:
            post = self._measure_latency()
            if post is None:
                findings.append(make_finding(
                    "DOS_UNRESPONSIVE",
                    severity="HIGH",
                    confidence=55,
                    verified=not self._is_alive(),
                    evidence=["no latency sample after the flood"],
                    note="server did not answer post-flood probes",
                ))
            elif baseline and post > max(0.1, baseline * 10):
                findings.append(make_finding(
                    "DOS_DEGRADATION",
                    severity="MEDIUM",
                    confidence=45,
                    evidence=[
                        "latency {:.3f}s -> {:.3f}s".format(
                            baseline, post),
                        "{} subscriptions".format(total),
                    ],
                    note="latency increased substantially",
                ))
        try:
            self.pentester.restart_server(initialize=True)
        except (TransportError, ProtocolError, RequestTimeout,
                OSError) as exc:
            logger.debug("post-flood restore failed: %s", exc)
        return findings

    def _measure_latency(self):
        samples = []
        for _ in range(2):
            start = time.perf_counter()
            try:
                self.pentester.send(
                    "tools/list", {}, skip_analysis=True, timeout=3)
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                return None
            samples.append(time.perf_counter() - start)
        return min(samples) if samples else None

    def _is_alive(self):
        if not self.pentester.is_alive():
            return False
        return self.pentester.ping(timeout=2.0)
