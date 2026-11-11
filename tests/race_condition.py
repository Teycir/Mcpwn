"""Race condition and TOCTOU tests.

The transport supports real concurrent requests, so the barrier below actually
overlaps calls instead of serializing them behind one pipe lock.  A collision is
only reported when two rounds both show multiple successful creations.
"""
from __future__ import annotations

import logging
import threading
import uuid
from typing import Any, List

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    result_text,
)

logger = logging.getLogger("mcpwn.race")


class RaceConditionTest:
    """Tests for uniqueness constraints and concurrency stability."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, tool):
        try:
            self.pentester.policy.require_destructive("race condition tests")
        except SafetyLimitExceeded as exc:
            logger.info("%s", exc)
            return []
        if not tool.get("inputSchema"):
            return []
        findings = []
        findings.extend(self._test_creation_collision(tool))
        findings.extend(self._test_concurrency_stability(tool))
        return findings

    def _generate_payload(self, tool, overrides=None):
        overrides = overrides or {}
        schema = tool.get("inputSchema", {}) or {}
        args = {}
        for prop, spec in schema.get("properties", {}).items():
            if prop in overrides:
                args[prop] = overrides[prop]
            elif not isinstance(spec, dict):
                continue
            elif spec.get("type") == "string":
                args[prop] = "test"
            elif spec.get("type") in ("integer", "number"):
                args[prop] = 10
            elif spec.get("type") == "boolean":
                args[prop] = True
        return {"name": tool.get("name"), "arguments": args}

    @staticmethod
    def _count_successes(results):
        successes = 0
        for result in results:
            if not isinstance(result, dict) or "error" in result:
                continue
            text = result_text(result).lower()
            if "exist" in text or "duplicate" in text or "conflict" in text:
                continue
            if text.strip():
                successes += 1
        return successes

    def _execute_race(self, func, count):
        count = self.pentester.policy.concurrency(count)
        barrier = threading.Barrier(count)
        results: List[Any] = [None] * count
        threads = []

        def worker(index):
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                results[index] = {"error": "barrier timeout"}
                return
            try:
                results[index] = func()
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded, OSError, ValueError) as exc:
                results[index] = {"error": str(exc)}

        for index in range(count):
            thread = threading.Thread(target=worker, args=(index,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        return results

    def _test_creation_collision(self, tool):
        tool_name = tool.get("name", "").lower()
        if not any(key in tool_name for key in (
                "create", "insert", "register", "make", "add")):
            return []
        schema = tool.get("inputSchema", {}) or {}
        target_arg = next(
            (arg for arg in schema.get("properties", {})
             if any(key in arg.lower() for key in (
                 "path", "name", "id", "key", "email"))), None)
        if not target_arg:
            return []
        count = min(5, self.pentester.policy.limits.max_concurrency)
        rounds = []
        for _ in range(2):
            value = "race_{}".format(uuid.uuid4().hex[:8])
            payload = self._generate_payload(tool, {target_arg: value})

            def send_request(payload=payload):
                response, _ = self.pentester.send(
                    "tools/call", payload, skip_analysis=True)
                return response

            results = self._execute_race(send_request, count)
            rounds.append(self._count_successes(results))
        if max(rounds) <= 1:
            return []
        verified = min(rounds) > 1
        return [make_finding(
            "RACE_CREATION_COLLISION",
            tool=tool.get("name"),
            arg=target_arg,
            severity="MEDIUM",
            confidence=70 if verified else 45,
            verified=verified,
            evidence=[
                "successful creations per round: {}".format(rounds),
                "{} concurrent requests per round".format(count),
            ],
            note="duplicate creates succeeded" if verified
                 else "one round collided; re-run before concluding",
        )]

    def _test_concurrency_stability(self, tool):
        payload = self._generate_payload(tool)
        concurrency = min(10, self.pentester.policy.limits.max_concurrency * 2)

        def send_request():
            self.pentester.send(
                "tools/call", payload, skip_analysis=True)
            return {"ok": True}

        results = self._execute_race(send_request, concurrency)
        lock_errors = [result for result in results
                       if isinstance(result, dict) and any(
                           marker in str(result).lower()
                           for marker in ("lock", "busy"))]
        internal = [result for result in results
                    if isinstance(result, dict) and "internal error" in str(
                        result).lower()]
        findings = []
        if lock_errors:
            findings.append(make_finding(
                "UNHANDLED_DB_LOCK",
                tool=tool.get("name"),
                severity="LOW",
                confidence=40,
                evidence=[str(lock_errors[0])[:200]],
                note="lock contention surfaced to the client",
            ))
        if internal:
            findings.append(make_finding(
                "CONCURRENCY_CRASH",
                tool=tool.get("name"),
                severity="MEDIUM",
                confidence=50,
                evidence=[str(internal[0])[:200]],
                note="internal error surfaced under concurrent load",
            ))
        return findings
