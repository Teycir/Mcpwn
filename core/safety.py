"""Safety controls for active security testing.

Every test that can modify state, exhaust resources or delay a server must go
through :class:`SafetyPolicy`.  Limits are configurable from the CLI and are
enforced centrally rather than ad hoc inside each module.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict

from core.protocol import SafetyLimitExceeded

logger = logging.getLogger("mcpwn.safety")


@dataclass
class SafetyLimits:
    """Hard limits applied to a scan."""

    safe_mode: bool = False
    allow_destructive: bool = False
    max_requests: int = 20000
    max_concurrency: int = 8
    max_payload_bytes: int = 1024 * 1024
    max_flood_subscriptions: int = 250
    max_payloads_per_argument: int = 12
    max_tools: int = 40
    request_timeout: float = 10.0
    destructive_budget: int = 400


class RequestBudget:
    """Thread-safe request counter shared by all tests."""

    def __init__(self, limit: int):
        self.limit = max(1, int(limit))
        self._used = 0
        self._lock = threading.Lock()

    def consume(self, count: int = 1, label: str = "") -> None:
        with self._lock:
            if self._used + count > self.limit:
                raise SafetyLimitExceeded(
                    "request budget exhausted ({}/{}), refusing {!r}".format(
                        self._used, self.limit, label or "request"))
            self._used += count

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self._used)

    def reset(self) -> None:
        with self._lock:
            self._used = 0


class SafetyPolicy:
    """Interpret scan configuration and enforce limits."""

    def __init__(self, limits: SafetyLimits):
        self.limits = limits
        self.budget = RequestBudget(limits.max_requests)

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "SafetyPolicy":
        limits = SafetyLimits(
            safe_mode=bool(config.get("safe_mode", False)),
            allow_destructive=bool(config.get("allow_destructive", False)),
            max_requests=int(config.get("max_requests", 20000)),
            max_concurrency=max(1, int(config.get("max_concurrency", 8))),
            max_payload_bytes=max(1024, int(config.get(
                "max_payload_bytes", 1024 * 1024))),
            max_flood_subscriptions=max(1, int(config.get(
                "max_flood_subscriptions", 250))),
            max_payloads_per_argument=max(1, int(config.get(
                "max_payloads_per_argument", 16))),
            max_tools=max(1, int(config.get("max_tools", 40))),
            request_timeout=float(config.get("timeout", 10.0)),
            destructive_budget=max(1, int(config.get(
                "destructive_budget", 400))),
        )
        if limits.safe_mode:
            limits.allow_destructive = False
        return cls(limits)

    @property
    def safe_mode(self) -> bool:
        return self.limits.safe_mode

    @property
    def destructive_allowed(self) -> bool:
        return self.limits.allow_destructive and not self.limits.safe_mode

    def require_destructive(self, test_name: str) -> None:
        """Raise unless the operator explicitly enabled active tests."""
        if self.limits.safe_mode:
            raise SafetyLimitExceeded(
                "{} skipped: --safe-mode forbids destructive tests".format(
                    test_name))
        if not self.limits.allow_destructive:
            raise SafetyLimitExceeded(
                "{} skipped: requires --allow-destructive".format(test_name))

    def concurrency(self, requested: int) -> int:
        return max(1, min(int(requested), self.limits.max_concurrency))

    def payload_limit(self) -> int:
        return self.limits.max_payloads_per_argument

    def clamp_bytes(self, text: str) -> str:
        """Truncate a probe to the configured payload ceiling."""
        limit = self.limits.max_payload_bytes
        if len(text) <= limit:
            return text
        return text[:limit]

    def subscription_count(self, requested: int) -> int:
        return max(1, min(int(requested), self.limits.max_flood_subscriptions))

    def summarize(self) -> Dict[str, Any]:
        return {
            "safe_mode": self.limits.safe_mode,
            "destructive_allowed": self.destructive_allowed,
            "max_requests": self.limits.max_requests,
            "max_concurrency": self.limits.max_concurrency,
            "max_payload_bytes": self.limits.max_payload_bytes,
            "max_flood_subscriptions": self.limits.max_flood_subscriptions,
        }
