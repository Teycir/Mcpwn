"""Safety policy tests."""
import pytest

from core.protocol import SafetyLimitExceeded
from core.safety import RequestBudget, SafetyPolicy


def test_destructive_tests_require_explicit_opt_in():
    policy = SafetyPolicy.from_config({})
    assert policy.destructive_allowed is False
    with pytest.raises(SafetyLimitExceeded):
        policy.require_destructive("flood")
    enabled = SafetyPolicy.from_config({"allow_destructive": True})
    enabled.require_destructive("flood")


def test_safe_mode_overrides_destructive_flag():
    policy = SafetyPolicy.from_config({
        "allow_destructive": True, "safe_mode": True})
    assert policy.destructive_allowed is False
    with pytest.raises(SafetyLimitExceeded):
        policy.require_destructive("flood")


def test_request_budget_is_enforced():
    budget = RequestBudget(2)
    budget.consume()
    budget.consume()
    with pytest.raises(SafetyLimitExceeded):
        budget.consume()
    assert budget.used == 2
    assert budget.remaining == 0


def test_limits_are_clamped():
    policy = SafetyPolicy.from_config({
        "max_payload_bytes": 2048,
        "max_concurrency": 2,
        "max_flood_subscriptions": 5,
    })
    assert policy.clamp_bytes("x" * 5000) == "x" * 2048
    assert policy.concurrency(99) == 2
    assert policy.subscription_count(99) == 5
