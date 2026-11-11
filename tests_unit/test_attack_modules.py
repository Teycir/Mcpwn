"""Focused module tests using stubbed transports (no live tool execution)."""
from types import SimpleNamespace
from urllib.request import urlopen

import pytest

from core.baseline import LatencyBaseline
from core.detector import SemanticDetector
from core.protocol import JsonRpcError, result_text
from core.safety import SafetyPolicy
from tests.auth_bypass import AuthBypassTest
from tests.capability_abuse import CapabilityAbuseTest
from tests.confused_deputy import ConfusedDeputyTest
from tests.deserialization import DeserializationTest
from tests.prompt_injection import PromptInjectionTest
from tests.race_condition import RaceConditionTest
from tests.resource_exhaustion import ResourceExhaustionTest
from tests.schema_pollution import SchemaPollutionTest
from tests.ssrf_injection import SSRFTest
from tests.subscription_flood import SubscriptionFloodTest


def text_response(text):
    return {"result": {"content": [{"type": "text", "text": text}]}}


class StubPentester:
    def __init__(self, sender, *, config=None, policy=None, target_url=None,
                 session=None, tools=None):
        self.sender = sender
        self.tools = tools or []
        self.resources = []
        self.prompts = []
        self.config = config or {}
        self.policy = policy or SafetyPolicy.from_config({
            "allow_destructive": True,
            "max_payloads_per_argument": 3,
            "max_concurrency": 4,
            "max_payload_bytes": 2048,
        })
        self.target_url = target_url
        self.session = session
        self.transport = None
        self.detector = SemanticDetector()

    def send(self, method, params=None, **kwargs):
        return self.sender(method, params, **kwargs)

    def send_raw(self, line):
        return None

    def scan_response(self, response):
        return self.detector.scan(result_text(response))

    def measure_baseline(self, *args, **kwargs):
        return 0.01

    def ping(self, *args, **kwargs):
        return True

    def is_alive(self):
        return True

    def restart_server(self, initialize=True):
        return None

    def send_notification(self, *args, **kwargs):
        return None

    def clear_subscription_state(self):
        return None


def echo_sender(method, params, **kwargs):
    arguments = (params or {}).get("arguments") or {}
    text = next(iter(arguments.values()), "")
    return text_response(str(text)), 0.01


def test_prompt_injection_reports_reflection_without_verification():
    tool = {"name": "echo", "inputSchema": {
        "properties": {"text": {"type": "string"}}}}
    findings = PromptInjectionTest(StubPentester(echo_sender)).run(tool)
    assert any(f["type"] == "MARKDOWN_IMAGE_INJECTION" for f in findings)
    assert all(f["verified"] is False for f in findings)


def test_schema_pollution_detects_execution_indicator():
    def sender(method, params, **kwargs):
        return text_response("uid=1000(user) gid=1000(user)"), 0.01

    tool = {"name": "configure", "inputSchema": {
        "properties": {"config": {"type": "object"}}}}
    findings = SchemaPollutionTest(StubPentester(sender)).run(tool)
    assert any(f["type"] == "SCHEMA_POLLUTION" for f in findings)


def test_deserialization_is_gated():
    tool = {"name": "load", "inputSchema": {
        "properties": {"data": {"type": "string"}}}}
    policy = SafetyPolicy.from_config({})
    assert DeserializationTest(
        StubPentester(echo_sender, policy=policy)).run(tool) == []


def test_deserialization_timing_oracle_is_not_verified():
    def sender(method, params, **kwargs):
        return text_response("ok"), 3.5

    tool = {"name": "load", "inputSchema": {
        "properties": {"data": {"type": "string",
                                "description": "serialized blob"}}}}
    findings = DeserializationTest(StubPentester(sender)).run(tool)
    assert any(f["type"] == "PICKLE_DESERIALIZATION_BLIND" for f in findings)
    assert all(f["verified"] is False for f in findings)


def test_race_condition_detects_reproducible_collision():
    def sender(method, params, **kwargs):
        return text_response("created"), 0.01

    tool = {"name": "create_user", "inputSchema": {
        "properties": {"name": {"type": "string"}}}}
    findings = RaceConditionTest(StubPentester(sender)).run(tool)
    assert any(f["type"] == "RACE_CREATION_COLLISION" for f in findings)
    collision = next(f for f in findings
                     if f["type"] == "RACE_CREATION_COLLISION")
    assert collision["verified"] is True


def test_subscription_flood_respects_limits_and_returns_clean():
    def sender(method, params, **kwargs):
        return {"result": {"tools": []}}, 0.01

    stub = StubPentester(sender, config={"flood_count": 3})
    assert SubscriptionFloodTest(stub).run(parallel=True) == []


def test_resource_exhaustion_is_gated():
    tool = {"name": "echo", "inputSchema": {
        "properties": {"text": {"type": "string"}}}}
    policy = SafetyPolicy.from_config({})
    assert ResourceExhaustionTest(
        StubPentester(echo_sender, policy=policy)).run(tool) == []


def test_resource_exhaustion_quick_paths_run():
    def sender(method, params, **kwargs):
        return text_response("ok"), 0.01

    tool = {"name": "echo", "inputSchema": {
        "properties": {"text": {"type": "string"},
                       "config": {"type": "object"}}}}
    assert ResourceExhaustionTest(
        StubPentester(sender)).run(tool, quick_mode=True) == []


def test_authorization_skips_stdio():
    stub = StubPentester(echo_sender, target_url=None)
    assert AuthBypassTest(stub).run() == []


def test_authorization_detects_missing_auth_over_http():
    def sender(method, params, **kwargs):
        return {"result": {"tools": [{"name": "t"}]}}, 0.01

    stub = StubPentester(
        sender, target_url="http://127.0.0.1:1/mcp",
        config={"headers": {"Authorization": "Bearer token"}})
    findings = AuthBypassTest(stub).run()
    assert any(f["type"] == "MISSING_AUTH" for f in findings)
    assert any(f["type"] == "BROKEN_AUTH_TOKEN" for f in findings)


def test_confused_deputy_detects_control_difference():
    def sender(method, params, **kwargs):
        value = (params or {}).get("arguments", {}).get("user_id", "")
        if value.startswith("mcpwn_control"):
            return {"error": {"code": -32000, "message": "not found"}}, 0.01
        return text_response("user data for {}".format(value)), 0.01

    tool = {"name": "get_user", "inputSchema": {
        "properties": {"user_id": {"type": "string"}}}}
    findings = ConfusedDeputyTest(StubPentester(sender)).run(tool)
    assert any(f["type"] == "IDOR" for f in findings)


def test_ssrf_url_argument_detection():
    assert SSRFTest._is_loopback("http://127.0.0.1/mcp")
    assert not SSRFTest._is_loopback("https://example.com/mcp")
    stub = StubPentester(echo_sender)
    test = SSRFTest(stub)
    args = test._find_url_args({"properties": {
        "endpoint": {"type": "string"},
        "callback": {"type": "string"},
        "query": {"type": "string"},
    }})
    assert args == ["endpoint", "callback"]


def test_ssrf_listener_captures_callback():
    test = SSRFTest(StubPentester(echo_sender))
    if not test._start_listener():
        pytest.skip("could not bind loopback listener")
    try:
        urlopen("http://127.0.0.1:{}/callback/token123".format(
            test.server_port), timeout=2).read()
        assert "token123" in test.captured_callbacks
    finally:
        test.cleanup()


def test_capability_abuse_detects_undeclared_notification():
    def sender(method, params, **kwargs):
        return {"error": {"code": -32601, "message": "unknown"}}, 0.01

    session = SimpleNamespace(
        server_requests=[],
        notifications=[{"method": "notifications/tools/list_changed"}],
        server_capabilities={},
    )
    findings = CapabilityAbuseTest(
        StubPentester(sender, session=session)).run()
    assert any(f["type"] == "CAPABILITY_ABUSE" for f in findings)


def test_session_refuses_sampling_request():
    class TransportStub:
        def set_message_handler(self, handler):
            self.handler = handler

    from core.session import McpSession
    session = McpSession(TransportStub())
    with pytest.raises(JsonRpcError):
        session._answer_server_request("sampling/createMessage", {})


def test_latency_baseline_requires_a_real_deviation():
    baseline = LatencyBaseline()
    baseline.extend([0.10, 0.11, 0.09, 0.10])
    slow, _, _ = baseline.anomaly(0.12)
    assert slow is False
    fast, ratio, _ = baseline.anomaly(3.0)
    assert fast is True
    assert ratio > 10
