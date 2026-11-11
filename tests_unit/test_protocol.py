"""Unit tests for JSON-RPC and MCP primitives."""
import pytest

from core.protocol import (
    LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    JsonRpcError,
    ProtocolError,
    RequestTimeout,
    TransportError,
    error_code,
    iter_messages,
    jsonrpc_notification,
    jsonrpc_request,
    parse_message,
    result_of,
    result_text,
)


def test_latest_version_is_supported():
    assert LATEST_PROTOCOL_VERSION == SUPPORTED_PROTOCOL_VERSIONS[0]
    assert "2024-11-05" in SUPPORTED_PROTOCOL_VERSIONS


def test_request_and_notification_shapes():
    request = jsonrpc_request(1, "ping", {})
    assert request == {"jsonrpc": "2.0", "id": 1, "method": "ping",
                       "params": {}}
    notification = jsonrpc_notification("notifications/initialized")
    assert "id" not in notification
    assert notification["method"] == "notifications/initialized"


def test_result_of_success_and_error():
    assert result_of({"result": {"tools": []}}) == {"tools": []}
    with pytest.raises(JsonRpcError) as exc:
        result_of({"error": {"code": -32601, "message": "nope"}})
    assert exc.value.code == -32601


def test_error_code_helper():
    assert error_code({"result": {}}) is None
    assert error_code({"error": {"code": -32601}}) == -32601
    assert error_code({"error": "not-an-object"}) is None


def test_parse_message_rejects_invalid_json():
    with pytest.raises(ProtocolError):
        parse_message("{not json")


def test_iter_messages_expands_batches():
    messages = list(iter_messages([
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "method": "notifications/progress"},
        "ignored",
    ]))
    assert len(messages) == 2


def test_result_text_extracts_content_blocks():
    response = {"result": {"content": [
        {"type": "text", "text": "uid=1000(user)"},
        {"type": "image", "data": "..."},
    ]}}
    text = result_text(response)
    assert "uid=1000(user)" in text
    assert "[image content]" in text


def test_result_text_handles_plain_and_none():
    assert result_text("hello") == "hello"
    assert result_text(None) == ""


def test_request_timeout_is_both_timeout_and_transport_error():
    error = RequestTimeout("slow")
    assert isinstance(error, TimeoutError)
    assert isinstance(error, TransportError)
