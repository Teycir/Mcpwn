"""JSON-RPC 2.0 and Model Context Protocol primitives.

This module contains only protocol-level definitions shared by the transports,
the session layer and the attack modules.  It deliberately has no I/O so that
it can be unit tested without spawning a server.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

JSONRPC_VERSION = "2.0"

#: Protocol revisions this client knows how to speak.  The first entry is the
#: version offered during ``initialize``.
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
)
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
DEFAULT_PROTOCOL_VERSION = LATEST_PROTOCOL_VERSION
DEFAULT_CLIENT_INFO = {"name": "mcpwn", "version": "2.0.0"}

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP-specific error codes.
RESOURCE_NOT_FOUND = -32002
CONNECTION_CLOSED = -32000

#: Errors a server should return when a request arrives before initialization.
NOT_INITIALIZED_CODES = (-32002, -32600)


class McpwnError(Exception):
    """Base class for all errors raised by Mcpwn."""


class ProtocolError(McpwnError):
    """The peer sent a message that violates JSON-RPC or MCP."""


class TransportError(McpwnError):
    """The transport could not deliver or receive a message."""


class TransportClosed(TransportError):
    """The peer closed the connection or exited."""


class AuthenticationError(TransportError):
    """The HTTP peer rejected the request with 401/403."""

    def __init__(self, status: int, body: str = ""):
        self.status = status
        self.body = body
        super().__init__("HTTP {}: {}".format(status, body[:200]))


class RequestTimeout(TimeoutError, TransportError):
    """A response did not arrive within the configured timeout."""


class JsonRpcError(ProtocolError):
    """The peer answered with a JSON-RPC error object."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__("JSON-RPC error {}: {}".format(code, message))


class SafetyLimitExceeded(McpwnError):
    """A scan limit or destructive-test gate refused an operation."""


def jsonrpc_request(request_id: Any, method: str,
                    params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a JSON-RPC request object."""
    message = {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": method,
    }
    if params is not None:
        message["params"] = params
    return message


def jsonrpc_notification(method: str,
                         params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a JSON-RPC notification (a request without an id)."""
    message = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        message["params"] = params
    return message


def jsonrpc_result(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def jsonrpc_error(request_id: Any, code: int, message: str,
                  data: Any = None) -> Dict[str, Any]:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


def parse_message(line: str) -> Any:
    """Parse one JSON-RPC message from a text line."""
    try:
        return json.loads(line)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid JSON: {}".format(exc)) from exc


def iter_messages(message: Any) -> Iterable[Dict[str, Any]]:
    """Yield individual messages, expanding a JSON-RPC batch."""
    if isinstance(message, list):
        for item in message:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(message, dict):
        yield message


def is_error_response(message: Any) -> bool:
    return isinstance(message, dict) and "error" in message


def result_of(message: Any) -> Any:
    """Return ``result`` from a JSON-RPC response or raise :class:`JsonRpcError`."""
    if not isinstance(message, dict):
        raise ProtocolError("response is not a JSON object: {!r}".format(message))
    if "error" in message:
        error = message.get("error") or {}
        if not isinstance(error, dict):
            raise ProtocolError("malformed error object: {!r}".format(error))
        raise JsonRpcError(
            int(error.get("code", INTERNAL_ERROR)),
            str(error.get("message", "unknown error")),
            error.get("data"),
        )
    return message.get("result", {})


def error_code(message: Any) -> Optional[int]:
    """Return the JSON-RPC error code, or ``None`` for a successful response."""
    if not isinstance(message, dict) or "error" not in message:
        return None
    error = message.get("error") or {}
    if not isinstance(error, dict):
        return None
    try:
        return int(error.get("code"))
    except (TypeError, ValueError):
        return None


def result_text(response: Any, limit: Optional[int] = None) -> str:
    """Extract human-readable text from an MCP result.

    MCP tool results keep their payloads in ``result.content`` (a list of
    typed content blocks) and/or ``result.structuredContent``.  Detection code
    must inspect those fields; dumping the whole envelope also works but makes
    indicator matching noisy.  Non-MCP payloads fall back to a JSON dump.
    """
    if response is None:
        return ""
    payload = response
    if isinstance(response, dict) and "result" in response:
        payload = response["result"]
    parts: List[str] = []
    if isinstance(payload, dict):
        content = payload.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                    elif block.get("type") in ("image", "audio"):
                        parts.append("[{} content]".format(block.get("type")))
                elif isinstance(block, str):
                    parts.append(block)
        structured = payload.get("structuredContent")
        if structured is not None:
            parts.append(json.dumps(structured, ensure_ascii=False))
        for key in ("uri", "name", "description", "message"):
            value = payload.get(key)
            if isinstance(value, str):
                parts.append(value)
        if not parts:
            parts.append(json.dumps(payload, ensure_ascii=False))
    elif isinstance(payload, str):
        parts.append(payload)
    else:
        parts.append(json.dumps(payload, ensure_ascii=False))
    text = "\n".join(part for part in parts if part)
    if limit is not None:
        return text[:limit]
    return text


def content_summary(response: Any, limit: int = 400) -> str:
    """Return a short, single-line summary suitable for evidence."""
    text = result_text(response, limit=limit * 2)
    collapsed = " ".join(text.split())
    return collapsed[:limit]
