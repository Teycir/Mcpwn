"""MCP client session.

The session owns protocol state (version, capabilities, server info) and turns
raw JSON-RPC responses into MCP-level results.  It also answers server-initiated
requests so a server waiting on ``roots/list`` or ``ping`` never deadlocks the
scanner.
"""
from __future__ import annotations

import collections
import logging
from typing import Any, Dict, List, Optional

from core.protocol import (
    LATEST_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    SUPPORTED_PROTOCOL_VERSIONS,
    JsonRpcError,
    ProtocolError,
    RequestTimeout,
    TransportError,
    result_of,
)
from core.transport import Transport

logger = logging.getLogger("mcpwn.session")

MAX_PAGES = 50


class McpSession:
    """A negotiated MCP session over a transport."""

    def __init__(self, transport: Transport, *, client_info: Optional[Dict[str, str]] = None,
                 timeout: float = 10.0,
                 protocol_version: str = LATEST_PROTOCOL_VERSION,
                 capabilities: Optional[Dict[str, Any]] = None,
                 strict_version: bool = False):
        self.transport = transport
        self.client_info = dict(client_info or {
            "name": "mcpwn", "version": "2.1.0"})
        self.timeout = timeout
        self.preferred_version = protocol_version
        self.client_capabilities = dict(capabilities or {})
        self.strict_version = strict_version

        self.initialized = False
        self.initialize_result: Dict[str, Any] = {}
        self.protocol_version: Optional[str] = None
        self.version_supported: Optional[bool] = None
        self.server_info: Dict[str, Any] = {}
        self.server_capabilities: Dict[str, Any] = {}
        self.instructions: Optional[str] = None
        self.notifications: collections.deque = collections.deque(maxlen=200)
        self.server_requests: collections.deque = collections.deque(maxlen=200)
        transport.set_message_handler(self._handle_message)

    # ------------------------------------------------------------------
    # Protocol lifecycle
    # ------------------------------------------------------------------
    def initialize(self, force: bool = False) -> Dict[str, Any]:
        """Perform the MCP initialization handshake.

        ``force`` deliberately re-sends ``initialize`` on an initialized
        session; it exists for protocol state tests.
        """
        if self.initialized and not force:
            return self.initialize_result

        params = {
            "protocolVersion": self.preferred_version,
            "capabilities": self.client_capabilities,
            "clientInfo": self.client_info,
        }
        response = self.transport.request(
            "initialize", params, timeout=self.timeout)
        result = result_of(response)
        if not isinstance(result, dict):
            raise ProtocolError("initialize result must be an object")
        version = result.get("protocolVersion")
        if not isinstance(version, str) or not version:
            raise ProtocolError(
                "server did not return a protocolVersion in initialize")
        self.protocol_version = version
        self.version_supported = version in SUPPORTED_PROTOCOL_VERSIONS
        if not self.version_supported:
            message = (
                "server negotiated unsupported protocol version {!r}; "
                "known versions: {}".format(
                    version, ", ".join(SUPPORTED_PROTOCOL_VERSIONS)))
            if self.strict_version:
                raise ProtocolError(message)
            logger.warning(message)

        capabilities = result.get("capabilities", {})
        if not isinstance(capabilities, dict):
            raise ProtocolError("initialize capabilities must be an object")
        server_info = result.get("serverInfo", {})
        if not isinstance(server_info, dict):
            server_info = {}
        self.server_capabilities = capabilities
        self.server_info = server_info
        instructions = result.get("instructions")
        self.instructions = instructions if isinstance(instructions, str) else None
        self.initialize_result = result
        self.initialized = True

        # The spec requires this notification once initialization completes.
        self.transport.notify("notifications/initialized", {})
        return result

    def _handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        if method is None:
            return None
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        if "id" in message:
            self.server_requests.append(
                {"method": method, "params": params, "id": message.get("id")})
            return self._answer_server_request(method, params)
        self.notifications.append({"method": method, "params": params})
        return None

    def _answer_server_request(self, method: str,
                               params: Dict[str, Any]) -> Dict[str, Any]:
        """Answer requests defined by the client capabilities we advertise."""
        if method == "ping":
            return {}
        if method == "roots/list":
            # We advertise no roots by default; returning an empty list is
            # valid and avoids stalling servers that ask.
            return {"roots": []}
        if method == "sampling/createMessage":
            raise JsonRpcError(
                METHOD_NOT_FOUND,
                "mcpwn does not provide sampling; no client sampling capability",
            )
        if method in ("elicitation/create", "elicitation/request"):
            return {"action": "decline"}
        raise JsonRpcError(
            METHOD_NOT_FOUND, "unsupported client method {}".format(method))

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------
    def request(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None,
                extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return self.transport.request(
            method, params, timeout=timeout, extra_headers=extra_headers)

    def result(self, method: str, params: Optional[Dict[str, Any]] = None,
               timeout: Optional[float] = None,
               extra_headers: Optional[Dict[str, str]] = None) -> Any:
        """Issue a request and return its ``result`` (raising on errors)."""
        return result_of(self.request(
            method, params, timeout=timeout, extra_headers=extra_headers))

    def notify(self, method: str,
               params: Optional[Dict[str, Any]] = None) -> None:
        self.transport.notify(method, params or {})

    def ping(self, timeout: Optional[float] = None) -> bool:
        """Liveness probe.

        Any JSON-RPC response proves the peer is processing input, including
        a method-not-found error from a server that does not implement ping.
        """
        try:
            response = self.request("ping", {}, timeout=timeout)
        except (TransportError, ProtocolError, RequestTimeout):
            return False
        return isinstance(response, dict) and (
            "result" in response or "error" in response)

    # ------------------------------------------------------------------
    # MCP convenience methods
    # ------------------------------------------------------------------
    def list_tools(self, max_pages: int = MAX_PAGES) -> List[Dict[str, Any]]:
        return self._paginate("tools/list", "tools", max_pages)

    def list_resources(self, max_pages: int = MAX_PAGES) -> List[Dict[str, Any]]:
        return self._paginate("resources/list", "resources", max_pages)

    def list_prompts(self, max_pages: int = MAX_PAGES) -> List[Dict[str, Any]]:
        return self._paginate("prompts/list", "prompts", max_pages)

    def list_resource_templates(
            self, max_pages: int = MAX_PAGES) -> List[Dict[str, Any]]:
        return self._paginate(
            "resources/templates/list", "resourceTemplates", max_pages)

    def _paginate(self, method: str, key: str,
                  max_pages: int) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(max_pages):
            params = {"cursor": cursor} if cursor else {}
            result = self.result(method, params)
            if not isinstance(result, dict):
                raise ProtocolError(
                    "{} result must be an object".format(method))
            page = result.get(key, [])
            if not isinstance(page, list):
                raise ProtocolError(
                    "{}.{} must be an array".format(method, key))
            items.extend(item for item in page if isinstance(item, dict))
            next_cursor = result.get("nextCursor")
            if not next_cursor or not isinstance(next_cursor, str):
                return items
            cursor = next_cursor
        logger.warning("%s exceeded %d pages; stopping pagination",
                       method, max_pages)
        return items

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                  timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("tools/call", {
            "name": name, "arguments": arguments or {}}, timeout=timeout)

    def read_resource(self, uri: str,
                      timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("resources/read", {"uri": uri}, timeout=timeout)

    def close(self) -> None:
        self.transport.close()
