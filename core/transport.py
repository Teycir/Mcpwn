"""MCP transports.

Two transports are supported:

* :class:`StdioTransport` -- newline-delimited JSON over a child process,
  with a reader thread and id-correlated pending futures.  This is what makes
  concurrent requests and interleaved notifications safe.
* :class:`StreamableHttpTransport` -- MCP Streamable HTTP, including
  ``Mcp-Session-Id`` handling and Server-Sent Events responses.

Both transports expose the same small interface:

``start()``, ``close()``, ``request()``, ``notify()``, ``send_raw()``,
``set_message_handler()`` and ``stats``.
"""
from __future__ import annotations

import collections
import itertools
import json
import logging
import threading
import urllib.error
import urllib.request
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any, Callable, Dict, List, Optional

from core.protocol import (
    INTERNAL_ERROR,
    JSONRPC_VERSION,
    METHOD_NOT_FOUND,
    AuthenticationError,
    JsonRpcError,
    ProtocolError,
    RequestTimeout,
    TransportClosed,
    TransportError,
    iter_messages,
    jsonrpc_error,
    jsonrpc_request,
    jsonrpc_result,
)

logger = logging.getLogger("mcpwn.transport")

MessageHandler = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


def _new_stats() -> Dict[str, int]:
    return collections.Counter()


class Transport:
    """Common transport interface."""

    def __init__(self) -> None:
        self.stats: Dict[str, int] = _new_stats()
        self._message_handler: Optional[MessageHandler] = None
        self.late_messages: List[Dict[str, Any]] = []
        self.malformed_lines: List[str] = []

    def set_message_handler(self, handler: MessageHandler) -> None:
        self._message_handler = handler

    def start(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def request(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None,
                extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def notify(self, method: str,
               params: Optional[Dict[str, Any]] = None) -> None:
        raise NotImplementedError

    def send_raw(self, line: str) -> None:
        raise NotImplementedError

    @property
    def is_alive(self) -> bool:
        raise NotImplementedError

    def _invoke_handler(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self._message_handler is None:
            return None
        try:
            return self._message_handler(message)
        except JsonRpcError:
            raise
        except Exception:  # pragma: no cover - defensive: handler bugs
            logger.exception("message handler failed")
            return None


class StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a child process."""

    def __init__(self, command: List[str], *, cwd: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None,
                 stderr_tail_lines: int = 200):
        super().__init__()
        self.command = list(command)
        self.cwd = cwd
        self.env = env
        self._proc = None
        self._ids = itertools.count(1)
        self._pending: Dict[Any, Future] = {}
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = threading.Event()
        self._reader: Optional[threading.Thread] = None
        self._stderr_reader: Optional[threading.Thread] = None
        self.stderr_tail: collections.deque = collections.deque(
            maxlen=stderr_tail_lines)

    @property
    def proc(self):
        return self._proc

    @property
    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if self.is_alive:
            return
        import subprocess

        try:
            # nosec B603 - the operator explicitly supplies the scanner's
            # target command; shell=False and no shell interpolation is used.
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=self.cwd,
                env=self.env,
                errors="replace",
            )
        except (OSError, ValueError) as exc:
            raise TransportError(
                "failed to start MCP server: {}".format(exc)) from exc
        self._closed.clear()
        self._reader = threading.Thread(
            target=self._read_loop, name="mcpwn-stdio-reader", daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(
            target=self._stderr_loop, name="mcpwn-stderr-reader", daemon=True)
        self._stderr_reader.start()

    def _stderr_loop(self) -> None:
        stream = self._proc.stderr if self._proc else None
        if stream is None:  # pragma: no cover - defensive
            return
        try:
            for line in stream:
                line = line.rstrip()
                if not line:
                    continue
                self.stderr_tail.append(line)
                logger.debug("[server stderr] %s", line)
        except (OSError, ValueError):  # pragma: no cover - pipe closed
            pass

    def _read_loop(self) -> None:
        stream = self._proc.stdout if self._proc else None
        if stream is None:  # pragma: no cover - defensive
            return
        try:
            for line in stream:
                if self._closed.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                self.stats["lines_received"] += 1
                try:
                    message = json.loads(line)
                except (TypeError, ValueError):
                    self.stats["malformed_lines"] += 1
                    self.malformed_lines.append(line[:500])
                    logger.debug("malformed JSON-RPC line: %r", line[:200])
                    continue
                for item in iter_messages(message):
                    self._dispatch(item)
        except (OSError, ValueError):
            if not self._closed.is_set():
                logger.debug("stdout reader stopped")
        finally:
            if not self._closed.is_set():
                self.stats["unexpected_eof"] += 1
            self._fail_pending(
                TransportClosed("MCP server closed its stdout stream"))

    def _dispatch(self, message: Dict[str, Any]) -> None:
        if not isinstance(message, dict):
            self.stats["malformed_messages"] += 1
            return

        method = message.get("method")
        has_id = "id" in message

        if method is not None and has_id:
            self.stats["server_requests"] += 1
            thread = threading.Thread(
                target=self._answer_server_request, args=(message,),
                name="mcpwn-server-request", daemon=True)
            thread.start()
            return

        if has_id and ("result" in message or "error" in message):
            with self._pending_lock:
                future = self._pending.pop(message.get("id"), None)
            if future is not None and not future.done():
                self.stats["responses_received"] += 1
                future.set_result(message)
            else:
                # A response for an id we no longer wait on (usually a late
                # reply after timeout).  Keep it for evidence, never let it
                # satisfy a different request.
                self.stats["late_responses"] += 1
                self.late_messages.append(message)
                logger.debug("late/unsolicited response id=%r",
                             message.get("id"))
            return

        if method is not None:
            self.stats["notifications_received"] += 1
            try:
                self._invoke_handler(message)
            except JsonRpcError:  # pragma: no cover - notifications have no reply
                pass
            return

        self.stats["unsolicited_messages"] += 1
        self.late_messages.append(message)

    def _answer_server_request(self, message: Dict[str, Any]) -> None:
        request_id = message.get("id")
        method = str(message.get("method", ""))
        try:
            result = self._invoke_handler(message)
            if result is None:
                response = jsonrpc_error(
                    request_id, METHOD_NOT_FOUND,
                    "client does not implement {}".format(method))
            else:
                response = jsonrpc_result(request_id, result)
        except JsonRpcError as exc:
            response = jsonrpc_error(
                request_id, exc.code, exc.message, exc.data)
        except Exception:  # pragma: no cover - handler bug
            logger.exception("server request handler crashed")
            response = jsonrpc_error(
                request_id, INTERNAL_ERROR, "client handler error")
        try:
            self._write_line(json.dumps(response))
        except TransportClosed:
            pass

    def _write_line(self, line: str) -> None:
        if not self.is_alive or self._proc.stdin is None:
            raise TransportClosed("MCP server is not running")
        with self._write_lock:
            try:
                self._proc.stdin.write(line + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise TransportClosed(
                    "failed to write to MCP server: {}".format(exc)) from exc

    def request(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None,
                extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        if extra_headers:
            logger.debug("stdio transport ignores HTTP headers")
        if not self.is_alive:
            raise TransportClosed("MCP server is not running")
        request_id = next(self._ids)
        future: Future = Future()
        with self._pending_lock:
            self._pending[request_id] = future
        payload = jsonrpc_request(request_id, method, params)
        try:
            self._write_line(json.dumps(payload))
        except TransportClosed:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise
        self.stats["requests_sent"] += 1
        wait_for = timeout if timeout is not None else 10.0
        try:
            return future.result(timeout=wait_for)
        except FutureTimeout:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            self.stats["timeouts"] += 1
            raise RequestTimeout(
                "no response to {!r} after {:.1f}s".format(method, wait_for))
        except TransportClosed:
            raise

    def notify(self, method: str,
               params: Optional[Dict[str, Any]] = None) -> None:
        if not self.is_alive:
            raise TransportClosed("MCP server is not running")
        message = {"jsonrpc": JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = params
        self._write_line(json.dumps(message))
        self.stats["notifications_sent"] += 1

    def send_raw(self, line: str) -> None:
        """Write an arbitrary text line without registering a pending id.

        Used by protocol fuzzing.  The line is always ``str`` so it is safe
        for a text-mode pipe (the previous implementation wrote bytes and
        every probe became a false crash).
        """
        if not isinstance(line, str):
            raise TypeError("send_raw expects str, not {}".format(
                type(line).__name__))
        self._write_line(line)
        self.stats["raw_messages_sent"] += 1

    def _fail_pending(self, exc: Exception) -> None:
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for future in pending:
            if not future.done():
                future.set_exception(exc)

    def close(self) -> None:
        self._closed.set()
        proc = self._proc
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=5)
                    except Exception:
                        logger.debug("failed to kill MCP server", exc_info=True)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass
        self._fail_pending(TransportClosed("transport closed"))
        for thread in (self._reader, self._stderr_reader):
            if thread is not None and thread.is_alive():
                thread.join(timeout=2)
        self._proc = None


def parse_sse_events(body: str) -> List[Any]:
    """Parse ``text/event-stream`` payloads into JSON messages."""
    messages: List[Any] = []
    data: List[str] = []
    for line in body.splitlines():
        if not line or line.startswith(":"):
            if data:
                messages.append(_decode_event("\n".join(data)))
                data = []
            continue
        if line.startswith("event:"):
            continue
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif data:
            # Unknown field inside an event; ignore per SSE spec.
            continue
    if data:
        messages.append(_decode_event("\n".join(data)))
    return [message for message in messages if message is not None]


def _decode_event(raw: str) -> Any:
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid JSON in SSE event: {}".format(exc)) from exc


class StreamableHttpTransport(Transport):
    """MCP Streamable HTTP transport (2025-03-26 and later)."""

    def __init__(self, url: str, *, headers: Optional[Dict[str, str]] = None,
                 timeout: float = 10.0):
        super().__init__()
        self.url = url
        self.base_headers = dict(headers or {})
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._started = False
        self._notifications_queue: collections.deque = collections.deque(
            maxlen=200)

    @property
    def is_alive(self) -> bool:
        return self._started

    def start(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise TransportError(
                "Streamable HTTP target must be an http(s) URL")
        self._started = True

    def _headers(self, extra: Optional[Dict[str, Optional[str]]] = None,
                 accept_sse: bool = True) -> Dict[str, str]:
        headers = dict(self.base_headers)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = (
            "application/json, text/event-stream" if accept_sse
            else "application/json")
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if extra:
            for key, value in extra.items():
                # ``None`` removes a header, which lets authorization tests
                # send the same request without credentials.
                if value is None:
                    headers.pop(key, None)
                else:
                    headers[key] = value
        return headers

    def _post(self, payload: Any, timeout: Optional[float],
              extra_headers: Optional[Dict[str, str]] = None,
              raw: bool = False) -> List[Any]:
        data = (payload if isinstance(payload, str)
                else json.dumps(payload)).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=data, headers=self._headers(extra_headers),
            method="POST")
        wait_for = timeout if timeout is not None else self.timeout
        try:
            # ``start()`` restricts the target to http(s); this is the
            # scanner's own configured MCP endpoint, not user content.
            with urllib.request.urlopen(  # nosec B310
                    request, timeout=wait_for) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session_id = session_id
                content_type = response.headers.get("Content-Type", "")
                body = response.read().decode("utf-8", errors="replace")
                status = getattr(response, "status", 200)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in (401, 403):
                raise AuthenticationError(exc.code, body) from exc
            raise TransportError(
                "HTTP {} from {}: {}".format(exc.code, self.url,
                                             body[:200])) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise TransportError(
                "HTTP request failed: {}".format(exc)) from exc
        if status == 202 or not body.strip():
            return []
        if "text/event-stream" in content_type:
            return parse_sse_events(body)
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                "invalid JSON response: {}".format(exc)) from exc
        return list(iter_messages(parsed))

    def _handle_extras(self, messages: List[Any], expected_id: Any) -> Optional[Dict[str, Any]]:
        matched = None
        for message in messages:
            if not isinstance(message, dict):
                self.stats["malformed_messages"] += 1
                continue
            if message.get("id") == expected_id and (
                    "result" in message or "error" in message):
                matched = message
                continue
            if "method" in message and "id" in message:
                self.stats["server_requests"] += 1
                try:
                    result = self._invoke_handler(message)
                except JsonRpcError as exc:
                    # Transport cannot answer on this HTTP exchange; record
                    # the observation.  Clients may POST a reply separately.
                    self.late_messages.append(
                        {"server_request_error": exc.message,
                         "request": message})
                    result = None
                self.late_messages.append(
                    {"server_request": message.get("method"),
                     "answered_inline": result is not None})
            elif "method" in message:
                self.stats["notifications_received"] += 1
                try:
                    self._invoke_handler(message)
                except JsonRpcError:
                    pass
                self._notifications_queue.append(message)
            else:
                self.stats["unsolicited_messages"] += 1
                self.late_messages.append(message)
        return matched

    def request(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None,
                extra_headers: Optional[Dict[str, Optional[str]]] = None
                ) -> Dict[str, Any]:
        if not self._started:
            raise TransportClosed("HTTP transport not started")
        request_id = next(self._ids)
        payload = jsonrpc_request(request_id, method, params)
        messages = self._post(payload, timeout, extra_headers)
        self.stats["requests_sent"] += 1
        matched = self._handle_extras(messages, request_id)
        if matched is None:
            raise ProtocolError(
                "no JSON-RPC response for id {} (received {} messages)".format(
                    request_id, len(messages)))
        self.stats["responses_received"] += 1
        return matched

    def notify(self, method: str,
               params: Optional[Dict[str, Any]] = None) -> None:
        if not self._started:
            raise TransportClosed("HTTP transport not started")
        message = {"jsonrpc": JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = params
        messages = self._post(message, self.timeout)
        self._handle_extras(messages, object())
        self.stats["notifications_sent"] += 1

    def send_raw(self, line: str) -> None:
        if not isinstance(line, str):
            raise TypeError("send_raw expects str")
        messages = self._post(line, self.timeout, raw=True)
        self._handle_extras(messages, object())
        self.stats["raw_messages_sent"] += 1

    def close(self) -> None:
        if self.session_id:
            try:
                request = urllib.request.Request(
                    self.url, headers=self._headers(accept_sse=False),
                    method="DELETE")
                # Same validated http(s) MCP endpoint.
                urllib.request.urlopen(  # nosec B310
                    request, timeout=self.timeout).close()
            except (urllib.error.URLError, OSError, ValueError):
                logger.debug("failed to delete HTTP session", exc_info=True)
        self._started = False
        self.session_id = None
