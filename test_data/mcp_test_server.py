#!/usr/bin/env python3
"""Deterministic MCP server used by Mcpwn's tests.

Behaviour is controlled by environment variables so a single fixture can
exercise correlation, notifications, server requests, pagination and timing:

* ``FAKE_SERVER_REQUEST=1`` -- send a ``roots/list`` request after initialize.
* ``FAKE_NOTIFICATION=1``   -- send a ``tools/list_changed`` notification.
* ``FAKE_PAGINATION=1``     -- paginate ``tools/list`` in two pages.
* ``FAKE_HANG=1``           -- the ``hang`` tool sleeps for five seconds.

Requests are handled in threads, so a slow request does not block later ones
and responses can legitimately arrive out of order.
"""
import json
import os
import sys
import threading
import time

WRITE_LOCK = threading.Lock()
INITIALIZED = threading.Event()


def send(message):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(message) + "\n")
        sys.stdout.flush()


def send_server_request(request_id, method, params=None):
    send({"jsonrpc": "2.0", "id": request_id, "method": method,
          "params": params or {}})


TOOLS = [
    {
        "name": "echo",
        "description": "Echo the provided text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "slow",
        "description": "Sleep, then echo.",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "number"}},
            "required": ["seconds"],
        },
    },
]


def tools_page(params):
    if os.environ.get("FAKE_PAGINATION") != "1":
        return {"tools": TOOLS}
    cursor = params.get("cursor")
    if cursor == "page2":
        return {"tools": [TOOLS[1]]}
    return {"tools": [TOOLS[0]], "nextCursor": "page2"}


def handle_tool_call(params):
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name == "echo":
        text = str(arguments.get("text", ""))
        return {"content": [{"type": "text", "text": text}]}
    if name == "slow":
        seconds = float(arguments.get("seconds", 0.3))
        time.sleep(min(max(seconds, 0.0), 5.0))
        return {"content": [{"type": "text", "text": "slept"}]}
    if name == "hang":
        time.sleep(5)
        return {"content": [{"type": "text", "text": "late"}]}
    raise ValueError("unknown tool {}".format(name))


def handle(request):
    method = request.get("method")
    params = request.get("params") or {}
    request_id = request.get("id")

    if method == "initialize":
        if os.environ.get("FAKE_SERVER_REQUEST") == "1":
            threading.Timer(
                0.05, send_server_request, args=("srv-1", "roots/list")
            ).start()
        if os.environ.get("FAKE_NOTIFICATION") == "1":
            threading.Timer(
                0.05, send,
                args=({"jsonrpc": "2.0",
                       "method": "notifications/tools/list_changed"},)
            ).start()
        result = {
            "protocolVersion": os.environ.get(
                "FAKE_PROTOCOL_VERSION", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": True},
                             "resources": {}},
            "serverInfo": {"name": "mcpwn-fake", "version": "1.0"},
        }
        send({"jsonrpc": "2.0", "id": request_id, "result": result})
        return
    if method == "notifications/initialized":
        INITIALIZED.set()
        return
    if method == "ping":
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
        return
    if method == "debug/initialized":
        send({"jsonrpc": "2.0", "id": request_id,
              "result": {"initialized": INITIALIZED.is_set()}})
        return
    if method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id,
              "result": tools_page(params)})
        return
    if method == "tools/call":
        try:
            result = handle_tool_call(params)
            send({"jsonrpc": "2.0", "id": request_id, "result": result})
        except (ValueError, TypeError) as exc:
            send({"jsonrpc": "2.0", "id": request_id,
                  "error": {"code": -32602, "message": str(exc)}})
        return
    if method == "resources/list":
        send({"jsonrpc": "2.0", "id": request_id,
              "result": {"resources": []}})
        return
    if method == "prompts/list":
        send({"jsonrpc": "2.0", "id": request_id,
              "result": {"prompts": []}})
        return
    if method == "resources/templates/list":
        send({"jsonrpc": "2.0", "id": request_id,
              "result": {"resourceTemplates": []}})
        return
    if method is None:
        return
    if request_id is not None:
        send({"jsonrpc": "2.0", "id": request_id,
              "error": {"code": -32601, "message": "Method not found"}})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            send({"jsonrpc": "2.0", "id": None,
                  "error": {"code": -32700,
                            "message": "Parse error: {}".format(exc)}})
            continue
        if not isinstance(request, dict):
            send({"jsonrpc": "2.0", "id": None,
                  "error": {"code": -32600, "message": "Invalid Request"}})
            continue
        if os.environ.get("FAKE_SERIAL") == "1":
            handle(request)
        else:
            threading.Thread(target=handle, args=(request,), daemon=True).start()


if __name__ == "__main__":
    main()
