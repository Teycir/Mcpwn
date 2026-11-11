# Mcpwn Architecture (v2.1.0)

## 1. Goals

1. Speak MCP correctly over both stdio and Streamable HTTP.
2. Correlate every response to its request; never infer state from line order.
3. Support true concurrent probes safely.
4. Keep detection scoped, reproducible and evidence-based.
5. Make destructive behavior explicit and bounded.
6. Keep modules small and independently testable without a live server.

## 2. Layers

```
┌──────────────────────────────────────────────────────────────┐
│ CLI (mcpwn.py)                                                │
│ flags, profiles, limits, exit codes                           │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│ MCPPentester (core/pentester.py)                              │
│ lifecycle, discovery, suite registry, reports, exit status    │
└───────┬───────────────────┬──────────────────┬───────────────┘
        │                   │                  │
┌───────▼────────┐  ┌───────▼────────┐  ┌──────▼──────────────┐
│ McpSession     │  │ SafetyPolicy   │  │ Evidence / Reporter  │
│ (core/session) │  │ (core/safety)  │  │ (core/evidence)      │
│ version, caps, │  │ budget, gates, │  │ normalize, dedupe,   │
│ pagination,    │  │ limits         │  │ confidence, SARIF    │
│ server requests│  └────────────────┘  └──────────────────────┘
└───────┬────────┘
        │
┌───────▼──────────────────────────────────────────────────────┐
│ Transport (core/transport.py)                                 │
│ StdioTransport: reader thread + pending futures + stderr drain │
│ StreamableHttpTransport: POST, SSE, Mcp-Session-Id, DELETE     │
└──────────────────────────────────────────────────────────────┘
```

Attack modules (`tests/*.py`) depend only on the `MCPPentester` facade
(`send`, `send_raw`, `scan_response`, `policy`, `tools`, `session`). They do not
own transports, sockets or process lifecycle.

## 3. JSON-RPC correlation

### stdio

- One reader thread consumes stdout line by line and parses JSON.
- Every request gets a monotonically increasing id and a `Future` stored in a
  pending map.
- Responses are matched **by id**. An id that is no longer pending is a *late
  response* (usually a reply after timeout); it is recorded in
  `late_messages` and discarded. It can never satisfy another request.
- Notifications are routed to `McpSession._handle_message` and recorded.
- Server-initiated requests (method + id) are answered on a short-lived thread,
  so a server waiting on `roots/list` cannot block the reader.
- Only the write side is locked; reads are single-threaded. This is what makes
  concurrent requests genuine rather than serialized.
- stderr is drained by a second thread into a bounded tail and debug log,
  preventing pipe backpressure and preserving diagnostics.

### Streamable HTTP

- `POST` with `Content-Type: application/json` and
  `Accept: application/json, text/event-stream`.
- `Mcp-Session-Id` returned by the server is captured and echoed on later
  requests; `DELETE` releases the session on close.
- Responses may be plain JSON or SSE. SSE `data:` events are parsed until the
  matching response id is found; notifications/server requests in the same
  stream are recorded.
- `extra_headers` may override or remove a header (`None`), which authorization
  tests use to send an unauthenticated variant of the same request.
- 401/403 raise `AuthenticationError`; other HTTP failures raise
  `TransportError`.

## 4. MCP lifecycle

```
client                                      server
  │ initialize(protocolVersion, caps, info)   │
  │──────────────────────────────────────────>│
  │<──────────────────────────────────────────│ result(version, caps, info)
  │ notifications/initialized                 │
  │──────────────────────────────────────────>│
  │ tools/list (+ cursor pagination)          │
  │ resources/list, prompts/list, templates   │
  │ ping                                      │
```

- The client offers `LATEST_PROTOCOL_VERSION` (`2025-06-18`).
- A known version is recorded as supported. An unknown version is accepted with
  a warning by default (so newer servers remain scannable), or rejected with
  `--strict-protocol`.
- `initialize` is idempotent unless `force=True` (protocol state tests use the
  forced path deliberately).
- Pagination follows `nextCursor` with a page cap and validates list types.
- `sampling/createMessage` is refused with `METHOD_NOT_FOUND`; `ping` returns
  `{}`; `roots/list` returns `{"roots": []}`; elicitation is declined.

## 5. Concurrency and timeouts

- `RequestBudget` counts every request across threads and raises
  `SafetyLimitExceeded` at the configured ceiling.
- `max_concurrency` clamps race/flood worker counts.
- Per-request timeout removes the pending future and raises `RequestTimeout`.
  The session remains usable; a later reply is counted as late.
- `health_check()` uses `ping` (any JSON-RPC response counts as alive) and
  restarts at most once, then re-initializes.
- A timeout is never treated as a crash. Crash findings require the process to
  be dead or two consecutive liveness probes to fail.

## 6. Evidence pipeline

```
raw response
  │ result_text() extracts MCP content blocks
  ▼
SemanticDetector.scan()  (pure, per response)
  │ indicators: RCE, FILE_READ
  ▼
attack module               confirms (repeat probe), builds Finding
  │ type, tool, arg, payload, evidence, severity, confidence, verified
  ▼
Reporter.add_findings()
  │ normalize → fingerprint → merge duplicates → summarize
  ▼
JSON / HTML / SARIF
```

**Severity** is impact if real; **confidence** is evidence strength. Status is
derived: `confirmed` (verified and ≥85), `likely` (≥85), `possible` (≥30),
`informational` (<30). Unverified findings are capped at 84. A timing anomaly
has its own type and title and is never reported as RCE.

Fingerprints are `(test, type, tool, arg, uri, title)`. Multiple payloads
proving the same injection point merge into one finding with combined evidence
and an `occurrences` count.

## 7. Safety model

- **Default:** destructive tests are off. `--allow-destructive` is required for
  resource exhaustion, flooding, race tests, deserialization timing probes and
  sleep payloads.
- `--safe-mode` overrides the destructive flag and additionally skips protocol
  and capability fuzzing.
- Limits: `--max-requests`, `--max-concurrency`, `--max-payload-bytes`,
  `--flood-count`, plus internal caps on payloads per argument and tools.
- All listeners bind loopback and are closed in `finally` blocks.
- Secrets are masked before entering evidence.

## 8. Backward compatibility

The historical surface remains: `MCPPentester(server_cmd, config)`,
`start`, `stop`, `send` (returns `(response, elapsed)`), `send_notification`,
`discover`, `tools`, `resources`, `detector`, `get_payloads`, `Reporter`
methods and the JSON fields `summary.total`, `by_type`, `by_severity`.
`skip_analysis` is still accepted but ignored: detection is explicit and
scoped. New fields (`confidence`, `status`, `verified`, `fingerprint`, `cwe`,
`remediation`) are additive.

## 9. GitHub target provider

`core/github.py` is a separate target provider, not part of the MCP protocol
stack:

- `GitHubClient` uses the REST API with a token from `.env` or the environment.
  Redirects to a different host drop the `Authorization` header.
- Static assessment fetches metadata, README, a bounded tree and selected
  blobs. It produces review indicators and launch candidates without executing
  repository code.
- `DockerSandbox` wraps a selected command with no network by default,
  a read-only root, dropped capabilities, no-new-privileges, PID/memory/CPU
  limits and a disposable writable workspace copy.
- Runtime scans feed the wrapped command to the normal `MCPPentester`, reusing
  session negotiation, safety gates, evidence normalization and reporting.
- Tarball extraction rejects absolute paths, `..`, links and special files, and
  enforces file-count and extracted-size ceilings.

## 10. Adding a test module

1. Accept the `MCPPentester` facade in `__init__`.
2. Read limits from `pentester.policy`; call `require_destructive()` when the
   probe can modify or exhaust the target.
3. Use `pentester.send()` / `send_raw()`; catch only the typed transport
   errors.
4. Scan the response with `pentester.scan_response()` or `result_text()`,
   never with global detector state.
5. Emit `make_finding(...)` with evidence and a confidence justified by the
   probe. Confirm candidates with an independent repeat before `verified=True`.
6. Register the suite in `MCPPentester.run()` with tags.
7. Add a stub-based unit test and, if relevant, a fake-server integration test.
