# Testing Mcpwn

## 1. Commands

```bash
# Unit + integration suite
python3 -m pytest tests_unit -q

# Coverage (fails nothing by default; inspect the report)
python3 -m pytest tests_unit --cov=. --cov-report=term-missing

# Lint
python3 -m flake8 core tests tests_unit mcpwn.py payloads.py \
    test_data/mcp_test_server.py

# Security lint (installed in a project-local venv if the system Python is
# externally managed)
python3 -m venv .venv-tools
.venv-tools/bin/pip install bandit
.venv-tools/bin/bandit -r core mcpwn.py payloads.py -ll

# End-to-end, non-destructive
python3 mcpwn.py --safe-mode \
    --output-json /tmp/report.json \
    python3 test_data/dvmcp_server.py

# Fast RCE regression
python3 mcpwn.py --quick --rce-only \
    --output-json /tmp/rce.json \
    python3 test_data/dvmcp_server.py
```

## 2. Test layers

| Layer | Files | What it proves |
|---|---|---|
| Protocol primitives | `test_protocol.py` | JSON-RPC shapes, errors, content extraction |
| Transport | `test_transport.py` | id correlation, out-of-order replies, true concurrency, notifications, server requests, timeout recovery |
| Session | `test_session.py` | initialize negotiation, initialized notification, strict/lenient versions, pagination |
| HTTP | `test_http_transport.py` | POST, SSE, `Mcp-Session-Id`, 401, notifications |
| Evidence | `test_evidence.py` | severity vs confidence, dedupe, redaction, SARIF |
| Safety | `test_safety.py` | destructive gate, budget, clamped limits |
| Static analysis | `test_static_analysis.py` | tool poisoning, masked credentials, attack chains |
| Attack modules | `test_attack_modules.py` | positive detection and gate behavior for every active module using stubs |
| Integration | `test_integration_scan.py` | real CLI scan, real traversal payloads, no protocol-fuzz false positives |
| GitHub provider | `test_github.py` | token handling without leakage, static indicators/recipe extraction, tarball path safety, Docker command constraints, report thresholds |
| Legacy regressions | `test_*` | detector, reporter, payloads, lifecycle, state desync, profiles |

## 3. Deterministic fixtures

- `test_data/mcp_test_server.py` — threaded stdio server. Environment switches:
  `FAKE_SERVER_REQUEST`, `FAKE_NOTIFICATION`, `FAKE_PAGINATION`,
  `FAKE_PROTOCOL_VERSION`, `FAKE_SERIAL`.
- `test_http_transport.py` — local `ThreadingHTTPServer` implementing
  initialize, JSON responses, SSE and a 401-protected path.
- `test_data/dvmcp_server.py` — intentionally vulnerable shell/file server used
  only for end-to-end detection regressions.

The automated suite requires no network access. SSRF tests bind loopback; the
DNS test skips cleanly when port 53 is unavailable. Live GitHub checks are
manual/opt-in: static search, `--github-dry-run`, and three Docker runtime scans
were exercised against the public API; the runtime scans required starting the
Docker daemon and switching the CLI from Docker Desktop's missing socket to the
system daemon.

## 4. Reproducibility and anti-flakiness rules

1. Never assert on wall-clock ordering. Assert on **ids** and results.
2. Concurrency tests use a barrier and a generous upper bound (5 × 0.3 s must
   finish under 1.2 s), not an exact duration.
3. Timing findings require a baseline (median + MAD) and a repeat; tests assert
   that such findings are `verified=False`.
4. A crash requires process death or two failed pings. Tests include a healthy
   server that must produce **zero** `PROTOCOL_CRASH` findings.
5. Fake servers cap sleeps and reply deterministically.
6. Every test that starts a process or listener closes it in `finally` or a
   fixture.

## 5. Results snapshot

Run on 2026-11-11 (Linux, Python 3.12.3):

| Check | Result |
|---|---|
| `pytest tests_unit -q` | **160 passed** |
| Coverage | **70%** overall; protocol 88%, session 85%, transport 74%, evidence 83%, reporter 100%, safety 95% |
| `flake8` | **0 violations** |
| `bandit -r core mcpwn.py payloads.py -ll` | **0 medium/high** (two low-severity subprocess-import notices are expected for a scanner that launches targets) |
| Non-destructive scan of `dvmcp_server.py` | verified RCE and path traversal, no protocol false crashes |
| Quick RCE scan | verified RCE, exit 0 with `--fail-on none` |
| Live GitHub static search | 5 repositories assessed; no code executed |
| GitHub Docker dry-run | constrained command generated |
| GitHub Docker runtime scans | 3 servers initialized and scanned: `server-memory`, `@playwright/mcp`, `server-sequential-thinking`; all showed confirmed state findings |

Coverage is deliberately reported rather than enforced at 100%: remaining gaps
are mostly destructive branches (flood/exhaustion/deserialization timing) that
are gated and covered at the entry point, plus platform-specific process
handling.

## 6. What is not covered

- Live third-party MCP servers (`npx`/`uvx` packages) were not available in the
  build environment; the fake servers exercise the protocol contract.
- GitHub `uvx` and custom-image runtime paths; the `npx` path was exercised
  end to end against a real server.
- OAuth/OIDC authorization-code flows; only header-based HTTP auth is tested.
- Windows process and console semantics.
- TLS pinning/custom CAs.
- Reading declared resources to hunt for secrets (requires explicit consent).
- End-to-end LLM prompt handling; Mcpwn tests the server boundary, not the
  agent's instruction-following robustness.
- Long-running soak tests and memory profiling.

## 7. Adding tests

- New module: add a stub-based positive test and a gate test.
- New protocol behavior: extend the fake server and add a transport/session
  test; do not sleep-and-hope.
- New finding type: add it to `FINDING_CATALOG` and assert normalization,
  confidence and dedupe behavior.
- Any test that can modify state must construct a `SafetyPolicy` with
  `allow_destructive=False` and assert the module refuses to run.
