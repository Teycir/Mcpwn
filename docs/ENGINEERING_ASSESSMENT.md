# Mcpwn Engineering Assessment — v2.1.0

**Scope:** commit `2efd027` (main), Python 3.12.3, Linux.
**Method:** full source review, dependency inspection, baseline test run, and
targeted probes against the bundled deliberately vulnerable server
(`test_data/dvmcp_server.py`). Previous audit claims were treated as hypotheses
and re-verified rather than assumed.

## 1. Baseline (before changes)

| Check | Result |
|---|---|
| `python3 -m pytest tests_unit -q` | **67 passed** |
| Coverage (`pytest-cov`) | **34%** overall; `core/pentester.py` 47% |
| `flake8` | Not configured; production code had unused imports and long lines |
| `bandit` | Not installed; no scan performed |
| Protocol tests | None |
| Transport tests | None; only subprocess CLI smoke tests |
| Streamable HTTP | Not implemented |

The 67 passing tests were not a quality signal: many attack modules had 0–24%
coverage, and several assertions were vacuous (for example
`test_timing_attack_detection` only asserted that a list was a list).

## 2. Verified defects

Severity here is engineering priority, not exploit impact. Every item marked
"verified" was reproduced locally.

| ID | Pri | Area | Defect | Evidence |
|---|---|---|---|---|
| F-01 | P0 | Protocol fuzzing | `ProtocolFuzzingTest` wrote `bytes` to a text-mode stdin. The resulting `TypeError` was caught and every probe was reported as a CRITICAL crash. | 7/7 probes produced `PROTOCOL_CRASH`; direct probe raised `TypeError: write() argument must be str, not bytes`. |
| F-02 | P0 | Path traversal | `get_payloads({'target_type': 'traversal'})` returned `[]` because the table has no `rce` key. The traversal suite sent **zero** payloads. | `PAYLOADS` keys were `command_injection`, `path_traversal`; `get_payloads` returned `[]`; suite returned no findings against a vulnerable server. |
| F-03 | P0 | Concurrency | `send_lock` covered write **and** read, serializing all requests. Race, flood and parallel tests were therefore sequential. | Code inspection; barrier-based tests could not overlap calls. |
| F-04 | P0 | Correlation | `send()` read the next available line and never checked the response `id`. Interleaved notifications or out-of-order responses were attributed to the wrong request. | Code inspection: no pending map, no id validation. |
| F-05 | P0 | Protocol state | Initialization sent `initialize` repeatedly, never sent `notifications/initialized`, hard-coded `2024-11-05`, and did not validate the negotiated version. | `discover()` and `initialize()` both sent initialize; no initialized notification existed. |
| F-06 | P0 | False positives | The double-initialize test reused an already-initialized process, so it fired on every scan. | `_cleanup()` only restarted a dead server; `start()` was idempotent. |
| F-07 | P1 | Detection | The detector accumulated findings globally. A detection from one probe (or from `tools/list`) could be attributed to an unrelated later probe. | `detector.findings` was consumed by whichever test drained it. |
| F-08 | P1 | Evidence | A delay > 5 s with `sleep` in the payload was reported as `BLIND_RCE_TIMING` / HIGH with no baseline, control or repeat. | `tool_injection.run()` timing branch. |
| F-09 | P1 | Resource handling | `resources/list` was read as `response['resources']` instead of `response['result']['resources']`; traversal targets were always empty. | Code inspection. |
| F-10 | P1 | Capability fuzzing | Any successful initialize with malformed **client** capabilities was reported as a HIGH validation bypass. Leniency there is spec-compliant. | `if "error" not in resp` branch. |
| F-11 | P1 | Auth bypass | Referenced `self.pentester.client`, which does not exist; all probes failed silently. Auth was not wired into `run()`. | Module never executed; `hasattr(client)` false. |
| F-12 | P1 | SSRF | Response heuristics marked any text containing `ami-id`/`computeMetadata` as CRITICAL, even documentation output. Not wired into `run()`. | Code inspection. |
| F-13 | P1 | DoS modules | `send_raw` was called on a non-existent `client`; recursion test mutated the process-wide recursion limit; giant payloads were hard-coded to 10 MB. | Code inspection. |
| F-14 | P1 | Subscription flood | `parallel` argument was ignored and the count was hard-coded to 2000. | Function signature vs body. |
| F-15 | P1 | Reporter | Mutated caller dicts, no deduplication, HTML severity class used `type`, SARIF lacked rules/fingerprints, no confidence model. | Code inspection. |
| F-16 | P2 | Lifecycle | `stop()` did not close pipes or wait after kill; stderr was `DEVNULL`, hiding server diagnostics. | Code inspection. |
| F-17 | P2 | Documentation | README claimed MCP 2025-12, 54 tests, port 5353 (code used 53), `--allowlist` (flag absent), and "SSRF implemented" in release notes although it was not wired. | README/RELEASE_NOTES vs code. |
| F-18 | P2 | OOB | Bind failure on port 53 skipped the suite (documented), but default port and README disagreed; no cleanup on some paths. | Code inspection. |
| F-19 | P2 | Test quality | No transport/HTTP/protocol tests; side-channel/DoS modules effectively untested; coverage 34%. | Coverage report. |
| F-20 | P2 | Schema pollution | Used global detector findings as evidence, so any prior RCE detection made every pollution probe "successful". | `_detect_pollution()` checked `pentester.detector.findings`. |

## 3. Additional architectural problems

- Transport, protocol state, attack logic and reporting were mixed in one
  488-line orchestrator, making independent testing impossible.
- No separation between **severity** (impact) and **confidence** (evidence),
  so statistical noise appeared alongside confirmed RCE.
- No request budget or destructive-test gate; the default scan could flood a
  server with 2000 subscriptions and multi-megabyte payloads.
- `--tags` was accepted but unused; `--parallel` was ignored by the flood test.
- Findings were plain dicts with inconsistent shapes (`risk` vs `type`,
  `detection` vs `detections`).

## 4. Prioritized backlog and disposition

### P0 — correctness and safety (completed)

1. Id-correlated transport with a reader thread, pending futures and typed
   errors (`core/transport.py`).
2. Real concurrent requests; write lock only; bounded concurrency.
3. Complete MCP initialization, version negotiation, initialized notification,
   pagination, server-initiated request handling (`core/session.py`).
4. Streamable HTTP transport with SSE and session ids.
5. Fix path-traversal payload resolution and result extraction.
6. Fix protocol fuzzing to send text and require liveness evidence.
7. Central request budget and explicit destructive gate (`core/safety.py`).

### P1 — detection quality (completed)

8. Scoped detector; per-response evidence.
9. Reproducibility checks before verification; severity/confidence/status model
   (`core/evidence.py`).
10. Finding fingerprints, merging and secret redaction.
11. Rewrite auth, SSRF, schema, deserialization, race, exhaustion and
    subscription modules; wire all suites into a registry.
12. Add tool poisoning, credential exposure, confused deputy, capability abuse
    and cross-tool attack-chain modules.
13. Normalize report schema (JSON/HTML/SARIF) with confidence.

### P2 — maintainability (completed)

14. Split core into protocol/transport/session/baseline/evidence/safety.
15. Add deterministic fake stdio server and local HTTP fixture.
16. Add 67 new tests (134 total), protocol/transport/HTTP/regression coverage.
17. Add `.flake8`, `pytest.ini`, CI workflow, architecture/threat-model/testing
    docs, and correct the README/CHANGELOG.

### Deferred (documented, not silently dropped)

- OAuth/OIDC interactive flows and token acquisition.
- Scanning resources for secrets by reading them (requires destructive opt-in
  and target-specific consent).
- Windows-specific process/console behavior.
- Third-party MCP server compatibility matrix (npx/uvx servers were not
  available in this environment).
- TLS certificate pinning and custom trust stores.

## 5. Result

The scanner now fails closed on safety, correlates every response, exercises
all attack modules, separates impact from evidence, and reports only
reproduced findings as `confirmed`. Remaining limitations are listed in
[TESTING.md](TESTING.md) and the README.
