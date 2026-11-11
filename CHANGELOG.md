# Changelog

## [2.1.0] - 2026-11-11

GitHub target-provider release.

### Added

- **GitHub MCP discovery and assessment** (`core/github.py`): search the GitHub
  API or target `owner/repo`, inspect manifests and a bounded set of source
  files, extract launch recipes, and report review indicators without executing
  repository code.
- **Sandboxed runtime testing**: `--github-run` requires `--allow-remote-code`
  and runs the selected command only inside Docker with a read-only root,
  dropped capabilities, no-new-privileges, resource limits and no network by
  default. `--github-dry-run` prints the command without executing it.
- **Local token handling**: `Github_Token`/`GITHUB_TOKEN` is read from
  `.env`/the environment, never forwarded to the sandbox, and never written to
  a report.
- **Reports and tests**: JSON/Markdown GitHub reports, 25 provider tests, an
  initialization-failure regression, and a live static/dry-run/runtime smoke
  check.

### Fixed

- Docker runtime scans now run as the host UID, keep the tmpfs executable, and
  run `npx`/`uvx` from a clean working directory so a repository manifest cannot
  shadow the requested package.
- A failed MCP initialization now skips active suites and marks the runtime scan
  failed instead of emitting misleading capability findings.

### Changed

- Bumped the application, report and MCP client versions to 2.1.0.

## [2.0.0] - 2026-11-11

Engineering modernization release. No attack capability was removed; several
modules that previously did nothing now work, and several false-positive
sources were eliminated.

### Added

- **MCP session layer** (`core/session.py`): version negotiation,
  `notifications/initialized`, server-initiated request handling, pagination,
  prompts/resources/templates discovery and idempotent initialization.
- **Streamable HTTP transport** (`core/transport.py`): POST, SSE parsing,
  `Mcp-Session-Id`, `DELETE` on close, 401/403 handling and per-request headers.
- **Correlated stdio transport**: reader thread, pending futures keyed by
  JSON-RPC id, late-response accounting, notification routing, drained stderr
  and typed transport errors.
- **True concurrency**: the global send/read lock was replaced with a write-only
  lock plus per-request futures.
- **Safety policy** (`core/safety.py`): global request budget, concurrency cap,
  payload/subscription limits and an explicit `--allow-destructive` gate.
- **Evidence model** (`core/evidence.py`): severity/confidence separation,
  status (`confirmed`/`likely`/`possible`/`informational`), reproducibility
  helper, stable fingerprints, deduplication/merging and secret redaction.
- **Robust latency baseline** (`core/baseline.py`): median + MAD comparison
  instead of raw timing thresholds.
- **New security modules**: `tool_poisoning`, `credential_exposure`,
  `confused_deputy`, `capability_abuse`, `attack_chains`.
- **Reports**: confidence summaries, SARIF rules/fingerprints/CWE properties,
  escaped HTML, deduplicated JSON.
- **CLI**: `--target`, `--header`, `--allow-destructive`, `--tags`,
  `--exclude-tags`, `--max-requests`, `--max-concurrency`,
  `--max-payload-bytes`, `--flood-count`, `--oob-callback-base`,
  `--ssrf-all-args`, `--fail-on`, `--strict-protocol`, `--verbose`.
- **Tests**: deterministic stdio fake server, local HTTP/SSE fixture, and 67
  new tests covering protocol, transport, sessions, evidence, safety, static
  analysis, attack modules and end-to-end regressions.
- **Documentation**: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
  `docs/TESTING.md`, `docs/ENGINEERING_ASSESSMENT.md`.

### Fixed

- **Protocol fuzzing false CRITICALs**: fuzzing wrote `bytes` into a text-mode
  pipe; every probe was reported as a server crash. Probes are now text lines,
  and a crash requires process death or two failed liveness probes.
- **Path traversal was a no-op**: `target_type='traversal'` resolved to an
  empty payload list and `resources/list` was read from the wrong envelope.
- **Request correlation**: responses are matched by id; notifications and
  server requests can no longer be mistaken for the current response.
- **Double-initialize false positive**: protocol state tests now spawn a fresh
  server per probe and restore state afterwards.
- **Capability fuzzing false positives**: accepting unknown *client*
  capabilities is spec-compliant and is no longer a HIGH finding.
- **Detector cross-contamination**: detection is scoped to the response being
  analyzed; global findings are no longer attributed to later probes.
- **Timing claims**: a delay is reported as a weak timing oracle, never as
  confirmed RCE; side-channel findings are LOW/possible.
- **Desynchronized payloads**: traversal aliases and quick-mode payload order
  now include the working newline injection.
- **Auth bypass**: removed references to a non-existent `client`; HTTP auth
  tests compare an authenticated baseline with an unauthenticated request.
- **SSRF**: callback-confirmed evidence only for CRITICAL; metadata strings in
  output are no longer treated as proof.
- **Race conditions**: tests use real concurrent requests and require the
  collision to reproduce in two rounds.
- **Exhaustion/flood**: removed `sys.setrecursionlimit` mutation, hard-coded
  10 MB payloads and the ignored `parallel` argument; all are bounded by policy.
- **Reporter**: no caller-dict mutation, deduplication, correct HTML severity
  classes and valid SARIF rule references.
- **Lifecycle**: pipes are closed, killed processes are reaped, and stderr is
  drained instead of discarded.
- **Documentation claims**: corrected port, test count, protocol version,
  removed non-existent flags and marked release notes as historical.

### Changed (breaking)

- **Destructive tests are off by default.** Resource exhaustion, subscription
  flooding, race tests and deserialization timing probes require
  `--allow-destructive`. `--safe-mode` disables them plus fuzzing.
- Findings now include `confidence`, `confidence_label`, `status`, `verified`,
  `cwe`, `remediation`, `fingerprint` and `occurrences`. Existing fields remain.
- `--rce-only` now runs only the command-injection suite, as documented, instead
  of also running state/capability tests.
- JSON `summary.by_severity` omits zero-count severities; `by_confidence` and
  `verified` were added.
- `Mcpwn --version` is `2.0.0`.

### Security

- Request/payload/concurrency ceilings prevent accidental denial of service.
- Secrets are masked in evidence and reports.
- Local listeners bind loopback; remote targets require an explicit
  `--oob-callback-base`.
- Bandit is part of the development toolchain; SHA-1 fingerprints were replaced
  with SHA-256.

## [1.2.0] - 2025-12-15

### Added
- Side-channel detection (timing, size, behavioral patterns)
- Paranoid security profile
- Allowlist configuration and runtime enforcer
- CI/CD integration guide
- Unit tests for side-channel detection

### Changed
- Timing variance check to reduce false positives
- More specific behavioral indicators
- Merged size and behavioral probes for fewer requests

### Security
- Thread-safe allowlist cache
- Path validation for configuration loading

## [1.1.0] - 2025

### Added
- API key support for LLM-guided payload generation
- Capability fuzzing
- SARIF output
- DVMCP test server

### Fixed
- Transport-level lock for parallel writes
- SSRF listener cleanup
- Multi-marker leak detection

## [1.0.0] - Initial release

- Semantic detection engine
- Tool/resource injection and traversal tests
- Protocol fuzzing, prompt injection, OOB, race and exhaustion tests
- JSON/HTML reporting and safe/quick modes
