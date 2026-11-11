<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**  
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->

# Mcpwn — MCP Security Testing Framework

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--06--18-orange.svg)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-160%20passing-brightgreen.svg)](tests_unit/)
[![Coverage](https://img.shields.io/badge/coverage-70%25-yellowgreen.svg)](docs/TESTING.md)

Mcpwn is an automated security scanner for **Model Context Protocol** servers.
It speaks MCP over **stdio** and **Streamable HTTP**, exercises tool arguments,
resources, metadata, protocol state and authorization boundaries, and reports
only evidence-backed findings.

**One vulnerable tool can mean full host compromise for the agent.**

## Safety first

Active tests that can flood, exhaust or delay a target are **disabled by
default**. Enable them deliberately:

```bash
python3 mcpwn.py --allow-destructive ...   # resource exhaustion, floods, timing
python3 mcpwn.py --safe-mode ...           # skip destructive and fuzzing suites
```

All probes are bounded by `--max-requests`, `--max-concurrency`,
`--max-payload-bytes` and `--flood-count`. See [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Quick start

```bash
git clone https://github.com/Teycir/Mcpwn.git
cd Mcpwn

# Non-destructive scan of the bundled vulnerable demo server
python3 mcpwn.py --safe-mode --output-json report.json \
    python3 test_data/dvmcp_server.py

# Fast RCE-only scan
python3 mcpwn.py --quick --rce-only python3 test_data/dvmcp_server.py

# Streamable HTTP endpoint
python3 mcpwn.py --target http://127.0.0.1:8080/mcp \
    --header "Authorization: Bearer $MCP_TOKEN" \
    --output-json report.json
```

Python 3.9+ is required. The scanner uses only the standard library; the
development tools (pytest, flake8, bandit) live in `requirements-dev.txt`.

## GitHub-hosted MCP servers

Mcpwn can discover MCP repositories through the GitHub API and assess them
without executing code. Put a token in the local, gitignored `.env`:

```bash
cp .env.example .env
# edit .env: Github_Token=github_pat_...
```

```bash
# Discover and profile repositories (metadata + bounded source inspection)
python3 mcpwn.py --github-search "topic:mcp-server language:python" \
    --github-limit 5 --github-json github-report.json \
    --github-markdown github-report.md

# Profile one repository
python3 mcpwn.py --github-repo modelcontextprotocol/servers \
    --github-json github-report.json

# Inspect the Docker command without running the repository
python3 mcpwn.py --github-repo owner/repo --github-run --github-dry-run \
    --allow-remote-code

# Run a launch recipe in the sandbox (requires Docker)
python3 mcpwn.py --github-repo owner/repo --github-run \
    --allow-remote-code --github-network --github-json github-report.json
```

Static mode reports review indicators (install scripts, unpinned dependencies,
dangerous process/network surfaces) and launch candidates. Runtime mode is
opt-in: `--github-run` requires `--allow-remote-code` and executes only inside a
Docker container with a read-only root, dropped capabilities, no-new-privileges
and network disabled by default. The token is never passed to the sandbox or
written to a report. See [GITHUB_TESTING.md](docs/GITHUB_TESTING.md).

## What it checks

| Area | Tests | Mode |
|---|---|---|
| Command injection / RCE | `tool_injection` | active, reproducible |
| Path traversal | `resource_traversal` | active, reproducible |
| Tool poisoning | `tool_poisoning` | static |
| Credential exposure | `credential_exposure` | static, masked evidence |
| Cross-tool attack chains | `attack_chains` | static, potential only |
| Confused deputy / IDOR | `confused_deputy` | active, control comparison |
| HTTP authorization | `auth_bypass` | active (HTTP only) |
| SSRF | `ssrf_injection` | active, callback-confirmed |
| OOB DNS exfiltration | `oob_detection` | active, callback-confirmed |
| Output / prompt injection | `prompt_injection` | active, confidence-graded |
| Schema / prototype pollution | `schema_pollution` | active |
| Unsafe deserialization | `deserialization` | destructive |
| Protocol state desync | `state_desync` | active, fresh session |
| Capability fuzzing / abuse | `capability_fuzzing`, `capability_abuse` | active (fuzzing requires `--allow-destructive`) |
| JSON-RPC parser robustness | `protocol_fuzzing` | active, liveness-verified |
| Race conditions | `race_condition` | destructive, reproducible |
| Resource exhaustion | `resource_exhaustion` | destructive, bounded |
| Subscription flood | `subscription_flood` | destructive, bounded |
| Side channels | `side_channel` | active, low confidence |

## Protocol support

- MCP **stdio** (newline-delimited JSON-RPC 2.0).
- MCP **Streamable HTTP** with `Mcp-Session-Id` and SSE responses.
- `initialize` negotiation (`2025-06-18`, `2025-03-26`, `2024-11-05`,
  `2024-10-07`), with `--strict-protocol` to reject unknown versions.
- `notifications/initialized`, server-initiated requests (`ping`,
  `roots/list`), pagination (`nextCursor`), prompts/resources/templates.
- Id-correlated responses, late-response accounting, concurrent requests and
  per-request timeouts. Transport failures are typed and never silently
  swallowed.

## Evidence model

**Severity** answers "how bad if true". **Confidence** answers "how sure are
we". They are reported separately, and findings carry a `status`:

| Status | Meaning |
|---|---|
| `confirmed` | Reproduced, verified evidence (≥85 confidence) |
| `likely` | Strong evidence, not independently reproduced |
| `possible` | Heuristic or single observation |
| `informational` | Context only; not a vulnerability claim |

Examples:

- Command output (`uid=…`) reproduced twice → `RCE`, CRITICAL,
  `confirmed`.
- A reproducible delay with `sleep` but no output oracle → `BLIND_RCE_TIMING`,
  MEDIUM, `possible` — **not** confirmed RCE.
- A timing side channel → `TIMING_SIDE_CHANNEL`, LOW, `informational`.
- Tool metadata with hidden Unicode → `TOOL_POISONING`, HIGH, static review.

Findings are deduplicated by `(test, type, tool, arg, uri, title)`; repeated
payloads merge into one finding with combined evidence and an `occurrences`
count. Secrets are masked before they enter a report.

## Reports

```bash
python3 mcpwn.py --output-json report.json \
                 --output-html report.html \
                 --output-sarif report.sarif \
                 python3 my_server.py
```

JSON includes `summary.total`, `by_type`, `by_severity`, `by_confidence` and
`verified`. SARIF includes rules, severity levels, fingerprints, CWE and
confidence properties for CI/CD. HTML is self-contained and escapes all
content.

## CLI reference

| Flag | Description | Default |
|---|---|---|
| `--target URL` | Streamable HTTP endpoint | none |
| `--header NAME:VALUE` | HTTP header (repeatable) | none |
| `--safe-mode` | Skip destructive and fuzzing suites | off |
| `--allow-destructive` | Enable exhaustion, flood, race and deserialization probes | off |
| `--quick` | Fewer payloads, 5 s timeout, stop on first injection finding | off |
| `--rce-only` | Only the command-injection suite | off |
| `--tags TAG...` | Run only matching suites (`protocol`, `fuzzing`, `injection`, `static`, `auth`, `ssrf`, `oob`, `timing`) | all |
| `--exclude-tags TAG...` | Skip matching suites | none |
| `--timeout SECONDS` | Per-request timeout | 10 |
| `--profile FILE` | Threshold/behavior profile (e.g. `profiles/paranoid.json`) | none |
| `--parallel` | Concurrent subscription flooding | off |
| `--max-requests N` | Global request budget | 20000 |
| `--max-concurrency N` | Worker ceiling | 8 |
| `--max-payload-bytes N` | Probe size ceiling | 1 MiB |
| `--flood-count N` | Subscriptions in the flood test | 200 |
| `--oob-port N` | UDP port for the OOB DNS listener | 53 |
| `--oob-callback-base URL` | Externally reachable SSRF callback base | local listener |
| `--ssrf-all-args` | Probe all arguments for SSRF, not only URL-like ones | off |
| `--fail-on LEVEL` | Exit 2 at or above this severity (`low`…`critical`) | `none` |
| `--strict-protocol` | Reject unknown negotiated protocol versions | off |
| `--verbose` | Debug logging | off |
| `--output-json/-html/-sarif` | Report paths | none |
| `--github-repo OWNER/REPO` | Assess a GitHub MCP repository (repeatable) | none |
| `--github-search QUERY` | Discover MCP repositories through GitHub search | none |
| `--github-limit N` | Maximum search results (1–50) | 10 |
| `--github-max-files N` | Source files inspected per repository | 25 |
| `--github-include-archived` | Include archived repositories in search | off |
| `--github-no-code` | Metadata/README only; skip source blobs | off |
| `--github-json PATH` | GitHub assessment JSON | none |
| `--github-markdown PATH` | GitHub assessment Markdown | none |
| `--github-token-env NAME` | Environment variable holding the token | `GITHUB_TOKEN` |
| `--github-run` | Run a launch recipe in Docker | off |
| `--github-dry-run` | Print the sandbox command without executing | off |
| `--github-command CMD` | Override the launch command (one repository) | none |
| `--github-network` | Allow network inside the Docker sandbox | off |
| `--github-sandbox {auto,docker}` | Runtime sandbox backend | `auto` |
| `--github-image IMAGE` | Docker image for `--github-run` | inferred |
| `--allow-remote-code` | Required gate for `--github-run` | off |

## Architecture

```
CLI → MCPPentester → McpSession → Transport (stdio | Streamable HTTP)
                        │              └── reader thread → pending futures by id
                        ├── SafetyPolicy (budget, gates, limits)
                        └── Evidence → Reporter (JSON / HTML / SARIF)
```

GitHub mode is a separate target provider:

```
GitHub API → GitHubClient → static assessment
                         └→ Docker sandbox → MCPPentester → McpSession
```

Full design, sequence diagrams and the extension guide:
[ARCHITECTURE.md](docs/ARCHITECTURE.md).
Threat surface and confidence policy: [THREAT_MODEL.md](docs/THREAT_MODEL.md).
Assessment and backlog: [ENGINEERING_ASSESSMENT.md](docs/ENGINEERING_ASSESSMENT.md).

## Testing

```bash
python3 -m pytest tests_unit -q
python3 -m pytest tests_unit --cov=. --cov-report=term-missing
python3 -m flake8 core tests tests_unit mcpwn.py payloads.py \
    test_data/mcp_test_server.py
.venv-tools/bin/bandit -r core mcpwn.py payloads.py -ll
```

Current snapshot: **160 tests passing**, **70% coverage**, flake8 clean, no
medium/high Bandit findings. Methodology and known gaps:
[TESTING.md](docs/TESTING.md).

## Limitations

- Static metadata findings (poisoning, credentials, chains) require manual
  review and are never marked confirmed.
- Timing analysis is weak on noisy hosts; it cannot prove command execution.
- Authorization testing needs credentials supplied with `--header`; OAuth/OIDC
  interactive flows are not implemented.
- The HTTP transport was verified against a local MCP-shaped server, not a
  production third-party deployment.
- GitHub runtime scans require a running Docker daemon. The static assessment
  and `--github-dry-run` work without one.
- GitHub static indicators are review prompts, not confirmed vulnerabilities;
  dynamic tool behavior still requires a runtime scan.
- Unauthenticated GitHub API access is limited to 60 requests/hour; use
  `GITHUB_TOKEN` for discovery at scale.
- Windows process semantics are not covered in this release.
- Reading declared resources to hunt for secrets is intentionally not done by
  default; it requires target-specific consent.
- Mcpwn complements, but does not replace, manual review of business logic and
  multi-step agent behavior.

## Disclaimer

Use this tool only on systems you are authorized to test. You are responsible
for complying with applicable law and contracts. The authors accept no liability
for misuse or damage.

## Author

**Teycir Ben Soltane**
- Website: [teycirbensoltane.tn](https://teycirbensoltane.tn)
- Email: teycir@pxdmail.net
- GitHub: [@Teycir](https://github.com/Teycir)

## License

MIT — see [LICENSE](LICENSE).
