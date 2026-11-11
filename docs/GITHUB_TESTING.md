# Testing GitHub-hosted MCP servers

Mcpwn can use the GitHub API to find MCP repositories, assess their supply-chain
and code surface, and optionally run a selected launch command in a Docker
sandbox. Static assessment is the default and never executes repository code.

## 1. Token setup

Create a local `.env` (already ignored by git) from the template:

```bash
cp .env.example .env
```

Set a token with read access to the repositories you want to assess. Both
`Github_Token` and `GITHUB_TOKEN` are accepted:

```dotenv
Github_Token=github_pat_...
```

The token is read from the environment first, then from `.env`; the mixed-case
spelling is canonicalized to `GITHUB_TOKEN` for the CLI. It is sent
only to the GitHub API. It is **not** forwarded to the Docker sandbox, the MCP
server, logs, JSON/Markdown reports, or SARIF. The client drops the
`Authorization` header if GitHub redirects to another host. `--github-token-env
NAME` selects a different variable name.

Unauthenticated access works for public repositories but is limited to roughly
60 API requests per hour. A token is strongly recommended for source inspection
or multiple repositories.

## 2. Static discovery and assessment

```bash
# Search repositories and inspect metadata, README, manifests and a bounded
# number of source files.
python3 mcpwn.py --github-search "topic:mcp-server language:python" \
    --github-limit 5 --github-max-files 25 \
    --github-json github-report.json \
    --github-markdown github-report.md

# Assess explicit repositories without executing them.
python3 mcpwn.py \
    --github-repo modelcontextprotocol/servers \
    --github-repo owner/another-server \
    --github-json github-report.json
```

Static mode reports:

- repository metadata, default branch, license and archived state;
- detected server kind (`npm`, `python`, `docker` or `unknown`) and package name;
- launch candidates extracted from README code blocks/JSON and `package.json`
  `bin` entries;
- review indicators for install lifecycle scripts, unpinned dependencies,
  Docker remote-install patterns, process execution, dynamic code/unsafe
  deserialization and network access;
- the files actually inspected, so the result is reproducible and its coverage
  is visible.

These indicators are **review prompts, not confirmed vulnerabilities**. A
`GITHUB_PROCESS_EXECUTION` indicator means the code has a process-execution
surface; it does not prove that an argument is attacker-controlled.

Use `--github-no-code` to skip source blobs and reduce API usage.

## 3. Runtime testing

Runtime testing is opt-in and has two independent gates:

```bash
python3 mcpwn.py --github-repo owner/repo \
    --github-run --allow-remote-code \
    --github-json github-report.json
```

`--github-run` selects the first runnable launch recipe. A recipe that requires
a package install, or a Docker-in-Docker command, is skipped; supply an explicit
command instead:

```bash
python3 mcpwn.py --github-repo owner/repo \
    --github-run --allow-remote-code \
    --github-network \
    --github-command "npx -y @scope/server"
```

Inspect the exact command and constraints first:

```bash
python3 mcpwn.py --github-repo owner/repo \
    --github-run --github-dry-run --allow-remote-code
```

A dry run downloads nothing and executes nothing. It prints the generated
`docker run` argv, including the image, mount and network mode, in the JSON
report.

### Docker sandbox

Runtime commands run only through `docker run`:

- no network by default (`--network none`); `--github-network` opts into the
  bridge network;
- read-only container root with a writable disposable workspace copy and
  `tmpfs` for `/tmp`;
- all Linux capabilities dropped and `no-new-privileges`;
- PID, memory and CPU limits;
- a fixed environment (`HOME=/tmp`, cache directories, no host secrets);
- no automatic host execution and no nested Docker commands.

The repository is downloaded from GitHub as a tarball into a temporary
directory. Extraction rejects absolute paths, `..`, symlinks, hard links, device
files and oversized archives before anything is mounted.

**Docker daemon:** a running Docker daemon is required for `--github-run`
(without `--github-dry-run`). If Docker is unavailable, static assessment still
works and the runtime result is reported as failed/skipped.

**Installs and builds:** the sandbox does not silently run `npm install` or
`pip install`. If a server needs a build, provide an explicit command that does
the setup inside the disposable container, for example:

```bash
--github-image node:20-bookworm-slim \
--github-command "sh -lc 'cd /workspace && npm ci && npm run build && node dist/index.js'"
```

That command runs inside the container, not on the host, and still needs
`--github-network` if it downloads dependencies. `--github-image` is also
available for Python/uv and custom base images.

## 4. Reports

`--github-json PATH` writes a machine-readable report containing repository
profiles, indicators, launch candidates, and optional runtime findings.
`--github-markdown PATH` writes a review-friendly table and per-repository
sections. `--fail-on LEVEL` applies to both static indicators and runtime MCP
findings.

## 5. Verification snapshot

Verified in this tree on 2026-11-11:

| Check | Result |
|---|---|
| Provider unit tests (`test_github.py`) | 25 passed |
| Full suite | 160 passed |
| Live GitHub static search (authenticated) | 5 repositories assessed; 20 indicators; no code executed |
| Curated static batch | 6 repositories assessed; 26 indicators |
| GitHub Docker dry-run | constrained command generated |
| Docker runtime scans | **3 completed**: `server-memory`, `@playwright/mcp`, `server-sequential-thinking` |
| Runtime findings | confirmed `STATE_BYPASS` and `STATE_RESET` on all three; Playwright also produced 3 `possible` attack-chain findings |

The live check validates API authentication/error handling, README/manifest
inspection, launch-candidate extraction and report generation. The runtime checks
validate Docker startup, MCP initialization, tool discovery, scanning and
cleanup across different packages and repositories. They do not prove that a
third-party server is safe; the state findings describe observed protocol
behavior, not a safety verdict.

The runtime exercises covered automatic recipe selection (`@playwright/mcp`) and
explicit `--github-command` selection (`server-sequential-thinking`). A large
monorepo (`n8n-io/n8n`) also exercised the graceful tree-size fallback during
live discovery.

## 6. Limitations

- GitHub search returns repositories, not a curated MCP registry; review the
  match before drawing conclusions.
- Static inspection is bounded by `--github-max-files` and inspects only known
  source extensions and root-level manifests.
- A README launch command is untrusted text until reviewed with
  `--github-dry-run`.
- The Docker sandbox reduces host risk but is not a formal security boundary
  against a Docker/kernel escape; use a dedicated test host for hostile code.
- Only the `npx` runtime path has been exercised end to end; `uvx` and custom
  images are implemented but not yet verified against a live server.
- OAuth/OIDC MCP authorization flows are not implemented; only header-based
  HTTP auth is tested.
