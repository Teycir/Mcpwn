"""Tests for GitHub discovery, static assessment, and sandbox planning."""
import base64
import io
import json
import subprocess
import sys
import tarfile
import urllib.error
from email.message import Message
from urllib.parse import urlsplit

import pytest

from core.github import (
    DockerSandbox,
    GitHubAuthError,
    GitHubClient,
    GitHubError,
    GitHubRateLimitError,
    Repository,
    assess_repository,
    build_report,
    extract_launch_candidates,
    load_env_file,
    report_exit_code,
    resolve_repository,
    safe_extract_tarball,
    select_runtime_command,
    write_json_report,
    write_markdown_report,
)
from mcpwn import build_parser


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self.body = body if isinstance(body, bytes) else str(body).encode()
        self.status = status
        self.headers = headers or {}

    def read(self, amount=-1):
        if amount is None or amount < 0:
            return self.body
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        path = urlsplit(request.full_url).path
        route = self.routes.get(path)
        if route is None:
            headers = Message()
            raise urllib.error.HTTPError(
                request.full_url, 404, "Not Found", headers,
                io.BytesIO(b"{}"))
        if isinstance(route, Exception):
            raise route
        return FakeResponse(route)


def _client(routes, token=None):
    opener = FakeOpener(routes)
    return GitHubClient(token=token, opener=opener), opener


def _blob(text):
    return {"content": base64.b64encode(text.encode()).decode()}


def _http_error(code, headers=None, body=b""):
    return urllib.error.HTTPError(
        "https://api.github.com/repos/acme/server", code, "error",
        headers or Message(), io.BytesIO(body))


def _tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload.encode()
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                archive.addfile(info)
    return buffer.getvalue()


def test_load_env_file_does_not_override_environment(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nexport GITHUB_TOKEN='from-file'\nOTHER=value\n"
        "BAD-KEY=nope\n", encoding="utf-8")
    environ = {"GITHUB_TOKEN": "from-shell"}
    values = load_env_file(env_file, environ)
    assert values["GITHUB_TOKEN"] == "from-file"
    assert values["OTHER"] == "value"
    assert "BAD-KEY" not in values
    assert environ["GITHUB_TOKEN"] == "from-shell"
    assert environ["OTHER"] == "value"

    alias_file = tmp_path / ".env.alias"
    alias_file.write_text("Github_Token=mixed\n", encoding="utf-8")
    alias_environ = {}
    load_env_file(alias_file, alias_environ)
    assert alias_environ["GITHUB_TOKEN"] == "mixed"
    assert alias_environ["Github_Token"] == "mixed"


@pytest.mark.parametrize("spec,expected", [
    ("acme/server", "acme/server"),
    ("https://github.com/acme/server", "acme/server"),
    ("https://github.com/acme/server.git/", "acme/server"),
    ("git@github.com:acme/server.git", "acme/server"),
])
def test_resolve_repository_variants(spec, expected):
    assert resolve_repository(spec) == expected


@pytest.mark.parametrize("spec", [
    "", "acme", "acme/server/extra",
    "https://gitlab.com/acme/server", "acme/../server",
])
def test_resolve_repository_rejects_invalid_values(spec):
    with pytest.raises(ValueError):
        resolve_repository(spec)


def test_search_uses_token_and_filters_archived():
    routes = {
        "/search/repositories": json.dumps({
            "items": [
                {"full_name": "acme/server", "stargazers_count": 50,
                 "default_branch": "main", "archived": False},
                {"full_name": "old/server", "stargazers_count": 100,
                 "default_branch": "main", "archived": True},
            ],
        }),
    }
    client, opener = _client(routes, token="ghp_secret")
    repos = client.search_repositories("mcp-server", limit=5)
    assert [repo.full_name for repo in repos] == ["acme/server"]
    request = opener.requests[0]
    assert request.headers.get("Authorization") == "Bearer ghp_secret"
    assert "archived%3Afalse" in request.full_url


def test_401_is_reported_without_leaking_the_token():
    client, _ = _client(
        {"/repos/acme/server": _http_error(401)}, token="ghp_secret")
    with pytest.raises(GitHubAuthError) as info:
        client.get_repository("acme/server")
    assert "ghp_secret" not in str(info.value)


def test_rate_limit_is_distinguishable_from_permission_error():
    headers = Message()
    headers["X-RateLimit-Remaining"] = "0"
    headers["X-RateLimit-Reset"] = "1700000000"
    client, _ = _client(
        {"/repos/acme/server": _http_error(403, headers)})
    with pytest.raises(GitHubRateLimitError) as info:
        client.get_repository("acme/server")
    assert info.value.reset_at == 1700000000


def test_static_assessment_finds_supply_chain_and_code_risks():
    readme = (
        "# Acme MCP\n\n"
        "```bash\nnpx -y @acme/server\n```\n\n"
        "```json\n"
        '{"mcpServers":{"acme":{"command":"uvx",'
        '"args":["acme-server"]}}}\n'
        "```\n"
    )
    package = json.dumps({
        "name": "@acme/server",
        "bin": {"acme-server": "dist/index.js"},
        "scripts": {"postinstall": "node install.js"},
        "dependencies": {"left-pad": "*", "good": "1.2.3"},
    })
    code = (
        'const { exec } = require("child_process");\n'
        "exec(userInput);\n"
        "eval(userInput);\n"
        'fetch("https://example.test");\n'
    )
    routes = {
        "/repos/acme/server/readme": readme,
        "/repos/acme/server/git/trees/main": json.dumps({
            "tree": [
                {"path": "package.json", "type": "blob",
                 "sha": "sha-pkg", "size": len(package)},
                {"path": "src/index.js", "type": "blob",
                 "sha": "sha-code", "size": len(code)},
                {"path": "LICENSE", "type": "blob",
                 "sha": "sha-license", "size": 20},
                {"path": "tests/test.js", "type": "blob",
                 "sha": "sha-test", "size": 20},
            ],
            "truncated": False,
        }),
        "/repos/acme/server/git/blobs/sha-pkg": json.dumps(_blob(package)),
        "/repos/acme/server/git/blobs/sha-code": json.dumps(_blob(code)),
        "/repos/acme/server/git/blobs/sha-license": json.dumps(
            _blob("MIT")),
    }
    client, _ = _client(routes)
    repo = Repository(full_name="acme/server", default_branch="main")
    assessment = assess_repository(client, repo, max_files=10)
    assert assessment["server"]["kind"] == "npm"
    assert assessment["server"]["package"] == "@acme/server"
    assert assessment["files_scanned"] == ["package.json", "src/index.js"]
    rules = {item["rule"] for item in assessment["risk_indicators"]}
    assert "GITHUB_INSTALL_SCRIPT" in rules
    assert "GITHUB_UNPINNED_DEPENDENCY" in rules
    assert "GITHUB_DYNAMIC_CODE" in rules
    assert "GITHUB_PROCESS_EXECUTION" in rules
    assert "GITHUB_REMOTE_LAUNCH" in rules
    assert "GITHUB_NO_LICENSE" not in rules
    sources = {
        candidate["source"]
        for candidate in assessment["server"]["launch_candidates"]
    }
    assert "readme" in sources and "readme-json" in sources
    assert assessment["risk_score"] >= 50


def test_assessment_survives_a_tree_fetch_failure():
    class BrokenSourceClient:
        def get_readme(self, full_name):
            return "npx -y @scope/mcp-server\n"

        def fetch_source(self, repo, max_files=25):
            raise GitHubError("tree exceeded the response ceiling")

    assessment = assess_repository(
        BrokenSourceClient(),
        Repository(full_name="acme/large", default_branch="main"),
        max_files=10,
    )
    assert "tree exceeded" in assessment["tree_error"]
    assert assessment["server"]["kind"] == "npm"
    assert assessment["server"]["launch_candidates"][0]["command"] == [
        "npx", "-y", "@scope/mcp-server"]


def test_launch_candidates_include_readme_json_and_package_bin():
    readme = (
        "npx -y @scope/server # docs-only suffix\n"
        "python3 server.py\n"
        "python\n"
        "docker run -i example/server\n"
    )
    candidates = extract_launch_candidates(readme, {
        "package.json": json.dumps({
            "name": "local",
            "bin": {"local-server": "dist/index.js"},
        }),
    })
    commands = [candidate.command for candidate in candidates]
    assert ["npx", "-y", "@scope/server"] in commands
    assert all("#" not in part for command in commands for part in command)
    assert ["python3", "server.py"] in commands
    assert ["docker", "run", "-i", "example/server"] in commands
    assert ["python"] not in commands
    assert ["node", "dist/index.js"] in commands
    docker = next(c for c in candidates if c.command[0] == "docker")
    assert docker.runnable is False
    package = next(c for c in candidates if c.command[0] == "node")
    assert package.requires_install is True


def test_safe_extract_tarball_accepts_a_normal_archive(tmp_path):
    data = _tar([
        ("acme-sha/README.md", "hello", "file"),
        ("acme-sha/src/app.py", "print(1)", "file"),
    ])
    safe_extract_tarball(data, tmp_path)
    assert (tmp_path / "README.md").read_text() == "hello"
    assert (tmp_path / "src" / "app.py").read_text() == "print(1)"


@pytest.mark.parametrize("entries", [
    [("../evil.py", "bad", "file")],
    [("acme-sha/link", "/etc/passwd", "symlink")],
    [("/etc/passwd", "bad", "file")],
])
def test_safe_extract_tarball_rejects_unsafe_members(tmp_path, entries):
    with pytest.raises(GitHubError):
        safe_extract_tarball(_tar(entries), tmp_path)


def test_docker_command_is_constrained(tmp_path):
    sandbox = DockerSandbox(docker="/usr/bin/docker")
    command = sandbox.command(tmp_path, ["python3", "server.py"])
    assert command[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "ALL" in command
    assert "no-new-privileges" in command
    assert "--user" in command
    tmpfs = command[command.index("--tmpfs") + 1]
    assert "exec" in tmpfs.split(",")
    assert "{}:/workspace:rw".format(tmp_path.resolve()) in command
    network_index = command.index("--network")
    assert command[network_index + 1] == "none"
    assert "python:3.12-slim" in command
    assert command[command.index("-w") + 1] == "/workspace"

    networked = sandbox.command(
        tmp_path, ["npx", "-y", "pkg"], network=True)
    network_index = networked.index("--network")
    assert networked[network_index + 1] == "bridge"
    assert "node:20-bookworm-slim" in networked
    assert networked[networked.index("-w") + 1] == "/tmp"


def test_runtime_selection_skips_install_only_recipes():
    assessment = {"server": {"launch_candidates": [
        {"command": ["node", "utils/generate-links.js"], "runnable": True,
         "requires_install": False, "requires_network": False},
        {"command": ["node", "dist/index.js"], "runnable": True,
         "requires_install": True, "requires_network": False},
        {"command": ["npx", "-y", "@scope/mcp-server"], "runnable": True,
         "requires_install": False, "requires_network": True},
        {"command": ["npx", "@scope/mcp-server", "--config",
                     "path/to/config.json"], "runnable": True,
         "requires_install": False, "requires_network": True},
        {"command": ["npx", "@scope/mcp-server", "--port", "8931"],
         "runnable": True, "requires_install": False,
         "requires_network": True},
        {"command": ["docker", "run", "image"], "runnable": False,
         "requires_install": False, "requires_network": True},
    ]}}
    assert select_runtime_command(assessment)["command"] == [
        "npx", "-y", "@scope/mcp-server"]
    assert select_runtime_command(
        assessment, "python3 server.py")["command"] == [
        "python3", "server.py"]


def test_report_serializes_and_applies_failure_threshold(tmp_path):
    assessment = {
        "repository": {"full_name": "acme/server"},
        "server": {"kind": "npm", "package": "acme",
                   "launch_candidates": []},
        "risk_score": 15,
        "risk_level": "low",
        "risk_indicators": [{
            "rule": "GITHUB_INSTALL_SCRIPT",
            "severity": "MEDIUM",
            "title": "install script",
        }],
    }
    report = build_report("mcp", [assessment])
    assert report["summary"]["repositories"] == 1
    assert report["summary"]["risk_indicators"] == 1
    assert report_exit_code(report, "medium") == 2
    assert report_exit_code(report, "high") == 0
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    write_json_report(str(json_path), report)
    write_markdown_report(str(markdown_path), report)
    assert json.loads(json_path.read_text())["mode"] == "github"
    assert "acme/server" in markdown_path.read_text()


def test_cli_exposes_github_mode_and_requires_explicit_runtime_gate():
    parser = build_parser()
    args = parser.parse_args([
        "--github-repo", "acme/server",
        "--github-run", "--github-dry-run", "--allow-remote-code",
        "--github-json", "report.json",
    ])
    assert args.github_repo == ["acme/server"]
    assert args.github_run is True
    assert args.github_dry_run is True
    assert args.allow_remote_code is True


def test_github_run_refuses_to_execute_without_remote_code_gate():
    result = subprocess.run(
        [sys.executable, "mcpwn.py", "--github-repo", "acme/server",
         "--github-run"],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 1
    assert "allow-remote-code" in (result.stdout + result.stderr)
