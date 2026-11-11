"""GitHub-hosted MCP repository discovery and assessment.

The default path is read-only: discover repositories through the GitHub API,
inspect manifests and a bounded set of source files, and report review
indicators plus launch recipes.  Runtime scanning is opt-in and always runs
the target command inside a Docker sandbox; no host execution path exists.

The GitHub token is read from ``GITHUB_TOKEN`` (or ``--github-token-env``),
including a local ``.env`` file.  It is only sent to the GitHub API, never to
the sandbox, the target server, or a report.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import re
import shlex
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from core.reporter import SCHEMA_VERSION, VERSION

logger = logging.getLogger("mcpwn.github")

API_URL = "https://api.github.com"
USER_AGENT = "Mcpwn/{}".format(VERSION)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_README_CHARS = 200_000
MAX_SOURCE_FILE_BYTES = 160_000
MAX_ARCHIVE_FILES = 2_000
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_LAUNCH_CANDIDATES = 12
MAX_INDICATORS_PER_RULE = 3
CONTAINER_TMP = "/tmp"  # nosec B108 - path inside the Docker container

RISK_WEIGHTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30}
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Dockerfile",
    "mcp.json",
    ".mcp.json",
    "server.json",
    "smithery.yaml",
}
CODE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".java", ".rb", ".sh", ".bash", ".ps1",
}
ENTRYPOINT_NAMES = {
    "index.js", "index.mjs", "index.ts", "server.js", "server.ts",
    "main.py", "server.py", "app.py", "app.js", "app.ts", "cli.py",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", "vendor", "dist", "build", "coverage",
    "htmlcov", "__pycache__", ".venv", "venv", "test", "tests", "docs",
    "examples", "fixtures",
}
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
RUNNERS = {"npx", "uvx", "python", "python3", "node", "docker"}

FENCED_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
INSTALL_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b", re.IGNORECASE)
REMOTE_ADD_RE = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE | re.MULTILINE)
UNPINNED_RE = re.compile(r"^(?:\*|latest)$", re.IGNORECASE)


class GitHubError(RuntimeError):
    """A recoverable GitHub API, repository, or sandbox error."""


class GitHubAuthError(GitHubError):
    """GitHub rejected the supplied token."""


class GitHubNotFound(GitHubError):
    """The requested repository or object does not exist."""


class GitHubRateLimitError(GitHubError):
    """The GitHub API rate limit was exhausted."""

    def __init__(self, message: str, reset_at: Optional[int] = None):
        super().__init__(message)
        self.reset_at = reset_at


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Drop Authorization when a redirect leaves the API host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(
            req, fp, code, msg, headers, newurl)
        if redirected is not None:
            old_host = urllib.parse.urlsplit(req.full_url).hostname
            new_host = urllib.parse.urlsplit(newurl).hostname
            if old_host != new_host:
                redirected.remove_header("Authorization")
        return redirected


def load_env_file(path: Optional[os.PathLike] = None,
                  environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Load simple ``KEY=VALUE`` entries from a local ``.env`` file.

    Existing environment variables win, so a shell export can override the
    file.  The parser intentionally supports only the subset used by Mcpwn and
    never logs values.
    """
    environ = os.environ if environ is None else environ
    env_path = Path(path or os.environ.get("MCPWN_ENV_FILE", ".env"))
    if not env_path.is_file():
        return {}
    values: Dict[str, str] = {}
    try:
        with open(env_path, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                    continue
                if (len(value) >= 2 and value[0] == value[-1]
                        and value[0] in "\"'"):
                    value = value[1:-1]
                values[key] = value
                if key not in environ:
                    environ[key] = value
    except OSError as exc:
        logger.warning("cannot read %s: %s", env_path, exc)
    # Accept the mixed-case spelling used in some local .env files while
    # keeping the canonical uppercase name for --github-token-env.
    for key, value in values.items():
        if key.lower() == "github_token":
            environ.setdefault("GITHUB_TOKEN", value)
    return values


def resolve_repository(spec: str) -> str:
    """Normalize ``owner/repo``, GitHub URLs, and git SSH URLs."""
    raw = str(spec or "").strip()
    if not raw:
        raise ValueError("repository must not be empty")
    if raw.startswith("git@github.com:"):
        raw = raw[len("git@github.com:"):]
    elif raw.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(raw)
        if parsed.hostname not in ("github.com", "www.github.com"):
            raise ValueError(
                "repository URL must point at github.com: {}".format(spec))
        raw = parsed.path.strip("/")
    raw = raw.strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    parts = raw.split("/")
    if len(parts) != 2:
        raise ValueError(
            "expected owner/repository, got {!r}".format(spec))
    owner, name = parts
    for part in (owner, name):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", part):
            raise ValueError("invalid GitHub repository: {!r}".format(spec))
    return "{}/{}".format(owner, name)


@dataclass
class Repository:
    """Subset of the GitHub repository resource used by Mcpwn."""

    full_name: str
    html_url: str = ""
    description: str = ""
    stars: int = 0
    archived: bool = False
    license_name: str = ""
    default_branch: str = "main"
    language: str = ""
    topics: List[str] = field(default_factory=list)
    updated_at: str = ""
    pushed_at: str = ""

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "Repository":
        license_info = data.get("license") or {}
        if not isinstance(license_info, dict):
            license_info = {}
        license_name = str(
            license_info.get("spdx_id") or license_info.get("name") or "")
        if license_name.upper() == "NOASSERTION":
            license_name = ""
        topics = data.get("topics") or []
        if not isinstance(topics, list):
            topics = []
        return cls(
            full_name=str(data.get("full_name") or ""),
            html_url=str(data.get("html_url") or ""),
            description=str(data.get("description") or ""),
            stars=int(data.get("stargazers_count") or 0),
            archived=bool(data.get("archived")),
            license_name=license_name,
            default_branch=str(data.get("default_branch") or "main"),
            language=str(data.get("language") or ""),
            topics=[str(topic) for topic in topics],
            updated_at=str(data.get("updated_at") or ""),
            pushed_at=str(data.get("pushed_at") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "full_name": self.full_name,
            "html_url": self.html_url,
            "description": self.description,
            "stars": self.stars,
            "archived": self.archived,
            "license": self.license_name,
            "default_branch": self.default_branch,
            "language": self.language,
            "topics": list(self.topics),
            "updated_at": self.updated_at,
            "pushed_at": self.pushed_at,
        }


@dataclass
class LaunchCandidate:
    """A command extracted from a README or package manifest."""

    command: List[str]
    source: str
    requires_network: bool = False
    requires_install: bool = False
    runnable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": list(self.command),
            "source": self.source,
            "requires_network": self.requires_network,
            "requires_install": self.requires_install,
            "runnable": self.runnable,
        }


@dataclass
class RiskIndicator:
    """A static observation that needs review; not a confirmed vulnerability."""

    rule: str
    severity: str
    title: str
    path: str = ""
    line: int = 0
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
        }


class GitHubClient:
    """Small GitHub REST client using only the standard library."""

    def __init__(self, token: Optional[str] = None, *,
                 base_url: str = API_URL, timeout: float = 20.0,
                 opener=None):
        self._token = (token or "").strip() or None
        self.base_url = base_url.rstrip("/")
        self.timeout = max(1.0, float(timeout))
        self._opener = opener or urllib.request.build_opener(
            _SafeRedirectHandler()).open

    def __repr__(self) -> str:
        return "GitHubClient(base_url={!r}, authenticated={})".format(
            self.base_url, bool(self._token))

    def _headers(self, accept: str) -> Dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = "Bearer {}".format(self._token)
        return headers

    def _fetch(self, path: str, params: Optional[Dict[str, Any]],
               accept: str, max_bytes: int) -> bytes:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(
            url, headers=self._headers(accept))
        try:
            with self._opener(request, timeout=self.timeout) as response:
                data = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            body = exc.read(4096).decode("utf-8", "replace")
            self._raise_http_error(exc, path, body)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise GitHubError(
                "GitHub API request failed for {}: {}".format(path, exc))
        if len(data) > max_bytes:
            raise GitHubError(
                "GitHub response for {} exceeded {} bytes".format(
                    path, max_bytes))
        return data

    @staticmethod
    def _raise_http_error(exc: urllib.error.HTTPError, path: str,
                          body: str) -> None:
        snippet = " ".join(body.split())[:160]
        if exc.code == 401:
            raise GitHubAuthError(
                "GitHub rejected the token (401); check the value in .env")
        if exc.code in (403, 429):
            headers = exc.headers or {}
            remaining = headers.get("X-RateLimit-Remaining")
            reset = headers.get("X-RateLimit-Reset")
            if exc.code == 429 or remaining == "0":
                reset_at = int(reset) if reset and reset.isdigit() else None
                when = (
                    datetime.fromtimestamp(
                        reset_at, timezone.utc).isoformat()
                    if reset_at else "unknown")
                raise GitHubRateLimitError(
                    "GitHub API rate limit exhausted (reset {})".format(when),
                    reset_at=reset_at)
            raise GitHubError(
                "GitHub API forbidden (403) for {}: {}".format(path, snippet))
        if exc.code == 404:
            raise GitHubNotFound("GitHub object not found: {}".format(path))
        raise GitHubError(
            "GitHub API HTTP {} for {}: {}".format(
                exc.code, path, snippet))

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None,
                 accept: str = "application/vnd.github+json") -> Any:
        data = self._fetch(path, params, accept, MAX_RESPONSE_BYTES)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GitHubError(
                "GitHub returned invalid JSON for {}: {}".format(path, exc))

    def search_repositories(self, query: str, limit: int = 10,
                            include_archived: bool = False
                            ) -> List[Repository]:
        query = str(query or "").strip()
        if not query:
            raise ValueError("GitHub search query must not be empty")
        limit = max(1, min(int(limit), 50))
        if not include_archived and "archived:" not in query:
            query += " archived:false"
        payload = self._request(
            "/search/repositories",
            {"q": query, "sort": "stars", "order": "desc",
             "per_page": limit},
        )
        items = payload.get("items", []) if isinstance(payload, dict) else []
        repositories = [
            Repository.from_api(item)
            for item in items if isinstance(item, dict)
        ]
        if not include_archived:
            repositories = [repo for repo in repositories if not repo.archived]
        return repositories[:limit]

    def get_repository(self, spec: str) -> Repository:
        full_name = resolve_repository(spec)
        payload = self._request(
            "/repos/{}".format(urllib.parse.quote(full_name, safe="/")))
        if not isinstance(payload, dict):
            raise GitHubError("unexpected repository response")
        repo = Repository.from_api(payload)
        if not repo.full_name:
            repo.full_name = full_name
        return repo

    def get_readme(self, full_name: str) -> str:
        full_name = resolve_repository(full_name)
        try:
            data = self._fetch(
                "/repos/{}/readme".format(
                    urllib.parse.quote(full_name, safe="/")),
                None, "application/vnd.github.raw+json", MAX_RESPONSE_BYTES)
        except GitHubNotFound:
            return ""
        return data.decode("utf-8", "replace")[:MAX_README_CHARS]

    def get_tree(self, full_name: str, ref: str) -> Dict[str, Any]:
        full_name = resolve_repository(full_name)
        payload = self._request(
            "/repos/{}/git/trees/{}".format(
                urllib.parse.quote(full_name, safe="/"),
                urllib.parse.quote(ref, safe="")),
            {"recursive": "1"},
        )
        if not isinstance(payload, dict):
            raise GitHubError("unexpected tree response")
        return payload

    def get_blob(self, full_name: str, sha: str) -> Optional[str]:
        full_name = resolve_repository(full_name)
        payload = self._request(
            "/repos/{}/git/blobs/{}".format(
                urllib.parse.quote(full_name, safe="/"),
                urllib.parse.quote(sha, safe="")),
        )
        content = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(content, str):
            return None
        try:
            raw = base64.b64decode(content)
        except (ValueError, TypeError):
            return None
        if len(raw) > MAX_SOURCE_FILE_BYTES or b"\x00" in raw:
            return None
        return raw.decode("utf-8", "replace")

    def fetch_source(self, repo: Repository, max_files: int = 25
                     ) -> Tuple[Dict[str, str], Set[str], bool]:
        tree = self.get_tree(repo.full_name, repo.default_branch)
        entries = [
            entry for entry in tree.get("tree", [])
            if isinstance(entry, dict) and entry.get("type") == "blob"
        ]
        all_paths = {
            str(entry.get("path")) for entry in entries
            if entry.get("path")
        }
        selected = _select_source_entries(entries, max_files)
        files: Dict[str, str] = {}
        for entry in selected:
            text = self.get_blob(repo.full_name, str(entry.get("sha") or ""))
            if text is not None:
                files[str(entry["path"])] = text
        return files, all_paths, bool(tree.get("truncated"))

    def download_archive(self, repo: Repository, destination: Path,
                         ref: Optional[str] = None) -> Path:
        full_name = resolve_repository(repo.full_name)
        ref = ref or repo.default_branch or "main"
        data = self._fetch(
            "/repos/{}/tarball/{}".format(
                urllib.parse.quote(full_name, safe="/"),
                urllib.parse.quote(ref, safe="")),
            None, "application/vnd.github+json", MAX_ARCHIVE_BYTES)
        safe_extract_tarball(data, Path(destination))
        return Path(destination)


def _select_source_entries(entries: Iterable[Dict[str, Any]],
                           max_files: int) -> List[Dict[str, Any]]:
    max_files = max(1, int(max_files))
    candidates: List[Tuple[int, int, str, Dict[str, Any]]] = []
    for entry in entries:
        path = str(entry.get("path") or "")
        if not path or _is_excluded(path):
            continue
        try:
            size = int(entry.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if size < 0 or size > MAX_SOURCE_FILE_BYTES:
            continue
        name = PurePosixPath(path).name
        depth = path.count("/")
        if name in MANIFEST_NAMES and depth == 0:
            priority = 0
        elif name.lower() in ENTRYPOINT_NAMES or _is_code_path(path):
            priority = 1
        elif name in MANIFEST_NAMES:
            # Nested Dockerfiles and package manifests should not crowd
            # actual source files out of the bounded inspection budget.
            priority = 2
        else:
            continue
        candidates.append((priority, path.count("/"), path, entry))
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in candidates[:max_files]]


def _is_excluded(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part in EXCLUDED_PARTS for part in parts)


def _is_code_path(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in CODE_EXTENSIONS


def _find_file(files: Dict[str, str],
               name: str) -> Tuple[Optional[str], Optional[str]]:
    matches = [
        path for path in files
        if PurePosixPath(path).name == name
    ]
    if not matches:
        return None, None
    path = min(matches, key=lambda item: (item.count("/"), item))
    return path, files[path]


def _load_json(text: Optional[str]) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _candidate_from_tokens(tokens: Sequence[str], source: str
                           ) -> Optional[LaunchCandidate]:
    if not tokens or any("\x00" in token for token in tokens):
        return None
    executable = Path(tokens[0]).name
    if executable not in RUNNERS:
        return None
    if executable == "docker":
        if len(tokens) < 3 or tokens[1] != "run":
            return None
    elif len(tokens) < 2:
        # A bare ``python``/``node`` in prose is not a launch recipe.
        return None
    return LaunchCandidate(
        command=list(tokens),
        source=source,
        requires_network=executable in {"npx", "uvx", "docker"},
        runnable=executable != "docker",
    )


def _parse_command_line(line: str, source: str
                        ) -> Optional[LaunchCandidate]:
    line = line.strip()
    if line.startswith("$ "):
        line = line[2:].strip()
    line = line.strip("`").strip()
    if not line or line.startswith("#") or line.endswith("\\"):
        return None
    try:
        tokens = shlex.split(line, comments=True)
    except ValueError:
        return None
    return _candidate_from_tokens(tokens, source)


def _walk_json_commands(value: Any) -> Iterable[LaunchCandidate]:
    if isinstance(value, dict):
        command = value.get("command")
        args = value.get("args")
        if (isinstance(command, str)
                and (args is None or isinstance(args, list))):
            tokens = [command]
            if args:
                tokens.extend(str(arg) for arg in args)
            candidate = _candidate_from_tokens(tokens, "readme-json")
            if candidate is not None:
                yield candidate
        for child in value.values():
            yield from _walk_json_commands(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json_commands(child)


def extract_launch_candidates(readme: str,
                              files: Optional[Dict[str, str]] = None
                              ) -> List[LaunchCandidate]:
    """Extract runnable MCP launch recipes from README/manifest data."""
    files = files or {}
    candidates: List[LaunchCandidate] = []
    for line in (readme or "").splitlines():
        candidate = _parse_command_line(line, "readme")
        if candidate is not None:
            candidates.append(candidate)
    for block in FENCED_BLOCK_RE.findall(readme or ""):
        try:
            parsed = json.loads(block)
        except (TypeError, ValueError):
            continue
        candidates.extend(_walk_json_commands(parsed))

    _, package_text = _find_file(files, "package.json")
    package = _load_json(package_text) or {}
    bin_value = package.get("bin")
    if isinstance(bin_value, str):
        bin_value = {str(package.get("name") or "server"): bin_value}
    if isinstance(bin_value, dict):
        for _, path in sorted(bin_value.items()):
            if isinstance(path, str) and path:
                candidate = _candidate_from_tokens(
                    ["node", path], "package.json")
                if candidate is not None:
                    candidate.requires_install = True
                    candidates.append(candidate)
    return _dedupe_candidates(candidates)


def _dedupe_candidates(candidates: Iterable[LaunchCandidate]
                       ) -> List[LaunchCandidate]:
    seen: Set[Tuple[str, ...]] = set()
    result: List[LaunchCandidate] = []
    for candidate in candidates:
        key = tuple(candidate.command)
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
        if len(result) >= MAX_LAUNCH_CANDIDATES:
            break
    return result


def detect_kind(files: Dict[str, str],
                readme: str) -> Tuple[str, str]:
    _, package_text = _find_file(files, "package.json")
    package = _load_json(package_text)
    if package is not None:
        return "npm", str(package.get("name") or "")
    for name in ("pyproject.toml", "setup.py", "requirements.txt"):
        _, text = _find_file(files, name)
        if text:
            return "python", _python_package_name(files)
    if _find_file(files, "Dockerfile")[1]:
        return "docker", ""
    lowered = (readme or "").lower()
    if "npx " in lowered:
        return "npm", ""
    if "uvx " in lowered:
        return "python", ""
    if "docker run " in lowered:
        return "docker", ""
    return "unknown", ""


def _python_package_name(files: Dict[str, str]) -> str:
    _, text = _find_file(files, "pyproject.toml")
    if text:
        match = re.search(
            r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
        if match:
            return match.group(1)
    return ""


def analyze_static(repo: Repository, files: Dict[str, str],
                   all_paths: Set[str], readme: str,
                   candidates: Sequence[LaunchCandidate]
                   ) -> List[RiskIndicator]:
    """Return review indicators; never call these confirmed vulnerabilities."""
    indicators: List[RiskIndicator] = []
    seen: Set[Tuple[str, str, int]] = set()

    def add(rule: str, severity: str, title: str, path: str = "",
            line: int = 0, evidence: str = "") -> None:
        key = (rule, path, line)
        if key in seen:
            return
        seen.add(key)
        indicators.append(RiskIndicator(
            rule=rule, severity=severity, title=title, path=path,
            line=line, evidence=evidence[:200]))

    if repo.archived:
        add("GITHUB_ARCHIVED", "LOW", "Repository is archived",
            evidence=repo.full_name)
    license_paths = [
        path for path in all_paths
        if PurePosixPath(path).name.upper().startswith(
            ("LICENSE", "COPYING", "LICENCE"))
    ]
    if not repo.license_name and not license_paths:
        add("GITHUB_NO_LICENSE", "INFO",
            "No license metadata or license file was found")

    package_path, package_text = _find_file(files, "package.json")
    package = _load_json(package_text) or {}
    scripts = package.get("scripts")
    if isinstance(scripts, dict):
        for name in INSTALL_SCRIPTS:
            value = scripts.get(name)
            if isinstance(value, str):
                add("GITHUB_INSTALL_SCRIPT", "MEDIUM",
                    "Package install lifecycle script runs automatically",
                    path=package_path or "package.json",
                    evidence="{}: {}".format(name, value))
    dependencies: Dict[str, Any] = {}
    for section in ("dependencies", "devDependencies",
                    "optionalDependencies"):
        value = package.get(section)
        if isinstance(value, dict):
            dependencies.update(value)
    for name, version in sorted(dependencies.items()):
        if _is_unpinned(version):
            add("GITHUB_UNPINNED_DEPENDENCY", "MEDIUM",
                "Dependency is not pinned to an immutable version",
                path=package_path or "package.json",
                evidence="{}: {}".format(name, version))

    requirements_path, requirements = _find_file(files, "requirements.txt")
    if requirements:
        for number, line in enumerate(requirements.splitlines(), 1):
            stripped = line.strip()
            if (not stripped or stripped.startswith("#")
                    or stripped.startswith("-")):
                continue
            if ("==" not in stripped and "~=" not in stripped) or \
                    stripped.lower().startswith("git+"):
                add("GITHUB_UNPINNED_DEPENDENCY", "LOW",
                    "Python requirement is not pinned to an exact version",
                    path=requirements_path or "requirements.txt",
                    line=number, evidence=stripped)

    dockerfile_path, dockerfile = _find_file(files, "Dockerfile")
    if dockerfile:
        if INSTALL_PIPE_RE.search(dockerfile):
            add("GITHUB_REMOTE_INSTALL", "MEDIUM",
                "Dockerfile pipes a remote download into a shell",
                path=dockerfile_path or "Dockerfile")
        if REMOTE_ADD_RE.search(dockerfile):
            add("GITHUB_REMOTE_INSTALL", "MEDIUM",
                "Dockerfile adds a remote URL",
                path=dockerfile_path or "Dockerfile")

    for path, text in sorted(files.items()):
        if not _is_code_path(path):
            continue
        for rule, severity, title, pattern in _CODE_RULES:
            matches = 0
            for number, line in enumerate(text.splitlines(), 1):
                if not pattern.search(line):
                    continue
                add(rule, severity, title, path=path, line=number,
                    evidence=line.strip())
                matches += 1
                if matches >= MAX_INDICATORS_PER_RULE:
                    break

    for candidate in candidates:
        if candidate.requires_network:
            add("GITHUB_REMOTE_LAUNCH", "INFO",
                "README recommends executing a remote package",
                evidence=" ".join(candidate.command))
    return indicators


def _is_unpinned(version: Any) -> bool:
    text = str(version).strip()
    return bool(
        not text or UNPINNED_RE.match(text)
        or text.startswith(("git+", "http://", "https://")))


_CODE_RULES = (
    ("GITHUB_DYNAMIC_CODE", "MEDIUM",
     "Dynamic code execution or unsafe deserialization",
     re.compile(
         r"\b(?:eval\s*\(|new\s+Function\s*\(|pickle\.loads\s*\(|"
         r"yaml\.load\s*\(|marshal\.loads\s*\(|vm\.runIn)")),
    ("GITHUB_PROCESS_EXECUTION", "LOW",
     "Process execution surface",
     re.compile(
         r"\b(?:subprocess\.(?:run|Popen|call|check_output|check_call)|"
         r"os\.system\s*\(|child_process|execSync\s*\()")),
    ("GITHUB_NETWORK_ACCESS", "INFO",
     "Network access surface",
     re.compile(
         r"\b(?:requests\.(?:get|post|put|delete)\s*\(|"
         r"urllib\.request\.|fetch\s*\(|axios\.)")),
)


def assess_repository(client: GitHubClient, repo: Repository,
                      include_code: bool = True,
                      max_files: int = 25) -> Dict[str, Any]:
    """Profile one repository without executing any of its code."""
    readme = client.get_readme(repo.full_name)
    files: Dict[str, str] = {}
    all_paths: Set[str] = set()
    truncated = False
    tree_error: Optional[str] = None
    if include_code:
        try:
            files, all_paths, truncated = client.fetch_source(
                repo, max_files=max_files)
        except GitHubError as exc:
            # Large monorepos can exceed the tree API response ceiling. Keep
            # the README/manifest metadata rather than failing the whole run.
            tree_error = str(exc)
            logger.warning("source tree unavailable for %s: %s",
                           repo.full_name, exc)
    kind, package_name = detect_kind(files, readme)
    candidates = extract_launch_candidates(readme, files)
    indicators = analyze_static(
        repo, files, all_paths, readme, candidates)
    score = min(100, sum(
        RISK_WEIGHTS.get(indicator.severity, 0)
        for indicator in indicators))
    return {
        "repository": repo.to_dict(),
        "server": {
            "kind": kind,
            "package": package_name,
            "launch_candidates": [
                candidate.to_dict() for candidate in candidates
            ],
        },
        "risk_score": score,
        "risk_level": _risk_level(score),
        "risk_indicators": [
            indicator.to_dict() for indicator in indicators
        ],
        "files_scanned": sorted(files),
        "tree_truncated": truncated,
        "tree_error": tree_error,
        "readme_chars": len(readme),
    }


def _risk_level(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def safe_extract_tarball(data: bytes, destination: Path,
                         max_files: int = MAX_ARCHIVE_FILES,
                         max_bytes: int = MAX_EXTRACTED_BYTES) -> None:
    """Extract a GitHub tarball without links, traversal, or device files."""
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise GitHubError("invalid repository archive: {}".format(exc))
    with archive:
        members = archive.getmembers()
        if len(members) > max_files:
            raise GitHubError(
                "repository archive has too many entries ({})".format(
                    len(members)))
        prefix = _archive_prefix(members)
        total = 0
        for member in members:
            name = member.name.replace("\\", "/")
            parts = [
                part for part in PurePosixPath(name).parts
                if part not in ("", ".")
            ]
            if not parts:
                continue
            if PurePosixPath(name).is_absolute() or ".." in parts:
                raise GitHubError(
                    "repository archive contains an unsafe path: {!r}".format(
                        member.name))
            if prefix and parts[0] == prefix:
                parts = parts[1:]
            if not parts:
                continue
            if member.isdir():
                target = _safe_target(destination, parts)
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise GitHubError(
                    "repository archive contains a link or special file: "
                    "{!r}".format(member.name))
            if member.size < 0 or total + member.size > max_bytes:
                raise GitHubError(
                    "repository archive exceeds the extraction limit")
            total += member.size
            target = _safe_target(destination, parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise GitHubError(
                    "cannot read archive member: {!r}".format(member.name))
            with open(target, "wb") as handle:
                shutil.copyfileobj(source, handle)
            mode = 0o755 if member.mode & 0o111 else 0o644
            os.chmod(target, mode)


def _archive_prefix(members: Sequence[tarfile.TarInfo]) -> Optional[str]:
    prefixes = set()
    for member in members:
        parts = [
            part for part in PurePosixPath(
                member.name.replace("\\", "/")).parts
            if part not in ("", ".")
        ]
        if len(parts) > 1:
            prefixes.add(parts[0])
    return next(iter(prefixes)) if len(prefixes) == 1 else None


def _safe_target(destination: Path, parts: Sequence[str]) -> Path:
    target = (destination.joinpath(*parts)).resolve()
    if target != destination and destination not in target.parents:
        raise GitHubError(
            "repository archive path escapes the destination: {!r}".format(
                "/".join(parts)))
    return target


class DockerSandbox:
    """Run an MCP server command in a constrained, disposable container."""

    def __init__(self, docker: Optional[str] = None):
        self.docker = docker or shutil.which("docker")

    @property
    def available(self) -> bool:
        return bool(self.docker)

    def command(self, repo_dir: Path, command: Sequence[str], *,
                network: bool = False,
                image: Optional[str] = None) -> List[str]:
        if not self.docker:
            raise GitHubError(
                "Docker is required for runtime testing; install Docker or "
                "use the default static assessment")
        if not command:
            raise GitHubError("no launch command selected")
        if Path(command[0]).name == "docker":
            raise GitHubError("nested Docker launch commands are not supported")
        image = image or _image_for(command)
        uid = getattr(os, "getuid", lambda: 1000)()
        gid = getattr(os, "getgid", lambda: 1000)()
        # Remote package runners must not inherit a repository package.json;
        # npm would resolve the checkout instead of the requested package.
        workdir = (CONTAINER_TMP
                   if Path(command[0]).name in {"npx", "uvx"}
                   else "/workspace")
        args = [
            self.docker, "run", "--rm", "-i", "--init",
            "--user", "{}:{}".format(uid, gid),
            "--network", "bridge" if network else "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",  # nosec B108 - container path
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--memory", "1g",
            "--cpus", "1.0",
            "-v", "{}:/workspace:rw".format(Path(repo_dir).resolve()),
            "-w", workdir,
            "-e", "HOME=/tmp",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PIP_NO_CACHE_DIR=1",
            "-e", "NPM_CONFIG_CACHE=/tmp/npm",
            "-e", "npm_config_cache=/tmp/npm",
            "-e", "UV_CACHE_DIR=/tmp/uv",
            "-e", "NO_COLOR=1",
            image,
        ]
        args.extend(str(part) for part in command)
        return args


def _image_for(command: Sequence[str]) -> str:
    executable = Path(command[0]).name
    if executable in {"npx", "node", "npm"}:
        return "node:20-bookworm-slim"
    if executable in {"uvx", "uv"}:
        return "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
    if executable in {"python", "python3"}:
        return "python:3.12-slim"
    return "debian:bookworm-slim"


def select_runtime_command(assessment: Dict[str, Any],
                           override: Optional[str] = None
                           ) -> Optional[Dict[str, Any]]:
    if override:
        tokens = shlex.split(override)
        if not tokens:
            raise ValueError("--github-command must not be empty")
        return {
            "command": tokens,
            "source": "cli",
            "requires_network": Path(tokens[0]).name in {"npx", "uvx"},
            "requires_install": False,
            "runnable": Path(tokens[0]).name != "docker",
        }
    runnable = [
        candidate for candidate in assessment.get("server", {}).get(
            "launch_candidates", [])
        if candidate.get("runnable") and not candidate.get("requires_install")
    ]
    if not runnable:
        return None
    return max(runnable, key=_runtime_candidate_score)


def _runtime_candidate_score(candidate: Dict[str, Any]) -> int:
    """Prefer server recipes over installers, inspectors and helper scripts."""
    text = " ".join(str(part) for part in candidate.get("command", [])).lower()
    if any(marker in text for marker in (
            "inspector", "generate-", "federation", " init", "wizard")):
        return -100
    score = 0
    if candidate.get("source") == "readme-json":
        score += 30
    if "mcp" in text:
        score += 20
    if Path(str(candidate.get("command", [""])[0])).name in {
            "npx", "uvx"}:
        score += 10
    if "server" in text:
        score += 5
    if any(marker in text for marker in (
            "--port", "--server-url", "--transport http",
            "streamablehttp")):
        score -= 40
    if any(marker in text for marker in (
            "path/to", "your_", "your-", "<", ">", "{", "}",
            "example.com")):
        score -= 20
    return score


def run_repository_scan(assessment: Dict[str, Any], repo_dir: Path,
                        candidate: Dict[str, Any], config: Dict[str, Any],
                        sandbox: DockerSandbox) -> Dict[str, Any]:
    """Run Mcpwn against a repository command inside the sandbox."""
    from core import MCPPentester

    command = list(candidate.get("command") or [])
    try:
        wrapped = sandbox.command(
            repo_dir, command,
            network=bool(config.get("github_network", False)),
            image=config.get("github_image"))
    except GitHubError as exc:
        return {"status": "failed", "error": str(exc)}

    scan_config = dict(config)
    scan_config.update({
        "target": None,
        "fail_on": "none",
        "output_json": None,
        "output_html": None,
        "output_sarif": None,
    })
    pentester = MCPPentester(wrapped, config=scan_config)
    try:
        pentester.run()
    except Exception as exc:  # noqa: BLE001 - boundary around an untrusted target
        logger.exception("GitHub MCP scan failed for %s",
                         assessment["repository"]["full_name"])
        return {
            "status": "failed",
            "command": command,
            "error": "{}: {}".format(type(exc).__name__, exc),
        }
    reporter = pentester.reporter
    discovery_errors = list(getattr(pentester, "discovery_errors", []))
    if any(error.startswith("initialize:") for error in discovery_errors):
        return {
            "status": "failed",
            "command": command,
            "error": "MCP initialization failed: {}".format(
                discovery_errors[0]),
        }
    return {
        "status": "completed",
        "command": command,
        "sandbox": "docker",
        "findings": reporter.findings,
        "summary": reporter.summary(),
        "confidence": reporter.confidence_summary(),
        "exit_code": pentester.exit_code,
    }


def build_report(query: Optional[str],
                 assessments: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for assessment in assessments:
        kind = assessment.get("server", {}).get("kind", "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        risk = assessment.get("risk_level", "none")
        by_risk[risk] = by_risk.get(risk, 0) + 1
        for indicator in assessment.get("risk_indicators", []):
            severity = indicator.get("severity", "INFO")
            by_severity[severity] = by_severity.get(severity, 0) + 1
    runtime_completed = 0
    runtime_failed = 0
    mcp_findings = 0
    for assessment in assessments:
        runtime = assessment.get("runtime") or {}
        status = runtime.get("status")
        if status == "completed":
            runtime_completed += 1
            mcp_findings += len(runtime.get("findings") or [])
        elif status in ("failed", "skipped"):
            runtime_failed += 1
    return {
        "tool": "Mcpwn",
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "github",
        "query": query,
        "repositories": list(assessments),
        "summary": {
            "repositories": len(assessments),
            "by_kind": by_kind,
            "by_risk": by_risk,
            "risk_indicators": sum(by_severity.values()),
            "by_severity": by_severity,
            "runtime_completed": runtime_completed,
            "runtime_failed": runtime_failed,
            "mcp_findings": mcp_findings,
        },
    }


def write_json_report(path: str, report: Dict[str, Any]) -> None:
    target = Path(path)
    with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(target.parent),
            prefix=target.name + ".", delete=False) as handle:
        json.dump(report, handle, indent=2)
        temporary = Path(handle.name)
    os.replace(str(temporary), str(target))


def write_markdown_report(path: str, report: Dict[str, Any]) -> None:
    lines = [
        "# Mcpwn GitHub MCP assessment",
        "",
        "Generated: {}".format(report.get("timestamp", "")),
        "",
        "| Repository | Kind | Risk | Score | Indicators | Runtime |",
        "|---|---|---|---|---|---|",
    ]
    for assessment in report.get("repositories", []):
        repository = assessment.get("repository", {})
        runtime = assessment.get("runtime") or {}
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            _md(repository.get("full_name", "unknown")),
            _md(assessment.get("server", {}).get("kind", "unknown")),
            _md(assessment.get("risk_level", "none")),
            assessment.get("risk_score", 0),
            len(assessment.get("risk_indicators", [])),
            _md(runtime.get("status", "not run")),
        ))
    lines.append("")
    for assessment in report.get("repositories", []):
        repository = assessment.get("repository", {})
        name = repository.get("full_name", "unknown")
        lines.extend([
            "## {}".format(name),
            "",
            str(repository.get("html_url") or ""),
            "",
            "Kind: `{}`  Package: `{}`  Risk: **{}** (score {})".format(
                assessment.get("server", {}).get("kind", "unknown"),
                assessment.get("server", {}).get("package", ""),
                assessment.get("risk_level", "none"),
                assessment.get("risk_score", 0),
            ),
            "",
        ])
        if assessment.get("risk_indicators"):
            lines.append("### Static review indicators")
            lines.append("")
            for indicator in assessment["risk_indicators"][:30]:
                location = indicator.get("path", "")
                if indicator.get("line"):
                    location += ":{}".format(indicator["line"])
                lines.append(
                    "- **{}** `{}` {} — `{}`".format(
                        indicator.get("severity", "INFO"),
                        indicator.get("rule", ""),
                        indicator.get("title", ""),
                        location,
                    ))
            lines.append("")
        candidates = assessment.get("server", {}).get(
            "launch_candidates", [])
        if candidates:
            lines.append("### Launch candidates")
            lines.append("")
            for candidate in candidates:
                lines.append("- `{}` ({})".format(
                    " ".join(candidate.get("command", [])),
                    candidate.get("source", "")))
            lines.append("")
        runtime = assessment.get("runtime") or {}
        if runtime:
            lines.append("### Runtime scan")
            lines.append("")
            lines.append("Status: **{}**".format(runtime.get("status")))
            if runtime.get("error"):
                lines.append("")
                lines.append("Error: `{}`".format(runtime["error"]))
            for finding in (runtime.get("findings") or [])[:20]:
                lines.append("- **{}** {} ({})".format(
                    finding.get("severity", "INFO"),
                    finding.get("type", "finding"),
                    finding.get("status", "")))
            lines.append("")
    target = Path(path)
    with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(target.parent),
            prefix=target.name + ".", delete=False) as handle:
        handle.write("\n".join(lines) + "\n")
        temporary = Path(handle.name)
    os.replace(str(temporary), str(target))


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def report_exit_code(report: Dict[str, Any], fail_on: str) -> int:
    """Return 2 when a configured severity threshold is met."""
    if not fail_on or str(fail_on).lower() == "none":
        return 0
    threshold = SEVERITY_RANK.get(str(fail_on).upper())
    if threshold is None:
        return 0
    severities: List[str] = []
    for assessment in report.get("repositories", []):
        severities.extend(
            indicator.get("severity", "INFO")
            for indicator in assessment.get("risk_indicators", []))
        runtime = assessment.get("runtime") or {}
        severities.extend(
            finding.get("severity", "INFO")
            for finding in (runtime.get("findings") or []))
    if any(SEVERITY_RANK.get(str(severity).upper(), 0) >= threshold
           for severity in severities):
        return 2
    return 0
