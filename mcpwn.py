#!/usr/bin/env python3
"""Mcpwn - MCP Security Testing Framework."""
import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from core import MCPPentester

VERSION = "2.0.0"


def load_profile(path):
    """Load a security profile JSON, raising ValueError on bad input."""
    try:
        with open(path, encoding="utf-8") as handle:
            profile = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("cannot load profile {}: {}".format(path, exc)) from exc
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object: {}".format(path))
    return profile


def parse_headers(values):
    """Parse repeated ``--header 'Name: value'`` arguments."""
    headers = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(
                "invalid --header {!r}; expected 'Name: value'".format(raw))
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("header name must not be empty")
        headers[name] = value.strip()
    return headers


def build_parser():
    parser = argparse.ArgumentParser(
        description="MCP Security Testing Framework",
    )
    parser.add_argument("--version", action="version",
                        version="Mcpwn {}".format(VERSION))
    parser.add_argument("--target", type=str, default=None,
                        help="Streamable HTTP MCP endpoint (e.g. "
                             "http://127.0.0.1:8080/mcp)")
    parser.add_argument("--header", action="append", default=[],
                        metavar="NAME:VALUE",
                        help="HTTP header for Streamable HTTP (repeatable)")
    parser.add_argument("--safe-mode", action="store_true",
                        help="Skip destructive/noisy tests")
    parser.add_argument("--allow-destructive", action="store_true",
                        help="Enable resource exhaustion, flooding, "
                             "deserialization and timing probes")
    parser.add_argument("--tags", nargs="+",
                        help="Only run suites with these tags")
    parser.add_argument("--exclude-tags", nargs="+", default=[],
                        help="Skip suites with these tags")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--parallel", action="store_true",
                        help="Use concurrent flooding where supported")
    parser.add_argument("--profile", type=str,
                        help="Security profile JSON "
                             "(e.g. profiles/paranoid.json)")
    parser.add_argument("--output-json", type=str,
                        help="Export findings as JSON")
    parser.add_argument("--output-html", type=str,
                        help="Export findings as HTML")
    parser.add_argument("--output-sarif", type=str,
                        help="Export findings as SARIF (for CI/CD)")
    parser.add_argument("--github-repo", action="append", default=[],
                        metavar="OWNER/REPO",
                        help="Assess a GitHub MCP repository (repeatable)")
    parser.add_argument("--github-search", type=str, metavar="QUERY",
                        help="Discover MCP repositories with GitHub search")
    parser.add_argument("--github-limit", type=int, default=10,
                        help="Maximum search results (default: 10)")
    parser.add_argument("--github-max-files", type=int, default=25,
                        help="Maximum source files inspected per repo "
                             "(default: 25)")
    parser.add_argument("--github-include-archived", action="store_true",
                        help="Include archived repositories in search")
    parser.add_argument("--github-no-code", action="store_true",
                        help="Skip source-file inspection (metadata only)")
    parser.add_argument("--github-json", type=str, metavar="PATH",
                        help="Write the GitHub assessment as JSON")
    parser.add_argument("--github-markdown", type=str, metavar="PATH",
                        help="Write the GitHub assessment as Markdown")
    parser.add_argument("--github-token-env", type=str,
                        default="GITHUB_TOKEN", metavar="NAME",
                        help="Environment variable holding the GitHub token "
                             "(default: GITHUB_TOKEN)")
    parser.add_argument("--github-run", action="store_true",
                        help="Run the selected launch recipe in Docker")
    parser.add_argument("--github-dry-run", action="store_true",
                        help="Show the Docker command without executing it")
    parser.add_argument("--github-command", type=str, metavar="COMMAND",
                        help="Override the launch command (one repository)")
    parser.add_argument("--github-network", action="store_true",
                        help="Allow network access inside the Docker sandbox")
    parser.add_argument("--github-sandbox", choices=("auto", "docker"),
                        default="auto",
                        help="Runtime sandbox backend (default: auto)")
    parser.add_argument("--github-image", type=str, metavar="IMAGE",
                        help="Docker image for --github-run (default: "
                             "chosen from the command)")
    parser.add_argument("--allow-remote-code", action="store_true",
                        help="Required with --github-run: explicitly allow "
                             "executing an untrusted repository in Docker")
    parser.add_argument("--rce-only", action="store_true",
                        help="Run only the command-injection suite")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan with fewer payloads")
    parser.add_argument("--oob-port", type=int, default=None,
                        help="UDP port for the OOB DNS listener (default: 53)")
    parser.add_argument("--oob-callback-base", type=str, default=None,
                        help="Externally reachable base URL for SSRF callbacks")
    parser.add_argument("--ssrf-all-args", action="store_true",
                        help="Probe all tool arguments for SSRF, not just URLs")
    parser.add_argument("--max-requests", type=int, default=20000,
                        help="Hard request budget for the whole scan")
    parser.add_argument("--max-concurrency", type=int, default=8,
                        help="Maximum concurrent requests in active tests")
    parser.add_argument("--max-payload-bytes", type=int,
                        default=1024 * 1024,
                        help="Largest probe payload in bytes")
    parser.add_argument("--flood-count", type=int, default=200,
                        help="Subscriptions used by the flood test")
    parser.add_argument("--fail-on", choices=(
        "none", "low", "medium", "high", "critical"), default="none",
                        help="Exit 2 when a finding at or above this "
                             "severity exists")
    parser.add_argument("--strict-protocol", action="store_true",
                        help="Reject servers that negotiate an unknown MCP "
                             "protocol version")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER,
                        help="MCP server command (stdio transport)")
    return parser


def run_github(args, logger):
    """Discover, assess, and optionally test GitHub-hosted MCP servers."""
    from core.github import (
        DockerSandbox,
        GitHubAuthError,
        GitHubClient,
        GitHubError,
        GitHubRateLimitError,
        assess_repository,
        build_report,
        load_env_file,
        report_exit_code,
        run_repository_scan,
        select_runtime_command,
        write_json_report,
        write_markdown_report,
    )

    if not 1 <= args.github_limit <= 50:
        logger.error("--github-limit must be between 1 and 50")
        return 1
    if not 1 <= args.github_max_files <= 100:
        logger.error("--github-max-files must be between 1 and 100")
        return 1
    if args.github_run and not args.allow_remote_code:
        logger.error("--github-run executes untrusted repository code; "
                     "add --allow-remote-code")
        return 1
    if args.github_dry_run and not args.github_run:
        logger.error("--github-dry-run requires --github-run")
        return 1
    if args.github_command and not args.github_run:
        logger.error("--github-command requires --github-run")
        return 1
    if args.github_network and not args.github_run:
        logger.warning("--github-network only applies with --github-run")

    load_env_file()
    token = os.environ.get(args.github_token_env)
    if not token:
        logger.warning("%s is not set; using unauthenticated GitHub API "
                       "(60 requests/hour)", args.github_token_env)
    client = GitHubClient(token=token)

    repositories = []
    seen = set()

    def add_repository(repo):
        key = repo.full_name.lower()
        if key and key not in seen:
            seen.add(key)
            repositories.append(repo)

    try:
        if args.github_search:
            for repo in client.search_repositories(
                    args.github_search, limit=args.github_limit,
                    include_archived=args.github_include_archived):
                add_repository(repo)
        for spec in args.github_repo:
            add_repository(client.get_repository(spec))
    except (GitHubAuthError, GitHubRateLimitError, GitHubError,
            ValueError) as exc:
        logger.error("GitHub discovery failed: %s", exc)
        return 1

    if not repositories:
        logger.error("no GitHub repositories matched")
        return 1
    if args.github_command and len(repositories) != 1:
        logger.error("--github-command requires exactly one repository")
        return 1
    if not args.github_include_archived:
        for repo in repositories:
            if repo.archived:
                logger.warning("%s is archived; results may be stale",
                               repo.full_name)

    sandbox = DockerSandbox()
    if args.github_run and not args.github_dry_run and not sandbox.available:
        logger.error("Docker is required for runtime testing; start Docker "
                     "or omit --github-run")
        return 1

    pairs = []
    for repo in repositories:
        logger.info("GitHub: assessing %s", repo.full_name)
        try:
            assessment = assess_repository(
                client, repo, include_code=not args.github_no_code,
                max_files=args.github_max_files)
        except (GitHubAuthError, GitHubRateLimitError) as exc:
            logger.error("GitHub API error: %s", exc)
            return 1
        except GitHubError as exc:
            logger.error("GitHub: %s failed: %s", repo.full_name, exc)
            assessment = {
                "repository": repo.to_dict(),
                "server": {"kind": "unknown", "package": "",
                           "launch_candidates": []},
                "risk_score": 0,
                "risk_level": "none",
                "risk_indicators": [],
                "files_scanned": [],
                "tree_truncated": False,
                "readme_chars": 0,
                "error": str(exc),
            }
        pairs.append((repo, assessment))

    if args.github_run:
        scan_config = {
            "safe_mode": args.safe_mode,
            "allow_destructive": args.allow_destructive,
            "timeout": args.timeout,
            "parallel": args.parallel,
            "quick": args.quick,
            "tags": args.tags,
            "exclude_tags": args.exclude_tags,
            "max_requests": args.max_requests,
            "max_concurrency": args.max_concurrency,
            "max_payload_bytes": args.max_payload_bytes,
            "flood_count": args.flood_count,
            "strict_protocol": args.strict_protocol,
            "github_network": args.github_network,
            "github_image": args.github_image,
        }
        with tempfile.TemporaryDirectory(
                prefix="mcpwn-github-") as temporary:
            for repo, assessment in pairs:
                if assessment.get("error"):
                    continue
                try:
                    candidate = select_runtime_command(
                        assessment, args.github_command)
                except ValueError as exc:
                    assessment["runtime"] = {
                        "status": "failed", "error": str(exc)}
                    continue
                if candidate is None:
                    assessment["runtime"] = {
                        "status": "skipped",
                        "reason": "no runnable launch recipe; supply "
                                  "--github-command",
                    }
                    continue
                if not candidate.get("runnable"):
                    assessment["runtime"] = {
                        "status": "skipped",
                        "reason": "Docker launch recipes are not executed "
                                  "inside the sandbox",
                    }
                    continue
                if (candidate.get("requires_network")
                        and not args.github_network
                        and not args.github_command
                        and not args.github_dry_run):
                    assessment["runtime"] = {
                        "status": "skipped",
                        "reason": "launch recipe needs network access; "
                                  "pass --github-network",
                    }
                    continue
                if (candidate.get("requires_network")
                        and not args.github_network
                        and args.github_command):
                    logger.warning("%s: command may need --github-network",
                                   repo.full_name)
                repo_dir = Path(temporary) / repo.full_name.replace("/", "--")
                command = list(candidate.get("command") or [])
                if args.github_dry_run:
                    try:
                        planned = sandbox.command(
                            repo_dir, command,
                            network=args.github_network)
                    except GitHubError as exc:
                        assessment["runtime"] = {
                            "status": "failed", "error": str(exc)}
                    else:
                        runtime = {
                            "status": "planned",
                            "command": command,
                            "wrapped_command": planned,
                            "requires_network": bool(
                                candidate.get("requires_network")),
                        }
                        if (candidate.get("requires_network")
                                and not args.github_network):
                            runtime["warning"] = (
                                "recipe requires network access; the "
                                "generated command uses --network none")
                        assessment["runtime"] = runtime
                    continue
                try:
                    logger.info("GitHub: downloading %s", repo.full_name)
                    client.download_archive(repo, repo_dir)
                except GitHubError as exc:
                    logger.error("GitHub: download failed for %s: %s",
                                 repo.full_name, exc)
                    assessment["runtime"] = {
                        "status": "failed", "error": str(exc)}
                    continue
                assessment["runtime"] = run_repository_scan(
                    assessment, repo_dir, candidate, scan_config, sandbox)

    assessments = [assessment for _, assessment in pairs]
    report = build_report(args.github_search, assessments)
    try:
        if args.github_json:
            write_json_report(args.github_json, report)
            logger.info("GitHub JSON report: %s", args.github_json)
        if args.github_markdown:
            write_markdown_report(args.github_markdown, report)
            logger.info("GitHub Markdown report: %s", args.github_markdown)
    except OSError as exc:
        logger.error("failed to write GitHub report: %s", exc)
        return 1

    summary = report["summary"]
    logger.info(
        "GitHub assessment: %d repositories, %d indicators, "
        "%d runtime scans completed, %d failed/skipped",
        summary["repositories"], summary["risk_indicators"],
        summary["runtime_completed"], summary["runtime_failed"])
    failures = sum(
        1 for assessment in assessments
        if assessment.get("error")
        or (assessment.get("runtime") or {}).get("status") == "failed")
    exit_code = report_exit_code(report, args.fail_on)
    if exit_code == 0 and failures:
        exit_code = 1
    return exit_code


def run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = logging.getLogger("mcpwn")

    if args.timeout <= 0:
        logger.error("Timeout must be positive")
        return 1
    if args.github_search or args.github_repo:
        if args.target or args.server_cmd:
            logger.error("GitHub mode cannot be combined with --target or "
                         "a server command")
            return 1
        try:
            return run_github(args, logger)
        except (ValueError, OSError) as exc:
            logger.error("GitHub mode failed: %s", exc)
            return 1
        except Exception as exc:  # noqa: BLE001 - CLI boundary
            logger.critical("Fatal GitHub error: %s", exc, exc_info=True)
            return 1
    if not args.target and not args.server_cmd:
        logger.error("MCP server command required (or use --target URL or "
                     "--github-repo)")
        parser.print_help()
        return 1

    try:
        headers = parse_headers(args.header)
        profile = load_profile(args.profile) if args.profile else None
    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    timeout = 5.0 if args.quick else args.timeout
    config = {
        "version": VERSION,
        "profile": profile,
        "safe_mode": args.safe_mode,
        "allow_destructive": args.allow_destructive,
        "tags": args.tags,
        "exclude_tags": args.exclude_tags,
        "timeout": timeout,
        "parallel": args.parallel,
        "output_json": args.output_json,
        "output_html": args.output_html,
        "output_sarif": args.output_sarif,
        "rce_only": args.rce_only,
        "quick": args.quick,
        "oob_dns_port": args.oob_port,
        "oob_callback_base": args.oob_callback_base,
        "ssrf_all_args": args.ssrf_all_args,
        "max_requests": args.max_requests,
        "max_concurrency": args.max_concurrency,
        "max_payload_bytes": args.max_payload_bytes,
        "flood_count": args.flood_count,
        "fail_on": args.fail_on,
        "strict_protocol": args.strict_protocol,
        "target": args.target,
        "headers": headers,
    }
    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if args.target and server_cmd:
        logger.warning("Both --target and a server command were provided; "
                       "using --target")
        server_cmd = []

    try:
        pentester = MCPPentester(server_cmd, config=config)
        pentester.run()
    except KeyboardInterrupt:
        logger.warning("Interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        logger.critical("Fatal error: %s", exc, exc_info=True)
        return 1
    return pentester.exit_code


def main():
    logging.basicConfig(
        level=logging.DEBUG if "--verbose" in sys.argv else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    return run()


if __name__ == "__main__":
    sys.exit(main())
