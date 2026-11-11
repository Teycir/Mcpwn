"""Cross-tool attack-chain analysis (static).

Individual tools can be safe while their combination is dangerous: a file
reader plus a network fetcher is an exfiltration chain.  This module infers
capabilities from tool names, descriptions and argument names, then reports
dangerous compositions as *potential* findings.  It never executes a chain.
"""
from __future__ import annotations

import logging
from typing import Dict, List

from core.evidence import make_finding

logger = logging.getLogger("mcpwn.attack_chains")

CAPABILITY_HINTS = {
    "filesystem_read": ("read", "cat", "open", "load", "get_file",
                        "download", "list_dir", "filesystem"),
    "filesystem_write": ("write", "save", "upload", "delete", "remove",
                         "move", "mkdir", "edit", "patch"),
    "network": ("http", "url", "fetch", "request", "webhook", "browse",
                "browser", "curl", "web"),
    "shell": ("exec", "command", "shell", "spawn", "system", "eval",
              "subprocess", "terminal"),
    "credentials": ("secret", "credential", "vault", "keychain", "password",
                    "env", "token"),
    "database": ("sql", "query", "database", "postgres", "sqlite", "table"),
}

CHAINS = [
    (("filesystem_read", "network"),
     "file read plus network egress enables data exfiltration",
     "CRITICAL"),
    (("credentials", "network"),
     "credential access plus network egress enables secret exfiltration",
     "CRITICAL"),
    (("filesystem_write", "shell"),
     "file write plus command execution enables persistence",
     "HIGH"),
    (("database", "network"),
     "database access plus network egress enables bulk exfiltration",
     "HIGH"),
    (("credentials", "shell"),
     "credential access plus command execution enables lateral movement",
     "HIGH"),
]


class AttackChainTest:
    """Infer and report dangerous cross-tool capability combinations."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        capabilities = self._capabilities()
        findings = []
        for required, rationale, severity in CHAINS:
            first, second = required
            tools_a = capabilities.get(first, [])
            tools_b = capabilities.get(second, [])
            if not tools_a or not tools_b:
                continue
            distinct = [
                (tool_a, tool_b) for tool_a in tools_a
                for tool_b in tools_b if tool_a != tool_b
            ]
            if not distinct:
                continue
            tool_a, tool_b = distinct[0]
            findings.append(make_finding(
                "ATTACK_CHAIN",
                tool="{}+{}".format(tool_a, tool_b),
                severity=severity,
                confidence=35,
                verified=False,
                evidence=[
                    "chain: {} -> {}".format(tool_a, tool_b),
                    "capabilities: {}, {}".format(first, second),
                    "{} pair(s) available".format(len(distinct)),
                ],
                note="capability composition only; no chain was executed",
            ))
        return findings

    def _capabilities(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for tool in self.pentester.tools:
            name = str(tool.get("name", ""))
            description = str(tool.get("description", ""))
            schema = tool.get("inputSchema", {}) or {}
            args = " ".join((schema.get("properties", {}) or {}).keys())
            haystack = "{} {} {}".format(name, description, args).lower()
            for capability, hints in CAPABILITY_HINTS.items():
                if any(hint in haystack for hint in hints):
                    result.setdefault(capability, []).append(name or "unknown")
        # A tool matching both sides of a chain is excluded by the caller.
        return result
