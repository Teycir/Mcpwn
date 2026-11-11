"""Credential exposure detection in MCP metadata.

Only static metadata and captured server stderr are inspected; tools are not
invoked to hunt for secrets.  Matches are masked before entering evidence, so a
report never becomes a second leak.
"""
from __future__ import annotations

import logging
import math
import re

from core.evidence import make_finding, redact_secret

logger = logging.getLogger("mcpwn.credentials")

PATTERNS = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("private key block",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
        r"[A-Za-z0-9_-]{5,}\b")),
]

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret|"
    r"access[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{16,})")

PLACEHOLDERS = ("example", "changeme", "your_", "replace", "xxxx",
                "dummy", "placeholder", "test_")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length)
                for count in counts.values())


class CredentialExposureTest:
    """Scan metadata for credential material."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        findings = []
        session = self.pentester.session
        sources = []
        if session and session.instructions:
            sources.append(("server instructions", session.instructions))
        for tool in self.pentester.tools:
            name = tool.get("name", "unknown")
            sources.append(("tool:{} description".format(name),
                            tool.get("description", "")))
            schema = tool.get("inputSchema", {}) or {}
            for prop, spec in (schema.get("properties", {}) or {}).items():
                if not isinstance(spec, dict):
                    continue
                sources.append(("tool:{} arg:{}".format(name, prop),
                                spec.get("description", "")))
                if isinstance(spec.get("default"), str):
                    sources.append(("tool:{} arg:{} default".format(name, prop),
                                    spec["default"]))
        for resource in self.pentester.resources:
            sources.append(("resource:{}".format(
                resource.get("uri", "unknown")),
                " ".join(str(resource.get(key, "")) for key in
                         ("name", "description", "uri"))))
        for prompt in self.pentester.prompts:
            sources.append(("prompt:{}".format(prompt.get("name", "unknown")),
                            prompt.get("description", "")))
        transport = self.pentester.transport
        for line in list(getattr(transport, "stderr_tail", []))[-50:]:
            sources.append(("server stderr", line))

        for source, text in sources:
            if not text:
                continue
            matches = self._scan(str(text))
            if not matches:
                continue
            findings.append(make_finding(
                "CREDENTIAL_EXPOSURE",
                tool=source,
                severity="HIGH",
                confidence=min(80, 65 + 5 * len(matches)),
                evidence=matches[:8],
                note="static match; rotate the credential if genuine",
            ))
        return findings

    def _scan(self, text):
        matches = []
        for label, pattern in PATTERNS:
            for match in pattern.finditer(text):
                matches.append("{}: {}".format(
                    label, redact_secret(match.group(0))))
        for match in GENERIC_ASSIGNMENT.finditer(text):
            value = match.group(2)
            if any(placeholder in value.lower() for placeholder in PLACEHOLDERS):
                continue
            if len(value) < 16 or shannon_entropy(value) < 3.2:
                continue
            matches.append("{} assignment: {}".format(
                match.group(1), redact_secret(value)))
        # De-duplicate masked representations.
        unique = []
        for item in matches:
            if item not in unique:
                unique.append(item)
        return unique
