"""Tool poisoning detection (static analysis).

MCP servers describe tools in natural language.  An attacker who can influence
that metadata can hide instructions for the calling model.  This module scans
descriptions, schemas and server instructions for hidden Unicode, adversarial
phrasing and metadata inconsistencies.  Findings are static observations and
explicitly require manual review.
"""
from __future__ import annotations

import logging
import re

from core.evidence import make_finding

logger = logging.getLogger("mcpwn.tool_poisoning")

HIDDEN_CHAR_PATTERN = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069"
    "\ue000-\uf8ff\U000e0000-\U000e007f]"
)

INSTRUCTION_PATTERNS = [
    ("ignore previous instructions",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+"
                r"(instructions|rules|directions)", re.IGNORECASE)),
    ("instructs silence",
     re.compile(r"do\s+not\s+(tell|inform|mention|reveal|report)", re.IGNORECASE)),
    ("instructs covert action",
     re.compile(r"\b(secretly|covertly|silently|without\s+(asking|telling|"
                r"informing))\b", re.IGNORECASE)),
    ("exfiltration instruction",
     re.compile(r"\b(exfiltrat\w*|send\s+.{0,40}\s+to\s+https?://)", re.IGNORECASE)),
    ("sensitive file access",
     re.compile(r"(read|cat|open)\s+.{0,20}(~/\.ssh|\.env|/etc/passwd|"
                r"id_rsa)", re.IGNORECASE)),
    ("pipe-to-shell instruction",
     re.compile(r"(curl|wget)\s+.{0,80}\|\s*(sh|bash)", re.IGNORECASE)),
    ("forced tool use",
     re.compile(r"you\s+(must|should)\s+(always\s+)?(call|invoke)\s+", re.IGNORECASE)),
    ("embedded markup/comment",
     re.compile(r"<!--|\[//\]:\s*#|<important>", re.IGNORECASE)),
]

WRITE_HINTS = ("write", "save", "delete", "remove", "upload", "exec",
               "command", "shell", "create")
READ_ONLY_CLAIMS = re.compile(r"\b(read[- ]only|no side effects?)\b",
                              re.IGNORECASE)


class ToolPoisoningTest:
    """Scan MCP metadata for poisoning and hidden content."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        findings = []
        session = self.pentester.session
        if session and session.instructions:
            findings.extend(self._scan_text(
                session.instructions, source="server instructions"))
        for tool in self.pentester.tools:
            findings.extend(self._scan_tool(tool))
        for prompt in self.pentester.prompts:
            findings.extend(self._scan_text(
                prompt.get("description", ""),
                source="prompt:{}".format(prompt.get("name", "unknown"))))
        findings.extend(self._duplicate_names())
        return findings

    def _scan_tool(self, tool):
        name = tool.get("name", "unknown")
        texts = [("tool description", tool.get("description", ""))]
        schema = tool.get("inputSchema", {}) or {}
        for prop, spec in (schema.get("properties", {}) or {}).items():
            if not isinstance(spec, dict):
                continue
            texts.append(("argument {}".format(prop),
                          spec.get("description", "")))
            default = spec.get("default")
            if isinstance(default, str):
                texts.append(("argument {} default".format(prop), default))
            enum = spec.get("enum")
            if isinstance(enum, list):
                texts.append(("argument {} enum".format(prop),
                              " ".join(str(item) for item in enum)))
        findings = []
        for label, text in texts:
            if not text:
                continue
            findings.extend(self._scan_text(
                str(text), source="{}:{}".format(name, label), tool=name))
        findings.extend(self._read_only_mismatch(tool))
        return findings

    def _scan_text(self, text, source, tool=None):
        hidden = HIDDEN_CHAR_PATTERN.findall(text)
        matches = []
        for label, pattern in INSTRUCTION_PATTERNS:
            match = pattern.search(text)
            if match:
                matches.append((label, match.group()[:80]))
        if not hidden and not matches:
            return []
        classes = []
        if hidden:
            classes.append("hidden_unicode({})".format(len(hidden)))
        classes.extend(label for label, _ in matches)
        confidence = 45
        if hidden:
            confidence += 20
        if matches:
            confidence += 10
        confidence = min(75, confidence)
        excerpt = text[:240]
        evidence = [
            "source: {}".format(source),
            "classes: {}".format(", ".join(classes)),
            "excerpt: {!r}".format(excerpt),
        ]
        if hidden:
            evidence.append("hidden characters: {}".format(
                " ".join("U+{:04X}".format(ord(char)) for char in hidden[:8])))
        return [make_finding(
            "TOOL_POISONING",
            tool=tool or source,
            severity="HIGH" if hidden or len(matches) >= 2 else "MEDIUM",
            confidence=confidence,
            evidence=evidence,
            note="static metadata analysis; verify how the client presents it",
        )]

    def _read_only_mismatch(self, tool):
        name = str(tool.get("name", "")).lower()
        description = str(tool.get("description", ""))
        if READ_ONLY_CLAIMS.search(description) and any(
                hint in name for hint in WRITE_HINTS):
            return [make_finding(
                "TOOL_METADATA_ANOMALY",
                tool=tool.get("name"),
                severity="MEDIUM",
                confidence=35,
                evidence=[
                    "description claims read-only",
                    "tool name suggests a write/exec operation",
                ],
                note="contradictory metadata; review tool behaviour",
            )]
        return []

    def _duplicate_names(self):
        seen = {}
        for tool in self.pentester.tools:
            name = tool.get("name")
            if name:
                seen[name] = seen.get(name, 0) + 1
        duplicates = [name for name, count in seen.items() if count > 1]
        if not duplicates:
            return []
        return [make_finding(
            "TOOL_METADATA_ANOMALY",
            tool=", ".join(duplicates[:5]),
            severity="MEDIUM",
            confidence=50,
            evidence=["duplicate tool names: {}".format(
                ", ".join(duplicates[:5]))],
            note="name shadowing confuses tool selection",
        )]
