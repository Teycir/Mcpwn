"""Path traversal tests for resources and tool arguments.

The previous implementation asked for ``target_type='traversal'``, which was
missing from the payload table and silently resolved to an empty list.  The
test therefore never sent a single traversal payload.  This version uses the
explicit ``path_traversal`` category and validates leaks with markers from the
response body.
"""
from __future__ import annotations

import logging
import urllib.parse

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    result_text,
)

logger = logging.getLogger("mcpwn.path_traversal")

SUSPICIOUS_ARGS = ("path", "file", "filename", "filepath", "src", "source",
                   "dir", "directory", "template")


class ResourceTraversalTest:
    """Test path traversal on resources and tools."""

    LEAK_MARKERS = {
        "passwd": ["root:x:0:0", "daemon:", "bin:"],
        "shadow": ["root:$", "$6$", "$y$"],
        "ssh_key": ["-----BEGIN", "PRIVATE KEY"],
        "config": ["[extensions]", "php.ini"],
        "windows": ["[boot loader]", "[operating systems]"],
        "error": ["PDO Exception", "java.io.FileNotFound"],
    }
    HIGH_CONFIDENCE_MARKERS = (
        "root:x:0:0:root",
        "-----BEGIN RSA PRIVATE KEY",
        "-----BEGIN OPENSSH PRIVATE KEY",
        "[boot loader]",
    )

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        findings = []
        findings.extend(self._test_resource_uris())
        findings.extend(self._test_tool_arguments())
        return findings

    def _payloads(self):
        limit = self.pentester.policy.payload_limit()
        return self.pentester.get_payloads(
            {"target_type": "path_traversal"})[:limit]

    def _test_resource_uris(self):
        resources = list(self.pentester.resources)
        if not resources:
            try:
                response, _ = self.pentester.send(
                    "resources/list", {}, skip_analysis=True)
                result = response.get("result", {}) if isinstance(
                    response, dict) else {}
                resources = result.get("resources", []) or []
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded):
                resources = []
        valid_uris = [item.get("uri") for item in resources
                      if isinstance(item, dict) and item.get("uri")]

        targets = set()
        for payload in self._payloads():
            if "://" in payload:
                targets.add(payload)
                continue
            for uri in valid_uris:
                parsed = urllib.parse.urlparse(uri)
                if parsed.scheme:
                    targets.add("{}://{}".format(parsed.scheme, payload))
            targets.add("file://{}".format(payload))

        findings = []
        for target in sorted(targets):
            finding = self._read_target(target)
            if finding:
                findings.append(finding)
        return findings

    def _read_target(self, target):
        try:
            response, _ = self.pentester.send(
                "resources/read", {"uri": target}, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None
        text = result_text(response)
        markers = self._match_leak(text)
        if not markers:
            return None
        verified = self._reproduce_read(target)
        return make_finding(
            "RESOURCE_TRAVERSAL",
            uri=target,
            payload=target,
            severity="CRITICAL",
            confidence=92 if verified else 65,
            verified=verified,
            evidence=[
                "markers: {}".format(", ".join(markers)),
                "response: {}".format(content_summary(response, 300)),
            ],
            note="file content returned by resources/read" if verified
                 else "single observation; reproduce manually",
        )

    def _reproduce_read(self, target):
        try:
            response, _ = self.pentester.send(
                "resources/read", {"uri": target}, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return False
        return bool(self._match_leak(result_text(response)))

    def _test_tool_arguments(self):
        findings = []
        for tool in self.pentester.tools[:self.pentester.policy.limits.max_tools]:
            schema = tool.get("inputSchema", {}) or {}
            properties = schema.get("properties", {}) or {}
            candidates = [name for name in properties
                          if any(hint in name.lower()
                                 for hint in SUSPICIOUS_ARGS)]
            if not candidates:
                continue
            required = schema.get("required", []) or []
            for arg_name in candidates:
                for payload in self._payloads():
                    args = {}
                    for required_name in required:
                        spec = properties.get(required_name, {}) or {}
                        args[required_name] = self._default_for(
                            spec.get("type", "string"))
                    args[arg_name] = payload
                    finding = self._probe_tool(tool, arg_name, args, payload)
                    if finding:
                        findings.append(finding)
                        break
        return findings

    @staticmethod
    def _default_for(prop_type):
        return {
            "string": "dummy", "integer": 0, "number": 0,
            "boolean": False, "array": [], "object": {},
        }.get(prop_type, "dummy")

    def _probe_tool(self, tool, arg_name, args, payload):
        params = {"name": tool.get("name"), "arguments": args}
        try:
            response, _ = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None
        text = result_text(response)
        markers = self._match_leak(text)
        if not markers:
            return None
        verified = self._reproduce_tool(params)
        return make_finding(
            "TOOL_PATH_TRAVERSAL",
            tool=tool.get("name"),
            arg=arg_name,
            payload=payload,
            severity="CRITICAL",
            confidence=92 if verified else 65,
            verified=verified,
            evidence=[
                "markers: {}".format(", ".join(markers)),
                "response: {}".format(content_summary(response, 300)),
            ],
            note="file content returned by tool call" if verified
                 else "single observation; reproduce manually",
        )

    def _reproduce_tool(self, params):
        try:
            response, _ = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return False
        return bool(self._match_leak(result_text(response)))

    def _match_leak(self, content):
        if not content:
            return []
        text = str(content)
        for marker in self.HIGH_CONFIDENCE_MARKERS:
            if marker in text:
                return [marker]
        for markers in self.LEAK_MARKERS.values():
            matched = [marker for marker in markers if marker in text]
            if len(matched) >= 2:
                return matched
        return []
