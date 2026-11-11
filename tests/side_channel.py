"""Side-channel detection for timing, size and behavioral anomalies.

Findings here are deliberately low-confidence observations: a consistent slow
response is not a directory walk, and a large response is not data theft.  They
exist to guide manual review, not to assert exploitation.
"""
from __future__ import annotations

import logging
import statistics
import time

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    result_text,
)

logger = logging.getLogger("mcpwn.side_channel")


class SideChannelTest:
    """Detect side-channel signals and risky output patterns."""

    def __init__(self, pentester, profile=None):
        self.pentester = pentester
        profile = profile or {}
        self.timing_threshold = profile.get(
            "timing_thresholds", {}).get("slow_query_ms", 500) / 1000
        self.size_threshold = profile.get(
            "size_thresholds", {}).get("large_response_bytes", 1048576)
        patterns = profile.get("behavioral_patterns", {})
        self.network_indicators = [
            item.lower() for item in patterns.get("network_indicators", [])]
        self.shell_indicators = [
            item.lower() for item in patterns.get("shell_indicators", [])]
        self.root_indicators = [
            item.lower() for item in
            patterns.get("filesystem_root_indicators", [])]

    def run(self, tool):
        findings = []
        findings.extend(self._test_timing_side_channel(tool))
        findings.extend(self._test_content_and_size(tool))
        return findings

    def _test_timing_side_channel(self, tool):
        """Measure three inputs; report only consistent slowness."""
        findings = []
        tool_name = tool.get("name", "unknown")
        properties = list(
            (tool.get("inputSchema") or {}).get("properties", {}).items())[:3]
        for arg, spec in properties:
            if not isinstance(spec, dict) or spec.get("type") != "string":
                continue
            timings = []
            for test_value in ("a", "aa", "aaa"):
                try:
                    start = time.time()
                    self.pentester.send(
                        "tools/call",
                        {"name": tool_name, "arguments": {arg: test_value}},
                        skip_analysis=True,
                    )
                    timings.append(time.time() - start)
                except (TransportError, ProtocolError, RequestTimeout,
                        SafetyLimitExceeded, OSError) as exc:
                    logger.debug("timing probe failed for %s.%s: %s",
                                 tool_name, arg, exc)
                    continue
            if len(timings) < 3:
                continue
            average = statistics.mean(timings)
            deviation = statistics.stdev(timings) if len(timings) > 1 else 0
            if average > self.timing_threshold and deviation < average * 0.5:
                findings.append(make_finding(
                    "TIMING_SIDE_CHANNEL",
                    tool=tool_name,
                    arg=arg,
                    severity="LOW",
                    confidence=25,
                    evidence=[
                        "mean {:.3f}s, stdev {:.3f}s".format(
                            average, deviation),
                        "consistent slow response; not proof of enumeration",
                    ],
                    note="timing observation only",
                ))
        return findings

    def _test_content_and_size(self, tool):
        """Combined size and behavioral-pattern scan to minimize I/O."""
        findings = []
        tool_name = tool.get("name", "unknown")
        properties = list(
            (tool.get("inputSchema") or {}).get("properties", {}).keys())[:3]
        for arg in properties:
            try:
                response, _ = self.pentester.send(
                    "tools/call",
                    {"name": tool_name, "arguments": {arg: "test"}},
                    skip_analysis=True,
                )
            except (TransportError, ProtocolError, RequestTimeout,
                    SafetyLimitExceeded, OSError) as exc:
                logger.debug("content probe failed for %s.%s: %s",
                             tool_name, arg, exc)
                continue

            text = result_text(response)
            size = len(text)
            if size > self.size_threshold:
                findings.append(make_finding(
                    "SIZE_SIDE_CHANNEL",
                    tool=tool_name,
                    arg=arg,
                    severity="LOW",
                    confidence=25,
                    response_size=size,
                    evidence=["response size {} bytes".format(size)],
                    note="large response; review whether unbounded",
                ))

            lowered = text.lower()
            if any(indicator in lowered
                   for indicator in self.network_indicators):
                findings.append(make_finding(
                    "NETWORK_ACTIVITY_DETECTED",
                    tool=tool_name,
                    arg=arg,
                    severity="MEDIUM",
                    confidence=40,
                    evidence=[content_summary(response, 300)],
                    note="output mentions network primitives",
                ))
            if any(indicator in lowered for indicator in self.shell_indicators):
                findings.append(make_finding(
                    "SHELL_ACTIVITY_DETECTED",
                    tool=tool_name,
                    arg=arg,
                    severity="HIGH",
                    confidence=50,
                    evidence=[content_summary(response, 300)],
                    note="output mentions shell primitives",
                ))
            if any(indicator in lowered for indicator in self.root_indicators):
                findings.append(make_finding(
                    "ROOT_FILESYSTEM_ACCESS",
                    tool=tool_name,
                    arg=arg,
                    severity="HIGH",
                    confidence=50,
                    evidence=[content_summary(response, 300)],
                    note="output mentions sensitive filesystem paths",
                ))
        return findings
