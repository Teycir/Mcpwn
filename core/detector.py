"""Semantic detection engine.

Detection is intentionally *scoped*: :meth:`SemanticDetector.scan` inspects one
response and returns the indicators found in it.  The orchestrator never
attributes findings from previous requests to the current probe, which was a
major source of false positives in earlier versions.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from payloads import INDICATORS, TimingAnalyzer

logger = logging.getLogger("mcpwn.detector")


class SemanticDetector:
    """Detects exploitation indicators in a single MCP response."""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.timing_analyzer = TimingAnalyzer()

    def scan(self, content: str) -> List[Dict[str, Any]]:
        """Return indicators found in ``content`` (no global state)."""
        detections: List[Dict[str, Any]] = []
        if not content or not isinstance(content, str):
            return detections
        seen = set()
        for key, finding_type in (("rce_success", "RCE"),
                                  ("file_read", "FILE_READ")):
            for pattern in INDICATORS.get(key, []):
                try:
                    match = pattern.search(content)
                except (TypeError, AttributeError) as exc:
                    logger.warning("%s pattern failed: %s", finding_type, exc)
                    continue
                if not match:
                    continue
                marker = (finding_type, pattern.pattern)
                if marker in seen:
                    continue
                seen.add(marker)
                detections.append({
                    "type": finding_type,
                    "indicator": pattern.pattern,
                    "match": match.group()[:200],
                })
        return detections

    def analyze(self, response: Any, raw_content: str, elapsed_time: float,
                is_baseline: bool = False) -> bool:
        """Legacy API used by library consumers and older tests.

        This accumulates findings on the instance.  Scanners should prefer
        :meth:`scan` so a finding cannot leak between probes.
        """
        if is_baseline:
            self.timing_analyzer.add_baseline(elapsed_time)
            return False
        content = raw_content if raw_content else (
            str(response) if response is not None else "")
        detections = self.scan(content)
        self.findings.extend(detections)

        # Timing observations are recorded separately and never labeled RCE.
        try:
            if self.timing_analyzer.is_anomaly(elapsed_time):
                self.findings.append({
                    "type": "TIMING",
                    "elapsed": elapsed_time,
                })
        except (AttributeError, TypeError, ValueError) as exc:
            logger.warning("timing analysis failed: %s", exc)

        return bool(detections)

    def report(self) -> List[Dict[str, Any]]:
        return list(self.findings)

    def reset(self) -> None:
        self.findings = []
