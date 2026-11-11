"""Report generation for findings."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, Iterable, List

from core.evidence import (
    FINDING_CATALOG,
    SEVERITY_ORDER,
    confidence_label,
    merge_findings,
    normalize_finding,
)

VERSION = "2.0.0"
SCHEMA_VERSION = "2.0"


class Reporter:
    """Generate structured reports from findings.

    Findings are normalized and deduplicated on insertion.  Severity (impact)
    and confidence (evidence strength) are always reported separately.
    """

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self._by_fingerprint: Dict[str, int] = {}

    def add_findings(self, test_name: str, findings: Iterable[Any]) -> None:
        for raw in findings or []:
            normalized = normalize_finding(test_name, raw)
            fingerprint = normalized["fingerprint"]
            if fingerprint in self._by_fingerprint:
                index = self._by_fingerprint[fingerprint]
                self.findings[index] = merge_findings(
                    self.findings[index], normalized)
            else:
                self._by_fingerprint[fingerprint] = len(self.findings)
                self.findings.append(normalized)

    def to_json(self, filepath: str) -> None:
        report = {
            "tool": "Mcpwn",
            "version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "by_type": self._count_by_type(),
                "by_severity": self.summary(),
                "by_confidence": self.confidence_summary(),
                "verified": sum(
                    1 for finding in self.findings if finding.get("verified")),
            },
        }
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    def to_html(self, filepath: str) -> None:
        rows = []
        for finding in self.findings:
            severity = str(finding.get("severity", "INFO")).lower()
            rows.append(
                '<div class="finding {css}">'
                '<div class="head"><strong>{title}</strong>'
                '<span class="badges">{severity} / {confidence}% '
                '({label})</span></div>'
                '<div class="meta">{test} &middot; {cwe} &middot; status: '
                '{status}</div>'
                '<pre>{body}</pre></div>'.format(
                    css=escape(severity),
                    title=escape(str(finding.get("title", "Finding"))),
                    severity=escape(str(finding.get("severity", "INFO"))),
                    confidence=escape(str(finding.get("confidence", 0))),
                    label=escape(str(finding.get("confidence_label", ""))),
                    test=escape(str(finding.get("test", ""))),
                    cwe=escape(str(finding.get("cwe", ""))),
                    status=escape(str(finding.get("status", ""))),
                    body=escape(json.dumps(finding, indent=2)),
                ))
        html = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Mcpwn Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #1b1b1b; }}
.finding {{ border-left: 6px solid #999; margin: 12px 0; padding: 10px 14px;
            background: #fafafa; }}
.head {{ display: flex; justify-content: space-between; gap: 1rem; }}
.badges {{ font: 12px monospace; white-space: nowrap; }}
.meta {{ color: #555; font-size: 12px; margin: 4px 0 8px; }}
pre {{ white-space: pre-wrap; font-size: 12px; margin: 0; }}
.critical {{ border-color: #b00020; background: #fff1f2; }}
.high {{ border-color: #d9480f; background: #fff4e6; }}
.medium {{ border-color: #b08900; background: #fffbe6; }}
.low {{ border-color: #2b6cb0; background: #f0f7ff; }}
.info {{ border-color: #718096; }}
</style></head>
<body>
<h1>Mcpwn Security Report</h1>
<p>Total findings: {total} &middot; verified: {verified}</p>
{rows}
</body></html>
""".format(
            total=len(self.findings),
            verified=sum(1 for f in self.findings if f.get("verified")),
            rows="\n".join(rows),
        )
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write(html)

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            finding_type = finding.get("type", "UNKNOWN")
            counts[finding_type] = counts.get(finding_type, 0) + 1
        return counts

    def summary(self) -> Dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            severity = str(finding.get("severity", "INFO")).upper()
            counts[severity] = counts.get(severity, 0) + 1
        return {key: value for key, value in counts.items() if value}

    def confidence_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            label = confidence_label(int(finding.get("confidence", 0)))
            counts[label] = counts.get(label, 0) + 1
        return counts

    def to_sarif(self, filepath: str) -> None:
        rules = {}
        for finding in self.findings:
            rule_id = finding.get("type", "UNKNOWN")
            if rule_id not in rules:
                spec = FINDING_CATALOG.get(rule_id, {})
                rules[rule_id] = {
                    "id": rule_id,
                    "name": spec.get("title", rule_id),
                    "shortDescription": {
                        "text": spec.get("title", rule_id)},
                    "help": {"text": spec.get("remediation", "")},
                    "properties": {
                        "cwe": spec.get("cwe", ""),
                        "tags": ["security", "mcp"],
                    },
                }
        sarif = {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"),
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Mcpwn",
                        "version": VERSION,
                        "informationUri": "https://github.com/Teycir/Mcpwn",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    self._to_sarif_result(finding)
                    for finding in self.findings
                ],
            }],
        }
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(sarif, handle, indent=2)

    def _to_sarif_result(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return {
            "ruleId": finding.get("type", "UNKNOWN"),
            "level": severity_map.get(
                str(finding.get("severity", "MEDIUM")).upper(), "warning"),
            "message": {
                "text": "{} ({}) — {}: {}".format(
                    finding.get("title", finding.get("type", "issue")),
                    finding.get("status", "possible"),
                    finding.get("test", "test"),
                    finding.get("note", "")).strip(),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "mcp-server",
                    }
                }
            }],
            "partialFingerprints": {
                "mcpwnFingerprint": finding.get("fingerprint", ""),
            },
            "properties": {
                "severity": finding.get("severity", "INFO"),
                "confidence": finding.get("confidence", 0),
                "confidenceLabel": finding.get("confidence_label", ""),
                "verified": finding.get("verified", False),
                "cwe": finding.get("cwe", ""),
                "toolName": finding.get("tool", ""),
                "evidence": finding.get("evidence", [])[:5],
            },
        }
