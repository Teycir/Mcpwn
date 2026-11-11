"""Finding and evidence model.

Design rules:

* **Severity** describes impact if the issue is real.
* **Confidence** describes how strongly Mcpwn's evidence supports the finding.
* A timing observation is never promoted to RCE.  Findings carry a ``status``
  (``confirmed``/``likely``/``possible``/``informational``) derived from
  confidence, plus an explicit ``verified`` flag.
* Findings are deduplicated by a stable fingerprint; repeated observations
  merge their evidence instead of inflating the report.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CONFIDENCE_LABELS = (
    (85, "confirmed"),
    (60, "likely"),
    (30, "possible"),
    (0, "informational"),
)

#: Impact and metadata per finding type.  Confidence defaults are deliberately
#: conservative for heuristic/static observations.
FINDING_CATALOG: Dict[str, Dict[str, Any]] = {
    "RCE": {
        "title": "Remote command execution via tool argument injection",
        "severity": "CRITICAL", "confidence": 95, "cwe": "CWE-78",
        "remediation": "Never pass tool arguments to a shell. Use an allowlist "
                       "of commands and argument vectors (execve without shell).",
    },
    "FILE_READ": {
        "title": "Arbitrary file read via tool argument injection",
        "severity": "HIGH", "confidence": 85, "cwe": "CWE-22",
        "remediation": "Resolve paths against an allowlisted root and reject "
                       "traversal after canonicalization.",
    },
    "BLIND_RCE_TIMING": {
        "title": "Possible blind command injection (timing anomaly)",
        "severity": "MEDIUM", "confidence": 40, "cwe": "CWE-78",
        "remediation": "Reproduce with a non-timing oracle before treating "
                       "this as command execution.",
    },
    "TIMING": {
        "title": "Timing anomaly observed",
        "severity": "LOW", "confidence": 20, "cwe": "CWE-400",
        "remediation": "Review for unbounded work; timing alone is not an exploit.",
    },
    "TIMING_SIDE_CHANNEL": {
        "title": "Consistent timing difference across inputs",
        "severity": "LOW", "confidence": 25, "cwe": "CWE-208",
        "remediation": "Use constant-time comparisons and bound query work.",
    },
    "SIZE_SIDE_CHANNEL": {
        "title": "Response size leaks data volume",
        "severity": "LOW", "confidence": 25, "cwe": "CWE-200",
        "remediation": "Bound and normalize response sizes for sensitive tools.",
    },
    "NETWORK_ACTIVITY_DETECTED": {
        "title": "Tool output indicates network activity",
        "severity": "MEDIUM", "confidence": 40, "cwe": "CWE-918",
        "remediation": "Verify network egress is intended and allowlisted.",
    },
    "SHELL_ACTIVITY_DETECTED": {
        "title": "Tool output indicates shell execution",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-78",
        "remediation": "Avoid shelling out; if required, use fixed commands.",
    },
    "ROOT_FILESYSTEM_ACCESS": {
        "title": "Tool output indicates access to sensitive filesystem paths",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-22",
        "remediation": "Sandbox filesystem access and restrict sensitive paths.",
    },
    "RESOURCE_TRAVERSAL": {
        "title": "Path traversal in resources/read",
        "severity": "CRITICAL", "confidence": 90, "cwe": "CWE-22",
        "remediation": "Canonicalize resource URIs and enforce a resource root.",
    },
    "TOOL_PATH_TRAVERSAL": {
        "title": "Path traversal in a tool argument",
        "severity": "CRITICAL", "confidence": 90, "cwe": "CWE-22",
        "remediation": "Canonicalize paths and reject traversal outside the root.",
    },
    "SSRF_CALLBACK": {
        "title": "Server-side request forgery confirmed by callback",
        "severity": "CRITICAL", "confidence": 95, "cwe": "CWE-918",
        "remediation": "Allowlist destinations, block link-local/metadata IPs "
                       "and re-resolve DNS at connect time.",
    },
    "SSRF_RESPONSE": {
        "title": "Server-side request forgery suggested by response",
        "severity": "HIGH", "confidence": 55, "cwe": "CWE-918",
        "remediation": "Allowlist destinations and block internal ranges.",
    },
    "MISSING_AUTH": {
        "title": "MCP endpoint accepts unauthenticated requests",
        "severity": "HIGH", "confidence": 75, "cwe": "CWE-306",
        "remediation": "Require authentication for all MCP endpoints and "
                       "tool calls.",
    },
    "BROKEN_AUTH_TOKEN": {
        "title": "Endpoint accepts invalid or expired credentials",
        "severity": "CRITICAL", "confidence": 65, "cwe": "CWE-287",
        "remediation": "Validate signature, expiry, issuer and audience.",
    },
    "JWT_BYPASS": {
        "title": "JWT validation bypass",
        "severity": "CRITICAL", "confidence": 65, "cwe": "CWE-347",
        "remediation": "Pin algorithms, verify signatures and claims.",
    },
    "IDOR": {
        "title": "Possible broken object-level authorization",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-639",
        "remediation": "Authorize every object access against the caller's "
                       "identity on the server.",
    },
    "VERTICAL_PRIVILEGE_ESCALATION": {
        "title": "Privileged tool reachable without elevated context",
        "severity": "HIGH", "confidence": 40, "cwe": "CWE-269",
        "remediation": "Enforce server-side role checks for privileged tools.",
    },
    "MASS_ASSIGNMENT": {
        "title": "Client-controlled role or permission field accepted",
        "severity": "HIGH", "confidence": 45, "cwe": "CWE-915",
        "remediation": "Bind only allowlisted fields; never accept roles from "
                       "tool input.",
    },
    "TOOL_POISONING": {
        "title": "Tool metadata contains hidden or adversarial instructions",
        "severity": "HIGH", "confidence": 60, "cwe": "CWE-1427",
        "remediation": "Treat tool descriptions as untrusted content, strip "
                       "hidden characters and review descriptions in CI.",
    },
    "TOOL_METADATA_ANOMALY": {
        "title": "Tool metadata is inconsistent or hides content",
        "severity": "MEDIUM", "confidence": 40, "cwe": "CWE-1427",
        "remediation": "Validate tool schemas/descriptions before exposing "
                       "them to an agent.",
    },
    "CREDENTIAL_EXPOSURE": {
        "title": "Credential material exposed in MCP metadata",
        "severity": "HIGH", "confidence": 75, "cwe": "CWE-200",
        "remediation": "Remove secrets from descriptions/defaults and rotate "
                       "any exposed credential.",
    },
    "ATTACK_CHAIN": {
        "title": "Tool capabilities compose into an exfiltration/execution chain",
        "severity": "HIGH", "confidence": 35, "cwe": "CWE-693",
        "remediation": "Enforce per-agent tool allowlists and least privilege.",
    },
    "CAPABILITY_ABUSE": {
        "title": "MCP capability or protocol state abused",
        "severity": "MEDIUM", "confidence": 50, "cwe": "CWE-863",
        "remediation": "Validate protocol state and restrict server-initiated "
                       "requests to negotiated capabilities.",
    },
    "STATE_BYPASS": {
        "title": "Request accepted before initialization",
        "severity": "MEDIUM", "confidence": 55, "cwe": "CWE-696",
        "remediation": "Reject requests until initialization completes.",
    },
    "STATE_RESET": {
        "title": "Server accepts duplicate initialization",
        "severity": "LOW", "confidence": 40, "cwe": "CWE-696",
        "remediation": "Reject a second initialize on an initialized session.",
    },
    "STATE_CRASH": {
        "title": "Server crashed on a protocol state violation",
        "severity": "HIGH", "confidence": 70, "cwe": "CWE-20",
        "remediation": "Validate protocol state before processing requests.",
    },
    "PROTOCOL_CRASH": {
        "title": "Server crashed or stopped responding after malformed input",
        "severity": "HIGH", "confidence": 60, "cwe": "CWE-20",
        "remediation": "Bound parser input and reject malformed JSON-RPC.",
    },
    "PROTOCOL_ERROR_LEAK": {
        "title": "Parser error details leaked to the client",
        "severity": "MEDIUM", "confidence": 45, "cwe": "CWE-209",
        "remediation": "Return generic JSON-RPC errors without stack traces.",
    },
    "CAPABILITY_DOS": {
        "title": "Initialization with malformed capabilities caused a timeout",
        "severity": "MEDIUM", "confidence": 45, "cwe": "CWE-400",
        "remediation": "Validate capability types and bound initialization work.",
    },
    "CAPABILITY_CRASH": {
        "title": "Server crashed on malformed capabilities",
        "severity": "HIGH", "confidence": 65, "cwe": "CWE-20",
        "remediation": "Validate capability objects during negotiation.",
    },
    "PICKLE_DESERIALIZATION_BLIND": {
        "title": "Possible insecure deserialization (timing oracle)",
        "severity": "HIGH", "confidence": 35, "cwe": "CWE-502",
        "remediation": "Never unpickle untrusted data; use a safe format.",
    },
    "YAML_DESERIALIZATION": {
        "title": "Unsafe YAML deserialization",
        "severity": "HIGH", "confidence": 35, "cwe": "CWE-502",
        "remediation": "Use yaml.safe_load and reject arbitrary object tags.",
    },
    "YAML_UNSAFE_LOAD_HINT": {
        "title": "YAML parser error indicates unsafe loader",
        "severity": "MEDIUM", "confidence": 35, "cwe": "CWE-502",
        "remediation": "Use a safe YAML loader.",
    },
    "JSON_GADGET_RCE": {
        "title": "Possible JSON gadget execution (timing oracle)",
        "severity": "HIGH", "confidence": 30, "cwe": "CWE-502",
        "remediation": "Disable type metadata in JSON deserializers.",
    },
    "JSON_GADGET_PARSED": {
        "title": "JSON deserializer processed type metadata",
        "severity": "MEDIUM", "confidence": 40, "cwe": "CWE-502",
        "remediation": "Disable polymorphic type handling.",
    },
    "SCHEMA_POLLUTION": {
        "title": "Prototype/schema pollution behaviour detected",
        "severity": "HIGH", "confidence": 45, "cwe": "CWE-1321",
        "remediation": "Reject __proto__/constructor keys and validate schemas.",
    },
    "ROOT_POLLUTION": {
        "title": "Root-level prototype pollution behaviour detected",
        "severity": "HIGH", "confidence": 45, "cwe": "CWE-1321",
        "remediation": "Reject prototype keys at every nesting level.",
    },
    "RACE_CREATION_COLLISION": {
        "title": "Concurrent creation of the same resource succeeded",
        "severity": "MEDIUM", "confidence": 50, "cwe": "CWE-362",
        "remediation": "Use atomic create-if-absent semantics.",
    },
    "UNHANDLED_DB_LOCK": {
        "title": "Database lock errors exposed under concurrency",
        "severity": "LOW", "confidence": 40, "cwe": "CWE-400",
        "remediation": "Handle lock contention and retry with backoff.",
    },
    "CONCURRENCY_CRASH": {
        "title": "Internal errors exposed under concurrent load",
        "severity": "MEDIUM", "confidence": 50, "cwe": "CWE-209",
        "remediation": "Harden concurrent paths and hide internal errors.",
    },
    "UNBOUNDED_PAYLOAD_SIZE": {
        "title": "Server accepts unbounded tool arguments",
        "severity": "MEDIUM", "confidence": 55, "cwe": "CWE-400",
        "remediation": "Enforce request and argument size limits.",
    },
    "DOS_LARGE_PAYLOAD": {
        "title": "Server failed on an oversized argument",
        "severity": "HIGH", "confidence": 55, "cwe": "CWE-400",
        "remediation": "Enforce argument size limits before dispatch.",
    },
    "STACK_OVERFLOW_EXPOSED": {
        "title": "Recursion error details exposed",
        "severity": "MEDIUM", "confidence": 45, "cwe": "CWE-209",
        "remediation": "Bound nesting depth and hide parser internals.",
    },
    "DOS_RECURSION_CRASH": {
        "title": "Server failed on deeply nested JSON",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-400",
        "remediation": "Bound JSON depth before parsing.",
    },
    "ARRAY_BOMB_SUSCEPTIBLE": {
        "title": "Large arrays cause disproportionate processing",
        "severity": "MEDIUM", "confidence": 45, "cwe": "CWE-400",
        "remediation": "Bound array sizes and processing time.",
    },
    "ARRAY_BOMB_CRASH": {
        "title": "Server failed on a large array",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-400",
        "remediation": "Bound array sizes.",
    },
    "REGEX_DOS": {
        "title": "Possible regular-expression denial of service",
        "severity": "MEDIUM", "confidence": 35, "cwe": "CWE-1333",
        "remediation": "Use linear-time regexes and input length caps.",
    },
    "BATCH_BOMB_CRASH": {
        "title": "Server failed on a large JSON-RPC batch",
        "severity": "HIGH", "confidence": 50, "cwe": "CWE-400",
        "remediation": "Bound batch size and processing time.",
    },
    "BATCH_PROCESSING_LAG": {
        "title": "Large JSON-RPC batch caused processing lag",
        "severity": "MEDIUM", "confidence": 35, "cwe": "CWE-400",
        "remediation": "Bound batch size.",
    },
    "CONNECTION_POOL_EXHAUSTION": {
        "title": "Concurrent requests degraded service",
        "severity": "MEDIUM", "confidence": 40, "cwe": "CWE-400",
        "remediation": "Add bounded concurrency and backpressure.",
    },
    "DOS_CONCURRENT_FLOOD": {
        "title": "Server stopped responding under concurrent load",
        "severity": "HIGH", "confidence": 60, "cwe": "CWE-400",
        "remediation": "Add rate limits and bounded queues.",
    },
    "DOS_CRASH": {
        "title": "Server crashed during a flood test",
        "severity": "HIGH", "confidence": 60, "cwe": "CWE-400",
        "remediation": "Bound resource creation and rate-limit subscriptions.",
    },
    "DOS_UNRESPONSIVE": {
        "title": "Server unresponsive after a flood test",
        "severity": "HIGH", "confidence": 60, "cwe": "CWE-400",
        "remediation": "Bound resource creation and restore service.",
    },
    "DOS_DEGRADATION": {
        "title": "Latency increased substantially after a flood test",
        "severity": "MEDIUM", "confidence": 45, "cwe": "CWE-400",
        "remediation": "Bound subscriptions and add backpressure.",
    },
    "OOB_DNS": {
        "title": "Out-of-band DNS interaction confirms command execution path",
        "severity": "CRITICAL", "confidence": 92, "cwe": "CWE-78",
        "remediation": "Block command injection and untrusted DNS egress.",
    },
    "MARKDOWN_IMAGE_INJECTION": {
        "title": "Tool output reflects Markdown image syntax",
        "severity": "MEDIUM", "confidence": 50, "cwe": "CWE-79",
        "remediation": "Sanitize tool output before rendering in a chat UI.",
    },
    "MARKDOWN_LINK_INJECTION": {
        "title": "Tool output reflects Markdown links",
        "severity": "LOW", "confidence": 45, "cwe": "CWE-79",
        "remediation": "Sanitize or render untrusted output as plain text.",
    },
    "DELIMITER_BREAKOUT": {
        "title": "Tool output reflects context delimiters",
        "severity": "LOW", "confidence": 35, "cwe": "CWE-1427",
        "remediation": "Escape delimiters and delimit tool output structurally.",
    },
    "PROMPT_REFLECTION": {
        "title": "Tool reflects prompt-like input",
        "severity": "INFO", "confidence": 20, "cwe": "CWE-1427",
        "remediation": "Reflection alone is not a vulnerability; review context.",
    },
    "POSSIBLE_CONTEXT_CONFUSION": {
        "title": "Tool output suggests context confusion",
        "severity": "MEDIUM", "confidence": 35, "cwe": "CWE-1427",
        "remediation": "Validate against a control input before concluding.",
    },
    "POSSIBLE_CONTEXT_INJECTION": {
        "title": "Tool output suggests injected instructions were followed",
        "severity": "MEDIUM", "confidence": 35, "cwe": "CWE-1427",
        "remediation": "Validate with an independent control and review prompts.",
    },
    "INJECTION_ANOMALY": {
        "title": "Anomalous tool response after injection probe",
        "severity": "MEDIUM", "confidence": 30, "cwe": "CWE-20",
        "remediation": "Reproduce and inspect the response manually.",
    },
}

DEFAULT_FINDING = {
    "title": "Security observation",
    "severity": "INFO",
    "confidence": 25,
    "cwe": "CWE-693",
    "remediation": "Review the evidence and reproduce manually.",
}


def confidence_label(value: int) -> str:
    for threshold, label in CONFIDENCE_LABELS:
        if value >= threshold:
            return label
    return "informational"


def status_for(confidence: int, verified: bool = False) -> str:
    if verified and confidence >= 85:
        return "confirmed"
    if confidence >= 85:
        return "likely"
    return confidence_label(confidence)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(str(severity).upper(), 0)


def _coerce_confidence(raw: Any, default: int) -> int:
    if isinstance(raw, bool):
        return 90 if raw else default
    if isinstance(raw, (int, float)):
        return max(0, min(100, int(raw)))
    if isinstance(raw, str):
        mapping = {
            "confirmed": 90, "high": 80, "likely": 70, "medium": 55,
            "possible": 45, "low": 30, "informational": 15, "info": 15,
        }
        return mapping.get(raw.strip().lower(), default)
    return default


def redact_secret(value: str, visible: int = 4) -> str:
    """Redact a secret while retaining enough shape for triage."""
    if not value:
        return ""
    if len(value) <= visible * 2:
        return "*" * len(value)
    return value[:visible] + "*" * max(4, len(value) - visible) + value[-2:]


def fingerprint(finding: Dict[str, Any]) -> str:
    """Stable identity used to merge duplicate observations.

    The payload is deliberately excluded: several payloads proving the same
    injection point are one finding with multiple pieces of evidence, not
    several findings that inflate severity counts.
    """
    parts = [
        finding.get("type", ""),
        finding.get("test", ""),
        finding.get("tool", ""),
        finding.get("arg", ""),
        finding.get("uri", ""),
        finding.get("title", ""),
    ]
    material = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(
        material.encode("utf-8", "replace")).hexdigest()[:16]


def make_finding(finding_type: str, *, test: Optional[str] = None,
                 tool: Optional[str] = None, arg: Optional[str] = None,
                 payload: Optional[str] = None, uri: Optional[str] = None,
                 severity: Optional[str] = None,
                 confidence: Optional[int] = None,
                 evidence: Optional[Iterable[str]] = None,
                 verified: bool = False,
                 note: Optional[str] = None,
                 **extra: Any) -> Dict[str, Any]:
    """Build a raw finding dict; normalization happens in the reporter."""
    finding: Dict[str, Any] = {
        "type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "verified": bool(verified),
        "evidence": list(evidence or []),
    }
    if test:
        finding["test"] = test
    for key, value in (("tool", tool), ("arg", arg), ("payload", payload),
                       ("uri", uri)):
        if value is not None:
            finding[key] = value
    if note:
        finding["note"] = note
    finding.update(extra)
    return finding


def normalize_finding(test_name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw finding into the report schema."""
    if not isinstance(raw, dict):
        raw = {"type": "UNKNOWN", "note": str(raw)}
    finding = dict(raw)
    finding_type = str(finding.get("type") or "UNKNOWN")
    spec = FINDING_CATALOG.get(finding_type, DEFAULT_FINDING)

    severity = str(finding.get("severity") or spec["severity"]).upper()
    if severity not in SEVERITY_ORDER:
        severity = spec["severity"]
    confidence = _coerce_confidence(
        finding.get("confidence"), int(spec.get("confidence", 25)))
    verified = bool(finding.get("verified", False))

    # A claim cannot be more confident than the evidence allows.
    if verified:
        confidence = max(confidence, 85)
    else:
        confidence = min(confidence, 84)

    evidence = finding.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    if not evidence:
        for key in ("detections", "response_snippet", "dns_query",
                    "callback_data", "detail", "note"):
            value = finding.get(key)
            if value:
                if isinstance(value, (list, dict)):
                    evidence.append(json.dumps(value, ensure_ascii=False)[:500])
                else:
                    evidence.append(str(value)[:500])
    evidence = [str(item)[:1000] for item in evidence if item]

    finding.setdefault("title", spec["title"])
    finding["type"] = finding_type
    finding["severity"] = severity
    finding["confidence"] = confidence
    finding["confidence_label"] = confidence_label(confidence)
    finding["status"] = status_for(confidence, verified)
    finding["verified"] = bool(verified and confidence >= 85)
    finding["cwe"] = finding.get("cwe") or spec.get("cwe", "CWE-693")
    finding["remediation"] = finding.get(
        "remediation") or spec.get("remediation", DEFAULT_FINDING["remediation"])
    finding["evidence"] = evidence
    finding["test"] = finding.get("test") or test_name
    finding["timestamp"] = finding.get(
        "timestamp") or datetime.now(timezone.utc).isoformat()
    finding["fingerprint"] = finding.get("fingerprint") or fingerprint(finding)
    finding["occurrences"] = int(finding.get("occurrences", 1))
    return finding


def merge_findings(existing: Dict[str, Any],
                   incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a duplicate finding, retaining the strongest evidence."""
    merged = dict(existing)
    if severity_rank(incoming["severity"]) > severity_rank(
            merged["severity"]):
        merged["severity"] = incoming["severity"]
    merged["confidence"] = max(
        int(merged.get("confidence", 0)), int(incoming.get("confidence", 0)))
    merged["confidence_label"] = confidence_label(merged["confidence"])
    merged["verified"] = bool(
        merged.get("verified") or incoming.get("verified"))
    merged["status"] = status_for(
        merged["confidence"], merged["verified"])
    evidence = list(merged.get("evidence", []))
    for item in incoming.get("evidence", []):
        if item not in evidence:
            evidence.append(item)
    merged["evidence"] = evidence[:20]
    merged["occurrences"] = int(merged.get("occurrences", 1)) + int(
        incoming.get("occurrences", 1))
    return merged


def confirm(probe: Callable[[], bool], attempts: int = 2,
            required: int = 2) -> Tuple[bool, List[bool]]:
    """Run a probe repeatedly; an exploit is confirmed only if it reproduces."""
    results: List[bool] = []
    for _ in range(max(1, attempts)):
        try:
            results.append(bool(probe()))
        except Exception:  # noqa: BLE001 - a failed probe is a negative result
            results.append(False)
    return results.count(True) >= required, results
