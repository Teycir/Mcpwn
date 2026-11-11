"""Tool argument injection tests.

Detection is scoped to the probe's own response.  A candidate is reported as
verified only when an independent repeat produces the same indicator.  Timing
payloads are sent only with ``--allow-destructive`` and are never labeled RCE.
"""
from __future__ import annotations

import copy
import logging
from typing import Any, Dict, List

from core.evidence import make_finding
from core.protocol import (
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
)

logger = logging.getLogger("mcpwn.tool_injection")

# Worst severity each detector finding type implies.
SEVERITY_BY_DETECTION = {
    "RCE": "CRITICAL",
    "OOB_DNS": "CRITICAL",
    "FILE_READ": "HIGH",
    "TIMING": "LOW",
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def classify_detections(detections):
    """Return (type, severity) for the strongest detection; MEDIUM if unknown."""
    types = [d["type"] for d in detections
             if isinstance(d, dict) and d.get("type")]
    if not types:
        return "INJECTION_ANOMALY", "MEDIUM"

    def rank(finding_type):
        return SEVERITY_RANK[SEVERITY_BY_DETECTION.get(finding_type, "MEDIUM")]

    strongest = max(types, key=rank)
    return strongest, SEVERITY_BY_DETECTION.get(strongest, "MEDIUM")


def is_timing_payload(payload: str) -> bool:
    lowered = payload.lower()
    return "sleep" in lowered or "timeout " in lowered


class ToolInjectionTest:
    """Inject payloads into tool arguments."""

    def __init__(self, pentester):
        self.pentester = pentester

    # -- schema handling -------------------------------------------------
    def _flatten_schema(self, schema, prefix="", visited=None,
                        root_schema=None):
        """Recursively flatten a JSON schema to ``path, type`` pairs."""
        if visited is None:
            visited = set()
        if root_schema is None:
            root_schema = schema
        if not isinstance(schema, dict):
            return
        schema_id = id(schema)
        if schema_id in visited:
            return
        visited.add(schema_id)
        try:
            if "$ref" in schema and isinstance(schema["$ref"], str):
                ref_target = self._resolve_ref(schema["$ref"], root_schema)
                if ref_target is not None:
                    yield from self._flatten_schema(
                        ref_target, prefix, visited, root_schema)
                return
            if schema.get("type") in ("string", "any") or "type" not in schema:
                yield prefix, schema.get("type", "string")
                return
            if schema.get("type") == "object":
                for key, sub_schema in schema.get("properties", {}).items():
                    new_prefix = "{}.{}".format(prefix, key) if prefix else key
                    yield from self._flatten_schema(
                        sub_schema, new_prefix, visited, root_schema)
            elif schema.get("type") == "array":
                yield from self._flatten_schema(
                    schema.get("items", {}), prefix + "[0]", visited,
                    root_schema)
        except (AttributeError, TypeError) as exc:
            logger.debug("schema flatten error at %r: %s", prefix, exc)

    @staticmethod
    def _resolve_ref(ref, root_schema):
        if not ref.startswith("#/"):
            return None
        target = root_schema
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or part not in target:
                return None
            target = target[part]
        return target

    def _generate_dummy_args(self, schema):
        if not isinstance(schema, dict) or schema.get("type") != "object":
            return {}
        result = {}
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in properties:
                continue
            prop_type = properties[key].get("type", "string")
            if prop_type in ("integer", "number"):
                result[key] = 0
            elif prop_type == "boolean":
                result[key] = False
            elif prop_type == "array":
                result[key] = []
            elif prop_type == "object":
                result[key] = {}
            else:
                result[key] = "test"
        return result

    def _parse_path(self, path):
        keys = []
        current = ""
        index = 0
        while index < len(path):
            char = path[index]
            if char == "[":
                if current:
                    keys.append(current)
                    current = ""
                end = path.find("]", index)
                if end == -1:
                    return []
                try:
                    keys.append(int(path[index + 1:end]))
                except ValueError:
                    return []
                index = end + 1
            elif char == ".":
                if current:
                    keys.append(current)
                    current = ""
                index += 1
            else:
                current += char
                index += 1
        if current:
            keys.append(current)
        return keys

    def _inject_value(self, base_args, path, value, schema=None,
                      root_schema=None):
        """Inject payload into a deep copy of ``base_args`` at ``path``."""
        data = copy.deepcopy(base_args)
        keys = self._parse_path(path)
        if not keys:
            return data
        root_schema = root_schema if root_schema is not None else (schema or {})
        current = data
        current_schema = root_schema
        for position, key in enumerate(keys[:-1]):
            if isinstance(key, int):
                if not isinstance(current, list):
                    return data
                item_schema = (current_schema.get("items", {})
                               if isinstance(current_schema, dict) else {})
                next_key = keys[position + 1]
                while len(current) <= key:
                    current.append({} if isinstance(next_key, str) else [])
                current = current[key]
                current_schema = item_schema
            else:
                if not isinstance(current, dict):
                    return data
                if isinstance(current_schema, dict) and "$ref" in current_schema:
                    current_schema = self._resolve_ref(
                        current_schema["$ref"], root_schema) or {}
                properties = (current_schema.get("properties", {})
                              if isinstance(current_schema, dict) else {})
                next_key = keys[position + 1]
                if key not in current:
                    current[key] = {} if isinstance(next_key, str) else []
                current = current[key]
                current_schema = properties.get(key, {})
        last_key = keys[-1]
        if isinstance(last_key, int):
            if not isinstance(current, list):
                return data
            item_schema = (current_schema.get("items", {})
                           if isinstance(current_schema, dict) else {})
            item_type = (item_schema.get("type", "object")
                         if isinstance(item_schema, dict) else "object")
            defaults = {
                "string": "", "integer": 0, "number": 0,
                "boolean": False, "array": [], "object": {},
            }
            while len(current) <= last_key:
                current.append(defaults.get(item_type, {}))
            current[last_key] = value
        else:
            if isinstance(current, dict):
                current[last_key] = value
        return data

    # -- execution -------------------------------------------------------
    def run(self, tool: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        schema = tool.get("inputSchema", {}) or {}
        base_args = self._generate_dummy_args(schema)
        config = self.pentester.config
        quick = bool(config.get("quick"))
        destructive = self.pentester.policy.destructive_allowed
        limit = self.pentester.policy.payload_limit()

        payloads = self.pentester.get_payloads({
            "tool_name": tool.get("name"),
            "target_type": "command_injection",
            "schema_hints": schema,
        })
        payloads = [p for p in payloads
                    if destructive or not is_timing_payload(p)]
        payloads = list(dict.fromkeys(payloads))[:limit]

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ("string", "any"):
                continue
            for payload in payloads:
                args = self._inject_value(
                    base_args, arg_path, payload, schema, schema)
                if args == base_args:
                    continue
                params = {"name": tool.get("name"), "arguments": args}
                try:
                    response, elapsed = self.pentester.send(
                        "tools/call", params, skip_analysis=True)
                except (TransportError, ProtocolError, RequestTimeout,
                        SafetyLimitExceeded) as exc:
                    logger.debug("send failed for %s: %s",
                                 tool.get("name"), exc)
                    if isinstance(exc, SafetyLimitExceeded):
                        return findings
                    continue

                detections = self.pentester.scan_response(response)
                if detections:
                    finding_type, severity = classify_detections(detections)
                    verified = self._reproduce(tool, params)
                    findings.append(make_finding(
                        finding_type,
                        tool=tool.get("name"),
                        arg=arg_path,
                        payload=payload,
                        severity=severity,
                        confidence=90 if verified else 55,
                        verified=verified,
                        evidence=[
                            "payload={!r}".format(payload),
                            "indicator: {}".format(
                                ", ".join(d.get("indicator", "")
                                          for d in detections)[:300]),
                            "response: {}".format(
                                content_summary(response, 300)),
                        ],
                        detections=detections,
                        note="indicator reproduced" if verified
                             else "single observation; reproduce manually",
                    ))
                    if quick:
                        return findings
                    continue

                if destructive and is_timing_payload(payload):
                    timing = self._timing_signal(
                        tool, params, elapsed, payload, arg_path)
                    if timing:
                        findings.append(timing)
                        if quick:
                            return findings
        return findings

    def _reproduce(self, tool, params):
        try:
            response, _ = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return False
        return bool(self.pentester.scan_response(response))

    def _timing_signal(self, tool, params, elapsed, payload, arg_path):
        """Report a timing delay as a weak signal, never as confirmed RCE."""
        baseline = self.pentester.measure_baseline("ping", {}, samples=3)
        if baseline is None:
            return None
        try:
            _, control_elapsed = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None
        try:
            _, repeat_elapsed = self.pentester.send(
                "tools/call", params, skip_analysis=True)
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded):
            return None
        if min(elapsed, control_elapsed, repeat_elapsed) < baseline + 2.0:
            return None
        return make_finding(
            "BLIND_RCE_TIMING",
            tool=tool.get("name"),
            arg=arg_path,
            payload=payload,
            severity="MEDIUM",
            confidence=40,
            verified=False,
            evidence=[
                "baseline median {:.2f}s".format(baseline),
                "probe {:.2f}s, repeat {:.2f}s".format(
                    control_elapsed, repeat_elapsed),
                "timing anomaly only; no output oracle",
            ],
            note="unverified timing anomaly; not confirmed command execution",
        )
