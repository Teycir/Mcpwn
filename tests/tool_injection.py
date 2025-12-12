"""Tool argument injection tests"""
from payloads import PAYLOADS, PAYLOAD_PRIORITY


class ToolInjectionTest:
    """Inject payloads into tool arguments"""
    def __init__(self, pentester):
        self.pentester = pentester

    def _flatten_schema(self, schema, prefix=""):
        """Recursively flatten nested schema to paths"""
        try:
            if schema.get('type') in ['string', 'any'] or 'type' not in schema:
                yield prefix, schema.get('type', 'string')
                return

            if schema.get('type') == 'object':
                props = schema.get('properties', {})
                for key, sub_schema in props.items():
                    new_prefix = f"{prefix}.{key}" if prefix else key
                    yield from self._flatten_schema(sub_schema, new_prefix)
        except (AttributeError, TypeError):
            return

    def _build_nested_args(self, path, value):
        """Build nested dict from dot-path"""
        if '.' not in path:
            return {path: value}
        
        parts = path.split('.')
        result = {}
        current = result
        for part in parts[:-1]:
            current[part] = {}
            current = current[part]
        current[parts[-1]] = value
        return result

    def run(self, tool):
        """Execute tool injection tests with recursive schema support"""
        self.pentester.health_check()
        findings = []
        schema = tool.get('inputSchema', {})
        config = self.pentester.config

        # Quick mode: use minimal payloads
        if config.get('quick'):
            from payloads import RCE_QUICK_PAYLOADS
            return self._quick_scan(tool, RCE_QUICK_PAYLOADS)

        # RCE-only mode: skip non-RCE categories
        if config.get('rce_only'):
            categories = ['command_injection']
        else:
            categories = PAYLOAD_PRIORITY + [
                c for c in PAYLOADS.keys() if c not in PAYLOAD_PRIORITY
            ]

        # Flatten nested schemas
        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for category in categories:
                for payload in PAYLOADS[category]:
                    args = self._build_nested_args(arg_path, payload)
                    params = {"name": tool['name'], "arguments": args}

                    _, elapsed = self.pentester.send("tools/call", params)

                    if self.pentester.detector.findings:
                        findings.append({
                            'tool': tool['name'],
                            'arg': arg_path,
                            'payload': payload,
                            'category': category,
                            'detections': self.pentester.detector.report()
                        })
                        self.pentester.detector.findings = []
                        
                        # Early exit on RCE in quick mode
                        if config.get('quick'):
                            return findings

        return findings

    def _quick_scan(self, tool, payloads):
        """Fast RCE-only scan with minimal payloads"""
        findings = []
        schema = tool.get('inputSchema', {})

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for payload in payloads:
                args = self._build_nested_args(arg_path, payload)
                params = {"name": tool['name'], "arguments": args}

                _, elapsed = self.pentester.send("tools/call", params)

                if self.pentester.detector.findings:
                    findings.append({
                        'tool': tool['name'],
                        'arg': arg_path,
                        'payload': payload,
                        'category': 'command_injection',
                        'detections': self.pentester.detector.report()
                    })
                    self.pentester.detector.findings = []
                    return findings  # Stop on first RCE

        return findings
