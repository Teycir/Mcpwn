"""Tool argument injection tests"""
import time
import copy
from payloads import PAYLOADS, PAYLOAD_PRIORITY


class ToolInjectionTest:
    """Inject payloads into tool arguments"""
    def __init__(self, pentester):
        self.pentester = pentester

    def _flatten_schema(self, schema, prefix=""):
        """Recursively flatten nested schema to paths (objects + arrays)"""
        try:
            if schema.get('type') in ['string', 'any'] or 'type' not in schema:
                yield prefix, schema.get('type', 'string')
                return

            if schema.get('type') == 'object':
                props = schema.get('properties', {})
                for key, sub_schema in props.items():
                    new_prefix = f"{prefix}.{key}" if prefix else key
                    yield from self._flatten_schema(sub_schema, new_prefix)
            
            elif schema.get('type') == 'array':
                items = schema.get('items', {})
                new_prefix = f"{prefix}[0]"
                yield from self._flatten_schema(items, new_prefix)
        except (AttributeError, TypeError):
            return

    def _generate_dummy_args(self, schema):
        """Generate valid args satisfying required fields"""
        if schema.get('type') == 'object':
            result = {}
            required = schema.get('required', [])
            properties = schema.get('properties', {})
            for key in required:
                if key in properties:
                    result[key] = "test"
            return result
        return {}

    def _inject_value(self, base_args, path, value):
        """Inject payload into base_args at path (supports dot and array notation)"""
        data = copy.deepcopy(base_args)
        keys = []
        for part in path.replace('[', '.').replace(']', '').split('.'):
            keys.append(int(part) if part.isdigit() else part)
        
        current = data
        for i, key in enumerate(keys[:-1]):
            if isinstance(key, int):
                while len(current) <= key:
                    current.append({})
                current = current[key]
            else:
                if key not in current:
                    current[key] = {} if isinstance(keys[i+1], str) else []
                current = current[key]
        
        last_key = keys[-1]
        if isinstance(last_key, int):
            while len(current) <= last_key:
                current.append("")
            current[last_key] = value
        else:
            current[last_key] = value
        return data

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

        base_args = self._generate_dummy_args(schema)

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for category in categories:
                for payload in PAYLOADS[category]:
                    args = self._inject_value(base_args, arg_path, payload)
                    params = {"name": tool['name'], "arguments": args}

                    try:
                        _, elapsed = self.pentester.send("tools/call", params)
                    except Exception:
                        continue

                    new_findings = self._check_detections(tool['name'], arg_path, payload, category)
                    if new_findings:
                        findings.extend(new_findings)
                        if config.get('quick'):
                            return findings
                    
                    # Wait for blind OOB callbacks
                    time.sleep(0.3)
                    new_findings = self._check_detections(tool['name'], arg_path, payload, category)
                    if new_findings:
                        findings.extend(new_findings)
                        if config.get('quick'):
                            return findings

        return findings

    def _quick_scan(self, tool, payloads):
        """Fast RCE-only scan with minimal payloads"""
        findings = []
        schema = tool.get('inputSchema', {})
        base_args = self._generate_dummy_args(schema)

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for payload in payloads:
                args = self._inject_value(base_args, arg_path, payload)
                params = {"name": tool['name'], "arguments": args}

                try:
                    _, elapsed = self.pentester.send("tools/call", params)
                except Exception:
                    continue

                new_findings = self._check_detections(tool['name'], arg_path, payload, 'command_injection')
                if new_findings:
                    return new_findings
                
                time.sleep(0.3)
                new_findings = self._check_detections(tool['name'], arg_path, payload, 'command_injection')
                if new_findings:
                    return new_findings

        return findings

    def _check_detections(self, tool_name, arg, payload, category):
        """Extract findings from detector"""
        results = []
        if self.pentester.detector.findings:
            results.append({
                'tool': tool_name,
                'arg': arg,
                'payload': payload,
                'category': category,
                'detections': self.pentester.detector.report()
            })
            self.pentester.detector.findings = []
        return results
