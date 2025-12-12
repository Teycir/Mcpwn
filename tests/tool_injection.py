"""Tool argument injection tests"""
import time
import copy
from payloads import PAYLOAD_PRIORITY


class ToolInjectionTest:
    """Inject payloads into tool arguments"""
    def __init__(self, pentester):
        self.pentester = pentester
        self.server_port = None

    def _flatten_schema(self, schema, prefix="", visited=None):
        """Recursively flatten nested schema to paths (objects + arrays)"""
        if visited is None:
            visited = set()
        
        schema_id = id(schema)
        if schema_id in visited:
            return
        visited.add(schema_id)
        
        try:
            if schema.get('type') in ['string', 'any'] or 'type' not in schema:
                yield prefix, schema.get('type', 'string')
                return

            if schema.get('type') == 'object':
                props = schema.get('properties', {})
                for key, sub_schema in props.items():
                    new_prefix = f"{prefix}.{key}" if prefix else key
                    yield from self._flatten_schema(sub_schema, new_prefix, visited)
            
            elif schema.get('type') == 'array':
                items = schema.get('items', {})
                new_prefix = f"{prefix}[0]"
                yield from self._flatten_schema(items, new_prefix, visited)
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
                    prop_type = properties[key].get('type', 'string')
                    if prop_type == 'integer' or prop_type == 'number':
                        result[key] = 0
                    elif prop_type == 'boolean':
                        result[key] = False
                    elif prop_type == 'array':
                        result[key] = []
                    elif prop_type == 'object':
                        result[key] = {}
                    else:
                        result[key] = "test"
            return result
        return {}

    def _parse_path(self, path):
        """Parse path into keys, handling array indices and dots in key names"""
        keys = []
        i = 0
        current_key = ""
        while i < len(path):
            if path[i] == '[':
                if current_key:
                    keys.append(current_key)
                    current_key = ""
                j = i + 1
                while j < len(path) and path[j] != ']':
                    j += 1
                keys.append(int(path[i+1:j]))
                i = j + 1
            elif path[i] == '.':
                if current_key:
                    keys.append(current_key)
                    current_key = ""
                i += 1
            else:
                current_key += path[i]
                i += 1
        if current_key:
            keys.append(current_key)
        return keys

    def _inject_value(self, base_args, path, value):
        """Inject payload into base_args at path (supports dot and array notation)"""
        data = copy.deepcopy(base_args)
        keys = self._parse_path(path)
        
        current = data
        for i, key in enumerate(keys[:-1]):
            if isinstance(key, int):
                while len(current) <= key:
                    next_key = keys[i+1]
                    current.append({} if isinstance(next_key, str) else [])
                current = current[key]
            else:
                if key not in current:
                    current[key] = {} if isinstance(keys[i+1], str) else []
                current = current[key]
        
        last_key = keys[-1]
        if isinstance(last_key, int):
            while len(current) <= last_key:
                current.append(None)
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
            context = {'tool_name': tool['name'], 'target_type': 'command_injection', 'schema_hints': schema}
            quick_payloads = self.pentester.get_payloads(context)
            return self._quick_scan(tool, quick_payloads)

        # RCE-only mode: skip non-RCE categories
        if config.get('rce_only'):
            categories = ['command_injection']
        else:
            categories = PAYLOAD_PRIORITY

        base_args = self._generate_dummy_args(schema)
        seen_payloads = set()

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for category in categories:
                # Get payloads: LLM-generated or static
                context = {
                    'tool_name': tool['name'],
                    'target_type': category,
                    'schema_hints': schema,
                    'previous_failure': None
                }
                payloads = self.pentester.get_payloads(context)
                
                for payload in payloads:
                    if payload in seen_payloads:
                        continue
                    seen_payloads.add(payload)
                    
                    args = self._inject_value(base_args, arg_path, payload)
                    params = {"name": tool['name'], "arguments": args}

                    try:
                        self.pentester.send("tools/call", params)
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
        seen_payloads = set()

        for arg_path, arg_type in self._flatten_schema(schema):
            if arg_type not in ['string', 'any']:
                continue

            for payload in payloads:
                if payload in seen_payloads:
                    continue
                seen_payloads.add(payload)
                
                args = self._inject_value(base_args, arg_path, payload)
                params = {"name": tool['name'], "arguments": args}

                try:
                    self.pentester.send("tools/call", params)
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
