"""Tool argument injection tests"""
import time
import copy
import logging
from payloads import PAYLOAD_PRIORITY


class ToolInjectionTest:
    """Inject payloads into tool arguments"""
    def __init__(self, pentester):
        self.pentester = pentester
        self.server_port = None

    def _flatten_schema(self, schema, prefix="", visited=None, root_schema=None):
        """Recursively flatten nested schema to paths (objects + arrays)"""
        if visited is None:
            visited = set()
        if root_schema is None:
            root_schema = schema
        
        schema_id = id(schema)
        if schema_id in visited:
            return
        visited.add(schema_id)
        
        try:
            # Handle $ref: dereference to target schema
            if '$ref' in schema:
                ref_path = schema['$ref'].split('/')
                ref_target = root_schema
                try:
                    for part in ref_path:
                        if part == '#':
                            continue
                        ref_target = ref_target[part]
                    yield from self._flatten_schema(ref_target, prefix, visited, root_schema)
                except (KeyError, TypeError):
                    return
                return
            
            if schema.get('type') in ['string', 'any'] or 'type' not in schema:
                yield prefix, schema.get('type', 'string')
                return

            if schema.get('type') == 'object':
                props = schema.get('properties', {})
                for key, sub_schema in props.items():
                    new_prefix = f"{prefix}.{key}" if prefix else key
                    yield from self._flatten_schema(sub_schema, new_prefix, visited, root_schema)
            
            elif schema.get('type') == 'array':
                items = schema.get('items', {})
                new_prefix = f"{prefix}[0]"
                yield from self._flatten_schema(items, new_prefix, visited, root_schema)
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

    def _inject_value(self, base_args, path, value, schema=None, root_schema=None):
        """Inject payload into base_args at path (supports dot and array notation)"""
        data = copy.deepcopy(base_args)
        keys = self._parse_path(path)
        if root_schema is None:
            root_schema = schema or {}
        
        current = data
        current_schema = root_schema
        
        for i, key in enumerate(keys[:-1]):
            if isinstance(key, int):
                item_schema = current_schema.get('items', {}) if isinstance(current_schema, dict) else {}
                while len(current) <= key:
                    next_key = keys[i+1]
                    current.append({} if isinstance(next_key, str) else [])
                current = current[key]
                current_schema = item_schema
            else:
                if isinstance(current_schema, dict) and '$ref' in current_schema:
                    ref_path = current_schema['$ref'].split('/')
                    ref_target = root_schema
                    try:
                        for part in ref_path:
                            if part != '#':
                                ref_target = ref_target[part]
                        current_schema = ref_target
                    except (KeyError, TypeError):
                        current_schema = {}
                
                props = current_schema.get('properties', {}) if isinstance(current_schema, dict) else {}
                if key not in current:
                    current[key] = {} if isinstance(keys[i+1], str) else []
                current = current[key]
                current_schema = props.get(key, {})
        
        last_key = keys[-1]
        if isinstance(last_key, int):
            item_schema = current_schema.get('items', {}) if isinstance(current_schema, dict) else {}
            item_type = item_schema.get('type', 'object') if isinstance(item_schema, dict) else 'object'
            
            while len(current) <= last_key:
                if item_type == 'string':
                    current.append("")
                elif item_type in ['integer', 'number']:
                    current.append(0)
                elif item_type == 'boolean':
                    current.append(False)
                elif item_type == 'array':
                    current.append([])
                else:
                    current.append({})
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
        stop_on_first = config.get('quick', False)

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
                    
                    args = self._inject_value(base_args, arg_path, payload, schema, schema)
                    params = {"name": tool['name'], "arguments": args}

                    try:
                        start_time = time.time()
                        self.pentester.send("tools/call", params)
                        duration = time.time() - start_time
                        
                        if category == 'command_injection' and duration > 5 and 'sleep' in payload:
                            findings.append({
                                'tool': tool['name'],
                                'arg': arg_path,
                                'payload': payload,
                                'category': 'BLIND_RCE_TIMING',
                                'detections': [f'Timing delay: {duration:.2f}s']
                            })
                            if stop_on_first:
                                return findings
                    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                        logging.debug(f"Tool injection send error: {e}")
                        continue

                    try:
                        new_findings = self._check_detections(tool['name'], arg_path, payload, category)
                        if new_findings:
                            findings.extend(new_findings)
                            if stop_on_first:
                                return findings
                    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                        logging.debug(f"Detection check error: {e}")
                    
                    if not stop_on_first:
                        time.sleep(0.1)
                        try:
                            new_findings = self._check_detections(tool['name'], arg_path, payload, category)
                            if new_findings:
                                findings.extend(new_findings)
                        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                            logging.debug(f"Detection check error: {e}")

        return findings

    def _check_detections(self, tool_name, arg, payload, category):
        """Extract findings from detector"""
        results = []
        try:
            if self.pentester.detector.findings:
                results.append({
                    'tool': tool_name,
                    'arg': arg,
                    'payload': payload,
                    'category': category,
                    'detections': self.pentester.detector.report()
                })
                self.pentester.detector.findings = []
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            logging.debug(f"Detector access error: {e}")
        return results
