"""Authentication and authorization bypass tests for MCP servers"""
from contextlib import contextmanager
import copy


class AuthBypassTest:
    """Test for missing/weak authentication and authorization controls"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    @contextmanager
    def _modified_headers(self, headers):
        """Safely modify headers with automatic restoration"""
        if not hasattr(self.pentester.client, '_extra_headers'):
            yield
            return
        original = copy.deepcopy(self.pentester.client._extra_headers)
        try:
            self.pentester.client._extra_headers = headers
            yield
        finally:
            self.pentester.client._extra_headers = original
    
    def _generate_valid_payload(self, tool, override_args=None):
        """Generate schema-compliant payloads to bypass validation layers"""
        override_args = override_args or {}
        schema = tool.get('inputSchema', {})
        args = {}
        
        for prop, spec in schema.get('properties', {}).items():
            if prop in override_args:
                args[prop] = override_args[prop]
            elif spec.get('type') == 'string':
                args[prop] = "test_value"
            elif spec.get('type') in ['integer', 'number']:
                args[prop] = 1
            elif spec.get('type') == 'boolean':
                args[prop] = True
        
        return {"name": tool['name'], "arguments": args}
    
    def run(self, tool):
        """Test auth/authz enforcement"""
        findings = []
        findings.extend(self._test_no_auth(tool))
        findings.extend(self._test_token_replay(tool))
        findings.extend(self._test_jwt_manipulation(tool))
        findings.extend(self._test_header_injection(tool))
        findings.extend(self._test_privilege_escalation(tool))
        findings.extend(self._test_vertical_escalation(tool))
        findings.extend(self._test_role_tampering(tool))
        return findings
    
    def _test_no_auth(self, tool):
        """Test if tools work without auth headers"""
        findings = []
        with self._modified_headers({}):
            try:
                params = self._generate_valid_payload(tool)
                resp, _ = self.pentester.send("tools/call", params)
                
                resp_str = str(resp).lower()
                is_auth_error = any(x in resp_str for x in ['unauthorized', 'forbidden', 'authentication', 'token'])
                has_content = resp and isinstance(resp, dict) and len(resp) > 0
                
                if has_content and not is_auth_error and 'error' not in resp_str:
                    findings.append({
                        'type': 'MISSING_AUTH',
                        'tool': tool['name'],
                        'severity': 'HIGH',
                        'note': 'Tool executed successfully without Authorization header'
                    })
            except Exception:
                pass
        return findings
    
    def _test_token_replay(self, tool):
        """Test expired/invalid token handling"""
        findings = []
        bad_tokens = ['Bearer expired_token', 'Bearer null', 'Bearer undefined', 'Bearer aaaa']
        
        for token in bad_tokens:
            with self._modified_headers({'Authorization': token}):
                try:
                    params = self._generate_valid_payload(tool)
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    resp_str = str(resp).lower()
                    if resp and 'unauthorized' not in resp_str and 'invalid' not in resp_str and 'error' not in resp_str:
                        findings.append({
                            'type': 'BROKEN_AUTH_TOKEN',
                            'tool': tool['name'],
                            'severity': 'CRITICAL',
                            'note': f'Accepted invalid token: {token[:30]}'
                        })
                        break
                except Exception:
                    pass
        return findings
    
    def _test_jwt_manipulation(self, tool):
        """Test JWT-specific vulnerabilities"""
        findings = []
        jwt_attacks = [
            ('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.', 'alg:none'),
            ('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.', 'no signature'),
            ('eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.fake', 'invalid signature'),
        ]
        
        for jwt, attack_type in jwt_attacks:
            with self._modified_headers({'Authorization': f'Bearer {jwt}'}):
                try:
                    params = self._generate_valid_payload(tool)
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    resp_str = str(resp).lower()
                    if resp and 'error' not in resp_str and 'invalid' not in resp_str:
                        findings.append({
                            'type': 'JWT_BYPASS',
                            'tool': tool['name'],
                            'severity': 'CRITICAL',
                            'note': f'Accepted JWT with {attack_type}'
                        })
                        break
                except Exception:
                    pass
        return findings
    
    def _test_header_injection(self, tool):
        """Test for header injection via auth values"""
        findings = []
        for token in ['valid\r\nX-Admin: true', 'valid\nX-Role: admin']:
            with self._modified_headers({'Authorization': token}):
                try:
                    params = self._generate_valid_payload(tool)
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    resp_str = str(resp).lower()
                    if resp and 'error' not in resp_str and ('admin' in resp_str or 'elevated' in resp_str):
                        findings.append({
                            'type': 'HEADER_INJECTION',
                            'tool': tool['name'],
                            'severity': 'HIGH',
                            'payload': repr(token[:30])
                        })
                        break
                except Exception:
                    pass
        return findings
    
    def _test_privilege_escalation(self, tool):
        """Test horizontal privilege escalation via resource IDs"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        for arg, spec in schema.get('properties', {}).items():
            if any(k in arg.lower() for k in ['user', 'id', 'owner', 'account']):
                for victim_id in ['admin', '0', 'root', '../other_user']:
                    try:
                        params = self._generate_valid_payload(tool, {arg: victim_id})
                        resp, _ = self.pentester.send("tools/call", params)
                        
                        resp_str = str(resp).lower()
                        # Must have positive data indicators, not just absence of error
                        has_data = isinstance(resp, dict) and any(k in resp for k in ['id', 'data', 'result', 'user', 'content'])
                        is_error = any(err in resp_str for err in ['forbidden', 'denied', 'unauthorized', 'not found', 'does not exist'])
                        
                        if has_data and not is_error:
                            findings.append({
                                'type': 'IDOR',
                                'tool': tool['name'],
                                'arg': arg,
                                'severity': 'CRITICAL',
                                'note': f'Accessed resource with ID: {victim_id}'
                            })
                            break
                    except Exception:
                        pass
        return findings
    
    def _test_vertical_escalation(self, tool):
        """Test access to admin-only tools (requires low-privilege context)"""
        findings = []
        tool_name = tool['name'].lower()
        
        if any(ind in tool_name for ind in ['admin', 'manage', 'delete', 'config', 'system']):
            try:
                params = self._generate_valid_payload(tool)
                resp, _ = self.pentester.send("tools/call", params)
                
                resp_str = str(resp).lower()
                is_denied = any(x in resp_str for x in ['unauthorized', 'forbidden', 'admin only', 'insufficient'])
                
                if resp and not is_denied and 'error' not in resp_str:
                    findings.append({
                        'type': 'VERTICAL_PRIVILEGE_ESCALATION',
                        'tool': tool['name'],
                        'severity': 'CRITICAL',
                        'note': 'Admin tool accessible without elevated privileges'
                    })
            except Exception:
                pass
        return findings
    
    def _test_role_tampering(self, tool):
        """Test if role/permission parameters are client-controllable"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        for arg, spec in schema.get('properties', {}).items():
            if any(k in arg.lower() for k in ['role', 'permission', 'scope', 'admin', 'privilege']):
                for value in ['admin', 'root', 'superuser']:
                    try:
                        params = self._generate_valid_payload(tool, {arg: value})
                        resp, _ = self.pentester.send("tools/call", params)
                        
                        resp_str = str(resp).lower()
                        # CRITICAL: Must verify the injected value is REFLECTED in response
                        value_reflected = value.lower() in resp_str and any(k in resp_str for k in ['role', 'permission', 'created'])
                        is_error = any(err in resp_str for err in ['invalid', 'denied', 'error', 'forbidden'])
                        
                        if value_reflected and not is_error:
                            findings.append({
                                'type': 'MASS_ASSIGNMENT',
                                'tool': tool['name'],
                                'arg': arg,
                                'value': value,
                                'severity': 'CRITICAL',
                                'note': f'Server accepted and reflected {arg}={value}'
                            })
                            break
                    except Exception:
                        pass
        return findings
