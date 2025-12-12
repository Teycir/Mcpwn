"""Authentication and authorization bypass tests for MCP servers"""
from contextlib import contextmanager


class AuthBypassTest:
    """Test for missing/weak authentication and authorization controls"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    @contextmanager
    def _modified_headers(self, headers):
        """Safely modify headers with automatic restoration"""
        original = getattr(self.pentester.client, '_extra_headers', {}).copy()
        try:
            if hasattr(self.pentester.client, '_extra_headers'):
                self.pentester.client._extra_headers = headers
            yield
        finally:
            if hasattr(self.pentester.client, '_extra_headers'):
                self.pentester.client._extra_headers = original
    
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
                params = {"name": tool['name'], "arguments": {}}
                resp, _ = self.pentester.send("tools/call", params)
                
                if resp and not any(err in str(resp).lower() for err in ['unauthorized', 'forbidden', 'auth']):
                    findings.append({
                        'type': 'MISSING_AUTH',
                        'tool': tool['name'],
                        'severity': 'HIGH',
                        'note': 'Tool executed without authentication'
                    })
            except Exception:
                pass
        return findings
    
    def _test_token_replay(self, tool):
        """Test expired/invalid token handling"""
        findings = []
        for token in ['expired_token_123', 'Bearer invalid', 'null', '']:
            with self._modified_headers({'Authorization': token}):
                try:
                    params = {"name": tool['name'], "arguments": {}}
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    if resp and 'unauthorized' not in str(resp).lower():
                        findings.append({
                            'type': 'INVALID_TOKEN_ACCEPTED',
                            'tool': tool['name'],
                            'severity': 'CRITICAL',
                            'token': token[:20]
                        })
                        break
                except Exception:
                    pass
        return findings
    
    def _test_jwt_manipulation(self, tool):
        """Test JWT-specific vulnerabilities"""
        findings = []
        jwt_attacks = [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',  # alg:none
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.',  # No signature
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiInIE9SICcxJz0nMSJ9.fake",  # SQL in claim
        ]
        
        for jwt in jwt_attacks:
            with self._modified_headers({'Authorization': f'Bearer {jwt}'}):
                try:
                    params = {"name": tool['name'], "arguments": {}}
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    if resp and 'error' not in str(resp).lower():
                        findings.append({
                            'type': 'JWT_BYPASS',
                            'tool': tool['name'],
                            'severity': 'CRITICAL',
                            'note': 'Malformed/unsigned JWT accepted'
                        })
                        break
                except Exception:
                    pass
        return findings
    
    def _test_header_injection(self, tool):
        """Test for header injection via auth values"""
        findings = []
        for token in ['valid\r\nX-Admin: true', 'valid\nX-Forwarded-For: 127.0.0.1']:
            with self._modified_headers({'Authorization': token}):
                try:
                    params = {"name": tool['name'], "arguments": {}}
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    if resp and 'admin' in str(resp).lower():
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
                for victim_id in ['admin', '0', '1', 'root', '../other_user']:
                    try:
                        params = {"name": tool['name'], "arguments": {arg: victim_id}}
                        resp, _ = self.pentester.send("tools/call", params)
                        
                        if resp and not any(err in str(resp).lower() for err in ['forbidden', 'denied', 'unauthorized']):
                            findings.append({
                                'type': 'HORIZONTAL_PRIVILEGE_ESCALATION',
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
        """Test access to admin-only tools"""
        findings = []
        tool_name = tool['name'].lower()
        
        if any(ind in tool_name for ind in ['admin', 'manage', 'delete', 'config', 'system', 'internal']):
            try:
                params = {"name": tool['name'], "arguments": {}}
                resp, _ = self.pentester.send("tools/call", params)
                
                if resp and 'unauthorized' not in str(resp).lower():
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
            if any(k in arg.lower() for k in ['role', 'permission', 'scope', 'admin', 'privilege', 'level', 'access']):
                for value in ['admin', 'root', 'superuser', '*', 'all', 'true', '1']:
                    try:
                        params = {"name": tool['name'], "arguments": {arg: value}}
                        resp, _ = self.pentester.send("tools/call", params)
                        
                        if resp and not any(err in str(resp).lower() for err in ['invalid', 'denied', 'error']):
                            findings.append({
                                'type': 'ROLE_TAMPERING',
                                'tool': tool['name'],
                                'arg': arg,
                                'value': value,
                                'severity': 'CRITICAL'
                            })
                            break
                    except Exception:
                        pass
        return findings
