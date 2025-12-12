"""Capability fuzzing during MCP initialization"""


class CapabilityFuzzingTest:
    """Test malformed capabilities during protocol negotiation"""
    
    OVERSIZED_LIST_THRESHOLD = 1000
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    FUZZ_CAPABILITIES = [
        # Type confusion
        {"tools": "invalid_string"},
        {"resources": 123},
        {"prompts": []},
        # Invalid capability names
        {"__proto__": {}},
        {"constructor": {}},
        {"../../../etc": {}},
        # Oversized lists
        {"tools": {"listChanged": True} * OVERSIZED_LIST_THRESHOLD},
        # Nested pollution
        {"tools": {"subscribe": {"__proto__": {"polluted": True}}}},
        # Null/undefined injection
        {"tools": None},
        {"logging": {"level": "\x00"}},
    ]
    
    def run(self):
        """Test capability fuzzing"""
        findings = []
        dos_threshold = 5  # seconds
        
        for cap in self.FUZZ_CAPABILITIES:
            try:
                self.pentester.stop()
                self.pentester.start()
                
                resp, elapsed = self.pentester.send("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": cap,
                    "clientInfo": {"name": "mcpwn", "version": "1.0"}
                }, skip_analysis=True)
                
                # Server should reject invalid capabilities
                if "error" not in resp:
                    findings.append({
                        'type': 'CAPABILITY_VALIDATION_BYPASS',
                        'severity': 'HIGH',
                        'payload': str(cap),
                        'response': str(resp)[:200]
                    })
                
                # Check for crash indicators
                if elapsed > dos_threshold or not resp:
                    findings.append({
                        'type': 'CAPABILITY_DOS',
                        'severity': 'MEDIUM',
                        'payload': str(cap),
                        'elapsed': elapsed
                    })
                    
            except Exception as e:
                # Crashes are findings
                if "crash" in str(e).lower() or "segfault" in str(e).lower():
                    findings.append({
                        'type': 'CAPABILITY_CRASH',
                        'severity': 'HIGH',
                        'payload': str(cap),
                        'error': str(e)
                    })
        
        return findings
