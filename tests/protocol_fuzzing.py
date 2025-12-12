"""JSON-RPC protocol fuzzing tests"""
import json


class ProtocolFuzzingTest:
    """Fuzz JSON-RPC structure for parser vulnerabilities"""
    def __init__(self, pentester):
        self.pentester = pentester

    MALFORMED_PACKETS = [
        '{"jsonrpc":"2.0","method":"initialize","params":"STRING"}',
        '{"jsonrpc":"2.0","method":123}',
        '{"incomplete":',
        '{"jsonrpc":"2.0","id":null,"method":"tools/list"}',
        '[]',
        'null',
    ]

    def run(self):
        """Test protocol parser robustness"""
        self.pentester.health_check()
        findings = []

        for packet in self.MALFORMED_PACKETS:
            try:
                with self.pentester.lock:
                    if not self.pentester.proc:
                        break
                    
                    self.pentester.proc.stdin.write(packet + '\n')
                    self.pentester.proc.stdin.flush()
                    
                    # Small delay to detect crash
                    import time
                    time.sleep(0.1)

                    # Check if server crashed
                    if self.pentester.proc.poll() is not None:
                        findings.append({
                            'type': 'CRASH',
                            'payload': packet,
                            'risk': 'DoS via malformed JSON-RPC'
                        })
                        self.pentester.restart_server()
            except Exception as e:
                findings.append({
                    'type': 'ERROR',
                    'payload': packet,
                    'error': str(e)
                })
                self.pentester.restart_server()

        return findings
