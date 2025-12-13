"""JSON-RPC protocol fuzzing tests"""
import json
import time
import logging


class ProtocolFuzzingTest:
    """Fuzz JSON-RPC structure for parser vulnerabilities and zombie states"""
    def __init__(self, pentester):
        self.pentester = pentester
        self.socket_pool = []

    def run(self):
        """Test protocol parser robustness"""
        self.pentester.health_check()
        findings = []

        payloads = [
            ('{"jsonrpc":"2.0", "method": "test", "params": ', 'PARSE_ERROR'),
            ('{"jsonrpc":"2.0", "method": 12345}', 'INVALID_REQUEST_TYPE'),
            ('{"jsonrpc":"2.0", "result": "unexpected"}', 'UNEXPECTED_MESSAGE'),
            ('[]', 'EMPTY_BATCH'),
            ('[{"jsonrpc":"2.0", "method": "ping"}, 1]', 'INVALID_BATCH_ITEM'),
            ('{"jsonrpc":"2.0", "method": "test\x00"}', 'NULL_BYTE_INJECTION'),
            (json.dumps({"jsonrpc": "2.0", "method": "echo", "params": {"data": "A" * 1024 * 1024}, "id": 9999}), 'LARGE_BUFFER_1MB'),
        ]

        for packet, test_type in payloads:
            if not self._run_single_fuzz(packet):
                findings.append({
                    'type': 'PROTOCOL_CRASH',
                    'variant': test_type,
                    'payload': packet[:100] + '...',
                    'severity': 'CRITICAL',
                    'note': 'Server crashed or became unresponsive (Zombie state)'
                })
                self.pentester.restart_server()
                
        return findings

    def _run_single_fuzz(self, packet):
        """Send malformed packet then verify server responsiveness via liveness probe"""
        try:
            if not self.pentester.proc or self.pentester.proc.poll() is not None:
                return False
            
            try:
                self.pentester.proc.stdin.write(packet.encode('utf-8') + b'\n')
                self.pentester.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                return False

            time.sleep(0.2)

            if self.pentester.proc.poll() is not None:
                return False

            # Liveness probe: detect zombie state
            try:
                self.pentester.send("ping", {}, timeout=2.0)
                return True
            except Exception:
                return False

        except Exception:
            return False
    
    def cleanup(self):
        """Clean up socket pool"""
        for sock in self.socket_pool:
            try:
                sock.close()
            except (OSError, ValueError, TypeError, AttributeError) as e:
                logging.debug(f"Socket close error: {e}")
        self.socket_pool.clear()
