"""State desynchronization tests"""


class StateDesyncTest:
    """Test protocol state violations"""
    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        """Execute state desync tests"""
        findings = []

        # Test: Skip initialize
        findings.extend(self._test_skip_initialize())

        # Test: Double initialize
        findings.extend(self._test_double_initialize())

        return findings

    def _test_skip_initialize(self):
        """Test calling methods without initialization"""
        findings = []
        self.pentester.start()
        try:
            resp, _ = self.pentester.send("tools/list")
            if isinstance(resp, dict) and 'result' in resp:
                findings.append({
                    'type': 'STATE_BYPASS',
                    'detail': 'tools/list executed without initialize handshake',
                    'severity': 'HIGH'
                })
            elif isinstance(resp, dict) and 'error' not in resp:
                findings.append({
                    'type': 'STATE_BYPASS',
                    'detail': 'Server ignored uninitialized state (no error returned)',
                    'severity': 'MEDIUM'
                })
        except (RuntimeError, IOError, OSError):
            if not self.pentester.is_alive():
                findings.append({
                    'type': 'STATE_CRASH',
                    'detail': 'Server crashed on uninitialized tools/list call',
                    'severity': 'CRITICAL'
                })
        finally:
            self._cleanup()
        return findings

    def _test_double_initialize(self):
        """Test double initialization"""
        findings = []
        self.pentester.start()
        try:
            init_params = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "audit-tool", "version": "1.0"}
            }
            self.pentester.send("initialize", init_params)
            self.pentester.send_notification("notifications/initialized")
            resp, _ = self.pentester.send("initialize", init_params)
            if isinstance(resp, dict) and 'result' in resp:
                findings.append({
                    'type': 'STATE_RESET',
                    'detail': 'Server accepted double initialization',
                    'severity': 'MEDIUM'
                })
        except (RuntimeError, IOError, OSError):
            if not self.pentester.is_alive():
                findings.append({
                    'type': 'STATE_CRASH',
                    'detail': 'Server crashed on double initialization',
                    'severity': 'CRITICAL'
                })
        finally:
            self._cleanup()
        return findings

    def _cleanup(self):
        """Safely terminate process"""
        self.pentester.restart_server()
