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
            if 'error' not in resp:
                findings.append("VULN: tools/list works without initialize")
        except (RuntimeError, IOError, OSError) as e:
            print(f"[!] Skip initialize test error: {e}")
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
                "clientInfo": {}
            }
            self.pentester.send("initialize", init_params)
            resp, _ = self.pentester.send("initialize", init_params)
            if 'error' not in resp:
                findings.append("VULN: Double initialize accepted")
        except (RuntimeError, IOError, OSError) as e:
            print(f"[!] Double initialize test error: {e}")
        finally:
            self._cleanup()
        return findings

    def _cleanup(self):
        """Safely terminate process"""
        self.pentester.restart_server()
