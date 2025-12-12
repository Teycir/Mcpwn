"""Resource path traversal tests"""
from payloads import PAYLOADS


class ResourceTraversalTest:
    """Test path traversal on resources"""
    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        """Execute resource traversal tests"""
        self.pentester.health_check()
        findings = []

        for payload in PAYLOADS['path_traversal']:
            try:
                resp, elapsed = self.pentester.send("resources/read",
                                                    {"uri": payload})
            except Exception as e:
                print(f"[!] Resource traversal test error for {payload}: {e}")
                continue

            if self.pentester.detector.findings:
                findings.append({
                    'uri': payload,
                    'detections': self.pentester.detector.report()
                })
                self.pentester.detector.findings = []

        return findings
