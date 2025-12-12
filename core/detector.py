"""Semantic Detection Engine - Identifies successful exploits"""
from payloads import INDICATORS, TimingAnalyzer


class SemanticDetector:
    """Detects semantic exploitation indicators in MCP responses"""
    def __init__(self):
        self.findings = []
        self.timing_analyzer = TimingAnalyzer()

    def analyze(self, response, elapsed_time, is_baseline=False):
        """Detect exploitation indicators in response"""
        try:
            content = str(response) if response else ""
        except Exception as e:
            print(f"[!] Response serialization error: {e}")
            content = ""

        # Record baseline timing
        if is_baseline:
            self.timing_analyzer.add_baseline(elapsed_time)
            return False

        try:
            # RCE detection (pre-compiled patterns)
            for pattern in INDICATORS['rce_success']:
                match = pattern.search(content)
                if match:
                    self.findings.append({
                        'type': 'RCE',
                        'indicator': pattern.pattern,
                        'match': match.group()
                    })

            # File read detection
            for pattern in INDICATORS['file_read']:
                match = pattern.search(content)
                if match:
                    self.findings.append({
                        'type': 'FILE_READ',
                        'indicator': pattern.pattern,
                        'match': match.group()
                    })

            # Statistical timing attack detection
            if self.timing_analyzer.is_anomaly(elapsed_time):
                self.findings.append({
                    'type': 'TIMING',
                    'elapsed': elapsed_time
                })
        except Exception as e:
            print(f"[!] Detection analysis error: {e}")

        return len(self.findings) > 0

    def report(self):
        """Return all detected findings"""
        return self.findings
