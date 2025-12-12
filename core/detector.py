"""Semantic Detection Engine - Identifies successful exploits"""
import logging
from payloads import INDICATORS, TimingAnalyzer

logger = logging.getLogger(__name__)


class SemanticDetector:
    """Detects semantic exploitation indicators in MCP responses"""
    def __init__(self):
        self.findings = []
        self.timing_analyzer = TimingAnalyzer()

    def analyze(self, response, raw_content, elapsed_time, is_baseline=False):
        """Detect exploitation indicators in response"""
        # Use raw JSON string to avoid Python serialization artifacts
        content = raw_content if raw_content else str(response) if response else ""

        # Record baseline timing
        if is_baseline:
            self.timing_analyzer.add_baseline(elapsed_time)
            return False

        # RCE detection (pre-compiled patterns)
        for pattern in INDICATORS.get('rce_success', []):
            try:
                match = pattern.search(content)
                if match:
                    self.findings.append({
                        'type': 'RCE',
                        'indicator': pattern.pattern,
                        'match': match.group()
                    })
            except (AttributeError, TypeError) as e:
                logger.warning("RCE pattern match failed: %s", e)

        # File read detection
        for pattern in INDICATORS.get('file_read', []):
            try:
                match = pattern.search(content)
                if match:
                    self.findings.append({
                        'type': 'FILE_READ',
                        'indicator': pattern.pattern,
                        'match': match.group()
                    })
            except (AttributeError, TypeError) as e:
                logger.warning("File read pattern match failed: %s", e)

        # Statistical timing attack detection
        try:
            if self.timing_analyzer.is_anomaly(elapsed_time):
                self.findings.append({
                    'type': 'TIMING',
                    'elapsed': elapsed_time
                })
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning("Timing analysis failed: %s", e)

        return len(self.findings) > 0

    def report(self):
        """Return all detected findings"""
        try:
            return self.findings
        except AttributeError:
            logger.error("Findings list not initialized")
            return []
