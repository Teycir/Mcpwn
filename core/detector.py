"""Semantic Detection Engine - Identifies successful exploits"""
import logging
from payloads import INDICATORS, TimingAnalyzer

logger = logging.getLogger(__name__)


class SemanticDetector:
    """Detects semantic exploitation indicators in MCP responses"""
    def __init__(self):
        self.findings = []
        self.timing_analyzer = TimingAnalyzer()

    def _detect_patterns(self, content, indicator_key, finding_type):
        """Detect patterns and add findings"""
        for pattern in INDICATORS.get(indicator_key, []):
            try:
                match = pattern.search(content)
                if match:
                    self.findings.append({
                        'type': finding_type,
                        'indicator': pattern.pattern,
                        'match': match.group()
                    })
            except (AttributeError, TypeError) as e:
                logger.warning("%s pattern match failed: %s", finding_type, e)

    def analyze(self, response, raw_content, elapsed_time, is_baseline=False):
        """Detect exploitation indicators in response"""
        # Use raw JSON string to avoid Python serialization artifacts
        content = raw_content if raw_content else str(response) if response else ""

        # Record baseline timing
        if is_baseline:
            self.timing_analyzer.add_baseline(elapsed_time)
            return False

        # RCE and file read detection
        self._detect_patterns(content, 'rce_success', 'RCE')
        self._detect_patterns(content, 'file_read', 'FILE_READ')

        # Statistical timing attack detection
        try:
            if self.timing_analyzer.is_anomaly(elapsed_time):
                self.findings.append({
                    'type': 'TIMING',
                    'elapsed': elapsed_time
                })
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning("Timing analysis failed: %s", e)

        # OOB DNS detection (captured externally)
        try:
            if content and 'oob.local' in content.lower():
                self.findings.append({
                    'type': 'OOB_DNS',
                    'indicator': 'DNS exfiltration domain'
                })
        except (AttributeError, TypeError) as e:
            logger.warning("OOB DNS detection failed: %s", e)

        return len(self.findings) > 0

    def report(self):
        """Return all detected findings"""
        return self.findings if self.findings else []
