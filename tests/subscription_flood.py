"""Subscription flooding tests"""
import time


class SubscriptionFloodTest:
    """Test resource exhaustion via subscriptions (DoS)"""
    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, count=2000):
        """Execute subscription flood and measure impact"""
        findings = []
        
        baseline = self._measure_latency() or 0.001
        
        start = time.time()
        try:
            for i in range(count):
                self.pentester.send("resources/subscribe",
                                    {"uri": f"file:///tmp/flood_{i}.txt"})
                
                if i % 100 == 0 and i > 0:
                    self.pentester.clear_subscription_state()
                
                if i > 0 and i % 500 == 0 and not self._is_alive():
                    findings.append({
                        'type': 'DOS_CRASH',
                        'detail': f'Server stopped responding after {i} subscriptions',
                        'severity': 'CRITICAL'
                    })
                    return findings
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            findings.append({
                'type': 'DOS_ERROR',
                'detail': f'Flood error: {str(e)}',
                'severity': 'LOW'
            })
        finally:
            self.pentester.restart_server()
        
        post_flood = self._measure_latency()
        
        if post_flood is None:
            findings.append({
                'type': 'DOS_UNRESPONSIVE',
                'detail': 'Server unresponsive after subscription flood',
                'severity': 'HIGH'
            })
        elif baseline > 0 and post_flood > (baseline * 10):
            ratio = post_flood / baseline
            findings.append({
                'type': 'DOS_DEGRADATION',
                'detail': f'Latency increased {ratio:.1f}x ({baseline:.3f}s → {post_flood:.3f}s)',
                'severity': 'MEDIUM'
            })
        
        return findings

    def _measure_latency(self):
        """Measure request latency"""
        start = time.time()
        try:
            self.pentester.send("tools/list")
            return time.time() - start
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            return None

    def _is_alive(self):
        """Check if server is responsive"""
        return self._measure_latency() is not None
