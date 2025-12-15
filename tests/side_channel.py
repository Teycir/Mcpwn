"""Side-channel detection for timing, size, and behavioral anomalies"""
import time
import statistics
import logging


class SideChannelTest:
    """Detect side-channel attacks and risky patterns"""
    
    def __init__(self, pentester, profile=None):
        self.pentester = pentester
        profile = profile or {}
        self.timing_threshold = profile.get('timing_thresholds', {}).get('slow_query_ms', 500) / 1000
        self.size_threshold = profile.get('size_thresholds', {}).get('large_response_bytes', 1048576)
        patterns = profile.get('behavioral_patterns', {})
        self.network_indicators = [i.lower() for i in patterns.get('network_indicators', [])]
        self.shell_indicators = [i.lower() for i in patterns.get('shell_indicators', [])]
        self.root_indicators = [i.lower() for i in patterns.get('filesystem_root_indicators', [])]
    
    def run(self, tool):
        """Test for side-channel vulnerabilities"""
        findings = []
        findings.extend(self._test_timing_side_channel(tool))
        findings.extend(self._test_content_and_size(tool))
        return findings
    
    def _test_timing_side_channel(self, tool):
        """Detect timing-based side channels"""
        findings = []
        tool_name = tool['name']
        
        for arg, spec in list(tool.get('inputSchema', {}).get('properties', {}).items())[:3]:
            if spec.get('type') != 'string':
                continue
            
            timings = []
            for test_val in ['a', 'aa', 'aaa']:
                try:
                    start = time.time()
                    self.pentester.send("tools/call", {"name": tool_name, "arguments": {arg: test_val}})
                    timings.append(time.time() - start)
                except (OSError, ValueError, TypeError, AttributeError, KeyError, RuntimeError, TimeoutError) as e:
                    logging.debug(f"Timing test failed for {tool_name}.{arg}: {e}")
                    continue
            
            if len(timings) >= 3:
                avg = statistics.mean(timings)
                stdev = statistics.stdev(timings) if len(timings) > 1 else 0
                if avg > self.timing_threshold and stdev < avg * 0.5:
                    findings.append({
                        'type': 'TIMING_SIDE_CHANNEL',
                        'tool': tool_name,
                        'arg': arg,
                        'severity': 'MEDIUM',
                        'avg_time': f'{avg:.3f}s',
                        'note': 'Consistent slow response indicates potential directory walk'
                    })
        
        return findings
    
    def _test_content_and_size(self, tool):
        """Combined test for size anomalies and behavioral patterns to minimize I/O"""
        findings = []
        tool_name = tool['name']
        net_inds = self.network_indicators
        shell_inds = self.shell_indicators
        root_inds = self.root_indicators
        
        for arg in list(tool.get('inputSchema', {}).get('properties', {}).keys())[:3]:
            try:
                resp, _ = self.pentester.send("tools/call", {"name": tool_name, "arguments": {arg: "test"}})
                resp_str = str(resp)
                resp_size = len(resp_str)
                
                if resp_size > self.size_threshold:
                    findings.append({
                        'type': 'SIZE_SIDE_CHANNEL',
                        'tool': tool_name,
                        'arg': arg,
                        'severity': 'MEDIUM',
                        'response_size': resp_size,
                        'note': f'Large response ({resp_size} bytes)'
                    })
                
                content_lower = resp_str.lower()
                
                if any(ind in content_lower for ind in net_inds):
                    findings.append({'type': 'NETWORK_ACTIVITY_DETECTED', 'tool': tool_name, 'arg': arg, 'severity': 'HIGH', 'note': 'Network activity detected'})
                
                if any(ind in content_lower for ind in shell_inds):
                    findings.append({'type': 'SHELL_ACTIVITY_DETECTED', 'tool': tool_name, 'arg': arg, 'severity': 'CRITICAL', 'note': 'Shell execution detected'})
                
                if any(ind in content_lower for ind in root_inds):
                    findings.append({'type': 'ROOT_FILESYSTEM_ACCESS', 'tool': tool_name, 'arg': arg, 'severity': 'HIGH', 'note': 'Filesystem access detected'})
            
            except (OSError, ValueError, TypeError, KeyError, TimeoutError) as e:
                logging.debug(f"Content test failed for {tool_name}.{arg}: {e}")
                continue
            except Exception as e:
                logging.warning(f"Unexpected error in {tool_name}.{arg}: {type(e).__name__}: {e}")
                continue
        
        return findings
