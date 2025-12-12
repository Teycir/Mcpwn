"""Resource exhaustion and DoS vulnerability tests for MCP servers"""
import time
import sys
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, wait


class ResourceExhaustionTest:
    """Test for resource exhaustion vulnerabilities"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    def run(self, tool, quick_mode=False):
        """Test resource exhaustion attacks"""
        findings = []
        findings.extend(self._test_recursive_nesting(tool))
        findings.extend(self._test_regex_dos(tool))
        
        if not quick_mode:
            findings.extend(self._test_giant_payload(tool))
            findings.extend(self._test_array_bomb(tool))
            findings.extend(self._test_batch_bomb(tool))
            findings.extend(self._test_parallel_flood(tool))
        
        return findings
    
    def _test_giant_payload(self, tool):
        """Test giant payload attacks (10MB+ arguments)"""
        findings = []
        schema = tool.get('inputSchema', {})
        target_arg = next((k for k, v in schema.get('properties', {}).items() 
                          if v.get('type') == 'string'), None)
        
        if not target_arg:
            return findings
        
        sizes = [1 * 1024 * 1024, 10 * 1024 * 1024]
        for size in sizes:
            try:
                giant = 'A' * size
                start = time.time()
                params = {"name": tool['name'], "arguments": {target_arg: giant}}
                resp, _ = self.pentester.send("tools/call", params, timeout=10)
                elapsed = time.time() - start
                
                resp_str = str(resp).lower()
                if 'error' not in resp_str and 'limit' not in resp_str:
                    findings.append({
                        'type': 'UNBOUNDED_PAYLOAD_SIZE',
                        'tool': tool['name'],
                        'severity': 'MEDIUM',
                        'note': f'Accepted {size//1024//1024}MB payload without validation ({elapsed:.2f}s)'
                    })
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                if 'broken pipe' in str(e).lower() or 'connection' in str(e).lower():
                    findings.append({
                        'type': 'DOS_LARGE_PAYLOAD',
                        'tool': tool['name'],
                        'severity': 'CRITICAL',
                        'note': f'Server crashed on {size//1024//1024}MB payload: {e}'
                    })
                    break
                logging.debug(f"Giant payload test error: {e}")
        
        return findings
    
    def _test_recursive_nesting(self, tool):
        """Test recursive JSON nesting - SAFE: won't crash tester"""
        findings = []
        schema = tool.get('inputSchema', {})
        target_arg = next((k for k, v in schema.get('properties', {}).items() 
                          if v.get('type') in ['object', 'array']), None)
        
        if not target_arg:
            return findings
        
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(5000)
        
        try:
            depth = 2000
            nested = {}
            curr = nested
            for _ in range(depth):
                curr['a'] = {}
                curr = curr['a']
            
            params = {"name": tool['name'], "arguments": {target_arg: nested}}
            try:
                resp, _ = self.pentester.send("tools/call", params)
                if resp and 'recursion' in str(resp).lower():
                    findings.append({
                        'type': 'STACK_OVERFLOW_EXPOSED',
                        'tool': tool['name'],
                        'severity': 'MEDIUM',
                        'note': 'Server exposed recursion error trace'
                    })
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                if 'connection' in str(e).lower():
                    findings.append({
                        'type': 'DOS_RECURSION_CRASH',
                        'tool': tool['name'],
                        'severity': 'HIGH',
                        'note': f'Server crashed on depth-{depth} JSON'
                    })
                else:
                    logging.debug(f"Recursive nesting test error: {e}")
        finally:
            sys.setrecursionlimit(old_limit)
        
        return findings
    
    def _test_array_bomb(self, tool):
        """Test billion laughs / array bomb style attacks"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        for arg, spec in schema.get('properties', {}).items():
            if spec.get('type') == 'array':
                try:
                    wide_array = ['x'] * 100000
                    start = time.time()
                    params = {"name": tool['name'], "arguments": {arg: wide_array}}
                    resp, _ = self.pentester.send("tools/call", params)
                    elapsed = time.time() - start
                    
                    if elapsed > 5:
                        findings.append({
                            'type': 'ARRAY_BOMB_SUSCEPTIBLE',
                            'tool': tool['name'],
                            'arg': arg,
                            'severity': 'HIGH',
                            'note': f'100K element array took {elapsed:.2f}s'
                        })
                        break
                except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                    if 'memory' in str(e).lower():
                        findings.append({
                            'type': 'ARRAY_BOMB_CRASH',
                            'tool': tool['name'],
                            'severity': 'CRITICAL',
                            'note': str(e)[:100]
                        })
                        break
                    logging.debug(f"Array bomb test error: {e}")
        return findings
    
    def _test_regex_dos(self, tool):
        """Test for ReDoS vulnerabilities"""
        findings = []
        schema = tool.get('inputSchema', {})
        redos_payloads = [
            'a' * 30 + '!',
            'a' * 30 + 'X',
            '0' * 30 + 'x',
            '<' + 'a' * 30,
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaa@' * 3,
        ]
        
        for arg, spec in schema.get('properties', {}).items():
            if spec.get('type') == 'string':
                for payload in redos_payloads:
                    try:
                        start = time.time()
                        params = {"name": tool['name'], "arguments": {arg: payload}}
                        self.pentester.send("tools/call", params)
                        elapsed = time.time() - start
                        
                        if elapsed > 3:
                            findings.append({
                                'type': 'REGEX_DOS',
                                'tool': tool['name'],
                                'arg': arg,
                                'severity': 'HIGH',
                                'payload': payload[:30] + '...',
                                'note': f'Regex processing took {elapsed:.2f}s'
                            })
                            break
                    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                        logging.debug(f"ReDoS test error: {e}")
        return findings
    
    def _test_batch_bomb(self, tool):
        """JSON-RPC batch bomb: massive array of requests"""
        findings = []
        batch_size = 2000
        
        batch = [{"jsonrpc": "2.0", "method": "tools/list", "id": i} 
                 for i in range(batch_size)]
        
        try:
            start = time.time()
            # Send raw batch if supported, otherwise skip
            if hasattr(self.pentester.client, 'send_raw'):
                self.pentester.client.send_raw(json.dumps(batch))
                elapsed = time.time() - start
                
                if elapsed > 5.0:
                    findings.append({
                        'type': 'BATCH_PROCESSING_LAG',
                        'severity': 'MEDIUM',
                        'note': f'{batch_size} batch requests took {elapsed:.2f}s'
                    })
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            if 'memory' in str(e).lower() or 'connection' in str(e).lower():
                findings.append({
                    'type': 'BATCH_BOMB_CRASH',
                    'severity': 'HIGH',
                    'note': f'Server crashed on batch of {batch_size}'
                })
            else:
                logging.debug(f"Batch bomb test error: {e}")
        
        return findings
    
    def _test_parallel_flood(self, tool):
        """ACTUAL concurrent flood - holds connections simultaneously"""
        findings = []
        
        def make_request():
            try:
                params = {"name": tool['name'], "arguments": {}}
                self.pentester.send("tools/call", params, timeout=5)
                return True
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                logging.debug(f"Parallel flood make_request error: {e}")
                return False
        
        try:
            start = time.time()
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(make_request) for _ in range(100)]
                wait(futures, timeout=10)
                results = [f.result() for f in futures if f.done()]
            elapsed = time.time() - start
            
            success_rate = sum(results) / len(results) if results else 0
            if success_rate < 0.5:
                findings.append({
                    'type': 'CONNECTION_POOL_EXHAUSTION',
                    'tool': tool['name'],
                    'severity': 'HIGH',
                    'note': f'Only {success_rate*100:.0f}% requests succeeded under load'
                })
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            findings.append({
                'type': 'DOS_CONCURRENT_FLOOD',
                'severity': 'CRITICAL',
                'note': f'Server crashed under concurrent load: {e}'
            })
        
        return findings
            try:
                start = time.time()
                params = {"name": tool['name'], "arguments": {}}
                resp, _ = self.pentester.send("tools/call", params)
                return time.time() - start, resp is not None
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                logging.debug(f"Parallel flood request error: {e}")
                return None, str(e)
        
        try:
            baseline, _ = make_request()
            if baseline is None:
                return findings
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(make_request) for _ in range(100)]
                results = [f.result() for f in as_completed(futures)]
            
            successes = [r[0] for r in results if r[0] is not None]
            failures = [r[1] for r in results if r[0] is None]
            
            if failures:
                findings.append({
                    'type': 'CONCURRENT_REQUEST_FAILURES',
                    'tool': tool['name'],
                    'severity': 'HIGH',
                    'note': f'{len(failures)}/100 requests failed under load'
                })
            
            if successes:
                avg_time = sum(successes) / len(successes)
                if avg_time > baseline * 5:
                    findings.append({
                        'type': 'CONCURRENCY_DEGRADATION',
                        'tool': tool['name'],
                        'severity': 'MEDIUM',
                        'note': f'Avg response: {avg_time:.2f}s vs baseline {baseline:.2f}s'
                    })
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            findings.append({
                'type': 'PARALLEL_FLOOD_CRASH',
                'tool': tool['name'],
                'severity': 'CRITICAL',
                'note': str(e)[:100]
            })
        
        return findings
    
    def _test_connection_exhaustion(self, tool):
        """Test connection pool starvation"""
        findings = []
        
        try:
            # Attempt to open multiple connections rapidly
            start = time.time()
            for i in range(50):
                try:
                    params = {"name": tool['name'], "arguments": {}}
                    self.pentester.send("tools/call", params)
                except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                    logging.debug(f"Connection exhaustion test error: {e}")
            elapsed = time.time() - start
            
            # If server slowed down significantly (connection pool exhausted)
            if elapsed > 10:
                findings.append({
                    'type': 'CONNECTION_POOL_EXHAUSTION',
                    'tool': tool['name'],
                    'severity': 'HIGH',
                    'note': f'50 requests took {elapsed:.2f}s (avg {elapsed/50:.2f}s each)'
                })
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
            if 'connection' in str(e).lower() or 'refused' in str(e).lower():
                findings.append({
                    'type': 'CONNECTION_EXHAUSTION',
                    'tool': tool['name'],
                    'severity': 'CRITICAL',
                    'note': f'Connection pool exhausted: {str(e)[:100]}'
                })
            else:
                logging.debug(f"Connection exhaustion test error: {e}")
        
        return findings
