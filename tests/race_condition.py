"""Race condition and TOCTOU vulnerability tests for MCP servers"""
import threading
import time


class RaceConditionTest:
    """TOCTOU and concurrent access vulnerabilities"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    def run(self, tool):
        """Test for race conditions"""
        findings = []
        findings.extend(self._test_double_spend(tool))
        findings.extend(self._test_state_corruption(tool))
        findings.extend(self._test_resource_locking(tool))
        return findings
    
    def _test_double_spend(self, tool):
        """Test parallel identical requests (double-spend scenarios)"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        # Look for financial/state-changing operations
        tool_name = tool['name'].lower()
        if any(k in tool_name for k in ['create', 'delete', 'update', 'transfer', 'withdraw', 'purchase', 'claim']):
            results = []
            errors = []
            
            def make_request():
                try:
                    params = {"name": tool['name'], "arguments": {}}
                    resp, _ = self.pentester.send("tools/call", params)
                    results.append(resp)
                except Exception as e:
                    errors.append(str(e))
            
            # Fire 5 parallel identical requests
            threads = [threading.Thread(target=make_request) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Check if multiple succeeded (should have locking/idempotency)
            success_count = sum(1 for r in results if r and 'error' not in str(r).lower())
            if success_count > 1:
                findings.append({
                    'type': 'DOUBLE_SPEND',
                    'tool': tool['name'],
                    'severity': 'CRITICAL',
                    'note': f'{success_count}/5 parallel requests succeeded',
                    'detail': 'Missing idempotency or locking mechanism'
                })
        
        return findings
    
    def _test_state_corruption(self, tool):
        """Test state corruption via interleaved operations"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        # Look for stateful parameters (counters, balances, etc.)
        for arg, spec in schema.get('properties', {}).items():
            if any(k in arg.lower() for k in ['count', 'amount', 'balance', 'quantity', 'limit']):
                results = []
                
                def increment_request(value):
                    try:
                        params = {"name": tool['name'], "arguments": {arg: value}}
                        resp, _ = self.pentester.send("tools/call", params)
                        results.append((value, resp))
                    except Exception:
                        pass
                
                # Interleave operations: set to 1, 2, 3 concurrently
                threads = [threading.Thread(target=increment_request, args=(i,)) for i in [1, 2, 3]]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                
                # Check for inconsistent state (all succeeded but final state unknown)
                if len(results) == 3:
                    findings.append({
                        'type': 'STATE_CORRUPTION',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'HIGH',
                        'note': 'Concurrent state modifications accepted without serialization'
                    })
                    break
        
        return findings
    
    def _test_resource_locking(self, tool):
        """Test resource locking bypass via TOCTOU"""
        findings = []
        schema = tool.get('inputSchema', {})
        
        # Look for resource identifiers
        for arg, spec in schema.get('properties', {}).items():
            if any(k in arg.lower() for k in ['file', 'path', 'resource', 'id', 'name']):
                resource_id = 'test_resource_123'
                results = []
                timings = []
                
                def access_resource():
                    try:
                        start = time.time()
                        params = {"name": tool['name'], "arguments": {arg: resource_id}}
                        resp, _ = self.pentester.send("tools/call", params)
                        elapsed = time.time() - start
                        results.append(resp)
                        timings.append(elapsed)
                    except Exception:
                        pass
                
                # Attempt concurrent access to same resource
                threads = [threading.Thread(target=access_resource) for _ in range(3)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                
                # If all succeeded quickly, locking may be missing
                success_count = sum(1 for r in results if r and 'lock' not in str(r).lower() and 'busy' not in str(r).lower())
                if success_count > 1 and timings and max(timings) < 1.0:
                    findings.append({
                        'type': 'RESOURCE_LOCKING_BYPASS',
                        'tool': tool['name'],
                        'arg': arg,
                        'severity': 'HIGH',
                        'note': f'{success_count}/3 concurrent accesses to same resource succeeded',
                        'detail': 'Missing or ineffective resource locking'
                    })
                    break
        
        return findings
