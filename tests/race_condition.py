"""Race condition and TOCTOU vulnerability tests for MCP servers"""
import threading
import random
import uuid
import logging


class RaceConditionTest:
    """Tests for uniqueness constraints and concurrency stability"""
    
    def __init__(self, pentester):
        self.pentester = pentester
    
    def run(self, tool):
        """Test for race conditions"""
        findings = []
        if not tool.get('inputSchema'):
            return findings
        findings.extend(self._test_creation_collision(tool))
        findings.extend(self._test_concurrency_stability(tool))
        return findings
    
    def _generate_payload(self, tool, overrides=None):
        """Generate valid payload from schema"""
        overrides = overrides or {}
        schema = tool.get('inputSchema', {})
        args = {}
        
        for prop, spec in schema.get('properties', {}).items():
            if prop in overrides:
                args[prop] = overrides[prop]
            elif spec.get('type') == 'string':
                args[prop] = 'test'
            elif spec.get('type') in ['integer', 'number']:
                args[prop] = 10
            elif spec.get('type') == 'boolean':
                args[prop] = True
        
        return {"name": tool['name'], "arguments": args}
    
    def _execute_race(self, func_with_args, count=10):
        """Execute requests with tight synchronization (pre-generated payloads)"""
        barrier = threading.Barrier(count)
        results = [None] * count
        threads = []

        def worker(idx):
            barrier.wait()
            try:
                results[idx] = func_with_args()
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                logging.debug(f"Race condition test error: {e}")
                results[idx] = {'error': str(e)}

        for i in range(count):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)
        
        return results
    
    def _test_creation_collision(self, tool):
        """Test if multiple threads can create the SAME resource (uniqueness constraint)"""
        findings = []
        tool_name = tool['name'].lower()
        
        if not any(k in tool_name for k in ['create', 'insert', 'register', 'make', 'add']):
            return findings

        schema = tool.get('inputSchema', {})
        target_arg = None
        for arg in schema.get('properties', {}):
            if any(k in arg.lower() for k in ['path', 'name', 'id', 'key', 'email']):
                target_arg = arg
                break
        
        if not target_arg:
            return findings

        # All threads attempt to create the SAME resource
        collision_val = f"race_collision_{uuid.uuid4().hex[:6]}"
        payload = self._generate_payload(tool, {target_arg: collision_val})
        
        def send_request():
            try:
                resp, _ = self.pentester.send("tools/call", payload)
                return resp
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                logging.debug(f"Creation collision test error: {e}")
                return {'error': str(e)}

        results = self._execute_race(send_request, count=5)
        
        # Count successes (no error/exists message)
        success_count = sum(1 for r in results 
                          if 'error' not in str(r).lower() and 'exist' not in str(r).lower())

        if success_count > 1:
            findings.append({
                'type': 'RACE_CREATION_COLLISION',
                'tool': tool['name'],
                'severity': 'HIGH',
                'note': f'{success_count}/5 threads created resource "{collision_val}"',
                'detail': 'Missing uniqueness locking (O_EXCL/INSERT checks)'
            })
        
        return findings
    
    def _test_concurrency_stability(self, tool):
        """Test for database locks and internal errors under concurrent load"""
        findings = []
        
        payload = self._generate_payload(tool)
        
        def send_request():
            try:
                resp, _ = self.pentester.send("tools/call", payload)
                return resp
            except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
                logging.debug(f"Concurrency stability test error: {e}")
                return {'error': str(e)}

        results = self._execute_race(send_request, count=10)
        
        lock_errors = [r for r in results if any(x in str(r).lower() for x in ['lock', 'busy'])]
        internal_errors = [r for r in results if 'internal error' in str(r).lower()]
        
        if lock_errors:
            findings.append({
                'type': 'UNHANDLED_DB_LOCK',
                'tool': tool['name'],
                'severity': 'MEDIUM',
                'note': 'Server exposed database locking errors',
                'detail': str(lock_errors[0])[:100]
            })
            
        if internal_errors:
            findings.append({
                'type': 'CONCURRENCY_CRASH',
                'tool': tool['name'],
                'severity': 'HIGH',
                'note': 'Server threw internal errors under load',
                'detail': str(internal_errors[0])[:100]
            })

        return findings
