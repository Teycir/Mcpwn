"""Runtime allowlist enforcer with thread-safe caching"""
import json
import threading
from pathlib import Path


class SecurityError(Exception):
    """Raised when a tool call violates security policy"""
    pass


class AllowlistEnforcer:
    _cache = None
    _cache_lock = threading.Lock()
    
    def __init__(self, allowlist_path):
        path = Path(allowlist_path)
        if not path.is_file():
            raise FileNotFoundError(f"Allowlist not found: {allowlist_path}")
        
        with self._cache_lock:
            if AllowlistEnforcer._cache is None:
                with open(path) as f:
                    AllowlistEnforcer._cache = json.load(f)
        self.allowlist = AllowlistEnforcer._cache
    
    def check_tool_call(self, tool_name, response):
        rules = self.allowlist.get('tools', {}).get(tool_name, {})
        
        if rules.get('allowed') is False:
            raise SecurityError(f"Tool {tool_name} is disabled: {rules.get('reason', 'No reason provided')}")
        
        forbidden = rules.get('forbidden_patterns', [])
        response_str = str(response).lower()
        
        for pattern in forbidden:
            if pattern in response_str:
                raise SecurityError(f"Tool {tool_name} violated allowlist: {pattern} detected")
        
        max_size = rules.get('max_response_size', float('inf'))
        if len(response_str) > max_size:
            raise SecurityError(f"Response size {len(response_str)} exceeds limit {max_size}")
        
        return True
