# LLM-Guided Payload Generation Usage

## Overview

The generator enables context-aware, adaptive payload synthesis based on target characteristics and previous test results.

## Architecture

```
Test Module → Context → Generator → LLM (simulated) → Novel Payloads → Execution
```

## Using in Test Modules

```python
# Example: Tool Injection Test with LLM generation

from core.pentester import MCPPentester

class ToolInjectionTest:
    def __init__(self, pentester: MCPPentester):
        self.pentester = pentester
    
    def run(self, tool):
        # Build context for generator
        context = {
            'tool_name': tool['name'],
            'target_type': 'rce',  # or 'ssrf', 'traversal', 'schema_pollution'
            'previous_failure': 'None',
            'schema_hints': tool.get('inputSchema', {})
        }
        
        # Get payloads (LLM-generated or static fallback)
        payloads = self.pentester.get_payloads(context)
        
        # Execute tests with generated payloads
        for payload in payloads:
            self.pentester.send('tools/call', {
                'name': tool['name'],
                'arguments': {'cmd': payload}
            })
```

## Context Parameters

| Field | Description | Example |
|-------|-------------|---------|
| `tool_name` | Target tool/resource name | `"execute_command"` |
| `target_type` | Attack category | `"rce"`, `"ssrf"`, `"traversal"` |
| `previous_failure` | Last attempt result | `"Filtered by WAF"` |
| `schema_hints` | Input schema metadata | `{"type": "object", "properties": {...}}` |

## Target Types

- `rce`: Command injection payloads
- `ssrf`: Server-side request forgery
- `traversal`: Path traversal attacks
- `schema_pollution`: Prototype pollution, class injection

## CLI Usage

```bash
# Enable LLM generation
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Combine with other modes
python mcpwn.py --llm-generate --quick --safe-mode npx ...
```

## Implementation Notes

- Generator is initialized once in `MCPPentester.__init__`
- Falls back to static payloads if generation fails
- Simulated responses for now (replace with actual LLM API)
- Thread-safe via pentester's existing locking mechanisms

## Future Enhancements

1. **Real LLM Integration**: Replace simulation with OpenAI/Anthropic/local model
2. **Feedback Loop**: Feed detection results back to generator for refinement
3. **Multi-turn Generation**: Iterative payload evolution based on responses
4. **Custom Templates**: User-defined generation prompts per attack type
