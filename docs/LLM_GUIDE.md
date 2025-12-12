# LLM-Guided Payload Generation Guide

## Overview

Mcpwn can use AI (OpenRouter, Gemini, or Claude) to generate context-aware security payloads that adapt to your specific MCP server implementation.

## Setup

### Option 1: OpenRouter (Free Models Available)
```bash
pip install openai
```

**Get API Key:**
1. Visit https://openrouter.ai/keys
2. Create an API key
3. Copy the key (starts with `sk-or-v1-`)

**Free Models:**
- Meta Llama 3.1 8B Instruct
- Google Gemma 2 9B
- Mistral 7B Instruct

### Option 2: Google Gemini (Free Tier Available)
```bash
pip install google-generativeai
```

**Get API Key:**
1. Visit https://makersuite.google.com/app/apikey
2. Create an API key
3. Copy the key (starts with `AIzaSy`)

### Option 3: Anthropic Claude
```bash
pip install anthropic
```

**Get API Key:**
1. Sign up at https://console.anthropic.com
2. Create an API key
3. Copy the key (starts with `sk-ant-`)

## Usage

### OpenRouter (Free Models)
```bash
# Environment variable
export OPENROUTER_API_KEY=sk-or-v1-...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Or CLI argument
python mcpwn.py --llm-generate --api-key sk-or-v1-... npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Gemini (Free Tier)
```bash
# Environment variable
export GEMINI_API_KEY=AIzaSy...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Or CLI argument
python mcpwn.py --llm-generate --api-key AIzaSy... npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Anthropic Claude
```bash
# Environment variable
export ANTHROPIC_API_KEY=sk-ant-...
python mcpwn.py --llm-generate npx -y @modelcontextprotocol/server-filesystem /tmp

# Or CLI argument
python mcpwn.py --llm-generate --api-key sk-ant-... npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Shell Script Example
```bash
#!/bin/bash
# scan.sh - Using Gemini
GEMINI_API_KEY=AIzaSy... \
python mcpwn.py --llm-generate \
  --output-json report.json \
  npx -y @modelcontextprotocol/server-filesystem /tmp
```

## How It Works

### Without LLM (Static Payloads)
```
Tool: execute_command
Payloads: ["; id", "| whoami", "$(id)", ...]
```

### With LLM (Context-Aware)
```
Tool: execute_command
Context: {
  "tool_name": "execute_command",
  "target_type": "rce",
  "schema_hints": {"command": "string"}
}

LLM Generates:
[
  "; id #bypass-filter",
  "| whoami 2>/dev/null",
  "$(id)${IFS}",
  "`cat /etc/passwd|base64`",
  "&&echo$IFS$9$(id)"
]
```

## Benefits

1. **Adaptive**: Payloads tailored to tool names and schemas
2. **Evasive**: Novel variations to bypass filters
3. **Context-Aware**: Considers previous failures
4. **Up-to-Date**: Leverages latest attack techniques

## Example Output

```bash
$ python mcpwn.py --llm-generate --api-key sk-ant-... python3 dvmcp_server.py

[INFO] Starting Mcpwn
[INFO] LLM Generator initialized with API key
[INFO] Discovery phase...
[INFO] Found 2 tools, 0 resources
[INFO] Testing tool injection...
[INFO] Generated 5 payloads for execute_command (rce)
[WARNING] execute_command: RCE via command
[WARNING]   Detection: uid=1000(user) gid=1000(user)
[INFO] Mcpwn complete
```

## Cost Estimation

### OpenRouter (Free Models)
- Model: Meta Llama 3.1 8B Instruct
- Cost: **FREE**
- Rate limits: Generous (varies by model)

### Gemini (Free Tier)
- Model: Gemini 1.5 Flash
- Free tier: 15 requests/minute, 1500 requests/day
- Cost: **FREE** for typical usage

### Anthropic Claude
- Model: Claude 3.5 Sonnet
- Tokens per request: ~200 input + 100 output
- Cost: ~$0.003 per tool tested
- Typical scan (10 tools): ~$0.03

## Fallback Behavior

If LLM generation fails (no API key, network error, rate limit):
```
[WARNING] LLM generation failed: API key not found, using templates
[INFO] Testing tool injection...
```

Mcpwn automatically falls back to static payloads.

## Security Notes

1. **Never commit API keys** to version control
2. Use environment variables in CI/CD
3. Rotate keys regularly
4. Monitor API usage at https://console.anthropic.com

## Troubleshooting

### "Package not installed"
```bash
# For OpenRouter
pip install openai

# For Gemini
pip install google-generativeai

# For Anthropic
pip install anthropic
```

### "LLM generation enabled but no API key provided"
```bash
# Set environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Or use CLI flag
python mcpwn.py --llm-generate --api-key sk-ant-...
```

### "Rate limit exceeded"
```bash
# Add delay between requests (future feature)
# Or use static payloads temporarily
python mcpwn.py <server-command>  # Without --llm-generate
```

### "Invalid API key"
**OpenRouter:**
- Check key starts with `sk-or-v1-`
- Verify at https://openrouter.ai/keys

**Gemini:**
- Check key starts with `AIzaSy`
- Verify at https://makersuite.google.com/app/apikey

**Anthropic:**
- Check key starts with `sk-ant-`
- Verify at https://console.anthropic.com

**All:**
- Ensure no extra spaces or quotes

## Advanced Usage

### Custom Prompts
Edit `core/generator.py`:
```python
def _build_prompt(self, tool_name: str, target_type: str, failure: str) -> str:
    return (
        f"Generate 10 advanced {target_type} payloads for '{tool_name}'. "
        f"Focus on WAF bypass and obfuscation. "
        f"Previous failure: {failure}. "
        f"Output JSON array only."
    )
```

### Different Models
```python
# In core/generator.py
response = self.client.messages.create(
    model="claude-3-opus-20240229",  # More powerful
    max_tokens=1000,
    messages=[{"role": "user", "content": prompt}]
)
```

## Comparison

| Feature | Static | OpenRouter | Gemini | Claude |
|---------|--------|-----------|--------|--------|
| Speed | Fast | ~1s/tool | ~1s/tool | ~1s/tool |
| Cost | Free | **FREE** | **FREE** | ~$0.003/tool |
| Coverage | Good | Excellent | Excellent | Excellent |
| Evasion | Basic | Advanced | Advanced | Advanced |
| Offline | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Models | N/A | 100+ | 1 | 1 |
| Rate Limit | None | Generous | 15/min | Varies |

## Recommendation

- **Development**: Use static payloads (fast, free)
- **Pre-Production**: Use LLM-guided (comprehensive)
- **CI/CD**: Use static (no API key management)
- **Security Audit**: Use LLM-guided (maximum coverage)
