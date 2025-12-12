# OpenRouter Setup (Free Models Available)

## Quick Start

### 1. Set API Key
```bash
export OPENROUTER_API_KEY=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
```

Or use the second key:
```bash
export OPENROUTER_API_KEY=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
```

### 2. Install OpenAI SDK
```bash
pip install openai
```

### 3. Run Mcpwn with LLM
```bash
python mcpwn.py --llm-generate python3 dvmcp_server.py
```

## Expected Output

```
[INFO] Starting Mcpwn
[INFO] LLM Generator initialized with OpenRouter
[INFO] Discovery phase...
[INFO] Found 2 tools, 0 resources
[INFO] Testing tool injection...
[INFO] Generated 5 payloads for execute_command (rce)
[WARNING] execute_command: RCE via command
```

## Features

✅ **Free Models**: Meta Llama 3.1 8B Instruct (free)
✅ **Multiple Providers**: Access to 100+ models
✅ **Automatic Detection**: Key prefix `sk-or-` auto-selects OpenRouter
✅ **Fallback**: Uses static payloads if API fails

## Available Free Models

- `meta-llama/llama-3.1-8b-instruct:free` (default)
- `google/gemma-2-9b-it:free`
- `mistralai/mistral-7b-instruct:free`

## Using .env File

```bash
# Copy example
cp .env.example .env

# Load and run
source .env
python mcpwn.py --llm-generate python3 dvmcp_server.py
```

## Comparison

| Feature | OpenRouter | Gemini | Claude |
|---------|-----------|--------|--------|
| Cost | **FREE** (some models) | **FREE** | ~$0.03/scan |
| Models | 100+ options | 1 model | 1 model |
| Speed | Fast | Fast | Fast |
| Setup | Easy | Easy | Requires billing |

## Troubleshooting

### "openai package not installed"
```bash
pip install openai
```

### "LLM generation failed"
Check:
1. API key is correct (starts with `sk-or-v1-`)
2. Internet connection active
3. Model is available

### Rate Limit
OpenRouter has generous limits. If exceeded, wait or use static payloads:
```bash
python mcpwn.py python3 dvmcp_server.py  # Without --llm-generate
```

## Advanced: Custom Model

Edit `core/generator.py`:
```python
def _init_openrouter(self):
    # Change model here
    model = "google/gemma-2-9b-it:free"  # Or any OpenRouter model
```

## Links

- OpenRouter Dashboard: https://openrouter.ai/
- Model List: https://openrouter.ai/models
- API Docs: https://openrouter.ai/docs
