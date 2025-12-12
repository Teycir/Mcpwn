# Gemini API Setup (Free Tier)

## Quick Start

### 1. Set API Key
```bash
export GEMINI_API_KEY=AIzaSyDQDqwxKTHPQDv03KjpZmG1YUDZ3U4XM8o
```

Or use the second key:
```bash
export GEMINI_API_KEY=AIzaSyDIKHolEyaOpY1gKWTgvMw27AtPBsRGmtE
```

### 2. Install Gemini SDK
```bash
pip install google-generativeai
```

### 3. Run Mcpwn with LLM
```bash
python mcpwn.py --llm-generate python3 dvmcp_server.py
```

## Expected Output

```
[INFO] Starting Mcpwn
[INFO] LLM Generator initialized with Gemini
[INFO] Discovery phase...
[INFO] Found 2 tools, 0 resources
[INFO] Testing tool injection...
[INFO] Generated 5 payloads for execute_command (rce)
[WARNING] execute_command: RCE via command
[WARNING]   Detection: uid=1000(user) gid=1000(user)
```

## Features

✅ **Free Tier**: 15 requests/minute, 1500/day
✅ **Fast**: Gemini 1.5 Flash model
✅ **Automatic Detection**: Key prefix `AIzaSy` auto-selects Gemini
✅ **Fallback**: Uses static payloads if API fails

## Using .env File

```bash
# Copy example
cp .env.example .env

# Edit .env
nano .env

# Load and run
source .env
python mcpwn.py --llm-generate python3 dvmcp_server.py
```

## Troubleshooting

### "google-generativeai package not installed"
```bash
pip install google-generativeai
```

### "LLM generation failed"
Check:
1. API key is correct
2. Internet connection active
3. Rate limit not exceeded (15/min)

### Rate Limit Exceeded
Wait 1 minute or use static payloads:
```bash
python mcpwn.py python3 dvmcp_server.py  # Without --llm-generate
```

## Comparison: Gemini vs Claude

| Feature | Gemini | Claude |
|---------|--------|--------|
| Cost | **FREE** | ~$0.03/scan |
| Speed | Fast | Fast |
| Quality | Excellent | Excellent |
| Rate Limit | 15/min | Higher |
| Setup | Easy | Requires billing |

**Recommendation**: Use Gemini for testing and development (free tier is generous).
