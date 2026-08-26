# Why The CLI Tools Don't Work In Subprocess

## The Problem

OpenCode, Kilo, Claude, and Gemini are all **Terminal UI (TUI) apps**. They:
1. Take over the terminal (render their own UI)
2. Need an interactive TTY (not a pipe)
3. Block on user input (even in "auto" mode)
4. Time out when called from Python subprocess

This is a **known issue** (GitHub issue #13851 for OpenCode).

## What This Means

```
python coordinator.py  →  calls kilo --auto "..."  →  kilo opens TUI  →  HANGS
```

## The Real Solution

**Option 1: API Keys (Recommended)**
If you have API keys for any of these services, we can call them directly:
- OpenAI API (for GPT models)
- Anthropic API (for Claude)
- Google API (for Gemini)
- DeepSeek API (free tier available)

This bypasses the TUI entirely and calls the model directly via HTTP.

**Option 2: Use Me (Freebuff)**
I already have tools (web search, file access, terminal). I can act as ONE of the models in the loop. The other models would need to be API-based.

**Option 3: Manual Orchestration**
The V2 coordinator generates prompts for each phase. You copy-paste them into the CLI tools manually. Slower but works.

**Option 4: Docker/PTY**
Run the CLI tools inside a Docker container with a pseudo-TTY. Complex but fully automated.

## Recommendation

**Option 1 (API keys) is the path to a fully autonomous loop.**
Without API keys, the loop requires manual orchestration (Option 3).

## Free API Options

| Service | Free Tier | How to Get Key |
|---------|-----------|----------------|
| DeepSeek | Yes (limited) | platform.deepseek.com |
| Google Gemini | Yes (generous) | aistudio.google.com |
| Groq | Yes (fast) | console.groq.com |
| Together AI | Yes (limited) | api.together.xyz |
| OpenRouter | Yes (varies) | openrouter.ai |
