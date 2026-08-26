import asyncio
import os

import pytest

# Hermetic arena tests: the real DeepSeek token lives in .env AND may be
# exported by the operator's shell; the arena LLM loader only fills unset env
# keys, so force-blanking (not setdefault — a shell-exported var survives
# setdefault) keeps every test on the canned offline path (no network,
# deterministic).
os.environ["DEEPSEEK_API_KEY"] = ""
os.environ["DEEPSEEK_AUTH_TOKEN"] = ""
os.environ["OLLAMA_HOST"] = ""


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
