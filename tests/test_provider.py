import os
import pytest
from unittest.mock import patch
from provider import DeepSeekProvider, ConfigurationError


@pytest.mark.asyncio
async def test_provider_raises_when_no_backend():
    with patch.dict(os.environ, {}, clear=True):
        provider = DeepSeekProvider()
        with pytest.raises(ConfigurationError):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_provider_calls_ollama():
    with patch.dict(os.environ, {"OLLAMA_HOST": "http://localhost:11434", "OLLAMA_MODEL": "test-model"}, clear=True):
        import requests
        with patch.object(requests, "post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"message": {"content": "No Issue"}}
            mock_post.return_value.raise_for_status = lambda: None
            provider = DeepSeekProvider()
            result = await provider.generate("test prompt")
            assert result == "No Issue"
