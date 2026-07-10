import os
import logging

from anthropic import AsyncAnthropic

from src.ai_providers.base import BaseAIProvider, SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseAIProvider):
    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for the Anthropic provider."
            )
        self._client = AsyncAnthropic(api_key=api_key)
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        logger.info(f"AnthropicProvider initialized with model '{self._model}'")

    async def _call_api(self, prompt: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
