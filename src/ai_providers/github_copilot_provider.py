import os
import logging

from openai import AsyncOpenAI

from src.ai_providers.base import BaseAIProvider, SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# GitHub Models API endpoint — OpenAI-compatible, authenticated with a
# GitHub Personal Access Token (requires the models:read permission).
_GITHUB_MODELS_BASE_URL = "https://models.inference.ai.azure.com"


class GitHubCopilotProvider(BaseAIProvider):
    def __init__(self):
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ValueError(
                "GITHUB_TOKEN environment variable is required for the GitHub Copilot provider. "
                "Create a Personal Access Token with the 'models:read' permission."
            )
        self._client = AsyncOpenAI(
            base_url=_GITHUB_MODELS_BASE_URL,
            api_key=token,
        )
        self._model = os.getenv("GITHUB_COPILOT_MODEL", "gpt-4o")
        logger.info(f"GitHubCopilotProvider initialized with model '{self._model}'")

    async def _call_api(self, prompt: str) -> str:
        # OpenAI-compatible API uses a system message rather than a separate
        # system parameter, so SYSTEM_PROMPT is the first message in the list.
        response = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content
