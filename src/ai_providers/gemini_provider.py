import os
import logging

import google.generativeai as genai

from src.ai_providers.base import BaseAIProvider, SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class GeminiProvider(BaseAIProvider):
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is required for the Gemini provider."
            )
        genai.configure(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
        # system_instruction keeps analysis instructions separate from event data,
        # mirroring the approach used for Anthropic's system parameter.
        self._model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=SYSTEM_PROMPT,
        )
        logger.info(f"GeminiProvider initialized with model '{model_name}'")

    async def _call_api(self, prompt: str) -> str:
        response = await self._model.generate_content_async(prompt)
        return response.text
