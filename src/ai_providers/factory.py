import os
import logging

from src.ai_providers.base import BaseAIProvider

logger = logging.getLogger(__name__)

_VALID_PROVIDERS = ("anthropic", "gemini", "github_copilot", "dummy")


def get_ai_provider() -> BaseAIProvider:
    """
    Instantiate and return the AI provider selected by the AI_PROVIDER
    environment variable (default: anthropic).

    Each provider validates that its required API key is present at
    construction time, so misconfiguration is caught at startup rather
    than on the first correlation attempt.
    """
    provider_name = os.getenv("AI_PROVIDER", "anthropic").lower()

    if provider_name == "anthropic":
        from src.ai_providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider()

    if provider_name == "gemini":
        from src.ai_providers.gemini_provider import GeminiProvider
        return GeminiProvider()

    if provider_name == "github_copilot":
        from src.ai_providers.github_copilot_provider import GitHubCopilotProvider
        return GitHubCopilotProvider()

    if provider_name == "dummy":
        from src.ai_providers.dummy_provider import DummyProvider
        return DummyProvider()

    raise ValueError(
        f"Unknown AI_PROVIDER: '{provider_name}'. "
        f"Valid options: {', '.join(_VALID_PROVIDERS)}"
    )
