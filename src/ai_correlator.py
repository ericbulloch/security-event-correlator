from typing import List

from src.ai_providers.factory import get_ai_provider
from src.models import Alert, SecurityEvent


class AICorrelator:
    """
    Thin facade over the pluggable AI provider system.

    Provider selection is controlled by the AI_PROVIDER environment variable.
    See src/ai_providers/factory.py for available options.
    """

    def __init__(self):
        self.provider = get_ai_provider()

    async def correlate(
        self,
        current_event: SecurityEvent,
        related_events: List[SecurityEvent],
    ) -> List[Alert]:
        return await self.provider.correlate(current_event, related_events)
