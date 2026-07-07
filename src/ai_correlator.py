from typing import List
import json
import asyncio
import logging
from functools import wraps
import random

from src.models import SecurityEvent, Alert
from anthropic import Anthropic

logger = logging.getLogger(__name__)


def async_retry(max_retries: int = 3, base_delay: float = 1, max_delay: float = 30):
    """
    Decorator for async functions with exponential backoff retry logic.
    
    Args:
        max_retries: Maximum number of retry attempts (default 3)
        base_delay: Initial delay in seconds (default 1)
        max_delay: Maximum delay between retries in seconds (default 30)
    
    Implements exponential backoff with jitter:
        Attempt 1: Immediate
        Attempt 2: ~1s
        Attempt 3: ~2s
        Attempt 4: ~4s (capped at 30s)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # If this was the last attempt, raise
                    if attempt == max_retries:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {str(e)}"
                        )
                        raise
                    
                    # Calculate delay with exponential backoff and jitter
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    # Add jitter: 50-150% of calculated delay
                    delay_with_jitter = delay * (0.5 + random.random())
                    
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1} failed: {str(e)}. "
                        f"Retrying in {delay_with_jitter:.2f}s..."
                    )
                    await asyncio.sleep(delay_with_jitter)
            
            raise last_exception
        return wrapper
    return decorator


class AICorrelator:
    def __init__(self):
        self.client = Anthropic()
    
    @async_retry(max_retries=3, base_delay=1, max_delay=30)
    async def _call_anthropic_api(self, prompt: str) -> str:
        """
        Call Anthropic API with exponential backoff retry logic.
        
        Retries up to 3 times with exponential backoff on failure.
        
        Args:
            prompt: The prompt to send to Claude
            
        Returns:
            The response text from Claude
            
        Raises:
            Exception: After all retries exhausted
        """
        response = await self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        return response.content[0].text
    
    async def correlate(
        self, 
        current_event: SecurityEvent, 
        related_events: List[SecurityEvent]
    ) -> List[Alert]:
        """
        Correlate security events using AI to detect attack patterns.
        
        Uses exponential backoff retry logic for API calls.
        
        Args:
            current_event: The primary event to analyze
            related_events: Related events for context
            
        Returns:
            List of Alert objects if threats detected, empty list otherwise
            
        Raises:
            Exception: If AI correlation fails after retries
        """
        events_text = self._format_events(current_event, related_events)
        prompt = f"""Analyze these security events for attack patterns:

{events_text}

Focus on the CURRENT EVENT (marked below) and its relationship to preceding events.

CURRENT EVENT:
{self._format_single_event(current_event)}

PRECEDING RELATED EVENTS (for context):
{chr(10).join(self._format_single_event(e) for e in related_events)}

Questions to answer:
1. Do these events together suggest an attack? (yes/no)
2. If yes, what type of attack? (brute force, exfiltration, privilege escalation, etc.)
3. Confidence level? (0-100%)
4. What evidence supports this conclusion? This should be a list of evidence objects. An evidence object has an event property that is a string and a timestamp property that is a datetime.
5. What actions should be taken?

Return ONLY valid JSON with no additional text:
{{
  "is_alert": boolean,
  "alert_type": string or null,
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": number (0-100),
  "description": string,
  "evidence": [evidence object that has an event property that is a string and a timestamp property that is a datetime],
  "recommended_actions": [string]
}}"""
        
        try:
            response_text = await self._call_anthropic_api(prompt)
            alert_data = json.loads(response_text)
            
            if alert_data.get("is_alert"):
                alert = Alert(
                    type=alert_data["alert_type"],
                    severity=alert_data["severity"],
                    description=alert_data["description"],
                    evidence=alert_data["evidence"],
                    confidence=alert_data["confidence"] / 100.0,
                    recommended_actions=alert_data["recommended_actions"],
                    timestamp=current_event.timestamp,
                    ai_reasoning=response_text
                )
                return [alert]
            
            return []
        except Exception as e:
            logger.error(f"Failed to correlate events after retries: {str(e)}", exc_info=True)
            raise
    
    def _format_events(self, current: SecurityEvent, related: List[SecurityEvent]) -> str:
        """Format events for display in AI prompt"""
        lines = []
        if related:
            lines.append("=== PRECEDING EVENTS (for context) ===")
            for e in related:
                lines.append(self._format_single_event(e))
        lines.append("\n=== CURRENT EVENT (FOCUS HERE) ===")
        lines.append(self._format_single_event(current))
        
        return "\n".join(lines)
    
    def _format_single_event(self, event: SecurityEvent) -> str:
        """Format a single event for display"""
        return (
            f"[{event.timestamp}] "
            f"User: {event.user or 'N/A'} | "
            f"Source: {event.source} | "
            f"Type: {event.event_type} | "
            f"Action: {event.action} | "
            f"Severity: {event.severity} | "
            f"Details: {event.details}"
        )
