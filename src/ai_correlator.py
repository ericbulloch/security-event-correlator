from typing import List
import json

from src.models import SecurityEvent, Alert

from anthropic import Anthropic


class AICorrelator:
    def __init__(self):
        self.client = Anthropic()
    
    async def correlate(
        self, 
        current_event: SecurityEvent, 
        related_events: List[SecurityEvent]
    ) -> List[Alert]:
        events_text = self._format_events(current_event, related_events)
        response = await self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": f"""Analyze these security events for attack patterns:

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
4. What evidence supports this conclusion?
5. What actions should be taken?

Return ONLY valid JSON with no additional text:
{{
  "is_alert": boolean,
  "alert_type": string or null,
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": number (0-100),
  "description": string,
  "evidence": [string],
  "recommended_actions": [string]
}}"""
            }]
        )
        
        response_text = response.content[0].text
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
                related_events=[e.id for e in related_events]
            )
            return [alert]
        
        return []
    
    def _format_events(self, current: SecurityEvent, related: List[SecurityEvent]) -> str:
        lines = []
        if related:
            lines.append("=== PRECEDING EVENTS (for context) ===")
            for e in related:
                lines.append(self._format_single_event(e))
        lines.append("\n=== CURRENT EVENT (FOCUS HERE) ===")
        lines.append(self._format_single_event(current))
        
        return "\n".join(lines)
    
    def _format_single_event(self, event: SecurityEvent) -> str:
        return (
            f"[{event.timestamp}] "
            f"User: {event.user or 'N/A'} | "
            f"Source: {event.source} | "
            f"Type: {event.event_type} | "
            f"Action: {event.action} | "
            f"Severity: {event.severity} | "
            f"Details: {event.details}"
        )
