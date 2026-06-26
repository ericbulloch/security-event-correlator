from typing import List
import asyncio
from datetime import datetime, timedelta

from src.models import SecurityEvent, Alert
from src.storage import event_store
from src.correlation_rules import CorrelationRule
from src.ai_correlator import AICorrelator


class CorrelationWorker:
    def __init__(self, poll_interval: int = 5):
        self.poll_interval = poll_interval
        self.ai_correlator = AICorrelator()
        self.is_running = False
    
    async def start(self):
        self.is_running = True
        print("Correlation worker started")
        
        while self.is_running:
            try:
                await self.process_batch()
            except Exception as e:
                print(f"Error in correlation worker: {e}")
            
            await asyncio.sleep(self.poll_interval)
    
    def stop(self):
        self.is_running = False
        print("Correlation worker stopped")
    
    async def process_batch(self):
        unprocessed_events = event_store.get_unprocessed_events(limit=10)
        if not unprocessed_events:
            return  # Nothing to do
        for event in unprocessed_events:
            await self.process_event(event)
    
    async def process_event(self, event: SecurityEvent):
        try:
            if not CorrelationRule.should_process(event):
                event_store.mark_as_processed(event.id)
                return
            event_store.mark_as_processing(event.id)
            related_events = self.get_related_events(event)
            print(f"Processing event {event.id}: {event.event_type} from {event.source}")
            print(f"  Including {len(related_events)} related events for context")
            alerts = self.ai_correlator.correlate(event, related_events)
            for alert in alerts:
                event_store.add_alert(alert)
                print(f"  Generated alert: {alert.type} (severity: {alert.severity})")
            event_store.mark_as_processed(event.id)
        except Exception as e:
            print(f"Error processing event {event.id}: {e}")
            event_store.mark_as_failed(event.id, str(e))
    
    def get_related_events(self, event: SecurityEvent) -> List[SecurityEvent]:
        lookback_seconds = CorrelationRule.get_lookback_window(event)
        related_types = CorrelationRule.get_related_event_types(event)
        cutoff_time = event.timestamp - timedelta(seconds=lookback_seconds)
        related_events = event_store.get_events_for_correlation(
            user=event.user,
            source=event.source,
            event_types=related_types,
            after=cutoff_time,
            before=event.timestamp,
            limit=20
        )
        related_events.sort(key=lambda e: e.timestamp)
        
        return related_events


correlation_worker = CorrelationWorker(poll_interval=5)
