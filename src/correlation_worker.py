from typing import List
import asyncio
from datetime import datetime, timedelta
import logging
import signal

from src.ai_correlator import AICorrelator
from src.correlation_rules import CorrelationRule
from src.error_handler import ErrorHandler
from src.models import SecurityEvent, Alert
from src.storage import event_store


logger = logging.getLogger(__name__)

class CorrelationWorker:
    def __init__(self, poll_interval: int = 5):
        self.poll_interval = poll_interval
        self.ai_correlator = AICorrelator()
        self.is_running = False

    def _signal_handler(self):
        logger.info("Received shutdown signal, gracefully stopping...")
        self.is_running = False
    
    async def start(self):
        self.is_running = True
        logger.info("Correlation worker started")
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._signal_handler)
        try:
            while self.is_running:
                try:
                    await self.process_batch()
                except Exception as e:
                    logger.error(f"Error in correlation worker: {str(e)}", exc_info=True)
                
                await asyncio.sleep(self.poll_interval)
        finally:
            await self._cleanup()
    
    def stop(self):
        self.is_running = False
        logger.info("Correlation worker stopped")
    
    async def process_batch(self):
        try:
            unprocessed_events = event_store.get_unprocessed_events(limit=10)
            if not unprocessed_events:
                return
            for event in unprocessed_events:
                await self.process_event(event)
        except Exception as e:
            logger.error("Error processing batch", exc_info=True)
    
    async def process_event(self, event: SecurityEvent):
        self.processing_events.add(event.id)
        try:
            if not CorrelationRule.should_process(event):
                event_store.mark_as_processed(event.id)
                return
            
            event_store.mark_as_processing(event.id)
            related_events = self.get_related_events(event)
            
            logger.debug(f"Processing event {event.id}: {event.event_type} from {event.source}")
            logger.debug(f"  Including {len(related_events)} related events for context")
            
            try:
                alerts = await self.ai_correlator.correlate(event, related_events)
            except Exception as e:
                ErrorHandler.handle_external_api_error(e, service_name="anthropic")
                event_store.mark_as_failed(event.id)
                return
            
            for alert in alerts:
                event_store.add_alert(alert)
                logger.info(f"Alert generated: {alert.type} (severity: {alert.severity})")
            
            event_store.mark_as_processed(event.id)
        except Exception as e:
            logger.error(f"Error processing event {event.id}", exc_info=True)
            event_store.mark_as_failed(event.id)
        finally:
            self.processing_events.discard(event.id)
    
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

    async def _cleanup(self):
        logger.info(f"Cleaning up {len(self.processing_events)} processing events")
        for event_id in self.processing_events:
            try:
                event_store.mark_as_unprocessed(event_id)
                logger.info(f"Rolled back event {event_id}")
            except Exception as e:
                logger.error(f"Failed to rollback event {event_id}: {str(e)}")
        logger.info("Cleanup complete")


correlation_worker = CorrelationWorker(poll_interval=5)
