import json
import os
import signal
import sys
from typing import Any, Dict

import pika

from src.correlation_worker import correlation_worker
from src.error_handler import ErrorHandler


class SecurityEventConsumer:
    def __init__(self) -> None:
        self.url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F")
        self.queue_name = os.getenv("RABBITMQ_QUEUE", "security-events")
        self.prefetch = int(os.getenv("RABBITMQ_PREFETCH", "10"))
        self.connection = None
        self.channel = None
        self._stopping = False

    def connect(self) -> None:
        params = pika.URLParameters(self.url)
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name, durable=True)
        self.channel.basic_qos(prefetch_count=self.prefetch)

    def stop(self, *_args: Any) -> None:
        self._stopping = True
        try:
            if self.channel and self.channel.is_open:
                self.channel.stop_consuming()
        except Exception:
            pass
        try:
            if self.connection and self.connection.is_open:
                self.connection.close()
        except Exception:
            pass

    def _parse_message(self, body: bytes) -> Dict[str, Any]:
        payload = json.loads(body.decode("utf-8"))
        if "event_id" not in payload:
            raise ValueError("Message missing required field: event_id")
        return payload

    def _on_message(self, ch, method, properties, body: bytes) -> None:
        try:
            payload = self._parse_message(body)
            event_id = payload["event_id"]
            # correlation worker uses async API
            import asyncio
            asyncio.run(correlation_worker.process_event_id(str(event_id)))
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            ErrorHandler.log_security_event(
                event_type="worker_processing_failed",
                client_name="worker",
                details=str(e),
            )
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    def run(self) -> None:
        self.connect()
        assert self.channel is not None
        self.channel.basic_consume(
            queue=self.queue_name,
            on_message_callback=self._on_message,
            auto_ack=False,
        )
        print(f"[*] Worker started. Waiting for messages on queue '{self.queue_name}'...")
        self.channel.start_consuming()


def main() -> int:
    consumer = SecurityEventConsumer()
    signal.signal(signal.SIGINT, consumer.stop)
    signal.signal(signal.SIGTERM, consumer.stop)
    try:
        consumer.run()
        return 0
    except KeyboardInterrupt:
        consumer.stop()
        return 0
    except Exception as e:
        ErrorHandler.log_security_event(
            event_type="worker_fatal_error",
            client_name="worker",
            details=str(e),
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
