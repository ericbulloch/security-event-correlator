from datetime import datetime, timezone
import json
import os
from typing import Optional

import pika


class RabbitMQClient:
    def __init__(self) -> None:
        self.url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F")
        self.queue_name = os.getenv("RABBITMQ_QUEUE", "security-events")
        self.exchange = os.getenv("RABBITMQ_EXCHANGE", "")
        self.routing_key = os.getenv("RABBITMQ_ROUTING_KEY", self.queue_name)
        self._connection: Optional[pika.BlockingConnection] = None
        self._channel: Optional[pika.adapters.blocking_connection.BlockingChannel] = None

    def connect(self) -> None:
        if self._connection and self._connection.is_open and self._channel and self._channel.is_open:
            return
        params = pika.URLParameters(self.url)
        self._connection = pika.BlockingConnection(params)
        self._channel = self._connection.channel()
        self._channel.queue_declare(queue=self.queue_name, durable=True)

    def close(self) -> None:
        try:
            if self._channel and self._channel.is_open:
                self._channel.close()
        finally:
            if self._connection and self._connection.is_open:
                self._connection.close()

    def publish_event_id(self, event_id: str, schema_version: int = 1) -> None:
        self.connect()
        assert self._channel is not None
        payload = {
            "event_id": event_id,
            "schema_version": schema_version,
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
        }
        self._channel.basic_publish(
            exchange=self.exchange,
            routing_key=self.routing_key,
            body=json.dumps(payload),
            properties=pika.BasicProperties(
                delivery_mode=2,  # persistent
                content_type="application/json",
            ),
        )

rabbitmq_client = RabbitMQClient()
