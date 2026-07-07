from fastapi import HTTPException
import json


class PayloadValidator:
    MAX_TOTAL_SIZE = 16 *  1024 * 1024
    MAX_EVENT_SIZE = 1 * 1024 * 1024
    MAX_EVENTS_PER_BATCH = 1000

    @staticmethod
    async def validate_and_parse(request) -> list:
        total_size = 0
        chunks = []
        async for chunk in request.stream():
            total_size += len(chunk)
            if total_size > PayloadValidator.MAX_TOTAL_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Total payload too large. Max: {PayloadValidator.MAX_TOTAL_SIZE / 1024 / 1024:.1f} MB"
                )
            chunks.append(chunk)
        body_bytes = b"".join(chunks)
        try:
            events = json.loads(body_bytes)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON in request body"
            )
        if not isinstance(events, list):
            raise HTTPException(
                status_code=400,
                detail="Request body must be a JSON array"
            )
        if len(events) > PayloadValidator.MAX_EVENTS_PER_BATCH:
            raise HTTPException(
                status_code=400,
                detail=f"Too many events. Max: {PayloadValidator.MAX_EVENTS_PER_BATCH}, "
                       f"received: {len(events)}"
            )
        for i, event in enumerate(events):
            if not isinstance(event, dict):
                raise HTTPException(
                    status_code=400,
                    detail=f"Event {i} is not a valid event object"
                )
            event_json = json.dumps(event)
            event_size = len(event_json.encode())
            if event_size > PayloadValidator.MAX_EVENT_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Event {i} too large. Max: {PayloadValidator.MAX_EVENT_SIZE / 1024 / 1024:.1f} MB, "
                           f"received: {event_size / 1024 / 1024:.1f} MB"
                )

        return events
