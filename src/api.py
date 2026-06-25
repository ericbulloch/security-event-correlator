from fastapi import FastAPI, HTTPException
from typing import list
from src.models import SecurityEvent
from src.storage import event_store
from src.normalizer import normalize_event

app = FastAPI()

@app.post("/events/ingest")
async def ingest_events(events: list[dict]) -> dict:
    try:
        if not events:
            raise HTTPException(
                status_code=400,
                detail="No events provided"
            )
        normalized_events = []
        for raw_event in events:
            try:
                event = SecurityEvent(**raw_event)
                normalized = normalize_event(event)
                normalized_events.append(normalized)
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid event format: {str(e)}"
                )
        for event in normalized_events:
            event_store.add(event)
        return {
            "status": "success",
            "events_stored": len(normalized_events),
            "message": f"{len(normalized_events)} events ingested and stored successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to store events: {str(e)}"
        )
