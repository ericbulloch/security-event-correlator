from typing import List

from src.models import Alert, SecurityEvent
from src.storage import event_store
from src.normalizer import normalize_event

from fastapi import FastAPI, HTTPException


app = FastAPI()


@app.post("/events/ingest")
async def ingest_events(events: List[dict]) -> dict:
    try:
        if not events:
            raise HTTPException(
                status_code=400,
                detail="No events provided"
            )
        normalized_events = []
        for raw_event in events:
            try:
                normalized = normalize_event(raw_event)
                normalized_events.append(normalized)
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid event format: {str(e)}"
                )
        for event in normalized_events:
            event_store.add_security_event(event)
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

@app.get("/alerts")
async def ingest_events(self) -> List[Alert]:
    return list(Alert(id=1))
