from typing import List
import asyncio
from contextlib import asynccontextmanager

from src.auth import verify_api_key
from src.correlation_worker import correlation_worker
from src.models import Alert, SecurityEvent
from src.storage import event_store
from src.normalizer import normalize_event

from fastapi import Depends, FastAPI, Header, HTTPException


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting correlation worker...")
    worker_task = None
    try:
        worker_task = asyncio.create_task(correlation_worker.start())
        yield
    finally:
        print("Stopping correlation worker...")
        if worker_task:
            worker_task.cancel()
        correlation_worker.stop()


app = FastAPI(lifespan=lifespan)


@app.post("/events/ingest")
async def ingest_events(
    events: List[dict]
    client_info: dict = Depends(verify_api_key)
) -> dict:
    client_name = client_info["client_name"]
    try:
        if not events:
            raise HTTPException(
                status_code=400,
                detail="No events provided"
            )
        normalized_events = []
        for raw_event in events:
            try:
                raw_event["details"] = raw_event.get("details", {})
                raw_event["details"]["client"] = client_name
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
            "client": client_name,
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
async def get_alerts() -> List[Alert]:
    return event_store.get_alerts()
