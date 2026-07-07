from typing import List, Optional
import asyncio
from contextlib import asynccontextmanager
import uuid

from src.auth import verify_api_key
from src.correlation_worker import correlation_worker
from src.error_handler import ErrorHandler
from src.models import Alert, SecurityEvent
from src.payload_validator import PayloadValidator
from src.storage import event_store
from src.normalizer import normalize_event

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request


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


@app.get("/health")
async def health_check() -> dict:
    try:
        event_count = event_store.count()
        return {
            "status": "healthy",
            "events_stored": event_count
        }
    except Exception as e:
        ErrorHandler.log_security_event(
            event_type="health_check_failed",
            client_name="system",
            details=str(e)
        )
        raise HTTPException(
            status_code=503,
            detail="Service unhealthy"
        )


@app.post("/v1/events/ingest")
async def ingest_events(
    request: Request,
    client_info: dict = Depends(verify_api_key)
) -> dict:
    request_id = str(uuid.uuid4())
    client_name = client_info["client_name"]
    rate_limit = client_info["rate_limit"]

    is_allowed, remaining = event_store.check_rate_limit(
        client_name,
        rate_limit
    )

    if not is_allowed:
        status = event_store.get_rate_limit_status(client_name, rate_limit)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(rate_limit),
                "X-RateLimit-Remaining": str(status["remaining"]),
                "X-RateLimit-Reset": status["reset_at"],
                "X-Request-ID": request_id
            }
        )

    try:
        events = await PayloadValidator.validate_and_parse(request)
        if not events:
            raise HTTPException(
                status_code=400,
                detail="No events provided"
            )
        normalized_events = []
        normalized_errors = []
        for i, raw_event in enumerate(events):
            try:
                raw_event["details"] = raw_event.get("details", {})
                raw_event["details"]["client"] = client_name
                raw_event["details"]["index"] = i
                normalized = normalize_event(raw_event)
                normalized_events.append(normalized)
            except Exception as e:
                normalized_errors.append({
                    "index": i,
                    "error": str(e)
                })
        ingestion_count = 0
        ingestion_errors = []
        for event in normalized_events:
            try:
                event_store.add_security_event(event)
                ingestion_count += 1
            except Exception as e:
                ingestion_errors.append({
                    "error": "Could not insert into the database.",
                    "index": event["details"]["index"]
                })
        status = "success"
        if ingested_count == 0:
            status = "failure"
        elif ingestion_errors or normalized_errors:
            status = "partial_success"
        return {
            "status": status,
            "events_ingested": ingestion_count,
            "events_requested": len(events),
            "normalized_errors": normalized_errors,
            "ingestion_errors": ingestion_errors,
            "client": client_name,
            "message": f"{len(normalized_events)} events ingested and stored successfully",
            "headers": {
                "X-RateLimit-Limit": rate_limit,
                "X-RateLimit-Remaining": str(remaining),
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        ErrorHandler.handle_processing_error(e, request_id)

@app.get("/v1/alerts")
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    client_info: dict = Depends(verify_api_key)
) -> dict:
    alerts = event_store.get_alerts(limit, offset, severity)
    total = event_store.count_alerts(severity)
    return {
        "data": alerts,
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total
        }
    }
