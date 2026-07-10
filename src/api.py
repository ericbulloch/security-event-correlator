from typing import List, Optional
import os
import uuid

from pydantic import BaseModel, field_validator

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from src.auth import (
    verify_api_key, verify_user_token,
    hash_password, verify_password, create_access_token,
)
from src.error_handler import ErrorHandler
from src.models import Alert, SecurityEvent, _VALID_STATUSES
from src.normalizer import normalize_event
from src.payload_validator import PayloadValidator
from src.rabbitmq_client import rabbitmq_client
from src.storage import event_store

app = FastAPI(title="Security Event Correlator")

# ── CORS ──────────────────────────────────────────────────────────────────────
# CORS_ORIGINS: comma-separated list of allowed frontend origins.
# Example: http://localhost:5173,https://siem.example.com
_cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


# ── Request / response models ─────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class AlertStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in _VALID_STATUSES:
            raise ValueError(
                f"status must be one of: {', '.join(sorted(_VALID_STATUSES))}"
            )
        return v


# ── Public routes ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check() -> dict:
    try:
        event_count = event_store.count()
        return {"status": "healthy", "events_stored": event_count}
    except Exception as e:
        ErrorHandler.log_security_event(
            event_type="health_check_failed",
            client_name="system",
            details=str(e),
        )
        raise HTTPException(status_code=503, detail="Service unhealthy")


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.post("/v1/auth/login")
async def login(body: LoginRequest) -> dict:
    user = event_store.get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(user["username"], bool(user["is_admin"]))
    return {"access_token": token, "token_type": "bearer"}


@app.get("/v1/auth/me")
async def me(current_user: dict = Depends(verify_user_token)) -> dict:
    return current_user


# ── Collector ingestion (API-key auth) ────────────────────────────────────────

@app.post("/v1/events/ingest")
async def ingest_events(
    request: Request,
    client_info: dict = Depends(verify_api_key),
) -> dict:
    request_id = str(uuid.uuid4())
    client_name = client_info["client_name"]
    rate_limit = client_info["rate_limit"]

    is_allowed, remaining = event_store.check_rate_limit(client_name, rate_limit)
    if not is_allowed:
        status = event_store.get_rate_limit_status(client_name, rate_limit)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(rate_limit),
                "X-RateLimit-Remaining": str(status["remaining"]),
                "X-RateLimit-Reset": status["reset_at"],
                "X-Request-ID": request_id,
            },
        )

    try:
        events = await PayloadValidator.validate_and_parse(request)
        if not events:
            raise HTTPException(status_code=400, detail="No events provided")

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
                normalized_errors.append({"index": i, "error": str(e)})

        ingestion_count = 0
        ingestion_errors = []
        for event in normalized_events:
            try:
                event = event_store.add_security_event(event)
                rabbitmq_client.publish_event_id(event_id=str(event.id))
                ingestion_count += 1
            except Exception as e:
                ingestion_errors.append({
                    "error": "Could not insert/publish event.",
                    "index": event["details"]["index"],
                })

        status = "success"
        if ingestion_count == 0:
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
            "message": f"{ingestion_count} events ingested and stored successfully",
            "headers": {
                "X-RateLimit-Limit": rate_limit,
                "X-RateLimit-Remaining": str(remaining),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        ErrorHandler.handle_processing_error(e, request_id)


# ── Alert routes (JWT auth) ───────────────────────────────────────────────────

@app.get("/v1/alerts")
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    current_user: dict = Depends(verify_user_token),
) -> dict:
    alerts = event_store.get_alerts(limit, offset, severity, status)
    total = event_store.count_alerts(severity, status)
    return {
        "data": alerts,
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total,
        },
    }


@app.patch("/v1/alerts/{alert_id}")
async def update_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    current_user: dict = Depends(verify_user_token),
) -> dict:
    found = event_store.update_alert_status(alert_id, body.status)
    if not found:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return {"id": alert_id, "status": body.status}
