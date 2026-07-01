from typing import Optional
from datetime import datetime, UTC
import hashlib
import json
import os

from fastapi import HTTPException, Header

from src.storage import event_store


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> dict:
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required"
        )
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    record = event_store.get_api_key(key_hash)
    if not record:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    if not record['is_active']:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    now = datetime.now(UTC)
    expires_at = datetime.fromisoformat(record['expires_at').astimezone(UTC)
    if now > expires_at:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    event_store.update_last_used(key_hash)
    client_name = record['client_name']
    return {
        "client_name": client_name
    }
