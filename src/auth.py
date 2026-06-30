# src/auth.py
from typing import Optional
import hashlib
import json
import os

from dotenv import load_dotenv
from fastapi import HTTPException, Header

from src.storage import event_store


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> dict:
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required"
        )
    record = event_store.get_api_key(x_api_key)
    if record:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    client_name = record['client_name']
    return {
        "client_name": client_name,
        "api_key": x_api_key
    }
