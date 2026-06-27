# src/auth.py
from typing import Optional
import os
import json

from dotenv import load_dotenv
from fastapi import HTTPException, Header

load_dotenv()

API_KEYS_JSON = os.getenv("API_KEYS_JSON", "{}")
VALID_API_KEYS: dict = json.loads(API_KEYS_JSON)

if not VALID_API_KEYS:
    raise ValueError("API_KEYS_JSON environment variable not set!")


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> dict:
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required"
        )
    
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    
    client_name = VALID_API_KEYS[x_api_key]
    return {
        "client_name": client_name,
        "api_key": x_api_key
    }
