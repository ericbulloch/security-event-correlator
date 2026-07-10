from typing import Optional
from datetime import datetime, timedelta, UTC
import hashlib
import os

from fastapi import HTTPException, Header, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.storage import event_store


# ── API-key auth (machine-to-machine, used by collectors) ────────────────────

async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> dict:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    record = event_store.get_api_key(key_hash)
    if not record:
        raise HTTPException(status_code=403, detail="Invalid API key")
    if not record['is_active']:
        raise HTTPException(status_code=403, detail="Invalid API key")
    now = datetime.now(UTC)
    if record['expires_at']:
        expires_at = datetime.fromisoformat(record['expires_at']).astimezone(UTC)
        if now > expires_at:
            raise HTTPException(status_code=403, detail="Invalid API key")
    event_store.update_last_used(key_hash)
    return {
        "client_name": record['client_name'],
        "rate_limit": record['rate_limit'],
    }


# ── JWT auth (human users, used by the frontend) ─────────────────────────────

_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))  # 8 hours

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed: str) -> bool:
    return _pwd_context.verify(plain_password, hashed)


def create_access_token(username: str, is_admin: bool) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=_EXPIRE_MINUTES)
    payload = {"sub": username, "is_admin": is_admin, "exp": expire}
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


async def verify_user_token(token: str = Depends(_oauth2_scheme)) -> dict:
    """FastAPI dependency — validates the Bearer JWT and returns the user info."""
    exc = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if not username:
            raise exc
        return {"username": username, "is_admin": payload.get("is_admin", False)}
    except JWTError:
        raise exc
