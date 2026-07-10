import hashlib
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


def make_fingerprint(*parts: str) -> str:
    """
    SHA-256 fingerprint from the identifying fields of an alert.
    Two alerts with the same fingerprint represent the same ongoing attack.
    Usage: make_fingerprint(alert_type, user, source)  — add more parts for finer granularity.
    """
    key = ":".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(key.encode()).hexdigest()


_VALID_STATUSES = frozenset({"open", "investigating", "resolved", "false_positive"})


class Evidence(BaseModel):
    event: str
    timestamp: datetime
    raw_log: Optional[str] = None


class SecurityEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    user: Optional[str] = None
    action: str
    resource: Optional[str] = None
    details: Optional[dict] = Field(default_factory=dict)
    raw_log: Optional[str] = None


class Alert(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    type: str
    severity: str
    description: str
    evidence: List[Evidence] = Field(default_factory=list)
    ai_reasoning: str
    confidence: float
    recommended_actions: List[str] = Field(default_factory=list)
    # Deduplication and lifecycle fields
    fingerprint: Optional[str] = None
    status: str = "open"
    hit_count: int = 1
    last_seen_at: Optional[datetime] = None
