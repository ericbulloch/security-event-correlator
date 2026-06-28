from typing import List, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


class Evidence(BaseModel):
    event: str
    timestamp: datetime


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
