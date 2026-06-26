from typing import List, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel


class Severity(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


class Evidence(BaseModel):
    event: str
    timestamp: datetime


class SecurityEvent(BaseModel):
    id: Optional[int]
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    user: str
    action: str
    resource: str
    details: dict


class Alert(BaseModel):
    id: int
    timestamp: datetime
    type: str
    severity: Severity
    description: str
    evidence: List[Evidence]
    ai_reasoning: str
    confidence: float
    recommended_actions: List[str]
