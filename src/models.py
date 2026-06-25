from enum import Enum
from pydantic import BaseModel


class Severity(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


class Evidence:
    event: str
    timestamp: datetime


class SecurityEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    user: str
    action: str
    resource: str
    details: dict


class Alert(BaseModel):
    id: str
    timestamp: datetime
    type: str,
    severity: Severity
    description: str
    evidence: list[Evidence]
    ai_reasoning: str
    confidence: float
    recommended_actions: list[str]
