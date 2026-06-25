from pydantic import BaseModel


class SecurityEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    user: str
    action: str
    resource: str
    details: dict
