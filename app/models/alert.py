from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.event import Severity


class AlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    alert_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    description: str

    severity: Severity
    status: AlertStatus = AlertStatus.NEW

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    username: str | None = None
    source_ip: str | None = None
    event_ids: list[UUID]

    evidence: dict = Field(default_factory=dict)
