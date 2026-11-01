from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventSource(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    NETWORK = "network"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    SYSTEM = "system"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HostInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str
    ip_address: str | None = None
    os_name: str | None = None


class ActorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = None
    user_id: str | None = None


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)

    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)

    protocol: str | None = None
    direction: str | None = None
    action: str | None = None
    connection_state: str | None = None

    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event_id: UUID = Field(default_factory=uuid4)

    timestamp: datetime
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    source: EventSource
    category: EventCategory
    event_name: str
    severity: Severity = Severity.INFO

    host: HostInfo
    actor: ActorInfo | None = None
    network: NetworkInfo | None = None

    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include a timezone")
        return value
