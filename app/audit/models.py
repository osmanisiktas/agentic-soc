from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class AuditDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class AuditEventType(str, Enum):
    POLICY_DECISION = "policy_decision"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_TIMED_OUT = "execution_timed_out"


class AuditEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    event_id: UUID = Field(default_factory=uuid4)

    event_type: AuditEventType = AuditEventType.POLICY_DECISION

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    actor_id: str = Field(min_length=3, max_length=64)
    actor_type: str = Field(min_length=3, max_length=32)

    tenant_id: str = Field(min_length=2, max_length=64)
    task_id: UUID

    action: str = Field(min_length=3, max_length=128)

    decision: AuditDecision | None = None

    reason_code: str = Field(min_length=3, max_length=128)

    evidence_ids: tuple[str, ...] = ()

    correlation_id: UUID

    @model_validator(mode="after")
    def validate_event_decision(self) -> "AuditEvent":
        if (
            self.event_type == AuditEventType.POLICY_DECISION
            and self.decision is None
        ):
            raise ValueError(
                "Policy decision events require a decision."
            )

        if (
            self.event_type != AuditEventType.POLICY_DECISION
            and self.decision is not None
        ):
            raise ValueError(
                "Execution events cannot contain a policy decision."
            )

        return self

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "Audit timestamp must be timezone-aware"
            )

        return value

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(not item.strip() for item in value):
            raise ValueError(
                "Evidence IDs cannot be empty"
            )

        if len(value) != len(set(value)):
            raise ValueError(
                "Duplicate evidence IDs are not allowed"
            )

        return value
