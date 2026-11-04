from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentExecutionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    REJECTED = "rejected"


class AgentResult(BaseModel):
    """Structured and auditable output from an agent execution."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    result_id: UUID = Field(default_factory=uuid4)
    task_id: UUID
    correlation_id: UUID

    agent_id: str = Field(min_length=3, max_length=64)
    tenant_id: str = Field(min_length=2, max_length=64)

    status: AgentExecutionStatus

    summary: str = Field(min_length=1, max_length=4000)

    confidence: float = Field(ge=0.0, le=1.0)

    evidence_ids: tuple[str, ...] = ()

    error_code: str | None = Field(default=None, max_length=128)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("created_at")
    @classmethod
    def validate_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timezone-aware datetime is required")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)

        if any(not value for value in normalized):
            raise ValueError("Evidence IDs cannot be empty")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate evidence IDs are not allowed")

        return normalized

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Error code cannot be empty")

        return value.strip() if value is not None else None
