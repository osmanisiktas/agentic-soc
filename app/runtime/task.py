from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AgentTask(BaseModel):
    """
    A task issued by the trusted orchestrator.

    Tasks must be created by trusted platform components,
    not directly from untrusted agent or external event input.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    task_id: UUID = Field(default_factory=uuid4)

    agent_id: str = Field(
        min_length=3,
        max_length=64,
    )

    tenant_id: str = Field(
        min_length=2,
        max_length=64,
    )

    task_type: str = Field(
        min_length=3,
        max_length=64,
    )

    requested_by: str = Field(
        min_length=3,
        max_length=64,
    )

    resource_scope: tuple[str, ...] = ()

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    expires_at: datetime

    max_runtime_seconds: int = Field(
        default=60,
        ge=1,
        le=300,
    )

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timezone-aware datetime is required")
        return value

    @field_validator("resource_scope")
    @classmethod
    def validate_resource_scope(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)

        if any(not value for value in normalized):
            raise ValueError("Resource scope cannot contain empty values")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate resources are not allowed")

        if "*" in normalized:
            raise ValueError("Wildcard resource scope is not allowed")

        return normalized

    @model_validator(mode="after")
    def validate_expiration(self):
        if self.expires_at <= self.created_at:
            raise ValueError("Task expiration must be after creation")

        return self
