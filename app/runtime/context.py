from uuid import UUID
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceItem(BaseModel):
    """Untrusted evidence provided to an agent."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    evidence_id: str = Field(min_length=1, max_length=128)
    evidence_type: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=128)
    content: dict[str, Any]
    trust_level: str = "untrusted"


class AgentContext(BaseModel):
    """
    Task-scoped context supplied by the trusted runtime.

    Evidence is data, never executable instruction.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    task_id: UUID
    agent_id: str = Field(min_length=3, max_length=64)
    tenant_id: str = Field(min_length=2, max_length=64)

    evidence: tuple[EvidenceItem, ...] = ()

    instructions: str = Field(
        min_length=1,
        max_length=4000,
    )

    @field_validator("evidence")
    @classmethod
    def validate_evidence(
        cls, values: tuple[EvidenceItem, ...]
    ) -> tuple[EvidenceItem, ...]:
        evidence_ids = [item.evidence_id for item in values]

        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Duplicate evidence IDs are not allowed")

        return values
