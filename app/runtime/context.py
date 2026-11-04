import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class EvidenceTrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    EXTERNALLY_VERIFIED = "externally_verified"
    PLATFORM_VERIFIED = "platform_verified"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({
            key: _freeze(item)
            for key, item in value.items()
        })

    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    raise ValueError("Evidence content contains an unsupported value.")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _thaw(item)
            for key, item in value.items()
        }

    if isinstance(value, tuple):
        return [_thaw(item) for item in value]

    return value


def _content_hash(content: Any) -> str:
    canonical_content = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    return hashlib.sha256(
        canonical_content.encode("utf-8")
    ).hexdigest()


class EvidenceItem(BaseModel):
    """Immutable evidence provided to an agent."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )

    evidence_id: str = Field(min_length=1, max_length=128)
    evidence_type: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=128)
    source_reference: str | None = Field(
        default=None,
        max_length=256,
    )
    tenant_id: str = Field(min_length=2, max_length=64)
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    content: Any
    content_hash: str | None = None
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.UNTRUSTED

    @field_validator("collected_at")
    @classmethod
    def validate_collected_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timezone-aware datetime is required")

        return value

    @field_validator("content", mode="before")
    @classmethod
    def freeze_content(cls, value: Any) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError("Evidence content must be a mapping.")

        frozen = _freeze(value)

        return frozen

    @model_validator(mode="after")
    def validate_content_hash(self) -> "EvidenceItem":
        canonical_content = _thaw(self.content)
        expected_hash = _content_hash(canonical_content)

        if self.content_hash is None:
            object.__setattr__(self, "content_hash", expected_hash)
        elif self.content_hash != expected_hash:
            raise ValueError("Evidence content hash mismatch.")

        return self

    def verify_integrity(self, content: Any | None = None) -> bool:
        candidate = (
            _thaw(self.content)
            if content is None
            else content
        )

        if not isinstance(candidate, Mapping):
            raise ValueError("Evidence content must be a mapping.")

        if _content_hash(candidate) != self.content_hash:
            raise ValueError("Evidence content integrity verification failed.")

        return True


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
    correlation_id: UUID

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
        cls,
        values: tuple[EvidenceItem, ...],
    ) -> tuple[EvidenceItem, ...]:
        evidence_ids = [item.evidence_id for item in values]

        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Duplicate evidence IDs are not allowed")

        return values

    @model_validator(mode="after")
    def validate_evidence_tenant(self) -> "AgentContext":
        for item in self.evidence:
            if item.tenant_id != self.tenant_id:
                raise ValueError(
                    "Evidence tenant does not match context tenant."
                )

            item.verify_integrity()

        return self
