from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentIdentity(BaseModel):
    """
    Trusted identity record issued and managed by the Agent Runtime.

    This model must not be populated directly from untrusted agent input.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    agent_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]+$",
    )

    agent_type: str = Field(
        min_length=2,
        max_length=64,
    )

    tenant_id: str = Field(
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]+$",
    )

    roles: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    @field_validator("roles", "capabilities")
    @classmethod
    def validate_permissions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)

        if any(not value for value in normalized):
            raise ValueError("Roles and capabilities cannot contain empty values")

        if "*" in normalized:
            raise ValueError("Wildcard permissions are not allowed")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate permissions are not allowed")

        return normalized
