from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WorkflowStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=3, max_length=64)
    task_type: str = Field(min_length=3, max_length=64)
    required_capabilities: tuple[str, ...] = Field(min_length=1)
    required_resources: tuple[str, ...] = Field(min_length=1)
    instructions: str = Field(min_length=1, max_length=4000)
    max_runtime_seconds: int = Field(default=60, gt=0, le=300)

    @field_validator("required_capabilities", "required_resources")
    @classmethod
    def validate_permissions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() or "*" in value for value in values):
            raise ValueError("Empty and wildcard permissions are not allowed.")

        if len(values) != len(set(values)):
            raise ValueError("Duplicate permissions are not allowed.")

        return values


class WorkflowDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    workflow_id: UUID = Field(default_factory=uuid4)
    tenant_id: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    steps: tuple[WorkflowStep, ...] = Field(min_length=1)
    max_runtime_seconds: int = Field(default=300, gt=0, le=3600)

    @field_validator("steps")
    @classmethod
    def validate_steps(
        cls,
        steps: tuple[WorkflowStep, ...],
    ) -> tuple[WorkflowStep, ...]:
        step_ids = [step.step_id for step in steps]

        if len(step_ids) != len(set(step_ids)):
            raise ValueError("Workflow step IDs must be unique.")

        return steps
