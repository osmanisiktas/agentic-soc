import pytest
from pydantic import ValidationError

from app.runtime.workflow import WorkflowDefinition, WorkflowStep


@pytest.fixture
def valid_step():
    return WorkflowStep(
        step_id="step-1",
        agent_id="triage-agent",
        task_type="alert_triage",
        required_capabilities=("alert:read",),
        required_resources=("alerts:tenant-a",),
        instructions="Analyze the supplied alert.",
        max_runtime_seconds=60,
    )


@pytest.fixture
def valid_workflow(valid_step):
    return WorkflowDefinition(
        tenant_id="tenant-a",
        name="Alert Triage",
        steps=(valid_step,),
        max_runtime_seconds=300,
    )


def test_valid_workflow_creation(valid_workflow):
    assert valid_workflow.tenant_id == "tenant-a"
    assert len(valid_workflow.steps) == 1


def test_duplicate_step_ids_are_rejected(valid_step):
    duplicate_step = valid_step.model_copy()

    with pytest.raises(ValidationError):
        WorkflowDefinition(
            tenant_id="tenant-a",
            name="Invalid Workflow",
            steps=(valid_step, duplicate_step),
        )


def test_wildcard_capability_is_rejected():
    with pytest.raises(ValidationError):
        WorkflowStep(
            step_id="step-1",
            agent_id="triage-agent",
            task_type="alert_triage",
            required_capabilities=("*",),
            instructions="Analyze the supplied alert.",
        )


def test_duplicate_capabilities_are_rejected():
    with pytest.raises(ValidationError):
        WorkflowStep(
            step_id="step-1",
            agent_id="triage-agent",
            task_type="alert_triage",
            required_capabilities=("alert:read", "alert:read"),
            instructions="Analyze the supplied alert.",
        )


def test_empty_workflow_is_rejected():
    with pytest.raises(ValidationError):
        WorkflowDefinition(
            tenant_id="tenant-a",
            name="Empty Workflow",
            steps=(),
        )


def test_workflow_is_immutable(valid_workflow):
    with pytest.raises(ValidationError):
        valid_workflow.tenant_id = "tenant-b"


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        WorkflowStep(
            step_id="step-1",
            agent_id="triage-agent",
            task_type="alert_triage",
            instructions="Analyze the supplied alert.",
            unauthorized_field="unexpected",
        )
