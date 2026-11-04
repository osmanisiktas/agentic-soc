import asyncio

import pytest

from app.agents.base import BaseAgent
from app.agents.registry import AgentRegistry
from app.audit.models import AuditDecision, AuditEventType
from app.audit.service import AuditService
from app.audit.storage import AuditStorage
from app.runtime.authorization import (
    AuthorizationAuditError,
    AuthorizationService,
)
from app.runtime.context import AgentContext
from app.runtime.orchestrator import (
    Orchestrator,
    WorkflowAuthorizationError,
)
from app.runtime.result import AgentExecutionStatus, AgentResult
from app.runtime.task import AgentTask
from app.runtime.workflow import WorkflowDefinition, WorkflowStep
from app.security.identity import AgentIdentity


class MockAgent(BaseAgent):
    def __init__(self, identity):
        super().__init__(identity)
        self.run_count = 0

    async def run(
        self,
        task: AgentTask,
        context: AgentContext,
    ) -> AgentResult:
        self.run_count += 1

        return AgentResult(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            agent_id=task.agent_id,
            tenant_id=task.tenant_id,
            status=AgentExecutionStatus.SUCCESS,
            summary="Alert triage completed.",
            confidence=0.95,
        )


@pytest.fixture
def integration_setup(tmp_path):
    identity = AgentIdentity(
        agent_id="triage-agent",
        agent_type="triage",
        tenant_id="tenant-a",
        capabilities=("alert:read",),
    )

    agent = MockAgent(identity)

    registry = AgentRegistry()
    registry.register(agent)

    storage = AuditStorage(
        file_path=str(tmp_path / "orchestrator-audit.jsonl")
    )
    audit_service = AuditService(storage)
    authorization_service = AuthorizationService(audit_service)

    orchestrator = Orchestrator(
        registry=registry,
        authorization_service=authorization_service,
    )

    step = WorkflowStep(
        step_id="triage-step",
        agent_id="triage-agent",
        task_type="alert_triage",
        required_capabilities=("alert:read",),
        required_resources=("alerts:tenant-a",),
        instructions="Analyze the supplied alert.",
        max_runtime_seconds=30,
    )

    workflow = WorkflowDefinition(
        tenant_id="tenant-a",
        name="Audit Integration Test",
        steps=(step,),
        max_runtime_seconds=60,
    )

    return {
        "agent": agent,
        "storage": storage,
        "orchestrator": orchestrator,
        "workflow": workflow,
    }


def test_authorized_execution_is_persisted_in_audit(integration_setup):
    setup = integration_setup

    execution = asyncio.run(
        setup["orchestrator"].execute(
            workflow=setup["workflow"],
            requested_by="soc-operator",
        )
    )

    events = setup["storage"].read_all()

    assert setup["agent"].run_count == 1
    assert [event.event_type for event in events] == [
        AuditEventType.POLICY_DECISION,
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_COMPLETED,
    ]

    assert events[0].decision == AuditDecision.ALLOW
    assert events[0].correlation_id == execution.correlation_id

    assert all(
        event.correlation_id == execution.correlation_id
        for event in events
    )

    assert len({event.task_id for event in events}) == 1
    assert setup["storage"].verify_chain() is True


def test_denied_execution_is_audited_and_agent_is_not_run(integration_setup):
    setup = integration_setup
    step = setup["workflow"].steps[0]

    denied_step = step.model_copy(
        update={"required_capabilities": ("alert:delete",)}
    )

    denied_workflow = setup["workflow"].model_copy(
        update={"steps": (denied_step,)}
    )

    with pytest.raises(WorkflowAuthorizationError):
        asyncio.run(
            setup["orchestrator"].execute(
                workflow=denied_workflow,
                requested_by="soc-operator",
            )
        )

    events = setup["storage"].read_all()

    assert setup["agent"].run_count == 0
    assert len(events) == 1
    assert events[0].event_type == AuditEventType.POLICY_DECISION
    assert events[0].decision == AuditDecision.DENY
    assert events[0].reason_code == "CAPABILITY_DENIED"
    assert setup["storage"].verify_chain() is True


def test_audit_failure_prevents_agent_execution(
    integration_setup,
    monkeypatch,
):
    setup = integration_setup

    def fail_append(event):
        raise OSError("Audit storage unavailable")

    monkeypatch.setattr(
        setup["storage"],
        "append",
        fail_append,
    )

    with pytest.raises(AuthorizationAuditError):
        asyncio.run(
            setup["orchestrator"].execute(
                workflow=setup["workflow"],
                requested_by="soc-operator",
            )
        )

    assert setup["agent"].run_count == 0


def test_completion_audit_failure_is_propagated(
    integration_setup,
    monkeypatch,
):
    setup = integration_setup
    original_append = setup["storage"].append
    append_count = 0

    def fail_completion_append(event):
        nonlocal append_count
        append_count += 1

        if append_count == 3:
            raise OSError("Audit storage unavailable")

        return original_append(event)

    monkeypatch.setattr(
        setup["storage"],
        "append",
        fail_completion_append,
    )

    with pytest.raises(AuthorizationAuditError):
        asyncio.run(
            setup["orchestrator"].execute(
                workflow=setup["workflow"],
                requested_by="soc-operator",
            )
        )

    events = setup["storage"].read_all()

    assert setup["agent"].run_count == 1
    assert len(events) == 2
    assert events[0].event_type == AuditEventType.POLICY_DECISION
    assert events[1].event_type == AuditEventType.EXECUTION_STARTED
    assert setup["storage"].verify_chain() is True
