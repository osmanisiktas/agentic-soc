import asyncio
from datetime import datetime, timezone

import pytest

from app.agents.base import BaseAgent
from app.agents.registry import AgentRegistry
from app.audit.models import AuditDecision, AuditEvent, AuditEventType
from app.runtime.authorization import AuthorizationResult
from app.runtime.context import AgentContext
from app.runtime.orchestrator import (
    AgentExecutionError,
    AgentExecutionTimeoutError,
    AgentResultValidationError,
    Orchestrator,
    WorkflowAuthorizationError,
)
from app.runtime.result import AgentExecutionStatus, AgentResult
from app.runtime.task import AgentTask
from app.runtime.workflow import WorkflowDefinition, WorkflowStep
from app.security.identity import AgentIdentity
from app.security.policy import PolicyDecision


class MockAgent(BaseAgent):
    def __init__(self, identity, behavior=None):
        super().__init__(identity)
        self.behavior = behavior
        self.run_count = 0
        self.received_task = None
        self.received_context = None

    async def run(
        self,
        task: AgentTask,
        context: AgentContext,
    ) -> AgentResult:
        self.run_count += 1
        self.received_task = task
        self.received_context = context

        if self.behavior is not None:
            return await self.behavior(task, context)

        return AgentResult(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            agent_id=task.agent_id,
            tenant_id=task.tenant_id,
            status=AgentExecutionStatus.SUCCESS,
            summary="Alert triage completed.",
            confidence=0.95,
        )


class MockAuthorizationService:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = 0
        self.execution_events = []

    def authorize(
        self,
        *,
        identity,
        task,
        context,
        required_capabilities,
        required_resources,
    ):
        self.calls += 1

        decision = PolicyDecision(
            allowed=self.allowed,
            reason_code="AUTHORIZED" if self.allowed else "CAPABILITY_DENIED",
        )

        audit_event = AuditEvent(
            actor_id=identity.agent_id,
            actor_type=identity.agent_type,
            tenant_id=identity.tenant_id,
            task_id=task.task_id,
            action=task.task_type,
            decision=(
                AuditDecision.ALLOW
                if self.allowed
                else AuditDecision.DENY
            ),
            reason_code=decision.reason_code,
            correlation_id=task.correlation_id,
        )

        return AuthorizationResult(
            decision=decision,
            audit_event=audit_event,
        )

    def record_execution_event(
        self,
        *,
        event_type,
        identity,
        task,
        reason_code,
        evidence_ids=(),
    ):
        event = AuditEvent(
            event_type=event_type,
            actor_id=identity.agent_id,
            actor_type=identity.agent_type,
            tenant_id=identity.tenant_id,
            task_id=task.task_id,
            action=task.task_type,
            reason_code=reason_code,
            evidence_ids=evidence_ids,
            correlation_id=task.correlation_id,
        )
        self.execution_events.append(event)
        return event


@pytest.fixture
def identity():
    return AgentIdentity(
        agent_id="triage-agent",
        agent_type="triage",
        tenant_id="tenant-a",
        capabilities=("alert:read",),
    )


@pytest.fixture
def workflow():
    step = WorkflowStep(
        step_id="triage-step",
        agent_id="triage-agent",
        task_type="alert_triage",
        required_capabilities=("alert:read",),
        required_resources=("alerts:tenant-a",),
        instructions="Analyze the supplied alert.",
        max_runtime_seconds=30,
    )

    return WorkflowDefinition(
        tenant_id="tenant-a",
        name="Alert Triage",
        steps=(step,),
        max_runtime_seconds=60,
    )


def create_orchestrator(agent, authorization_service):
    registry = AgentRegistry()
    registry.register(agent)

    return Orchestrator(
        registry=registry,
        authorization_service=authorization_service,
    )


def test_authorized_workflow_executes_agent(identity, workflow):
    agent = MockAgent(identity)
    authorization = MockAuthorizationService()
    orchestrator = create_orchestrator(agent, authorization)

    execution = asyncio.run(
        orchestrator.execute(
            workflow=workflow,
            requested_by="soc-operator",
        )
    )

    assert len(execution.results) == 1
    assert execution.results[0].status == AgentExecutionStatus.SUCCESS
    assert agent.run_count == 1
    assert authorization.calls == 1
    assert [
        event.event_type for event in authorization.execution_events
    ] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_COMPLETED,
    ]


def test_correlation_id_is_propagated(identity, workflow):
    agent = MockAgent(identity)
    orchestrator = create_orchestrator(
        agent,
        MockAuthorizationService(),
    )

    execution = asyncio.run(
        orchestrator.execute(
            workflow=workflow,
            requested_by="soc-operator",
        )
    )

    result = execution.results[0]

    assert result.correlation_id == execution.correlation_id
    assert agent.received_task.correlation_id == execution.correlation_id
    assert agent.received_context.correlation_id == execution.correlation_id


def test_denied_workflow_does_not_execute_agent(identity, workflow):
    agent = MockAgent(identity)
    authorization = MockAuthorizationService(allowed=False)
    orchestrator = create_orchestrator(agent, authorization)

    with pytest.raises(WorkflowAuthorizationError):
        asyncio.run(
            orchestrator.execute(
                workflow=workflow,
                requested_by="soc-operator",
            )
        )

    assert agent.run_count == 0
    assert authorization.calls == 1
    assert authorization.execution_events == []


def test_mismatched_result_identity_is_rejected(identity, workflow):
    async def invalid_behavior(task, context):
        return AgentResult(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            agent_id=task.agent_id,
            tenant_id="tenant-b",
            status=AgentExecutionStatus.SUCCESS,
            summary="Invalid tenant result.",
            confidence=0.9,
        )

    agent = MockAgent(identity, behavior=invalid_behavior)
    authorization = MockAuthorizationService()
    orchestrator = create_orchestrator(agent, authorization)

    with pytest.raises(AgentResultValidationError):
        asyncio.run(
            orchestrator.execute(
                workflow=workflow,
                requested_by="soc-operator",
            )
        )

    assert [
        event.event_type for event in authorization.execution_events
    ] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_FAILED,
    ]


def test_agent_timeout_is_enforced(identity):
    async def slow_behavior(task, context):
        await asyncio.sleep(2)
        return AgentResult(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            agent_id=task.agent_id,
            tenant_id=task.tenant_id,
            status=AgentExecutionStatus.SUCCESS,
            summary="Completed.",
            confidence=0.9,
        )

    agent = MockAgent(identity, behavior=slow_behavior)
    step = WorkflowStep(
        step_id="timeout-step",
        agent_id="triage-agent",
        task_type="alert_triage",
        required_capabilities=("alert:read",),
        required_resources=("alerts:tenant-a",),
        instructions="Analyze the supplied alert.",
        max_runtime_seconds=1,
    )
    short_workflow = WorkflowDefinition(
        tenant_id="tenant-a",
        name="Timeout Test",
        steps=(step,),
        max_runtime_seconds=10,
    )
    authorization = MockAuthorizationService()
    orchestrator = create_orchestrator(agent, authorization)

    with pytest.raises(AgentExecutionTimeoutError):
        asyncio.run(
            orchestrator.execute(
                workflow=short_workflow,
                requested_by="soc-operator",
            )
        )

    assert [
        event.event_type for event in authorization.execution_events
    ] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_TIMED_OUT,
    ]


def test_agent_exception_is_wrapped(identity, workflow):
    async def failing_behavior(task, context):
        raise RuntimeError("Internal agent failure")

    agent = MockAgent(identity, behavior=failing_behavior)
    authorization = MockAuthorizationService()
    orchestrator = create_orchestrator(agent, authorization)

    with pytest.raises(AgentExecutionError):
        asyncio.run(
            orchestrator.execute(
                workflow=workflow,
                requested_by="soc-operator",
            )
        )

    assert [
        event.event_type for event in authorization.execution_events
    ] == [
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_FAILED,
    ]


def test_unknown_evidence_reference_is_rejected(identity, workflow):
    async def invalid_evidence_behavior(task, context):
        return AgentResult(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            agent_id=task.agent_id,
            tenant_id=task.tenant_id,
            status=AgentExecutionStatus.SUCCESS,
            summary="Analysis completed.",
            confidence=0.9,
            evidence_ids=("unknown-evidence",),
        )

    agent = MockAgent(identity, behavior=invalid_evidence_behavior)
    authorization = MockAuthorizationService()
    orchestrator = create_orchestrator(agent, authorization)

    with pytest.raises(AgentResultValidationError):
        asyncio.run(
            orchestrator.execute(
                workflow=workflow,
                requested_by="soc-operator",
            )
        )

    assert authorization.execution_events[-1].event_type == (
        AuditEventType.EXECUTION_FAILED
    )
