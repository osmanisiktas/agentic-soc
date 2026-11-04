import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.agents.registry import AgentRegistry
from app.audit.models import AuditEvent, AuditEventType
from app.runtime.authorization import (
    AuthorizationAuditError,
    AuthorizationService,
)
from app.runtime.context import AgentContext, EvidenceItem
from app.runtime.result import AgentExecutionStatus, AgentResult
from app.runtime.task import AgentTask
from app.runtime.workflow import WorkflowDefinition


class WorkflowAuthorizationError(PermissionError):
    """Raised when a workflow step is denied by the policy engine."""


class WorkflowTimeoutError(TimeoutError):
    """Raised when the workflow exceeds its execution time limit."""


class AgentExecutionTimeoutError(TimeoutError):
    """Raised when an agent exceeds its assigned execution time."""


class AgentExecutionError(RuntimeError):
    """Raised when an agent fails during execution."""


class AgentResultValidationError(ValueError):
    """Raised when an agent returns an invalid or untrusted result."""


class EvidenceValidationError(ValueError):
    """Raised when evidence fails tenant or integrity validation."""


@dataclass(frozen=True)
class WorkflowExecutionResult:
    correlation_id: UUID
    results: tuple[AgentResult, ...]


@dataclass(frozen=True)
class StepExecution:
    result: AgentResult
    authorization_audit: AuditEvent


class Orchestrator:
    """
    Trusted workflow execution coordinator.

    The orchestrator creates tasks and contexts, resolves trusted agents,
    validates evidence, requests authorization, audits execution lifecycle
    events, and validates agent results.
    """

    def __init__(
        self,
        *,
        registry: AgentRegistry,
        authorization_service: AuthorizationService,
    ) -> None:
        self._registry = registry
        self._authorization_service = authorization_service

    async def execute(
        self,
        *,
        workflow: WorkflowDefinition,
        requested_by: str,
        evidence: tuple[EvidenceItem, ...] = (),
    ) -> WorkflowExecutionResult:
        if not requested_by.strip():
            raise ValueError("A trusted requester identity is required.")

        self._validate_evidence(
            evidence=evidence,
            tenant_id=workflow.tenant_id,
        )

        correlation_id = uuid4()
        workflow_deadline = (
            asyncio.get_running_loop().time()
            + workflow.max_runtime_seconds
        )

        results: list[AgentResult] = []

        for step in workflow.steps:
            remaining = (
                workflow_deadline
                - asyncio.get_running_loop().time()
            )

            if remaining <= 0:
                raise WorkflowTimeoutError(
                    "Workflow execution time limit exceeded."
                )

            timeout_seconds = min(
                step.max_runtime_seconds,
                remaining,
            )

            step_execution = await self._execute_step(
                workflow=workflow,
                step=step,
                requested_by=requested_by,
                correlation_id=correlation_id,
                evidence=evidence,
                timeout_seconds=timeout_seconds,
            )

            results.append(step_execution.result)

            if step_execution.result.status in (
                AgentExecutionStatus.FAILED,
                AgentExecutionStatus.REJECTED,
            ):
                break

        return WorkflowExecutionResult(
            correlation_id=correlation_id,
            results=tuple(results),
        )

    async def _execute_step(
        self,
        *,
        workflow: WorkflowDefinition,
        step,
        requested_by: str,
        correlation_id: UUID,
        evidence: tuple[EvidenceItem, ...],
        timeout_seconds: float,
    ) -> StepExecution:
        agent = self._registry.resolve(
            agent_id=step.agent_id,
            tenant_id=workflow.tenant_id,
        )

        identity = agent.identity
        created_at = datetime.now(timezone.utc)

        task = AgentTask(
            correlation_id=correlation_id,
            agent_id=identity.agent_id,
            tenant_id=workflow.tenant_id,
            task_type=step.task_type,
            requested_by=requested_by,
            resource_scope=step.required_resources,
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=timeout_seconds),
            max_runtime_seconds=max(1, int(timeout_seconds)),
        )

        context = AgentContext(
            task_id=task.task_id,
            correlation_id=correlation_id,
            agent_id=identity.agent_id,
            tenant_id=workflow.tenant_id,
            evidence=evidence,
            instructions=step.instructions,
        )

        authorization = self._authorization_service.authorize(
            identity=identity,
            task=task,
            context=context,
            required_capabilities=step.required_capabilities,
            required_resources=step.required_resources,
        )

        if not authorization.decision.allowed:
            raise WorkflowAuthorizationError(
                f"Workflow step denied: {authorization.decision.reason_code}"
            )

        evidence_ids = tuple(
            item.evidence_id for item in context.evidence
        )

        self._authorization_service.record_execution_event(
            event_type=AuditEventType.EXECUTION_STARTED,
            identity=identity,
            task=task,
            reason_code="EXECUTION_AUTHORIZED",
            evidence_ids=evidence_ids,
        )

        try:
            result = await asyncio.wait_for(
                agent.run(task, context),
                timeout=timeout_seconds,
            )

            self._validate_result(
                result=result,
                task=task,
                evidence=evidence,
            )

        except asyncio.TimeoutError as exc:
            self._authorization_service.record_execution_event(
                event_type=AuditEventType.EXECUTION_TIMED_OUT,
                identity=identity,
                task=task,
                reason_code="AGENT_EXECUTION_TIMEOUT",
                evidence_ids=evidence_ids,
            )
            raise AgentExecutionTimeoutError(
                "Agent execution exceeded its time limit."
            ) from exc

        except AuthorizationAuditError:
            raise

        except Exception as exc:
            self._authorization_service.record_execution_event(
                event_type=AuditEventType.EXECUTION_FAILED,
                identity=identity,
                task=task,
                reason_code="AGENT_EXECUTION_FAILED",
                evidence_ids=evidence_ids,
            )

            if isinstance(exc, AgentResultValidationError):
                raise

            raise AgentExecutionError(
                "Agent execution failed."
            ) from exc

        if result.status in (
            AgentExecutionStatus.FAILED,
            AgentExecutionStatus.REJECTED,
        ):
            self._authorization_service.record_execution_event(
                event_type=AuditEventType.EXECUTION_FAILED,
                identity=identity,
                task=task,
                reason_code=f"AGENT_RESULT_{result.status.value.upper()}",
                evidence_ids=evidence_ids,
            )
        else:
            self._authorization_service.record_execution_event(
                event_type=AuditEventType.EXECUTION_COMPLETED,
                identity=identity,
                task=task,
                reason_code="EXECUTION_SUCCEEDED",
                evidence_ids=evidence_ids,
            )

        return StepExecution(
            result=result,
            authorization_audit=authorization.audit_event,
        )

    @staticmethod
    def _validate_evidence(
        *,
        evidence: tuple[EvidenceItem, ...],
        tenant_id: str,
    ) -> None:
        for item in evidence:
            if item.tenant_id != tenant_id:
                raise EvidenceValidationError(
                    "Evidence tenant does not match workflow tenant."
                )

            try:
                item.verify_integrity()
            except (TypeError, ValueError) as exc:
                raise EvidenceValidationError(
                    "Evidence integrity validation failed."
                ) from exc

    @staticmethod
    def _validate_result(
        *,
        result: AgentResult,
        task: AgentTask,
        evidence: tuple[EvidenceItem, ...],
    ) -> None:
        if not isinstance(result, AgentResult):
            raise AgentResultValidationError(
                "Agent returned an unsupported result type."
            )

        if result.task_id != task.task_id:
            raise AgentResultValidationError("Task ID mismatch.")

        if result.correlation_id != task.correlation_id:
            raise AgentResultValidationError("Correlation ID mismatch.")

        if result.agent_id != task.agent_id:
            raise AgentResultValidationError("Agent ID mismatch.")

        if result.tenant_id != task.tenant_id:
            raise AgentResultValidationError("Tenant ID mismatch.")

        allowed_evidence_ids = {
            item.evidence_id for item in evidence
        }

        if not set(result.evidence_ids).issubset(allowed_evidence_ids):
            raise AgentResultValidationError(
                "Agent result references unknown evidence."
            )
