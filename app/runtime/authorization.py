from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.audit.models import AuditEvent, AuditEventType
from app.audit.service import AuditService
from app.runtime.context import AgentContext
from app.runtime.task import AgentTask
from app.security.identity import AgentIdentity
from app.security.policy import PolicyDecision, evaluate_task


class AuthorizationAuditError(RuntimeError):
    """Raised when an authorization or execution event cannot be audited."""


@dataclass(frozen=True)
class AuthorizationResult:
    decision: PolicyDecision
    audit_event: AuditEvent


class AuthorizationService:
    """
    Coordinates policy evaluation and mandatory audit persistence.

    No authorization result is returned unless its audit event
    has been successfully persisted.
    """

    def __init__(self, audit_service: AuditService) -> None:
        self._audit_service = audit_service

    def authorize(
        self,
        *,
        identity: AgentIdentity,
        task: AgentTask,
        context: AgentContext,
        required_capabilities: tuple[str, ...],
        required_resources: tuple[str, ...],
        now: datetime | None = None,
    ) -> AuthorizationResult:
        decision = evaluate_task(
            identity=identity,
            task=task,
            context=context,
            required_capabilities=required_capabilities,
            required_resources=required_resources,
            now=now,
        )

        try:
            audit_event = self._audit_service.record_policy_decision(
                actor_id=identity.agent_id,
                actor_type=identity.agent_type,
                tenant_id=identity.tenant_id,
                task_id=task.task_id,
                action=task.task_type,
                decision=decision,
                evidence_ids=tuple(
                    item.evidence_id for item in context.evidence
                ),
                correlation_id=task.correlation_id,
            )
        except Exception as exc:
            raise AuthorizationAuditError(
                "Authorization aborted because the audit event "
                "could not be persisted."
            ) from exc

        return AuthorizationResult(
            decision=decision,
            audit_event=audit_event,
        )

    def record_execution_event(
        self,
        *,
        event_type: AuditEventType,
        identity: AgentIdentity,
        task: AgentTask,
        reason_code: str,
        evidence_ids: tuple[str, ...] = (),
    ) -> AuditEvent:
        try:
            return self._audit_service.record_execution_event(
                event_type=event_type,
                actor_id=identity.agent_id,
                actor_type=identity.agent_type,
                tenant_id=identity.tenant_id,
                task_id=task.task_id,
                action=task.task_type,
                reason_code=reason_code,
                correlation_id=task.correlation_id,
                evidence_ids=evidence_ids,
            )
        except Exception as exc:
            raise AuthorizationAuditError(
                "Execution lifecycle event could not be persisted."
            ) from exc
