from uuid import UUID

from app.audit.models import (
    AuditDecision,
    AuditEvent,
    AuditEventType,
)
from app.audit.storage import AuditStorage
from app.security.policy import PolicyDecision


class AuditService:
    def __init__(self, storage: AuditStorage) -> None:
        self._storage = storage

    def record_policy_decision(
        self,
        *,
        actor_id: str,
        actor_type: str,
        tenant_id: str,
        task_id: UUID,
        action: str,
        decision: PolicyDecision,
        evidence_ids: tuple[str, ...] = (),
        correlation_id: UUID,
    ) -> AuditEvent:
        audit_event = AuditEvent(
            event_type=AuditEventType.POLICY_DECISION,
            actor_id=actor_id,
            actor_type=actor_type,
            tenant_id=tenant_id,
            task_id=task_id,
            action=action,
            decision=(
                AuditDecision.ALLOW
                if decision.allowed
                else AuditDecision.DENY
            ),
            reason_code=decision.reason_code,
            evidence_ids=evidence_ids,
            correlation_id=correlation_id,
        )

        self._storage.append(audit_event)
        return audit_event

    def record_execution_event(
        self,
        *,
        event_type: AuditEventType,
        actor_id: str,
        actor_type: str,
        tenant_id: str,
        task_id: UUID,
        action: str,
        reason_code: str,
        correlation_id: UUID,
        evidence_ids: tuple[str, ...] = (),
    ) -> AuditEvent:
        if event_type == AuditEventType.POLICY_DECISION:
            raise ValueError(
                "Use record_policy_decision for policy events."
            )

        audit_event = AuditEvent(
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            tenant_id=tenant_id,
            task_id=task_id,
            action=action,
            reason_code=reason_code,
            evidence_ids=evidence_ids,
            correlation_id=correlation_id,
        )

        self._storage.append(audit_event)
        return audit_event
