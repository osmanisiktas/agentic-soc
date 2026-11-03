from uuid import UUID

from app.audit.models import AuditDecision, AuditEvent
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

        # Fail closed: audit kaydı yazılamazsa çağırana hata döner.
        self._storage.append(audit_event)

        return audit_event
