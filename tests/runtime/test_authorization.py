from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.audit.models import AuditDecision
from app.audit.service import AuditService
from app.audit.storage import AuditStorage
from app.runtime.authorization import (
    AuthorizationAuditError,
    AuthorizationService,
)
from app.runtime.context import AgentContext, EvidenceItem
from app.runtime.task import AgentTask
from app.security.identity import AgentIdentity


@pytest.fixture
def authorization_setup(tmp_path):
    now = datetime.now(timezone.utc)

    identity = AgentIdentity(
        agent_id="triage-agent",
        agent_type="triage",
        tenant_id="tenant-a",
        capabilities=("alert:read",),
    )

    task = AgentTask(
        agent_id="triage-agent",
        tenant_id="tenant-a",
        task_type="investigate",
        requested_by="orchestrator",
        resource_scope=("alerts:123",),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    context = AgentContext(
        task_id=task.task_id,
        agent_id="triage-agent",
        tenant_id="tenant-a",
        evidence=(
            EvidenceItem(
                evidence_id="evidence-001",
                evidence_type="alert",
                source="detection-engine",
                content={"alert_id": "123"},
            ),
        ),
        instructions="Investigate the security alert.",
    )

    storage = AuditStorage(
        file_path=str(tmp_path / "audit.jsonl")
    )
    audit_service = AuditService(storage)
    authorization_service = AuthorizationService(audit_service)

    return {
        "identity": identity,
        "task": task,
        "context": context,
        "storage": storage,
        "authorization_service": authorization_service,
        "now": now,
    }


def test_authorized_decision_is_audited(authorization_setup):
    setup = authorization_setup

    result = setup["authorization_service"].authorize(
        identity=setup["identity"],
        task=setup["task"],
        context=setup["context"],
        required_capabilities=("alert:read",),
        required_resources=("alerts:123",),
        correlation_id=uuid4(),
        now=setup["now"],
    )

    assert result.decision.allowed is True
    assert result.decision.reason_code == "AUTHORIZED"
    assert result.audit_event.decision == AuditDecision.ALLOW
    assert len(setup["storage"].read_all()) == 1
    assert setup["storage"].verify_chain() is True


def test_denied_decision_is_audited(authorization_setup):
    setup = authorization_setup

    result = setup["authorization_service"].authorize(
        identity=setup["identity"],
        task=setup["task"],
        context=setup["context"],
        required_capabilities=("alert:delete",),
        required_resources=("alerts:123",),
        correlation_id=uuid4(),
        now=setup["now"],
    )

    assert result.decision.allowed is False
    assert result.decision.reason_code == "CAPABILITY_DENIED"
    assert result.audit_event.decision == AuditDecision.DENY
    assert len(setup["storage"].read_all()) == 1
    assert setup["storage"].verify_chain() is True


def test_audit_failure_blocks_authorization(authorization_setup, monkeypatch):
    setup = authorization_setup

    def fail_append(event):
        raise OSError("Audit storage unavailable")

    monkeypatch.setattr(
        setup["storage"],
        "append",
        fail_append,
    )

    with pytest.raises(AuthorizationAuditError):
        setup["authorization_service"].authorize(
            identity=setup["identity"],
            task=setup["task"],
            context=setup["context"],
            required_capabilities=("alert:read",),
            required_resources=("alerts:123",),
            correlation_id=uuid4(),
            now=setup["now"],
        )
