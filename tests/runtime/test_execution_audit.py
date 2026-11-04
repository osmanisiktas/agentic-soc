from uuid import uuid4

import pytest

from app.audit.models import AuditEventType
from app.audit.service import AuditService
from app.audit.storage import AuditStorage


def test_execution_events_are_persisted_in_hash_chain(tmp_path):
    storage = AuditStorage(
        file_path=str(tmp_path / "audit.jsonl")
    )
    service = AuditService(storage)

    task_id = uuid4()
    correlation_id = uuid4()

    started = service.record_execution_event(
        event_type=AuditEventType.EXECUTION_STARTED,
        actor_id="triage-agent",
        actor_type="agent",
        tenant_id="tenant-001",
        task_id=task_id,
        action="execute_workflow_step",
        reason_code="EXECUTION_AUTHORIZED",
        correlation_id=correlation_id,
    )

    completed = service.record_execution_event(
        event_type=AuditEventType.EXECUTION_COMPLETED,
        actor_id="triage-agent",
        actor_type="agent",
        tenant_id="tenant-001",
        task_id=task_id,
        action="execute_workflow_step",
        reason_code="EXECUTION_SUCCEEDED",
        correlation_id=correlation_id,
    )

    events = storage.read_all()

    assert len(events) == 2
    assert events[0].event_type == AuditEventType.EXECUTION_STARTED
    assert events[1].event_type == AuditEventType.EXECUTION_COMPLETED

    assert events[0].task_id == task_id
    assert events[1].task_id == task_id

    assert events[0].correlation_id == correlation_id
    assert events[1].correlation_id == correlation_id

    assert started.event_id == events[0].event_id
    assert completed.event_id == events[1].event_id

    assert storage.verify_chain() is True


def test_policy_decision_cannot_be_recorded_as_execution_event(tmp_path):
    storage = AuditStorage(
        file_path=str(tmp_path / "audit.jsonl")
    )
    service = AuditService(storage)

    with pytest.raises(ValueError):
        service.record_execution_event(
            event_type=AuditEventType.POLICY_DECISION,
            actor_id="triage-agent",
            actor_type="agent",
            tenant_id="tenant-001",
            task_id=uuid4(),
            action="execute_workflow_step",
            reason_code="EXECUTION_AUTHORIZED",
            correlation_id=uuid4(),
        )
