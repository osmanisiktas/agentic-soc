from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.runtime.context import AgentContext, EvidenceItem


def create_evidence(**overrides):
    values = {
        "evidence_id": "evidence-001",
        "evidence_type": "alert",
        "source": "detection-engine",
        "tenant_id": "tenant-a",
        "content": {"alert_id": "123"},
    }
    values.update(overrides)
    return EvidenceItem(**values)


def create_context(evidence=()):
    return AgentContext(
        task_id=uuid4(),
        correlation_id=uuid4(),
        agent_id="triage-agent",
        tenant_id="tenant-a",
        evidence=evidence,
        instructions="Investigate the security alert.",
    )


def test_evidence_content_is_deeply_immutable():
    evidence = create_evidence(
        content={
            "severity": "high",
            "metadata": {"source_ip": "192.0.2.10"},
            "tags": ["suspicious", "network"],
        }
    )

    with pytest.raises(TypeError):
        evidence.content["severity"] = "critical"

    with pytest.raises(TypeError):
        evidence.content["metadata"]["source_ip"] = "198.51.100.10"

    with pytest.raises(TypeError):
        evidence.content["tags"][0] = "modified"


def test_evidence_content_hash_is_stable():
    first = create_evidence(
        content={"alert_id": "123", "severity": "high"}
    )
    second = create_evidence(
        content={"severity": "high", "alert_id": "123"}
    )

    assert first.content_hash == second.content_hash


def test_evidence_content_hash_detects_tampering():
    evidence = create_evidence()

    with pytest.raises(ValueError):
        evidence.verify_integrity(
            {"alert_id": "999"}
        )


def test_evidence_requires_valid_trust_level():
    with pytest.raises(ValidationError):
        create_evidence(trust_level="trusted-by-agent")


def test_context_rejects_duplicate_evidence_ids():
    first = create_evidence()
    second = create_evidence(evidence_id="evidence-002")

    with pytest.raises(ValidationError):
        create_context(evidence=(first, second, first))


def test_context_rejects_evidence_from_another_tenant():
    evidence = create_evidence(tenant_id="tenant-b")

    with pytest.raises(ValidationError):
        create_context(evidence=(evidence,))


def test_evidence_requires_timezone_aware_collection_time():
    with pytest.raises(ValidationError):
        create_evidence(
            collected_at=datetime(2026, 1, 1, 12, 0, 0)
        )
