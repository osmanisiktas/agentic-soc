from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.runtime.result import AgentExecutionStatus, AgentResult


def test_agent_result_accepts_correlation_id():
    task_id = uuid4()
    correlation_id = uuid4()

    result = AgentResult(
        task_id=task_id,
        correlation_id=correlation_id,
        agent_id="triage-agent",
        tenant_id="tenant-a",
        status=AgentExecutionStatus.SUCCESS,
        summary="Authentication activity analyzed.",
        confidence=0.95,
    )

    assert result.task_id == task_id
    assert result.correlation_id == correlation_id


def test_agent_result_requires_correlation_id():
    with pytest.raises(ValidationError):
        AgentResult(
            task_id=uuid4(),
            agent_id="triage-agent",
            tenant_id="tenant-a",
            status=AgentExecutionStatus.SUCCESS,
            summary="Authentication activity analyzed.",
            confidence=0.95,
        )


def test_agent_result_is_immutable():
    result = AgentResult(
        task_id=uuid4(),
        correlation_id=uuid4(),
        agent_id="triage-agent",
        tenant_id="tenant-a",
        status=AgentExecutionStatus.SUCCESS,
        summary="Authentication activity analyzed.",
        confidence=0.95,
    )

    with pytest.raises(ValidationError):
        result.correlation_id = uuid4()

