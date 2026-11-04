import pytest

from app.agents.base import BaseAgent
from app.agents.registry import AgentNotFoundError, AgentRegistry
from app.runtime.result import AgentResult
from app.runtime.task import AgentTask
from app.runtime.context import AgentContext
from app.security.identity import AgentIdentity


class MockAgent(BaseAgent):
    async def run(
        self,
        task: AgentTask,
        context: AgentContext,
    ) -> AgentResult:
        raise NotImplementedError


@pytest.fixture
def registered_agent():
    identity = AgentIdentity(
        agent_id="triage-agent",
        agent_type="triage",
        tenant_id="tenant-a",
        capabilities=("alert:read",),
    )

    return MockAgent(identity)


def create_agent(tenant_id: str) -> MockAgent:
    identity = AgentIdentity(
        agent_id="triage-agent",
        agent_type="triage",
        tenant_id=tenant_id,
        capabilities=("alert:read",),
    )
    return MockAgent(identity)


def test_register_and_resolve_agent(registered_agent):
    registry = AgentRegistry()
    registry.register(registered_agent)

    resolved = registry.resolve(
        agent_id="triage-agent",
        tenant_id="tenant-a",
    )

    assert resolved is registered_agent


def test_duplicate_agent_registration_is_rejected(registered_agent):
    registry = AgentRegistry()
    registry.register(registered_agent)

    with pytest.raises(ValueError):
        registry.register(registered_agent)


def test_cross_tenant_agent_resolution_is_rejected(registered_agent):
    registry = AgentRegistry()
    registry.register(registered_agent)

    with pytest.raises(AgentNotFoundError):
        registry.resolve(
            agent_id="triage-agent",
            tenant_id="tenant-b",
        )


def test_unknown_agent_resolution_is_rejected():
    registry = AgentRegistry()

    with pytest.raises(AgentNotFoundError):
        registry.resolve(
            agent_id="unknown-agent",
            tenant_id="tenant-a",
        )


def test_registry_contains_registered_agent(registered_agent):
    registry = AgentRegistry()
    registry.register(registered_agent)

    assert registry.contains(
        agent_id="triage-agent",
        tenant_id="tenant-a",
    ) is True

    assert registry.contains(
        agent_id="triage-agent",
        tenant_id="tenant-b",
    ) is False


def test_same_agent_id_can_be_registered_for_different_tenants():
    registry = AgentRegistry()
    tenant_a_agent = create_agent("tenant-a")
    tenant_b_agent = create_agent("tenant-b")

    registry.register(tenant_a_agent)
    registry.register(tenant_b_agent)

    assert registry.resolve(
        agent_id="triage-agent",
        tenant_id="tenant-a",
    ) is tenant_a_agent

    assert registry.resolve(
        agent_id="triage-agent",
        tenant_id="tenant-b",
    ) is tenant_b_agent
