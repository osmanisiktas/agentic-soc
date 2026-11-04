from app.agents.base import BaseAgent


class AgentNotFoundError(LookupError):
    """Raised when an agent cannot be resolved for the requested tenant."""


class AgentRegistry:
    """
    Trusted tenant-scoped registry for platform-managed agents.

    Registration must only be performed by trusted platform components.
    """

    def __init__(self) -> None:
        self._agents: dict[tuple[str, str], BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        identity = agent.identity
        key = (identity.tenant_id, identity.agent_id)

        if key in self._agents:
            raise ValueError("Agent is already registered for this tenant.")

        self._agents[key] = agent

    def resolve(
        self,
        *,
        agent_id: str,
        tenant_id: str,
    ) -> BaseAgent:
        key = (tenant_id, agent_id)
        agent = self._agents.get(key)

        if agent is None:
            raise AgentNotFoundError(
                "Agent is not available for the requested tenant."
            )

        return agent

    def contains(
        self,
        *,
        agent_id: str,
        tenant_id: str,
    ) -> bool:
        return (tenant_id, agent_id) in self._agents
