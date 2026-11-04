from app.agents.base import BaseAgent


class AgentNotFoundError(LookupError):
    """Raised when an agent cannot be resolved for the requested tenant."""


class AgentRegistry:
    """
    Trusted in-memory registry for platform-managed agents.

    Registration must only be performed by trusted platform components.
    """

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        agent_id = agent.identity.agent_id

        if agent_id in self._agents:
            raise ValueError(f"Agent is already registered: {agent_id}")

        self._agents[agent_id] = agent

    def resolve(
        self,
        *,
        agent_id: str,
        tenant_id: str,
    ) -> BaseAgent:
        agent = self._agents.get(agent_id)

        if agent is None or agent.identity.tenant_id != tenant_id:
            raise AgentNotFoundError(
                "Agent is not available for the requested tenant."
            )

        return agent

    def contains(self, agent_id: str) -> bool:
        return agent_id in self._agents
