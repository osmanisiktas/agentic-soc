from abc import ABC, abstractmethod

from app.runtime.context import AgentContext
from app.runtime.result import AgentResult
from app.runtime.task import AgentTask
from app.security.identity import AgentIdentity


class BaseAgent(ABC):
    """
    Common contract for all Agentic SOC agents.

    Agent identity is injected by the trusted platform,
    not selected by the agent at execution time.
    """

    def __init__(self, identity: AgentIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    @abstractmethod
    async def run(
        self,
        task: AgentTask,
        context: AgentContext,
    ) -> AgentResult:
        """
        Execute an assigned task and return a structured result.

        Authorization and execution boundaries are enforced
        by the Agent Runtime, not by the agent itself.
        """
        raise NotImplementedError
