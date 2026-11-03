from dataclasses import dataclass
from datetime import datetime, timezone

from app.runtime.context import AgentContext
from app.runtime.task import AgentTask
from app.security.identity import AgentIdentity


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str


def evaluate_task(
    identity: AgentIdentity,
    task: AgentTask,
    context: AgentContext,
    required_capabilities: tuple[str, ...],
    required_resources: tuple[str, ...],
    now: datetime | None = None,
) -> PolicyDecision:

    current_time = now or datetime.now(timezone.utc)

    # 1. Validate policy evaluation time
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        return PolicyDecision(False, "INVALID_POLICY_TIME")

    # 2. Validate required capabilities
    if not required_capabilities:
        return PolicyDecision(False, "NO_REQUIRED_CAPABILITIES")

    if any(
        not capability.strip() or "*" in capability
        for capability in required_capabilities
    ):
        return PolicyDecision(False, "INVALID_REQUIRED_CAPABILITIES")

    # 3. Validate required resources
    if not required_resources:
        return PolicyDecision(False, "NO_REQUIRED_RESOURCES")

    if any(
        not resource.strip() or "*" in resource
        for resource in required_resources
    ):
        return PolicyDecision(False, "INVALID_REQUIRED_RESOURCES")

    # 4. Verify agent identity
    if identity.agent_id != task.agent_id:
        return PolicyDecision(False, "AGENT_ID_MISMATCH")

    if identity.agent_id != context.agent_id:
        return PolicyDecision(False, "CONTEXT_AGENT_MISMATCH")

    # 5. Verify tenant isolation
    if identity.tenant_id != task.tenant_id:
        return PolicyDecision(False, "TASK_TENANT_MISMATCH")

    if identity.tenant_id != context.tenant_id:
        return PolicyDecision(False, "CONTEXT_TENANT_MISMATCH")

    # 6. Verify task-context binding
    if task.task_id != context.task_id:
        return PolicyDecision(False, "TASK_CONTEXT_MISMATCH")

    # 7. Verify task validity
    if task.created_at > current_time:
        return PolicyDecision(False, "TASK_NOT_YET_VALID")

    if task.expires_at <= current_time:
        return PolicyDecision(False, "TASK_EXPIRED")

    # 8. Verify capabilities
    if not set(required_capabilities).issubset(
        set(identity.capabilities)
    ):
        return PolicyDecision(False, "CAPABILITY_DENIED")

    # 9. Verify resource scope
    if not set(required_resources).issubset(
        set(task.resource_scope)
    ):
        return PolicyDecision(False, "RESOURCE_SCOPE_DENIED")

    # 10. Explicit allow
    return PolicyDecision(True, "AUTHORIZED")
