"""Policy engine module for MCP Agent Gateway.

Responsible for declarative policy evaluation, role-based access control,
tool authorization rules, and execution constraints.
"""

from mcp_agent_gateway.policy.evaluator import PolicyConfigError, PolicyEngine
from mcp_agent_gateway.policy.models import (
    ArgumentConstraint,
    PolicyConfig,
    PolicyDecision,
    PolicyRule,
    RoleDefinition,
)

__all__ = [
    "PolicyEngine",
    "PolicyConfig",
    "PolicyRule",
    "PolicyDecision",
    "ArgumentConstraint",
    "RoleDefinition",
    "PolicyConfigError",
]
