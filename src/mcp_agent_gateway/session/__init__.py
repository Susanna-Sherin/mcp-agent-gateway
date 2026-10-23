"""Session state module for MCP Agent Gateway.

Responsible for tracking agent session lifecycles, conversation context,
per-session permissions, chain rules, and transient execution state.
"""

from mcp_agent_gateway.session.manager import SessionManager
from mcp_agent_gateway.session.models import (
    ChainEvaluationError,
    ChainRuleDecision,
    SessionCallSummary,
    SessionError,
    SessionRoleMismatchError,
    SessionState,
    SessionStateError,
    generate_session_timestamp_utc,
)
from mcp_agent_gateway.session.rules import ChainRuleEngine

__all__ = [
    "ChainEvaluationError",
    "ChainRuleDecision",
    "ChainRuleEngine",
    "SessionCallSummary",
    "SessionError",
    "SessionManager",
    "SessionRoleMismatchError",
    "SessionState",
    "SessionStateError",
    "generate_session_timestamp_utc",
]
