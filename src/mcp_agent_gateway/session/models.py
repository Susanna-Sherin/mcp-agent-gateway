"""Session models and chain rule decision structures for MCP Agent Gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


class SessionError(Exception):
    """Base exception for session-related errors."""


class SessionRoleMismatchError(SessionError):
    """Raised when an existing session is accessed with a conflicting caller role."""


class SessionStateError(SessionError):
    """Raised when session state is corrupted, missing, or inactive."""


class ChainEvaluationError(SessionError):
    """Raised when an error occurs during chain rule evaluation."""


@dataclass
class SessionCallSummary:
    """Minimal audit summary of an executed tool call in a session.

    Never retains raw arguments, tool outputs, document contents, email bodies,
    or other sensitive payloads.
    """

    sequence_number: int
    server_name: str
    tool_name: str
    outcome: str  # "success", "error", "denied"
    timestamp_utc: str

    def to_dict(self) -> dict[str, Any]:
        """Convert summary to serializable dictionary."""
        return asdict(self)


@dataclass
class SessionState:
    """Isolated state container for a single caller session."""

    session_id: str
    caller_role: str
    created_at_utc: str
    history: list[SessionCallSummary] = field(default_factory=list)
    taints: set[str] = field(default_factory=set)
    tool_counts: dict[str, int] = field(default_factory=dict)
    is_active: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert session state to dictionary representation."""
        return {
            "session_id": self.session_id,
            "caller_role": self.caller_role,
            "created_at_utc": self.created_at_utc,
            "history": [h.to_dict() for h in self.history],
            "taints": sorted(self.taints),
            "tool_counts": dict(self.tool_counts),
            "is_active": self.is_active,
        }


@dataclass
class ChainRuleDecision:
    """Result of evaluating tool invocation against session chain rules."""

    allowed: bool
    action: Literal["allow", "deny", "block"]
    rule_id: str | None
    reason_code: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Convert decision to dictionary representation."""
        return asdict(self)


def generate_session_timestamp_utc() -> str:
    """Generate ISO 8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()
