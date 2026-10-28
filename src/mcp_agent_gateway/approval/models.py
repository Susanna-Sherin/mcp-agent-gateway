"""Data models and cryptographic request fingerprinting for approval queue."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

ApprovalStatusType = Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"]


@dataclass
class ApprovalRequest:
    """Structured representation of a tool call requiring human authorization."""

    approval_id: str
    request_hash: str
    session_id: str
    caller_role: str
    server_name: str
    tool_name: str
    arguments_sanitized: dict[str, Any]
    status: ApprovalStatusType
    created_at_utc: str
    expires_at_utc: str
    reviewed_at_utc: str | None = None
    reviewed_by: str | None = None
    review_decision_reason: str | None = None
    consumed_at_utc: str | None = None
    consumed_by_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert approval request to serializable dictionary."""
        return asdict(self)


def generate_approval_id() -> str:
    """Generate an unpredictable, cryptographically random approval identifier."""
    return f"appr_{secrets.token_urlsafe(16)}"


def generate_approval_timestamp_utc() -> str:
    """Generate ISO 8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


def compute_request_hash(
    session_id: str,
    caller_role: str,
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    """Compute deterministic SHA-256 fingerprint binding the exact invocation request.

    Binds session, trusted caller role, server, tool, and canonical sorted arguments.
    """
    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    payload = f"{session_id}|{caller_role}|{server_name}|{tool_name}|{canonical_args}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
