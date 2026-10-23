"""Thread-safe in-memory session manager for MCP Agent Gateway."""

from __future__ import annotations

import asyncio
import logging
import secrets
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_agent_gateway.session.models import SessionCallSummary, SessionState

from mcp_agent_gateway.session.models import (
    SessionCallSummary,
    SessionRoleMismatchError,
    SessionState,
    SessionStateError,
    generate_session_timestamp_utc,
)

logger = logging.getLogger(__name__)


class SessionManager:
    """Thread-safe manager for tracking isolated agent execution sessions.

    Guarantees:
    1. Unpredictable cryptographically secure session IDs when not caller-supplied.
    2. Strict one-to-one binding between a session and an authorized caller role.
    3. Complete state isolation across sessions (zero cross-session taint leakage).
    4. Minimal history recording: sequence number, server, tool, outcome, timestamp.
    5. Atomic, thread-safe sequence numbering and invocation counting.
    6. Tombstoning of deleted session IDs to prevent resurrection attacks.
    7. Per-session event-loop-safe serialization locks for async gateway calls.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._revoked_session_ids: set[str] = set()
        self._async_locks: dict[tuple[str, asyncio.AbstractEventLoop], asyncio.Lock] = {}
        self._lock = threading.RLock()

    @staticmethod
    def generate_session_id() -> str:
        """Generate an unpredictable, cryptographically random session identifier."""
        return f"sess_{secrets.token_urlsafe(16)}"

    def get_or_create_session(
        self,
        session_id: str | None,
        caller_role: str,
    ) -> tuple[SessionState, bool]:
        """Resolve an existing session or initialize a new isolated session.

        Args:
            session_id: Optional caller-supplied session identifier.
            caller_role: Trusted caller role requesting the session.

        Returns:
            Tuple of (SessionState, is_new: bool).

        Raises:
            SessionStateError: If the session has been revoked/deleted or is inactive.
            SessionRoleMismatchError: If an existing session is bound to a different role.
        """
        with self._lock:
            if not session_id:
                sid = self.generate_session_id()
                state = SessionState(
                    session_id=sid,
                    caller_role=caller_role,
                    created_at_utc=generate_session_timestamp_utc(),
                )
                self._sessions[sid] = state
                return state, True

            if session_id in self._revoked_session_ids:
                raise SessionStateError(
                    f"Session '{session_id}' has been deleted/revoked and cannot be reused."
                )

            if session_id in self._sessions:
                existing = self._sessions[session_id]
                if not existing.is_active:
                    raise SessionStateError(
                        f"Session '{session_id}' is inactive and cannot accept further invocations."
                    )
                if existing.caller_role != caller_role:
                    raise SessionRoleMismatchError(
                        f"Session '{session_id}' is bound to role '{existing.caller_role}', "
                        f"rejecting attempt to access under conflicting role '{caller_role}'."
                    )
                return existing, False

            # Supplied session_id does not exist and is not revoked; create it bound to caller_role
            state = SessionState(
                session_id=session_id,
                caller_role=caller_role,
                created_at_utc=generate_session_timestamp_utc(),
            )
            self._sessions[session_id] = state
            return state, True

    def get_session(self, session_id: str) -> SessionState | None:
        """Retrieve a session by identifier without creating or modifying it."""
        with self._lock:
            return self._sessions.get(session_id)

    def is_revoked(self, session_id: str) -> bool:
        """Check if a session identifier has been revoked/tombstoned."""
        with self._lock:
            return session_id in self._revoked_session_ids

    def get_async_lock(self, session_id: str) -> asyncio.Lock:
        """Retrieve or create an asyncio.Lock for the session in the current running loop.

        Locks are scoped to (session_id, running_event_loop) to guarantee safe
        event-loop affinity when proxies or session managers are reused across
        different asyncio.run() calls or test event loops.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.Lock()

        with self._lock:
            # Clean up references to closed event loops
            closed_keys = [k for k in self._async_locks if k[1].is_closed()]
            for k in closed_keys:
                del self._async_locks[k]

            key = (session_id, loop)
            if key not in self._async_locks:
                self._async_locks[key] = asyncio.Lock()
            return self._async_locks[key]

    def record_call(
        self,
        session_id: str,
        server_name: str,
        tool_name: str,
        outcome: str,
    ) -> SessionCallSummary:
        """Atomically append a call summary to session history and update counts.

        Args:
            session_id: Identifier of the target session.
            server_name: Name of the server handling the tool.
            tool_name: Name of the invoked tool.
            outcome: Final outcome of the call ("success", "error", "denied").

        Returns:
            The recorded SessionCallSummary.

        Raises:
            SessionStateError: If the session does not exist or is inactive.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not session.is_active:
                raise SessionStateError(
                    f"Cannot record call: session '{session_id}' not found or inactive."
                )

            seq = len(session.history) + 1
            summary = SessionCallSummary(
                sequence_number=seq,
                server_name=server_name,
                tool_name=tool_name,
                outcome=outcome,
                timestamp_utc=generate_session_timestamp_utc(),
            )
            session.history.append(summary)

            # Update forwarded invocation count if not denied (forwarded to MCP)
            if outcome in ("success", "error"):
                session.tool_counts[tool_name] = session.tool_counts.get(tool_name, 0) + 1

            return summary

    def add_taint(self, session_id: str, taint: str) -> None:
        """Apply a security taint flag to the specified session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not session.is_active:
                raise SessionStateError(
                    f"Cannot add taint: session '{session_id}' not found or inactive."
                )
            session.taints.add(taint)
            logger.info("Session '%s' tainted with '%s'", session_id, taint)

    def has_taint(self, session_id: str, taint: str) -> bool:
        """Check if a session carries the specified taint."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            return taint in session.taints

    def get_tool_count(self, session_id: str, tool_name: str) -> int:
        """Return the forwarded invocation count of a tool in the specified session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return 0
            return session.tool_counts.get(tool_name, 0)

    def delete_session(self, session_id: str) -> bool:
        """Explicitly purge a session and mark its ID as permanently revoked (tombstoned).

        Returns:
            True if the session was an active session that was purged, False if it was
            not present in the active sessions map. In all cases, the session ID is
            recorded as revoked and cannot be resurrected.
        """
        with self._lock:
            was_active = False
            if session_id in self._sessions:
                existing = self._sessions.pop(session_id)
                existing.is_active = False
                was_active = True
            self._revoked_session_ids.add(session_id)

            # Clean up any locks associated with this session
            keys_to_remove = [k for k in self._async_locks if k[0] == session_id]
            for k in keys_to_remove:
                del self._async_locks[k]

            return was_active

    def clear(self, preserve_revocations: bool = True) -> None:
        """Purge active sessions and cached async locks.

        Args:
            preserve_revocations: If True (default), maintains tombstones so
                previously revoked session IDs cannot be resurrected even after
                ordinary session state is purged. If False, resets all state
                including revocation tombstones (e.g. for complete test suite reset).
        """
        with self._lock:
            self._sessions.clear()
            self._async_locks.clear()
            if not preserve_revocations:
                self._revoked_session_ids.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
