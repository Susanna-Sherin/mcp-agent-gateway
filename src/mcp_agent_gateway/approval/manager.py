"""Persistent SQLite-backed Approval Queue Manager."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp_agent_gateway.approval.models import (
    ApprovalRequest,
    generate_approval_id,
    generate_approval_timestamp_utc,
)

logger = logging.getLogger(__name__)


class ApprovalStoreError(Exception):
    """Raised when an unrecoverable database or storage error occurs."""


class ApprovalManager:
    """Thread-safe persistent manager for human-in-the-loop approval workflows."""

    def __init__(
        self,
        db_path: Path | str = "data/gateway.db",
        timeout_seconds: int = 300,
    ) -> None:
        self.db_path = Path(db_path)
        self.timeout_seconds = timeout_seconds
        self._lock = threading.RLock()
        self._initialized = False
        try:
            self._init_db()
            self._initialized = True
        except Exception:
            pass

    def _ensure_init(self) -> None:
        """Ensure database table schema is initialized."""
        if not self._initialized:
            self._init_db()
            self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        """Create a configured SQLite connection with WAL mode and busy timeout."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            return conn
        except Exception as ex:
            raise ApprovalStoreError(f"Failed to connect to approval database: {ex}") from ex

    def _init_db(self) -> None:
        """Initialize SQLite table schema and indexes."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_queue (
                    approval_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    caller_role TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_sanitized TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    reviewed_at_utc TEXT,
                    reviewed_by TEXT,
                    review_decision_reason TEXT,
                    consumed_at_utc TEXT,
                    consumed_by_call_id TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_queue(status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_session ON approval_queue(session_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_hash ON approval_queue(request_hash);"
            )
            conn.commit()

    def _row_to_request(self, row: sqlite3.Row) -> ApprovalRequest:
        """Convert a database row into a typed ApprovalRequest."""
        try:
            sanitized_args = json.loads(row["arguments_sanitized"])
        except Exception:
            sanitized_args = {}

        return ApprovalRequest(
            approval_id=row["approval_id"],
            request_hash=row["request_hash"],
            session_id=row["session_id"],
            caller_role=row["caller_role"],
            server_name=row["server_name"],
            tool_name=row["tool_name"],
            arguments_sanitized=sanitized_args,
            status=row["status"],
            created_at_utc=row["created_at_utc"],
            expires_at_utc=row["expires_at_utc"],
            reviewed_at_utc=row["reviewed_at_utc"],
            reviewed_by=row["reviewed_by"],
            review_decision_reason=row["review_decision_reason"],
            consumed_at_utc=row["consumed_at_utc"],
            consumed_by_call_id=row["consumed_by_call_id"],
        )

    def create_or_get_pending(
        self,
        session_id: str,
        caller_role: str,
        server_name: str,
        tool_name: str,
        arguments_sanitized: dict[str, Any],
        request_hash: str,
    ) -> ApprovalRequest:
        """Create a pending approval request or return an active unexpired pending match."""
        self._ensure_init()
        now_dt = datetime.now(UTC)
        now_iso = now_dt.isoformat()

        with self._lock, self._get_connection() as conn:
            # Check for existing active unexpired pending request with identical hash
            cursor = conn.execute(
                """
                SELECT * FROM approval_queue
                WHERE session_id = ? AND request_hash = ? AND status = 'PENDING'
                  AND expires_at_utc > ?
                LIMIT 1;
                """,
                (session_id, request_hash, now_iso),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_request(row)

            # Create new approval request
            approval_id = generate_approval_id()
            expires_dt = now_dt + timedelta(seconds=self.timeout_seconds)
            expires_iso = expires_dt.isoformat()
            args_json = json.dumps(arguments_sanitized, sort_keys=True)

            conn.execute(
                """
                INSERT INTO approval_queue (
                    approval_id, request_hash, session_id, caller_role,
                    server_name, tool_name, arguments_sanitized, status,
                    created_at_utc, expires_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?);
                """,
                (
                    approval_id,
                    request_hash,
                    session_id,
                    caller_role,
                    server_name,
                    tool_name,
                    args_json,
                    now_iso,
                    expires_iso,
                ),
            )
            conn.commit()

            return ApprovalRequest(
                approval_id=approval_id,
                request_hash=request_hash,
                session_id=session_id,
                caller_role=caller_role,
                server_name=server_name,
                tool_name=tool_name,
                arguments_sanitized=arguments_sanitized,
                status="PENDING",
                created_at_utc=now_iso,
                expires_at_utc=expires_iso,
            )

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        """Retrieve an approval request by its unique identifier, auto-expiring if stale."""
        self._ensure_init()
        now_iso = generate_approval_timestamp_utc()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM approval_queue WHERE approval_id = ?;",
                (approval_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            req = self._row_to_request(row)
            if req.status == "PENDING" and req.expires_at_utc < now_iso:
                conn.execute(
                    "UPDATE approval_queue SET status = 'EXPIRED' WHERE approval_id = ?;",
                    (approval_id,),
                )
                conn.commit()
                req.status = "EXPIRED"

            return req

    def list_pending(self, limit: int = 50, offset: int = 0) -> list[ApprovalRequest]:
        """List active pending approval requests with pagination after expiring stale rows."""
        self._ensure_init()
        now_iso = generate_approval_timestamp_utc()
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        with self._lock, self._get_connection() as conn:
            # Auto-expire any stale pending rows
            conn.execute(
                "UPDATE approval_queue SET status = 'EXPIRED' "
                "WHERE status = 'PENDING' AND expires_at_utc < ?;",
                (now_iso,),
            )
            conn.commit()

            cursor = conn.execute(
                """
                SELECT * FROM approval_queue
                WHERE status = 'PENDING'
                ORDER BY created_at_utc ASC
                LIMIT ? OFFSET ?;
                """,
                (safe_limit, safe_offset),
            )
            return [self._row_to_request(r) for r in cursor.fetchall()]

    def approve(
        self,
        approval_id: str,
        reviewer_id: str,
        reason: str = "",
    ) -> tuple[bool, str, ApprovalRequest | None]:
        """Approve a pending request atomically."""
        req = self.get_approval(approval_id)
        if not req:
            return False, f"Approval request '{approval_id}' not found", None

        if req.status == "EXPIRED":
            return False, f"Approval request '{approval_id}' has expired", req

        if req.status != "PENDING":
            return (
                False,
                f"Approval request '{approval_id}' is no longer PENDING (status: {req.status})",
                req,
            )

        now_iso = generate_approval_timestamp_utc()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE approval_queue
                SET status = 'APPROVED',
                    reviewed_at_utc = ?,
                    reviewed_by = ?,
                    review_decision_reason = ?
                WHERE approval_id = ? AND status = 'PENDING';
                """,
                (now_iso, reviewer_id, reason, approval_id),
            )
            conn.commit()
            if cursor.rowcount == 0:
                current = self.get_approval(approval_id)
                status_str = current.status if current else "unknown"
                return (
                    False,
                    f"Approval request '{approval_id}' is no longer PENDING (status: {status_str})",
                    current,
                )

        updated = self.get_approval(approval_id)
        return True, "APPROVED", updated

    def reject(
        self,
        approval_id: str,
        reviewer_id: str,
        reason: str = "",
    ) -> tuple[bool, str, ApprovalRequest | None]:
        """Reject a pending request atomically."""
        req = self.get_approval(approval_id)
        if not req:
            return False, f"Approval request '{approval_id}' not found", None

        if req.status == "EXPIRED":
            return False, f"Approval request '{approval_id}' has expired", req

        if req.status != "PENDING":
            return (
                False,
                f"Approval request '{approval_id}' is no longer PENDING (status: {req.status})",
                req,
            )

        now_iso = generate_approval_timestamp_utc()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE approval_queue
                SET status = 'REJECTED',
                    reviewed_at_utc = ?,
                    reviewed_by = ?,
                    review_decision_reason = ?
                WHERE approval_id = ? AND status = 'PENDING';
                """,
                (now_iso, reviewer_id, reason, approval_id),
            )
            conn.commit()
            if cursor.rowcount == 0:
                current = self.get_approval(approval_id)
                status_str = current.status if current else "unknown"
                return (
                    False,
                    f"Approval request '{approval_id}' is no longer PENDING (status: {status_str})",
                    current,
                )

        updated = self.get_approval(approval_id)
        return True, "REJECTED", updated

    def validate_approval(
        self,
        approval_id: str,
        request_hash: str,
        session_id: str,
        caller_role: str,
        server_name: str,
        tool_name: str,
    ) -> tuple[bool, str, ApprovalRequest | None]:
        """Validate request binding and approval state without consuming it."""
        self._ensure_init()
        req = self.get_approval(approval_id)
        if not req:
            return False, "APPROVAL_NOT_FOUND", None

        if req.status == "CONSUMED":
            return False, "APPROVAL_ALREADY_CONSUMED", req

        if req.status == "REJECTED":
            return False, "APPROVAL_REJECTED", req

        if req.status == "EXPIRED":
            return False, "APPROVAL_EXPIRED", req

        now_iso = generate_approval_timestamp_utc()
        if req.expires_at_utc < now_iso:
            with self._lock, self._get_connection() as conn:
                conn.execute(
                    "UPDATE approval_queue SET status = 'EXPIRED' WHERE approval_id = ?;",
                    (approval_id,),
                )
                conn.commit()
            req.status = "EXPIRED"
            return False, "APPROVAL_EXPIRED", req

        # Revalidate exact binding
        if req.session_id != session_id:
            return False, "APPROVAL_SESSION_MISMATCH", req

        if req.caller_role != caller_role:
            return False, "APPROVAL_ROLE_MISMATCH", req

        if req.server_name != server_name or req.tool_name != tool_name:
            return False, "APPROVAL_TARGET_MISMATCH", req

        if req.request_hash != request_hash:
            return False, "APPROVAL_BINDING_MISMATCH", req

        if req.status != "APPROVED":
            return False, "APPROVAL_NOT_APPROVED", req

        return True, "VALID", req

    def claim_and_consume(
        self,
        approval_id: str,
        request_hash: str,
        session_id: str,
        caller_role: str,
        server_name: str,
        tool_name: str,
        call_id: str,
    ) -> tuple[bool, str, ApprovalRequest | None]:
        """Verify request binding and atomically consume approval immediately prior to execution.

        Transition APPROVED -> CONSUMED is atomic and irreversible.
        Never restores a consumed approval even after exceptions, timeouts, or crashes.
        """
        valid, code, req = self.validate_approval(
            approval_id=approval_id,
            request_hash=request_hash,
            session_id=session_id,
            caller_role=caller_role,
            server_name=server_name,
            tool_name=tool_name,
        )
        if not valid:
            return False, code, req

        now_iso = generate_approval_timestamp_utc()
        # Atomic state transition APPROVED -> CONSUMED
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE approval_queue
                SET status = 'CONSUMED',
                    consumed_at_utc = ?,
                    consumed_by_call_id = ?
                WHERE approval_id = ? AND status = 'APPROVED';
                """,
                (now_iso, call_id, approval_id),
            )
            conn.commit()
            if cursor.rowcount == 0:
                # Concurrent claimant won the race
                current = self.get_approval(approval_id)
                return False, "APPROVAL_ALREADY_CONSUMED", current

        updated = self.get_approval(approval_id)
        return True, "CONSUMED", updated
