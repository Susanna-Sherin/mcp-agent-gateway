"""Persistent SQLite-backed audit storage for MCP Agent Gateway."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_agent_gateway.gateway.records import ToolCallRecord

logger = logging.getLogger(__name__)


class AuditPersistenceError(Exception):
    """Raised when an unrecoverable failure occurs while persisting an audit record."""


class SQLiteAuditStore:
    """Thread-safe persistent audit log store backed by SQLite."""

    def __init__(self, db_path: Path | str = "data/gateway.db") -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._initialized = False
        try:
            self._init_db()
            self._initialized = True
        except Exception:
            pass

    def _ensure_init(self) -> None:
        """Ensure database schema is initialized."""
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
            raise AuditPersistenceError(f"Failed to connect to audit database: {ex}") from ex

    def _init_db(self) -> None:
        """Initialize SQLite audit table schema and indexes."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT NOT NULL UNIQUE,
                    timestamp_utc TEXT NOT NULL,
                    session_id TEXT,
                    session_seq INTEGER,
                    caller_role TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_sanitized TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    result_sanitized TEXT,
                    error_message TEXT,
                    duration_ms REAL NOT NULL,
                    policy_decision TEXT,
                    chain_decision TEXT,
                    scanner_results TEXT,
                    approval_id TEXT,
                    metadata TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records(timestamp_utc);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_records(session_id);"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_records(tool_name);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_records(outcome);")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_approval ON audit_records(approval_id);"
            )
            conn.commit()

    def record_call(
        self,
        record: ToolCallRecord,
        approval_id: str | None = None,
    ) -> None:
        """Persist a sanitized ToolCallRecord into the durable SQLite audit log.

        Raises AuditPersistenceError if the database transaction fails.
        """
        self._ensure_init()
        # Resolve caller role from policy decision or metadata
        caller_role = "unknown"
        if record.policy_decision and isinstance(record.policy_decision, dict):
            caller_role = record.policy_decision.get("caller_role", "unknown")
        elif record.metadata and "caller_role" in record.metadata:
            caller_role = str(record.metadata["caller_role"])

        appr_id = approval_id or record.metadata.get("approval_id")

        try:
            args_json = json.dumps(record.arguments, sort_keys=True)
            result_json = (
                json.dumps(record.result, sort_keys=True) if record.result is not None else None
            )
            policy_json = (
                json.dumps(record.policy_decision, sort_keys=True)
                if record.policy_decision is not None
                else None
            )
            chain_json = (
                json.dumps(record.chain_decision, sort_keys=True)
                if record.chain_decision is not None
                else None
            )
            scanner_json = (
                json.dumps(record.scanner_results, sort_keys=True)
                if record.scanner_results is not None
                else None
            )
            meta_json = json.dumps(record.metadata, sort_keys=True) if record.metadata else "{}"

            with self._lock, self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_records (
                        call_id, timestamp_utc, session_id, session_seq,
                        caller_role, server_name, tool_name, arguments_sanitized,
                        outcome, result_sanitized, error_message, duration_ms,
                        policy_decision, chain_decision, scanner_results,
                        approval_id, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        record.call_id,
                        record.timestamp_utc,
                        record.session_id,
                        record.session_seq,
                        caller_role,
                        record.server_name,
                        record.tool_name,
                        args_json,
                        record.outcome,
                        result_json,
                        record.error_message,
                        record.duration_ms,
                        policy_json,
                        chain_json,
                        scanner_json,
                        appr_id,
                        meta_json,
                    ),
                )
                conn.commit()
        except Exception as ex:
            err_msg = f"Failed to persist audit record '{record.call_id}': {ex}"
            logger.error(err_msg)
            raise AuditPersistenceError(err_msg) from ex

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a database row into a structured dictionary with parsed JSON fields."""

        def safe_json_loads(val: Any) -> Any:
            if val is None or not isinstance(val, str):
                return val
            try:
                return json.loads(val)
            except Exception:
                return val

        return {
            "id": row["id"],
            "call_id": row["call_id"],
            "timestamp_utc": row["timestamp_utc"],
            "session_id": row["session_id"],
            "session_seq": row["session_seq"],
            "caller_role": row["caller_role"],
            "server_name": row["server_name"],
            "tool_name": row["tool_name"],
            "arguments_sanitized": safe_json_loads(row["arguments_sanitized"]),
            "outcome": row["outcome"],
            "result_sanitized": safe_json_loads(row["result_sanitized"]),
            "error_message": row["error_message"],
            "duration_ms": row["duration_ms"],
            "policy_decision": safe_json_loads(row["policy_decision"]),
            "chain_decision": safe_json_loads(row["chain_decision"]),
            "scanner_results": safe_json_loads(row["scanner_results"]),
            "approval_id": row["approval_id"],
            "metadata": safe_json_loads(row["metadata"]),
        }

    def query_records(
        self,
        session_id: str | None = None,
        tool_name: str | None = None,
        outcome: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query persistent audit records with validated filtering and pagination."""
        self._ensure_init()
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        clauses: list[str] = []
        params: list[Any] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query_sql = f"""
            SELECT * FROM audit_records
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([safe_limit, safe_offset])

        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(query_sql, params)
            return [self._row_to_dict(r) for r in cursor.fetchall()]

    def get_record(self, call_id: str) -> dict[str, Any] | None:
        """Retrieve a specific audit record by its call_id."""
        self._ensure_init()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_records WHERE call_id = ?;",
                (call_id,),
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None

    def purge_older_than(self, days: int) -> int:
        """Administrative retention utility: purge records older than specified days."""
        self._ensure_init()
        if days < 1:
            raise ValueError("Retention days must be at least 1")
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM audit_records WHERE timestamp_utc < ?;",
                (cutoff,),
            )
            conn.commit()
            return cursor.rowcount
