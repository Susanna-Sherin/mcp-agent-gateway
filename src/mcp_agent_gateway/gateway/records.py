"""In-memory call recording and structured audit models for MCP Gateway."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ToolCallRecord:
    """Structured record of an intercepted MCP tool invocation."""

    call_id: str
    timestamp_utc: str
    server_name: str
    tool_name: str
    arguments: dict[str, Any]
    outcome: str  # "success", "error", "unknown_tool"
    result: dict[str, Any] | None = None
    error_message: str | None = None
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to JSON-serializable dictionary."""
        return asdict(self)


class InMemoryCallRecorder:
    """Thread-safe in-memory recorder for gateway tool call audits."""

    def __init__(self) -> None:
        self._records: list[ToolCallRecord] = []
        self._lock = threading.Lock()

    def record(self, entry: ToolCallRecord) -> None:
        """Append a tool call record."""
        with self._lock:
            self._records.append(entry)

    def get_records(self) -> list[ToolCallRecord]:
        """Retrieve a shallow copy of all recorded tool calls."""
        with self._lock:
            return list(self._records)

    def find_by_call_id(self, call_id: str) -> ToolCallRecord | None:
        """Find a specific call record by its unique call_id."""
        with self._lock:
            for rec in self._records:
                if rec.call_id == call_id:
                    return rec
            return None

    def clear(self) -> None:
        """Clear all in-memory records."""
        with self._lock:
            self._records.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


def generate_timestamp_utc() -> str:
    """Generate ISO 8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()
