"""Audit logging module for MCP Agent Gateway.

Responsible for immutable compliance logs, structured event recording,
tamper-evident audit trails, and execution forensics.
"""

from mcp_agent_gateway.audit.storage import AuditPersistenceError, SQLiteAuditStore

__all__ = [
    "AuditPersistenceError",
    "SQLiteAuditStore",
]
