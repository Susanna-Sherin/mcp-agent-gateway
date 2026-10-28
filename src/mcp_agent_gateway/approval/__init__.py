"""Approval workflow module for MCP Agent Gateway.

Responsible for human-in-the-loop (HITL) authorization gates, interactive
confirmation flows, and asynchronous approval timeouts for sensitive tool executions.
"""

from mcp_agent_gateway.approval.manager import ApprovalManager, ApprovalStoreError
from mcp_agent_gateway.approval.models import (
    ApprovalRequest,
    ApprovalStatusType,
    compute_request_hash,
    generate_approval_id,
    generate_approval_timestamp_utc,
)

__all__ = [
    "ApprovalManager",
    "ApprovalRequest",
    "ApprovalStatusType",
    "ApprovalStoreError",
    "compute_request_hash",
    "generate_approval_id",
    "generate_approval_timestamp_utc",
]
