"""FastAPI Application factory for MCP Agent Gateway."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query
from pydantic import BaseModel, Field

from mcp_agent_gateway import __version__
from mcp_agent_gateway.api.dependencies import ReviewerIdentity, get_authenticated_reviewer
from mcp_agent_gateway.approval.manager import ApprovalManager
from mcp_agent_gateway.audit.storage import SQLiteAuditStore
from mcp_agent_gateway.config.settings import get_settings


class ReviewDecisionRequest(BaseModel):
    """Payload for human reviewer decision."""

    model_config = {"extra": "forbid"}

    reason: str = Field(
        default="", max_length=500, description="Optional rationale for review decision."
    )


def create_app(
    approval_manager: ApprovalManager | None = None,
    audit_store: SQLiteAuditStore | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    settings = get_settings()

    app_approval_mgr = (
        approval_manager
        if approval_manager is not None
        else ApprovalManager(
            db_path=settings.audit_db_path,
            timeout_seconds=settings.approval_timeout_seconds,
        )
    )

    app_audit_store = (
        audit_store if audit_store is not None else SQLiteAuditStore(db_path=settings.audit_db_path)
    )

    app = FastAPI(
        title="MCP Agent Gateway",
        description="Security, governance, and observability gateway for MCP agents.",
        version=__version__,
    )

    # Attach instances to app state for lifecycle/test inspection
    app.state.approval_manager = app_approval_mgr
    app.state.audit_store = app_audit_store

    @app.get("/healthz", tags=["System"])
    def health_check() -> dict[str, str]:
        """Basic health check endpoint."""
        return {
            "status": "ok",
            "service": "mcp-agent-gateway",
            "version": __version__,
        }

    # --------------------------------------------------------------------------
    # Human Approval Queue Endpoints
    # --------------------------------------------------------------------------

    @app.get("/approvals/pending", tags=["Approvals"])
    def list_pending_approvals(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        limit: int = Query(default=50, ge=1, le=100, description="Number of items to return."),
        offset: int = Query(default=0, ge=0, description="Pagination offset."),
    ) -> list[dict[str, Any]]:
        """List active pending approval requests (requires reviewer authentication)."""
        pending = app_approval_mgr.list_pending(limit=limit, offset=offset)
        return [p.to_dict() for p in pending]

    @app.get("/approvals/{approval_id}", tags=["Approvals"])
    def get_approval_details(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        approval_id: str = Path(
            ..., pattern=r"^appr_[A-Za-z0-9_-]+$", description="Unique approval ID."
        ),
    ) -> dict[str, Any]:
        """Retrieve details of a specific approval request."""
        req = app_approval_mgr.get_approval(approval_id)
        if not req:
            raise HTTPException(
                status_code=404, detail=f"Approval request '{approval_id}' not found."
            )
        return req.to_dict()

    @app.post("/approvals/{approval_id}/approve", tags=["Approvals"])
    def approve_request(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        payload: ReviewDecisionRequest,
        approval_id: str = Path(
            ..., pattern=r"^appr_[A-Za-z0-9_-]+$", description="Unique approval ID."
        ),
    ) -> dict[str, Any]:
        """Approve a pending tool invocation request (requires reviewer authentication)."""
        success, message, updated = app_approval_mgr.approve(
            approval_id=approval_id,
            reviewer_id=reviewer.reviewer_id,
            reason=payload.reason,
        )
        if not success:
            if updated is None:
                raise HTTPException(status_code=404, detail=message)
            if updated.status == "EXPIRED":
                raise HTTPException(status_code=400, detail=message)
            raise HTTPException(status_code=409, detail=message)

        return updated.to_dict()  # type: ignore[union-attr]

    @app.post("/approvals/{approval_id}/reject", tags=["Approvals"])
    def reject_request(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        payload: ReviewDecisionRequest,
        approval_id: str = Path(
            ..., pattern=r"^appr_[A-Za-z0-9_-]+$", description="Unique approval ID."
        ),
    ) -> dict[str, Any]:
        """Reject a pending tool invocation request (requires reviewer authentication)."""
        success, message, updated = app_approval_mgr.reject(
            approval_id=approval_id,
            reviewer_id=reviewer.reviewer_id,
            reason=payload.reason,
        )
        if not success:
            if updated is None:
                raise HTTPException(status_code=404, detail=message)
            if updated.status == "EXPIRED":
                raise HTTPException(status_code=400, detail=message)
            raise HTTPException(status_code=409, detail=message)

        return updated.to_dict()  # type: ignore[union-attr]

    # --------------------------------------------------------------------------
    # Audit Log Endpoints
    # --------------------------------------------------------------------------

    @app.get("/audit/records", tags=["Audit"])
    def query_audit_records(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        session_id: str | None = Query(
            default=None, max_length=100, description="Filter by session ID."
        ),
        tool_name: str | None = Query(
            default=None, max_length=100, description="Filter by tool name."
        ),
        outcome: str | None = Query(default=None, max_length=50, description="Filter by outcome."),
        limit: int = Query(default=50, ge=1, le=100, description="Number of items to return."),
        offset: int = Query(default=0, ge=0, description="Pagination offset."),
    ) -> list[dict[str, Any]]:
        """Query persistent audit records with filtering and pagination."""
        return app_audit_store.query_records(
            session_id=session_id,
            tool_name=tool_name,
            outcome=outcome,
            limit=limit,
            offset=offset,
        )

    @app.get("/audit/records/{call_id}", tags=["Audit"])
    def get_audit_record(
        reviewer: Annotated[ReviewerIdentity, Depends(get_authenticated_reviewer)],
        call_id: str = Path(
            ..., pattern=r"^gw_call_[A-Za-z0-9_-]+$", description="Unique gateway call ID."
        ),
    ) -> dict[str, Any]:
        """Retrieve a specific audit record by its call ID."""
        rec = app_audit_store.get_record(call_id)
        if not rec:
            raise HTTPException(status_code=404, detail=f"Audit record '{call_id}' not found.")
        return rec

    return app
