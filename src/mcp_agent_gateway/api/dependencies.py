"""FastAPI security dependencies and reviewer authentication."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Security
from fastapi.security import APIKeyHeader

from mcp_agent_gateway.config.settings import Settings, get_settings

admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)


@dataclass
class ReviewerIdentity:
    """Authenticated human reviewer identity."""

    reviewer_id: str


def get_authenticated_reviewer(
    x_admin_key: str | None = Security(admin_key_header),
    authorization: str | None = Header(default=None),
    x_reviewer_id: str | None = Header(default=None),
) -> ReviewerIdentity:
    """Validate administrative credentials and extract reviewer identity.

    Fails closed if GATEWAY_ADMIN_API_KEY is not configured.
    Enforces constant-time token verification and mandatory reviewer identity.
    """
    settings: Settings = get_settings()

    # Rule 5: Fail closed if administrative key is not explicitly configured
    if not settings.admin_api_key or not settings.admin_api_key.strip():
        raise HTTPException(
            status_code=503,
            detail=(
                "Administrative endpoints are disabled: GATEWAY_ADMIN_API_KEY is not configured."
            ),
        )

    # Extract key from X-Admin-Key or Authorization Bearer header
    provided_key: str | None = None
    if x_admin_key:
        provided_key = x_admin_key.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        provided_key = authorization[7:].strip()

    if not provided_key:
        raise HTTPException(
            status_code=401,
            detail=(
                "Missing required administrative authentication key in 'X-Admin-Key' or "
                "'Authorization' header."
            ),
        )

    # Require reviewer identity
    if not x_reviewer_id or not x_reviewer_id.strip():
        raise HTTPException(
            status_code=400,
            detail="Missing required 'X-Reviewer-Id' header identifying the human reviewer.",
        )

    # Constant-time comparison to prevent timing side-channels
    if not secrets.compare_digest(provided_key, settings.admin_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid administrative credentials.",
        )

    return ReviewerIdentity(reviewer_id=x_reviewer_id.strip())
