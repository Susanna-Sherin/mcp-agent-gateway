"""API module for MCP Agent Gateway.

Responsible for HTTP/REST endpoints, health checks, management routes,
and interactive administration dashboard interfaces.
"""

from mcp_agent_gateway.api.app import create_app

__all__ = ["create_app"]
