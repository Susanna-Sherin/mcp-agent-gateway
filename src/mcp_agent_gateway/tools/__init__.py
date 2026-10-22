"""Tools module for MCP Agent Gateway.

Provides synthetic local MCP servers for inventory, file operations, and fake email.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_agent_gateway.tools.email_server import create_email_server
    from mcp_agent_gateway.tools.files_server import create_files_server
    from mcp_agent_gateway.tools.parts_server import create_parts_server


def __getattr__(name: str) -> Any:
    """Lazy module attributes avoiding premature runpy execution warnings."""
    if name == "create_parts_server":
        from mcp_agent_gateway.tools.parts_server import create_parts_server

        return create_parts_server
    if name == "create_files_server":
        from mcp_agent_gateway.tools.files_server import create_files_server

        return create_files_server
    if name == "create_email_server":
        from mcp_agent_gateway.tools.email_server import create_email_server

        return create_email_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "create_parts_server",
    "create_files_server",
    "create_email_server",
]
