"""FastAPI Application factory for MCP Agent Gateway."""

from fastapi import FastAPI

from mcp_agent_gateway import __version__


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="MCP Agent Gateway",
        description="Security, governance, and observability gateway for MCP agents.",
        version=__version__,
    )

    @app.get("/healthz", tags=["System"])
    def health_check() -> dict[str, str]:
        """Basic health check endpoint."""
        return {
            "status": "ok",
            "service": "mcp-agent-gateway",
            "version": __version__,
        }

    return app
