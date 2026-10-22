"""Phase 0 smoke tests.

Validates that the mcp_agent_gateway package installs cleanly, all architectural
subpackages import without errors, configuration models initialize, and the FastAPI
application factory creates a valid app instance with health check routing.
"""

import importlib

import pytest


def test_package_version():
    """Verify package import and semantic version."""
    import mcp_agent_gateway

    assert hasattr(mcp_agent_gateway, "__version__")
    assert mcp_agent_gateway.__version__ == "0.1.0"


@pytest.mark.parametrize(
    "subpackage",
    [
        "mcp_agent_gateway.gateway",
        "mcp_agent_gateway.policy",
        "mcp_agent_gateway.session",
        "mcp_agent_gateway.scanners",
        "mcp_agent_gateway.approval",
        "mcp_agent_gateway.audit",
        "mcp_agent_gateway.tools",
        "mcp_agent_gateway.api",
        "mcp_agent_gateway.agent",
        "mcp_agent_gateway.observability",
        "mcp_agent_gateway.config",
    ],
)
def test_subpackages_importable(subpackage: str):
    """Verify each architectural component module imports successfully."""
    mod = importlib.import_module(subpackage)
    assert mod is not None


def test_settings_initialization():
    """Verify Pydantic settings load with expected defaults."""
    from mcp_agent_gateway.config import Settings, get_settings

    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.gateway_name == "mcp-agent-gateway"
    assert settings.app_port == 8000
    assert settings.environment in ("development", "testing", "production")


def test_fastapi_app_creation():
    """Verify FastAPI application initializes and exposes /healthz route."""
    from mcp_agent_gateway.api import create_app

    app = create_app()
    assert app.title == "MCP Agent Gateway"
    assert app.version == "0.1.0"

    # Verify /healthz route is registered
    routes = [route.path for route in app.routes]  # type: ignore[attr-defined]
    assert "/healthz" in routes


def test_fastapi_healthz_endpoint():
    """Verify /healthz returns HTTP 200 with service info using FastAPI TestClient."""
    from fastapi.testclient import TestClient

    from mcp_agent_gateway import __version__
    from mcp_agent_gateway.api import create_app

    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "mcp-agent-gateway"
    assert data["version"] == __version__
