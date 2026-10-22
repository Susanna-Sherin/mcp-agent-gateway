"""Application settings loaded from environment and defaults."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env file if present in working directory or parents
load_dotenv()


class Settings(BaseModel):
    """Core settings for MCP Agent Gateway."""

    environment: Literal["development", "testing", "production"] = Field(
        default="development",
        description="Operating environment name.",
    )
    debug: bool = Field(
        default=False,
        description="Debug mode toggle.",
    )
    app_host: str = Field(
        default="127.0.0.1",
        description="Host interface to bind.",
    )
    app_port: int = Field(
        default=8000,
        description="Port to listen on.",
    )
    log_level: str = Field(
        default="INFO",
        description="Log level name.",
    )
    gateway_name: str = Field(
        default="mcp-agent-gateway",
        description="Logical gateway service name.",
    )
    policy_enforcement_mode: str = Field(
        default="permissive",
        description="Policy mode: permissive, strict, or audit.",
    )
    policy_config_path: Path = Field(
        default=Path("config/policies.yaml"),
        description="Path to declarative policies configuration file.",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings populated from environment variables."""
    raw_debug = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    try:
        raw_port = int(os.getenv("APP_PORT", "8000"))
    except ValueError:
        raw_port = 8000

    return Settings(
        environment=os.getenv("ENVIRONMENT", "development"),  # type: ignore[arg-type]
        debug=raw_debug,
        app_host=os.getenv("APP_HOST", "127.0.0.1"),
        app_port=raw_port,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        gateway_name=os.getenv("GATEWAY_NAME", "mcp-agent-gateway"),
        policy_enforcement_mode=os.getenv("POLICY_ENFORCEMENT_MODE", "permissive"),
        policy_config_path=Path(os.getenv("POLICY_CONFIG_PATH", "config/policies.yaml")),
    )
