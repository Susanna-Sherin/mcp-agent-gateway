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
    scanner_pii_enabled: bool = Field(
        default=True,
        description="Enable PII inspection on arguments and results.",
    )
    scanner_injection_enabled: bool = Field(
        default=True,
        description="Enable prompt injection inspection on arguments.",
    )
    scanner_gemini_judge_enabled: bool = Field(
        default=False,
        description="Enable Gemini judge for ambiguous injection scores.",
    )
    tool_pinning_enabled: bool = Field(
        default=False,
        description="Enforce canonical SHA-256 tool description hash pinning.",
    )
    tool_pins_path: Path = Field(
        default=Path("config/tool_pins.json"),
        description="Path to enrolled tool pins configuration file.",
    )
    audit_db_path: Path = Field(
        default=Path("data/gateway.db"),
        description="Path to persistent SQLite database for audit and approval records.",
    )
    approval_timeout_seconds: int = Field(
        default=300,
        description="Time-to-live for pending approval requests in seconds.",
    )
    audit_retention_days: int = Field(
        default=90,
        description="Audit record retention period in days.",
    )
    admin_api_key: str | None = Field(
        default=None,
        description=(
            "Pre-shared administrative API key for reviewer endpoints. "
            "If None, reviewer endpoints fail closed."
        ),
    )
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry distributed tracing.",
    )
    otel_service_name: str = Field(
        default="mcp-agent-gateway",
        description="Service name for OpenTelemetry resource.",
    )
    otel_exporter_otlp_endpoint: str | None = Field(
        default=None,
        description="OTLP endpoint for OpenTelemetry trace exporter.",
    )
    langfuse_enabled: bool = Field(
        default=False,
        description="Enable Langfuse LLM/agent observability.",
    )
    langfuse_public_key: str | None = Field(
        default=None,
        description="Langfuse public API key.",
    )
    langfuse_secret_key: str | None = Field(
        default=None,
        description="Langfuse secret API key.",
    )
    langfuse_host: str = Field(
        default="https://cloud.langfuse.com",
        description="Langfuse host endpoint URL.",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings populated from environment variables."""
    raw_debug = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    try:
        raw_port = int(os.getenv("APP_PORT", "8000"))
    except ValueError:
        raw_port = 8000

    try:
        approval_timeout = int(os.getenv("APPROVAL_TIMEOUT_SECONDS", "300"))
    except ValueError:
        approval_timeout = 300

    try:
        audit_retention = int(os.getenv("AUDIT_RETENTION_DAYS", "90"))
    except ValueError:
        audit_retention = 90

    raw_admin_key = os.getenv("GATEWAY_ADMIN_API_KEY")
    admin_key = raw_admin_key if raw_admin_key and raw_admin_key.strip() else None

    return Settings(
        environment=os.getenv("ENVIRONMENT", "development"),  # type: ignore[arg-type]
        debug=raw_debug,
        app_host=os.getenv("APP_HOST", "127.0.0.1"),
        app_port=raw_port,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        gateway_name=os.getenv("GATEWAY_NAME", "mcp-agent-gateway"),
        policy_enforcement_mode=os.getenv("POLICY_ENFORCEMENT_MODE", "permissive"),
        policy_config_path=Path(os.getenv("POLICY_CONFIG_PATH", "config/policies.yaml")),
        scanner_pii_enabled=os.getenv("SCANNER_PII_ENABLED", "true").lower()
        in ("true", "1", "yes"),
        scanner_injection_enabled=os.getenv("SCANNER_INJECTION_ENABLED", "true").lower()
        in ("true", "1", "yes"),
        scanner_gemini_judge_enabled=os.getenv("SCANNER_GEMINI_JUDGE_ENABLED", "false").lower()
        in ("true", "1", "yes"),
        tool_pinning_enabled=os.getenv("TOOL_PINNING_ENABLED", "false").lower()
        in ("true", "1", "yes"),
        tool_pins_path=Path(os.getenv("TOOL_PINS_PATH", "config/tool_pins.json")),
        audit_db_path=Path(os.getenv("AUDIT_DB_PATH", "data/gateway.db")),
        approval_timeout_seconds=approval_timeout,
        audit_retention_days=audit_retention,
        admin_api_key=admin_key,
        otel_enabled=os.getenv("OTEL_ENABLED", "false").lower() in ("true", "1", "yes"),
        otel_service_name=os.getenv("OTEL_SERVICE_NAME", "mcp-agent-gateway"),
        otel_exporter_otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
        langfuse_enabled=os.getenv("LANGFUSE_ENABLED", "false").lower() in ("true", "1", "yes"),
        langfuse_public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        langfuse_secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        langfuse_host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
    )
