"""Optional, pluggable Langfuse integration for LLM and agent observability.

Ensures:
- Operates in complete no-op mode when unconfigured, missing credentials, or library is absent.
- 100% offline testability with mock/contract adapters without live credentials.
- Strict data sanitization (allowlisted attributes, canary/PII scrubbing).
- Telemetry failure containment: errors never alter gateway policy decisions or tool execution.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_agent_gateway.config.settings import get_settings
from mcp_agent_gateway.observability.attributes import (
    ALLOWLISTED_SPAN_ATTRIBUTES,
    sanitize_attribute_value,
)

logger = logging.getLogger(__name__)

_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "raw_tool_arguments",
        "raw_arguments",
        "tool_output",
        "password",
        "secret",
        "api_key",
        "token",
        "credentials",
        "prompt",
        "user_query",
    }
)

_ALLOWED_EXTRA_METADATA_KEYS = frozenset(
    {"session_id", "caller_role", "iteration", "outcome", "duration_ms", "call_id", "status"}
)


def _sanitize_metadata(raw_meta: dict[str, Any] | None) -> dict[str, Any]:
    """Sanitize and filter metadata for Langfuse.

    - Drops forbidden keys (credentials, raw arguments, raw outputs).
    - Retains only allowlisted or safe metadata keys.
    - Sanitizes all values recursively (redacts canaries, cards, SSNs, emails, phones, credentials).
    """
    if not isinstance(raw_meta, dict):
        return {}

    sanitized: dict[str, Any] = {}
    for k, v in raw_meta.items():
        if not isinstance(k, str):
            continue
        lower_k = k.lower()
        if any(f in lower_k for f in _FORBIDDEN_METADATA_KEYS):
            continue
        if k in ALLOWLISTED_SPAN_ATTRIBUTES or lower_k in _ALLOWED_EXTRA_METADATA_KEYS:
            sanitized[k] = sanitize_attribute_value(v)
    return sanitized


class LangfuseAdapter:
    """Pluggable adapter for Langfuse telemetry."""

    def __init__(
        self,
        enabled: bool | None = None,
        public_key: str | None = None,
        secret_key: str | None = None,
        host: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._custom_client = client
        settings = get_settings()

        self._enabled = (
            enabled if enabled is not None else getattr(settings, "langfuse_enabled", False)
        )
        self._public_key = public_key or getattr(settings, "langfuse_public_key", None)
        self._secret_key = secret_key or getattr(settings, "langfuse_secret_key", None)
        self._host = host or getattr(settings, "langfuse_host", "https://cloud.langfuse.com")
        self._client: Any | None = client

    @property
    def is_enabled(self) -> bool:
        """Return True if Langfuse is explicitly enabled and credentials are configured."""
        if not self._enabled:
            return False
        if self._custom_client is not None:
            return True
        return bool(self._public_key and self._secret_key)

    def _get_client(self) -> Any | None:
        """Retrieve or lazily initialize the Langfuse client if enabled."""
        if not self.is_enabled:
            return None
        if self._client is not None:
            return self._client

        try:
            from langfuse import Langfuse

            self._client = Langfuse(
                public_key=self._public_key,
                secret_key=self._secret_key,
                host=self._host,
            )
            return self._client
        except Exception as ex:
            logger.warning("Could not initialize Langfuse client: %s", type(ex).__name__)
            return None

    def trace_event(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Record a discrete event in Langfuse with sanitized attributes and metadata."""
        if not self.is_enabled:
            return

        try:
            client = self._get_client()
            if client is None:
                return

            safe_name_val = sanitize_attribute_value(name)
            safe_name = str(safe_name_val) if isinstance(safe_name_val, str) else str(name)

            combined = {**(attributes or {}), **(metadata or {})}
            clean_meta = _sanitize_metadata(combined)

            sess = session_id or combined.get("session_id")
            if sess is not None:
                clean_meta["session_id"] = sanitize_attribute_value(sess)

            if hasattr(client, "event"):
                client.event(name=safe_name, metadata=clean_meta)
        except Exception as ex:
            logger.warning("Langfuse error recording event: %s", type(ex).__name__)

    def trace_generation(
        self,
        name: str,
        model: str,
        prompt_summary: Any = None,
        completion_summary: Any = None,
        attributes: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        input_messages: Any = None,
        input: Any = None,
        output: Any = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Record an LLM generation step with strictly sanitized summaries and attributes."""
        if not self.is_enabled:
            return

        try:
            client = self._get_client()
            if client is None:
                return

            safe_name_val = sanitize_attribute_value(name)
            safe_name = str(safe_name_val) if isinstance(safe_name_val, str) else str(name)

            safe_model_val = sanitize_attribute_value(model)
            safe_model = str(safe_model_val) if isinstance(safe_model_val, str) else str(model)

            raw_input = (
                prompt_summary
                if prompt_summary is not None
                else (input_messages if input_messages is not None else input)
            )
            clean_prompt = sanitize_attribute_value(raw_input) if raw_input is not None else None

            raw_output = completion_summary if completion_summary is not None else output
            clean_completion = (
                sanitize_attribute_value(raw_output) if raw_output is not None else None
            )

            combined = {**(attributes or {}), **(metadata or {})}
            clean_meta = _sanitize_metadata(combined)

            sess = session_id or combined.get("session_id")
            if sess is not None:
                clean_meta["session_id"] = sanitize_attribute_value(sess)

            if hasattr(client, "generation"):
                client.generation(
                    name=safe_name,
                    model=safe_model,
                    input=clean_prompt,
                    output=clean_completion,
                    metadata=clean_meta,
                )
        except Exception as ex:
            logger.warning("Langfuse error recording generation: %s", type(ex).__name__)

    def trace_tool_call(
        self,
        tool_name: str,
        call_id: str,
        session_id: str,
        outcome: str,
        duration_ms: float,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Record a tool invocation outcome event in Langfuse with sanitized attributes."""
        if not self.is_enabled:
            return

        try:
            safe_tool_name = sanitize_attribute_value(tool_name)
            safe_call_id = sanitize_attribute_value(call_id)
            safe_session_id = sanitize_attribute_value(session_id)
            safe_outcome = sanitize_attribute_value(outcome)
            safe_duration = float(duration_ms) if isinstance(duration_ms, (int, float)) else 0.0

            attrs = {
                **(attributes or {}),
                "mcp.tool.name": safe_tool_name,
                "mcp.gateway.call_id": safe_call_id,
                "mcp.gateway.session_id": safe_session_id,
                "mcp.gateway.outcome": safe_outcome,
                "mcp.gateway.duration_ms": safe_duration,
            }
            self.trace_event(
                name=f"tool_call:{safe_tool_name}",
                attributes=attrs,
                session_id=str(safe_session_id),
            )
        except Exception as ex:
            logger.warning("Langfuse error recording tool call: %s", type(ex).__name__)


_GLOBAL_LANGFUSE_ADAPTER: LangfuseAdapter | None = None


def get_langfuse_adapter() -> LangfuseAdapter:
    """Retrieve global cached LangfuseAdapter instance."""
    global _GLOBAL_LANGFUSE_ADAPTER
    if _GLOBAL_LANGFUSE_ADAPTER is None:
        _GLOBAL_LANGFUSE_ADAPTER = LangfuseAdapter()
    return _GLOBAL_LANGFUSE_ADAPTER
