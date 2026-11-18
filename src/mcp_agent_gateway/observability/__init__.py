"""Observability module for MCP Agent Gateway.

Responsible for distributed tracing, metrics export, OpenTelemetry hooks,
and telemetry collectors.
"""

from __future__ import annotations

from mcp_agent_gateway.observability.attributes import (
    ALLOWLISTED_SPAN_ATTRIBUTES,
    sanitize_attribute_value,
    sanitize_span_attributes,
)
from mcp_agent_gateway.observability.langfuse import LangfuseAdapter, get_langfuse_adapter
from mcp_agent_gateway.observability.tracer import (
    get_current_trace_and_span_id,
    get_in_memory_exporter,
    get_tracer,
    initialize_tracer,
    is_telemetry_enabled,
    reset_tracer_for_testing,
    safe_set_span_attributes,
    safe_start_span,
)

__all__: list[str] = [
    "ALLOWLISTED_SPAN_ATTRIBUTES",
    "LangfuseAdapter",
    "get_current_trace_and_span_id",
    "get_in_memory_exporter",
    "get_langfuse_adapter",
    "get_tracer",
    "initialize_tracer",
    "is_telemetry_enabled",
    "reset_tracer_for_testing",
    "safe_set_span_attributes",
    "safe_start_span",
    "sanitize_attribute_value",
    "sanitize_span_attributes",
]
