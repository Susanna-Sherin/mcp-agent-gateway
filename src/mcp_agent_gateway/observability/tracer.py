"""OpenTelemetry tracing management, context propagation, and safe span execution.

Provides thread-safe initialization, safe context management, in-memory test export,
and strict failure containment ensuring telemetry errors never affect gateway logic.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span, Tracer

from mcp_agent_gateway.config.settings import get_settings
from mcp_agent_gateway.observability.attributes import (
    sanitize_attribute_value,
    sanitize_span_attributes,
)

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_INITIALIZED: bool = False
_IN_MEMORY_EXPORTER: InMemorySpanExporter | None = None


def is_telemetry_enabled() -> bool:
    """Return True if OpenTelemetry tracing is enabled in application settings."""
    try:
        return bool(get_settings().otel_enabled)
    except Exception:
        return False


def initialize_tracer(
    service_name: str | None = None,
    otlp_endpoint: str | None = None,
    in_memory: bool = False,
    force_reinit: bool = False,
) -> TracerProvider:
    """Initialize OpenTelemetry tracer provider safely and only once in production.

    Args:
        service_name: Logical service identifier (defaults to settings.otel_service_name).
        otlp_endpoint: Optional OTLP collector URI.
        in_memory: If True, configures InMemorySpanExporter for offline testing.
        force_reinit: Forces re-initialization (used for test isolation).

    Returns:
        The configured TracerProvider instance.
    """
    global _INITIALIZED, _IN_MEMORY_EXPORTER

    with _LOCK:
        if _INITIALIZED and not force_reinit and not in_memory:
            return trace.get_tracer_provider()  # type: ignore[return-value]

        settings = get_settings()
        svc_name = service_name or getattr(settings, "otel_service_name", "mcp-agent-gateway")
        resource = Resource.create({"service.name": svc_name})

        if in_memory or force_reinit:
            try:
                trace._TRACER_PROVIDER = None
                if hasattr(trace, "_TRACER_PROVIDER_SET_ONCE"):
                    trace._TRACER_PROVIDER_SET_ONCE._done = False
            except Exception:
                pass

        if in_memory:
            provider = TracerProvider(resource=resource)
            exporter = InMemorySpanExporter()
            processor = SimpleSpanProcessor(exporter)
            provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)
            _IN_MEMORY_EXPORTER = exporter
            _INITIALIZED = True
            return provider

        if is_telemetry_enabled():
            provider = TracerProvider(resource=resource)
            endpoint = otlp_endpoint or getattr(settings, "otel_exporter_otlp_endpoint", None)
            if endpoint:
                try:
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    otlp_exporter = OTLPSpanExporter(endpoint=endpoint)
                    provider.add_span_processor(SimpleSpanProcessor(otlp_exporter))
                except Exception as ex:
                    logger.warning("Could not initialize OTLP exporter: %s", type(ex).__name__)

            trace.set_tracer_provider(provider)
            _IN_MEMORY_EXPORTER = None
            _INITIALIZED = True
            return provider

        # Telemetry is disabled: configure NoOp provider
        noop_provider = trace.NoOpTracerProvider()
        trace.set_tracer_provider(noop_provider)
        _IN_MEMORY_EXPORTER = None
        _INITIALIZED = True
        return noop_provider  # type: ignore[return-value]


def get_in_memory_exporter() -> InMemorySpanExporter | None:
    """Retrieve active InMemorySpanExporter if configured (for offline test assertions)."""
    return _IN_MEMORY_EXPORTER


def reset_tracer_for_testing() -> None:
    """Reset tracer state and clear in-memory spans for isolated test execution."""
    global _INITIALIZED, _IN_MEMORY_EXPORTER
    with _LOCK:
        if _IN_MEMORY_EXPORTER is not None:
            _IN_MEMORY_EXPORTER.clear()
        _IN_MEMORY_EXPORTER = None
        _INITIALIZED = False
        try:
            trace._TRACER_PROVIDER = None
            if hasattr(trace, "_TRACER_PROVIDER_SET_ONCE"):
                trace._TRACER_PROVIDER_SET_ONCE._done = False
        except Exception:
            pass
        trace.set_tracer_provider(trace.NoOpTracerProvider())


def get_tracer(name: str = "mcp-agent-gateway") -> Tracer:
    """Retrieve an OpenTelemetry tracer for instrumenting gateway or agent operations."""
    return trace.get_tracer(name)


def get_current_trace_and_span_id() -> tuple[str | None, str | None]:
    """Retrieve current (trace_id, span_id) hex strings if an active span exists."""
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            trace_id_hex = f"{ctx.trace_id:032x}"
            span_id_hex = f"{ctx.span_id:016x}"
            return trace_id_hex, span_id_hex
    except Exception as ex:
        logger.debug("Could not extract trace/span ID from context: %s", type(ex).__name__)
    return None, None


@contextmanager
def safe_start_span(
    name: str,
    attributes: dict[str, Any] | None = None,
    tracer_name: str = "mcp-agent-gateway",
) -> Generator[Span | None]:
    """Context manager for safely creating and managing an OpenTelemetry span.

    Guarantees:
    - Tracer retrieval, attribute sanitization, span creation and context entry
      are all strictly enclosed in a failure boundary.
    - If telemetry setup fails, yields None and allows caller to proceed unhindered.
    - Active span context is automatically propagated to child spans and async calls.
    - Telemetry cleanup failures never replace or mask an application exception.
    - Normal caller execution is never interrupted by telemetry errors.
    """
    cm: Any = None
    span: Span | None = None
    safe_name: str = "unknown"

    try:
        safe_name_val = sanitize_attribute_value(name)
        safe_name = str(safe_name_val) if isinstance(safe_name_val, str) else str(name)
        tracer = get_tracer(tracer_name)
        sanitized_attrs = sanitize_span_attributes(attributes)

        # Prepare OTel-safe attributes (primitives and homogeneous primitive sequences)
        otel_attrs: dict[str, Any] = {}
        for k, v in sanitized_attrs.items():
            if isinstance(v, (int, float, bool, str)):
                otel_attrs[k] = v
            elif isinstance(v, (list, tuple)):
                otel_attrs[k] = [x for x in v if isinstance(x, (int, float, bool, str))]

        cm = tracer.start_as_current_span(safe_name, attributes=otel_attrs)
        span = cm.__enter__()
    except Exception as ex:
        logger.warning(
            "Telemetry error creating span '%s': %s",
            safe_name,
            type(ex).__name__,
        )
        cm = None
        span = None

    try:
        yield span
    except BaseException as exc:
        if cm is not None:
            try:
                cm.__exit__(type(exc), exc, exc.__traceback__)
            except Exception as exit_err:
                logger.warning(
                    "Telemetry error exiting span '%s': %s",
                    safe_name,
                    type(exit_err).__name__,
                )
        raise
    else:
        if cm is not None:
            try:
                cm.__exit__(None, None, None)
            except Exception as exit_err:
                logger.warning(
                    "Telemetry error exiting span '%s': %s",
                    safe_name,
                    type(exit_err).__name__,
                )


def safe_set_span_attributes(span: Span | None, attributes: dict[str, Any] | None) -> None:
    """Safely apply allowlisted attributes to an active span."""
    if span is None or not attributes:
        return
    try:
        sanitized = sanitize_span_attributes(attributes)
        for k, v in sanitized.items():
            if isinstance(v, (int, float, bool, str)):
                span.set_attribute(k, v)
            elif isinstance(v, (list, tuple)):
                span.set_attribute(k, [x for x in v if isinstance(x, (int, float, bool, str))])
    except Exception as ex:
        logger.warning("Telemetry error setting span attributes: %s", type(ex).__name__)
