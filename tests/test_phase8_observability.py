"""Deterministic offline test suite for Phase 8 Observability and Tracing.

Tests span hierarchy, correlation, strict attribute allowlisting, data privacy,
disabled telemetry behavior, missing credentials, and injected telemetry failure containment.
Requires NO live Gemini, Langfuse, or OTLP collector.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mcp_agent_gateway.agent.client import ToolDefinition
from mcp_agent_gateway.agent.gateway_agent import GatewayAgent
from mcp_agent_gateway.agent.llm_interface import LLMInterface
from mcp_agent_gateway.config.settings import get_settings
from mcp_agent_gateway.gateway.proxy import MCPGatewayProxy
from mcp_agent_gateway.observability import (
    ALLOWLISTED_SPAN_ATTRIBUTES,
    LangfuseAdapter,
    get_in_memory_exporter,
    initialize_tracer,
    is_telemetry_enabled,
    reset_tracer_for_testing,
    safe_set_span_attributes,
    safe_start_span,
    sanitize_attribute_value,
    sanitize_span_attributes,
)


class MockMCPClient:
    """Mock MultiServerMCPClient for hermetic and fast offline tests."""

    def __init__(self) -> None:
        self.tool_to_server = {
            "search_parts": "parts",
            "get_inventory": "parts",
            "send_email": "email",
            "read_file": "files",
            "list_files": "files",
        }

    async def discover_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="search_parts",
                description="Search parts catalog",
                server_name="parts",
                input_schema={},
            ),
            ToolDefinition(
                name="get_inventory",
                description="Get inventory stock",
                server_name="parts",
                input_schema={},
            ),
            ToolDefinition(
                name="read_file",
                description="Read technical document",
                server_name="files",
                input_schema={},
            ),
            ToolDefinition(
                name="send_email",
                description="Send internal email",
                server_name="email",
                input_schema={},
            ),
        ]

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "result": f"mock_executed_{tool_name}"}


class CannedOfflineLLM(LLMInterface):
    """Deterministic offline planner for testing agent lifecycle telemetry."""

    def __init__(self, tool_name: str, arguments: dict[str, Any], final_resp: str) -> None:
        self.tool_name = tool_name
        self.arguments = arguments
        self.final_resp = final_resp

    def plan_next_step(
        self,
        user_query: str,
        available_tools: list[dict[str, Any]],
        conversation_history: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], str | None]:
        executed = [
            m.get("tool_name") for m in conversation_history if m.get("role") == "tool_result"
        ]
        if not executed:
            return [{"tool_name": self.tool_name, "arguments": self.arguments}], None
        return [], self.final_resp


class SequentialMultiStepOfflineLLM(LLMInterface):
    """Deterministic planner yielding sequential tool calls across multiple iterations."""

    def __init__(self, steps: list[tuple[str, dict[str, Any]]], final_resp: str) -> None:
        self.steps = steps
        self.final_resp = final_resp

    def plan_next_step(
        self,
        user_query: str,
        available_tools: list[dict[str, Any]],
        conversation_history: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], str | None]:
        executed = [
            m.get("tool_name") for m in conversation_history if m.get("role") == "tool_result"
        ]
        step_idx = len(executed)
        if step_idx < len(self.steps):
            tool_name, arguments = self.steps[step_idx]
            return [{"tool_name": tool_name, "arguments": arguments}], None
        return [], self.final_resp


class BatchMultiCallOfflineLLM(LLMInterface):
    """Deterministic planner yielding multiple tool calls in a single planning iteration."""

    def __init__(self, calls: list[dict[str, Any]], final_resp: str) -> None:
        self.calls = calls
        self.final_resp = final_resp

    def plan_next_step(
        self,
        user_query: str,
        available_tools: list[dict[str, Any]],
        conversation_history: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], str | None]:
        executed = [
            m.get("tool_name") for m in conversation_history if m.get("role") == "tool_result"
        ]
        if not executed:
            return self.calls, None
        return [], self.final_resp


@pytest.fixture(autouse=True)
def clean_telemetry():
    """Ensure tracer is reset before and after every test."""
    reset_tracer_for_testing()
    yield
    reset_tracer_for_testing()


@pytest.fixture
def memory_tracer():
    """Initialize OpenTelemetry with an isolated in-memory exporter for offline assertions."""
    initialize_tracer(in_memory=True, force_reinit=True)
    exporter = get_in_memory_exporter()
    assert exporter is not None
    exporter.clear()
    return exporter


def make_test_gateway(caller_role: str = "operator") -> MCPGatewayProxy:
    """Helper creating a test gateway configured with an in-memory MockMCPClient."""
    client = MockMCPClient()
    proxy = MCPGatewayProxy(mcp_client=client, default_caller_role=caller_role)
    proxy._server_map = dict(client.tool_to_server)
    return proxy


# ==============================================================================
# 1. Span Hierarchy & Context Propagation Tests
# ==============================================================================


def test_span_hierarchy_agent_to_mcp_execution(memory_tracer):
    """Verify agent.run -> agent.plan -> agent.execute_tools -> gateway -> mcp execution

    maintains a strict parent-child relationship across asynchronous execution.
    """

    async def _test():
        llm = CannedOfflineLLM(
            tool_name="search_parts",
            arguments={"query": "motor", "category": "actuators"},
            final_resp="Motor parts inspection completed.",
        )
        gateway = make_test_gateway(caller_role="operator")
        agent = GatewayAgent(gateway=gateway, llm=llm, caller_role="operator")
        result = await agent.run("Find motor parts in catalog")

        assert result["is_complete"] is True
        assert len(result["executed_calls"]) == 1
        assert result["executed_calls"][0]["gateway_outcome"] == "success"

        spans = memory_tracer.get_finished_spans()
        span_names = [s.name for s in spans]

        assert "agent.run" in span_names
        assert "agent.plan" in span_names
        assert "agent.execute_tools" in span_names
        assert "gateway.invoke_tool" in span_names
        assert "mcp.tool.execute" in span_names

        # Lookup spans by name
        run_span = next(s for s in spans if s.name == "agent.run")
        plan_span = next(s for s in spans if s.name == "agent.plan")
        exec_span = next(s for s in spans if s.name == "agent.execute_tools")
        gw_span = next(s for s in spans if s.name == "gateway.invoke_tool")
        mcp_span = next(s for s in spans if s.name == "mcp.tool.execute")

        # Verify parentage
        assert run_span.parent is None or run_span.parent.span_id is None
        assert plan_span.parent.span_id == run_span.context.span_id
        assert exec_span.parent.span_id == run_span.context.span_id
        assert gw_span.parent.span_id == exec_span.context.span_id
        assert mcp_span.parent.span_id == gw_span.context.span_id

    asyncio.run(_test())


def test_gateway_invoke_tool_standalone_span(memory_tracer):
    """Verify gateway invocation generates parent and child spans when called directly."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")
        res = await gateway.invoke_tool(
            "search_parts",
            {"query": "sensor", "category": "sensors"},
            caller_role="operator",
        )

        assert res.outcome == "success"
        spans = memory_tracer.get_finished_spans()
        span_names = [s.name for s in spans]

        assert "gateway.invoke_tool" in span_names
        assert "mcp.tool.execute" in span_names

        gw_span = next(s for s in spans if s.name == "gateway.invoke_tool")
        mcp_span = next(s for s in spans if s.name == "mcp.tool.execute")

        assert mcp_span.parent.span_id == gw_span.context.span_id

    asyncio.run(_test())


def test_span_hierarchy_sequential_multi_step_tool_calls(memory_tracer):
    """Verify sequential tool calls across iterations maintain strict parentage

    without inheriting stale context from preceding steps.
    """

    async def _test():
        llm = SequentialMultiStepOfflineLLM(
            steps=[
                ("search_parts", {"query": "motor", "category": "actuators"}),
                ("get_inventory", {"part_id": "PART-100"}),
            ],
            final_resp="Verified motor parts and stock count.",
        )
        gateway = make_test_gateway(caller_role="operator")
        agent = GatewayAgent(gateway=gateway, llm=llm, caller_role="operator")
        result = await agent.run("Find motor and check stock")

        assert result["is_complete"] is True
        assert len(result["executed_calls"]) == 2

        spans = memory_tracer.get_finished_spans()
        run_span = next(s for s in spans if s.name == "agent.run")
        exec_spans = [s for s in spans if s.name == "agent.execute_tools"]
        gw_spans = [s for s in spans if s.name == "gateway.invoke_tool"]
        mcp_spans = [s for s in spans if s.name == "mcp.tool.execute"]

        assert len(exec_spans) == 2
        assert len(gw_spans) == 2
        assert len(mcp_spans) == 2

        # Distinguish spans using safe correlation attributes
        exec_1 = next(s for s in exec_spans if s.attributes.get("agent.iteration") == 1)
        exec_2 = next(s for s in exec_spans if s.attributes.get("agent.iteration") == 2)

        gw_1 = next(s for s in gw_spans if s.attributes.get("mcp.tool.name") == "search_parts")
        gw_2 = next(s for s in gw_spans if s.attributes.get("mcp.tool.name") == "get_inventory")

        mcp_1 = next(s for s in mcp_spans if s.attributes.get("mcp.tool.name") == "search_parts")
        mcp_2 = next(s for s in mcp_spans if s.attributes.get("mcp.tool.name") == "get_inventory")

        # Safe correlation via call_id attribute across gateway and MCP spans
        call_id_1 = gw_1.attributes.get("mcp.gateway.call_id")
        call_id_2 = gw_2.attributes.get("mcp.gateway.call_id")
        assert call_id_1 is not None and call_id_2 is not None
        assert call_id_1 != call_id_2
        assert mcp_1.attributes.get("mcp.gateway.call_id") == call_id_1
        assert mcp_2.attributes.get("mcp.gateway.call_id") == call_id_2

        # Trace ID propagation: all spans belong to the single agent.run trace
        assert run_span.context.trace_id is not None
        assert exec_1.context.trace_id == run_span.context.trace_id
        assert exec_2.context.trace_id == run_span.context.trace_id
        assert gw_1.context.trace_id == run_span.context.trace_id
        assert gw_2.context.trace_id == run_span.context.trace_id
        assert mcp_1.context.trace_id == run_span.context.trace_id
        assert mcp_2.context.trace_id == run_span.context.trace_id

        # Root and iteration execution parents (actual span IDs vs parent span IDs)
        assert run_span.parent is None or run_span.parent.span_id is None
        assert exec_1.parent.span_id == run_span.context.span_id
        assert exec_2.parent.span_id == run_span.context.span_id

        # Direct parent-child matching for each iteration
        assert gw_1.parent.span_id == exec_1.context.span_id
        assert mcp_1.parent.span_id == gw_1.context.span_id

        assert gw_2.parent.span_id == exec_2.context.span_id
        assert mcp_2.parent.span_id == gw_2.context.span_id

        # Anti-pollution assertions: Second call must not inherit first call's context
        assert gw_2.parent.span_id != gw_1.context.span_id
        assert gw_2.parent.span_id != mcp_1.context.span_id
        assert gw_2.parent.span_id != exec_1.context.span_id
        assert exec_1.context.span_id != exec_2.context.span_id
        assert gw_1.context.span_id != gw_2.context.span_id
        assert mcp_1.context.span_id != mcp_2.context.span_id

    asyncio.run(_test())


def test_span_hierarchy_multiple_tool_calls_in_one_iteration(memory_tracer):
    """Verify multiple tool calls in a single planning iteration execute as siblings

    under one shared execution span without sibling nesting.
    """

    async def _test():
        llm = BatchMultiCallOfflineLLM(
            calls=[
                {
                    "tool_name": "search_parts",
                    "arguments": {"query": "motor", "category": "actuators"},
                },
                {"tool_name": "get_inventory", "arguments": {"part_id": "PART-100"}},
            ],
            final_resp="Batch parts and inventory check completed.",
        )
        gateway = make_test_gateway(caller_role="operator")
        agent = GatewayAgent(gateway=gateway, llm=llm, caller_role="operator")
        result = await agent.run("Find motor and stock together")

        assert result["is_complete"] is True
        assert len(result["executed_calls"]) == 2

        spans = memory_tracer.get_finished_spans()
        run_span = next(s for s in spans if s.name == "agent.run")
        exec_spans = [s for s in spans if s.name == "agent.execute_tools"]
        gw_spans = [s for s in spans if s.name == "gateway.invoke_tool"]
        mcp_spans = [s for s in spans if s.name == "mcp.tool.execute"]

        # Exactly one agent.execute_tools span for the single iteration
        assert len(exec_spans) == 1
        exec_span = exec_spans[0]
        assert len(gw_spans) == 2
        assert len(mcp_spans) == 2

        # Distinguish spans using safe correlation attributes
        gw_1 = next(s for s in gw_spans if s.attributes.get("mcp.tool.name") == "search_parts")
        gw_2 = next(s for s in gw_spans if s.attributes.get("mcp.tool.name") == "get_inventory")

        mcp_1 = next(s for s in mcp_spans if s.attributes.get("mcp.tool.name") == "search_parts")
        mcp_2 = next(s for s in mcp_spans if s.attributes.get("mcp.tool.name") == "get_inventory")

        # Safe correlation via call_id attribute across sibling gateway and MCP spans
        call_id_1 = gw_1.attributes.get("mcp.gateway.call_id")
        call_id_2 = gw_2.attributes.get("mcp.gateway.call_id")
        assert call_id_1 is not None and call_id_2 is not None
        assert call_id_1 != call_id_2
        assert mcp_1.attributes.get("mcp.gateway.call_id") == call_id_1
        assert mcp_2.attributes.get("mcp.gateway.call_id") == call_id_2

        # Trace ID propagation: all spans belong to the single agent.run trace
        assert run_span.context.trace_id is not None
        assert exec_span.context.trace_id == run_span.context.trace_id
        assert gw_1.context.trace_id == run_span.context.trace_id
        assert gw_2.context.trace_id == run_span.context.trace_id
        assert mcp_1.context.trace_id == run_span.context.trace_id
        assert mcp_2.context.trace_id == run_span.context.trace_id

        # Root and agent.execute_tools parentage
        assert run_span.parent is None or run_span.parent.span_id is None
        assert exec_span.parent.span_id == run_span.context.span_id

        # Both gateway invocations are children of the SAME agent.execute_tools span
        assert gw_1.parent.span_id == exec_span.context.span_id
        assert gw_2.parent.span_id == exec_span.context.span_id

        # The gateway invocation spans are siblings, NOT parent and child of each other
        assert gw_1.parent.span_id != gw_2.context.span_id
        assert gw_2.parent.span_id != gw_1.context.span_id
        assert gw_1.context.span_id != gw_2.context.span_id

        # Each MCP execution span is a direct child of its own corresponding gateway invocation
        assert mcp_1.parent.span_id == gw_1.context.span_id
        assert mcp_2.parent.span_id == gw_2.context.span_id

        # Cross-isolation between sibling execution branches
        assert mcp_1.parent.span_id != gw_2.context.span_id
        assert mcp_2.parent.span_id != gw_1.context.span_id
        assert gw_2.parent.span_id != mcp_1.context.span_id
        assert mcp_1.context.span_id != mcp_2.context.span_id

    asyncio.run(_test())


# ==============================================================================
# 2. Correlation Identifier Tests
# ==============================================================================


def test_correlation_identifiers_in_spans_and_records(memory_tracer):
    """Verify call_id, session_id, and trace/span IDs are preserved and correlated."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")
        session_id = "test_sess_corr_123"

        res = await gateway.invoke_tool(
            "search_parts",
            {"query": "motor", "category": "actuators"},
            caller_role="operator",
            session_id=session_id,
        )

        assert res.outcome == "success"
        assert res.call_id is not None
        assert res.trace_id is not None
        assert res.span_id is not None

        # Check record metadata
        assert res.record is not None
        assert res.record.metadata.get("trace_id") == res.trace_id
        assert res.record.metadata.get("span_id") == res.span_id

        spans = memory_tracer.get_finished_spans()
        gw_span = next(s for s in spans if s.name == "gateway.invoke_tool")

        assert gw_span.attributes.get("mcp.gateway.call_id") == res.call_id
        assert gw_span.attributes.get("mcp.gateway.session_id") == session_id
        assert gw_span.attributes.get("mcp.gateway.session_seq") == 1
        assert gw_span.attributes.get("mcp.gateway.caller_role") == "operator"
        assert gw_span.attributes.get("mcp.gateway.outcome") == "success"

    asyncio.run(_test())


def test_approval_correlation_when_approval_required(memory_tracer):
    """Verify approval_id is attached to spans when human approval is triggered."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")
        # send_email with all@example.internal by operator requires approval per policy
        res = await gateway.invoke_tool(
            "send_email",
            {"to": "all@example.internal", "subject": "All staff", "body": "Meeting notice"},
            caller_role="operator",
        )

        assert res.outcome == "denied"
        assert res.approval_id is not None

        spans = memory_tracer.get_finished_spans()
        gw_span = next(s for s in spans if s.name == "gateway.invoke_tool")

        assert gw_span.attributes.get("mcp.approval.id") == res.approval_id
        assert gw_span.attributes.get("mcp.gateway.reason_code") == "REQUIRE_APPROVAL"

    asyncio.run(_test())


# ==============================================================================
# 3. Privacy Allowlist & Redaction Tests
# ==============================================================================


def test_sanitize_span_attributes_strict_allowlist():
    """Verify that only attributes in ALLOWLISTED_SPAN_ATTRIBUTES are retained."""
    raw_attrs = {
        "mcp.tool.name": "read_file",
        "mcp.gateway.call_id": "call_12345",
        "raw_tool_arguments": {"secret": "super_secret_value"},  # FORBIDDEN
        "tool_output": "confidential database dump",  # FORBIDDEN
        "password": "my_admin_password",  # FORBIDDEN
        "agent.session_id": "sess_999",
    }

    sanitized = sanitize_span_attributes(raw_attrs)

    assert "mcp.tool.name" in sanitized
    assert "mcp.gateway.call_id" in sanitized
    assert "agent.session_id" in sanitized
    assert "raw_tool_arguments" not in sanitized
    assert "tool_output" not in sanitized
    assert "password" not in sanitized


def test_sanitize_attribute_values_redact_sensitive_content():
    """Verify canaries, card numbers, and SSNs in allowlisted attributes are scrubbed."""
    val_with_canary = "Found CANARY_SYNTHETIC_ALPHA_987654321 in file."
    val_with_card = "Card number 4111-1111-1111-1111 was checked."
    val_with_ssn = "Tax id 123-45-6789 provided."

    clean_canary = sanitize_attribute_value(val_with_canary)
    clean_card = sanitize_attribute_value(val_with_card)
    clean_ssn = sanitize_attribute_value(val_with_ssn)

    assert "CANARY_SYNTHETIC_ALPHA" not in clean_canary
    assert "[REDACTED_CONFIDENTIAL_TOKEN]" in clean_canary

    assert "4111-1111-1111-1111" not in clean_card
    assert "[REDACTED_CARD]" in clean_card

    assert "123-45-6789" not in clean_ssn
    assert "[REDACTED_SSN]" in clean_ssn


def test_no_raw_arguments_or_outputs_in_spans(memory_tracer):
    """Verify that tool invocations never leak raw arguments, outputs, or canaries into spans."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")

        # 1. Allowed call with arguments
        res1 = await gateway.invoke_tool(
            "search_parts",
            {"query": "actuator_42", "category": "actuators"},
            caller_role="operator",
        )
        assert res1.outcome == "success"

        # 2. Blocked call targeting canary document
        res2 = await gateway.invoke_tool(
            "read_file",
            {"filename": "internal_memo_canary.txt"},
            caller_role="operator",
        )
        assert res2.outcome == "denied"

        spans = memory_tracer.get_finished_spans()
        for s in spans:
            attrs = s.attributes
            # Check that every attribute key is on the allowlist
            for k, v in attrs.items():
                assert k in ALLOWLISTED_SPAN_ATTRIBUTES, (
                    f"Disallowed attribute key '{k}' found on span!"
                )
                val_str = str(v)
                assert "CANARY_SYNTHETIC_ALPHA" not in val_str
                assert "actuator_42" not in val_str, (
                    "Raw argument value leaked into span attribute!"
                )
                assert "internal_memo_canary.txt" not in val_str, (
                    "Raw filename argument leaked into span attribute!"
                )

    asyncio.run(_test())


# ==============================================================================
# 4. Disabled Telemetry Tests (Default Behavior)
# ==============================================================================


def test_telemetry_disabled_by_default():
    """Verify that telemetry is disabled by default in settings and tracer behaves safely."""
    settings = get_settings()
    assert settings.otel_enabled is False
    assert is_telemetry_enabled() is False

    # Initialize with default settings (disabled)
    initialize_tracer(force_reinit=True)
    exporter = get_in_memory_exporter()
    assert exporter is None

    # Context manager still yields safely without raising
    with safe_start_span("test.span") as span:
        safe_set_span_attributes(span, {"mcp.tool.name": "test"})


def test_agent_and_gateway_operate_normally_with_telemetry_disabled():
    """Ensure agent and gateway perform enforcement and execution when telemetry is disabled."""

    async def _test():
        reset_tracer_for_testing()
        llm = CannedOfflineLLM(
            tool_name="search_parts",
            arguments={"query": "motor", "category": "actuators"},
            final_resp="Finished search.",
        )
        gateway = make_test_gateway(caller_role="operator")
        agent = GatewayAgent(gateway=gateway, llm=llm, caller_role="operator")
        res = await agent.run("Search motor parts")

        assert res["is_complete"] is True
        assert len(res["executed_calls"]) == 1
        assert res["executed_calls"][0]["gateway_outcome"] == "success"

    asyncio.run(_test())


# ==============================================================================
# 5. Missing Credentials & Optional Langfuse Tests
# ==============================================================================


def test_langfuse_disabled_by_default_and_missing_credentials():
    """Verify LangfuseAdapter cleanly operates as a no-op when disabled or keys are missing."""
    adapter = LangfuseAdapter(enabled=False)
    assert adapter.is_enabled is False

    # Should not raise any error
    adapter.trace_event("test_event", {"key": "val"})
    adapter.trace_generation("test_gen", "model", [], {})
    adapter.trace_tool_call("test_tool", "call_1", "sess_1", "success", 12.5)


def test_langfuse_missing_keys_gracefully_disables():
    """Verify LangfuseAdapter disables itself if enabled=True but keys are absent."""
    adapter = LangfuseAdapter(
        enabled=True,
        public_key="",
        secret_key=None,
    )
    assert adapter.is_enabled is False


def test_langfuse_client_import_failure_is_handled():
    """Verify LangfuseAdapter handles missing library gracefully."""
    adapter = LangfuseAdapter(enabled=True, public_key="pk_test", secret_key="sk_test")
    with patch("builtins.__import__", side_effect=ImportError("No module named langfuse")):
        # Should not crash
        assert adapter._get_client() is None


# ==============================================================================
# 6. Injected Telemetry Failure Containment Tests
# ==============================================================================


def test_telemetry_failure_in_safe_start_span_does_not_break_caller(memory_tracer):
    """Verify that an exception in tracer.start_as_current_span is caught and logged."""
    with patch("mcp_agent_gateway.observability.tracer.get_tracer") as mock_get_tracer:
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.side_effect = RuntimeError("Simulated OTLP SDK crash")
        mock_get_tracer.return_value = mock_tracer

        executed = False
        with safe_start_span("resilient.span") as span:
            assert span is None
            executed = True

        assert executed is True


def test_gateway_enforces_policy_even_if_telemetry_raises():
    """Verify that telemetry failures never bypass policy or block gateway enforcement."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")

        with patch("mcp_agent_gateway.observability.tracer.get_tracer") as mock_get_tracer:
            failing_tracer = MagicMock()
            failing_tracer.start_as_current_span.side_effect = RuntimeError(
                "OTLP collector disconnected"
            )
            mock_get_tracer.return_value = failing_tracer

            # 1. Benign authorized call succeeds despite telemetry failure
            res = await gateway.invoke_tool(
                "search_parts",
                {"query": "fastener", "category": "fasteners"},
                caller_role="operator",
            )
            assert res.outcome == "success"

            # 2. Denied call is still DENIED despite telemetry failure
            res_denied = await gateway.invoke_tool(
                "read_file", {"filename": "unknown.txt"}, caller_role="untrusted"
            )
            assert res_denied.outcome == "denied"
            assert res_denied.policy_decision is not None
            assert res_denied.policy_decision.get("allowed") is False

    asyncio.run(_test())


def test_langfuse_failure_does_not_affect_gateway():
    """Verify that an exception raised by LangfuseAdapter never bubbles up to the gateway."""

    async def _test():
        gateway = make_test_gateway(caller_role="operator")

        with patch("mcp_agent_gateway.gateway.proxy.get_langfuse_adapter") as mock_lf:
            failing_adapter = MagicMock()
            failing_adapter.is_enabled = True
            failing_adapter.trace_tool_call.side_effect = RuntimeError("Langfuse server 500 error")
            mock_lf.return_value = failing_adapter

            # Tool invocation should succeed without raising
            res = await gateway.invoke_tool(
                "search_parts",
                {"query": "sensor", "category": "sensors"},
                caller_role="operator",
            )
            assert res.outcome == "success"
            assert res.result.get("status") == "ok"

    asyncio.run(_test())


# ==============================================================================
# 7. Enhanced Security & Privacy Remediation Tests
# ==============================================================================


def test_sanitize_attribute_values_redact_emails_and_phones():
    """Verify that email addresses and phone numbers are redacted across formats."""
    val_email = "Contact user at alice.smith+support@company.internal or admin@example.com."
    val_phone1 = "Call (415) 555-2671 for immediate assistance."
    val_phone2 = "Direct line is 555-123-4567 or +1-800-555-0199."
    val_intl = "London office: +44 20 7946 0958."

    clean_email = sanitize_attribute_value(val_email)
    clean_phone1 = sanitize_attribute_value(val_phone1)
    clean_phone2 = sanitize_attribute_value(val_phone2)
    clean_intl = sanitize_attribute_value(val_intl)

    assert "alice.smith+support@company.internal" not in clean_email
    assert "admin@example.com" not in clean_email
    assert "[REDACTED_EMAIL]" in clean_email

    assert "415) 555-2671" not in clean_phone1
    assert "[REDACTED_PHONE]" in clean_phone1

    assert "555-123-4567" not in clean_phone2
    assert "800-555-0199" not in clean_phone2
    assert "[REDACTED_PHONE]" in clean_phone2

    assert "7946 0958" not in clean_intl
    assert "[REDACTED_PHONE]" in clean_intl

    # Non-sensitive dates and identifiers must remain untouched
    val_safe = "Record date 2026-11-04 for PART-101 and gw_call_12345 seq 42."
    clean_safe = sanitize_attribute_value(val_safe)
    assert clean_safe == val_safe


def test_sanitize_attribute_values_redact_credentials():
    """Verify that bearer tokens, api keys, and passwords are redacted."""
    val_bearer = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
    val_apikey = "Configured api_key=sk-proj-9876543210fedcba in client."
    val_password = "User set password: supersecretpassword123 for service."

    clean_bearer = sanitize_attribute_value(val_bearer)
    clean_apikey = sanitize_attribute_value(val_apikey)
    clean_password = sanitize_attribute_value(val_password)

    assert "eyJhbGci" not in clean_bearer
    assert "[REDACTED_CREDENTIAL]" in clean_bearer

    assert "sk-proj-9876543210" not in clean_apikey
    assert "[REDACTED_CREDENTIAL]" in clean_apikey

    assert "supersecretpassword123" not in clean_password
    assert "[REDACTED_CREDENTIAL]" in clean_password


def test_sanitize_nested_dictionaries_and_sequences():
    """Verify recursive sanitization across nested dicts, lists, and tuples."""
    raw_nested = {
        "user_profile": {
            "contact_email": "person@example.com",
            "contact_phone": "415-555-9999",
            "account_card": "4111-1111-1111-1111",
        },
        "flags": [
            "CANARY_SYNTHETIC_ALPHA_888",
            "bearer secret_access_token_abc",
            123,
            True,
        ],
        "meta_tuple": (
            {"internal_memo": "memo with CANARY_SYNTHETIC_ALPHA_777"},
            "regular_identifier",
        ),
        "status_code": 200,
    }

    sanitized = sanitize_attribute_value(raw_nested)

    assert sanitized["user_profile"]["contact_email"] == "[REDACTED_EMAIL]"
    assert sanitized["user_profile"]["contact_phone"] == "[REDACTED_PHONE]"
    assert sanitized["user_profile"]["account_card"] == "[REDACTED_CARD]"

    assert sanitized["flags"][0] == "[REDACTED_CONFIDENTIAL_TOKEN]"
    assert sanitized["flags"][1] == "[REDACTED_CREDENTIAL]"
    assert sanitized["flags"][2] == 123
    assert sanitized["flags"][3] is True

    assert sanitized["meta_tuple"][0]["internal_memo"] == "memo with [REDACTED_CONFIDENTIAL_TOKEN]"
    assert sanitized["meta_tuple"][1] == "regular_identifier"
    assert sanitized["status_code"] == 200


def test_sanitize_attribute_values_avoids_unsafe_stringification():
    """Verify that arbitrary complex objects are not unsafely converted via str()."""

    class MaliciousExploitObject:
        def __str__(self):
            raise AssertionError("str() should never be called on arbitrary objects!")

        def __repr__(self):
            return "LEAKED_PRIVATE_STATE"

    res = sanitize_attribute_value(MaliciousExploitObject())
    assert res == "<MaliciousExploitObject>"
    assert "LEAKED_PRIVATE_STATE" not in res


def test_sanitize_oversized_and_malicious_strings():
    """Verify that oversized telemetry strings are capped and sanitized."""
    huge_str = "A" * 5000 + " CANARY_SYNTHETIC_ALPHA_SECRET " + "B" * 5000
    cleaned = sanitize_attribute_value(huge_str)

    assert len(cleaned) <= 550
    assert "...[TRUNCATED]" in cleaned
    assert "CANARY_SYNTHETIC_ALPHA" not in cleaned


def test_langfuse_mock_client_payload_sanitization():
    """Verify Langfuse mock client receives strictly sanitized payloads."""
    mock_client = MagicMock()
    adapter = LangfuseAdapter(enabled=True, client=mock_client)

    # 1. Event recording with sensitive metadata
    adapter.trace_event(
        name="user_action:alice@example.com",
        attributes={
            "mcp.tool.name": "search_parts",
            "raw_tool_arguments": {"secret": "secret_argument_val"},  # Must be dropped
            "mcp.gateway.call_id": "call_123",
            "bearer_token": "bearer eyJhbGciOi...secret",  # Must be dropped
        },
        session_id="sess_canary_CANARY_SYNTHETIC_ALPHA_999",
    )

    assert mock_client.event.called
    call_kwargs = mock_client.event.call_args.kwargs
    assert call_kwargs["name"] == "user_action:[REDACTED_EMAIL]"
    meta = call_kwargs["metadata"]
    assert meta["session_id"] == "sess_canary_[REDACTED_CONFIDENTIAL_TOKEN]"
    assert meta["mcp.tool.name"] == "search_parts"
    assert "raw_tool_arguments" not in meta
    assert "bearer_token" not in meta

    # 2. Generation recording with prompt and completion containing canaries & credentials
    mock_client.reset_mock()
    adapter.trace_generation(
        name="plan:eng@corp.internal",
        model="gemini-2.5-api_key=secretkey123",
        prompt_summary="Query for user 4111-1111-1111-1111 and phone 415-555-1234",
        completion_summary="Found CANARY_SYNTHETIC_ALPHA_444 and password: mypass",
        metadata={
            "agent.iteration": 1,
            "secret_key": "should_be_stripped",
            "mcp.tool.name": "get_inventory",
        },
        session_id="sess_user@domain.com",
    )

    assert mock_client.generation.called
    gen_kwargs = mock_client.generation.call_args.kwargs
    assert gen_kwargs["name"] == "plan:[REDACTED_EMAIL]"
    assert gen_kwargs["model"] == "gemini-2.5-[REDACTED_CREDENTIAL]"
    assert "[REDACTED_CARD]" in gen_kwargs["input"]
    assert "[REDACTED_PHONE]" in gen_kwargs["input"]
    assert "4111-1111-1111-1111" not in gen_kwargs["input"]
    assert "415-555-1234" not in gen_kwargs["input"]
    assert "[REDACTED_CONFIDENTIAL_TOKEN]" in gen_kwargs["output"]
    assert "[REDACTED_CREDENTIAL]" in gen_kwargs["output"]
    assert "CANARY_SYNTHETIC_ALPHA" not in gen_kwargs["output"]
    assert "mypass" not in gen_kwargs["output"]
    assert gen_kwargs["metadata"]["session_id"] == "[REDACTED_EMAIL]"
    assert "secret_key" not in gen_kwargs["metadata"]


def test_langfuse_session_id_sanitization():
    """Verify session_id scrubbing in trace_event, trace_generation, and trace_tool_call."""
    mock_client = MagicMock()
    adapter = LangfuseAdapter(enabled=True, client=mock_client)

    dirty_session = "sess_user@test.org_phone_555-123-4567"
    adapter.trace_tool_call(
        tool_name="read_file",
        call_id="call_99",
        session_id=dirty_session,
        outcome="success",
        duration_ms=10.0,
    )

    assert mock_client.event.called
    meta = mock_client.event.call_args.kwargs["metadata"]
    assert "user@test.org" not in meta["session_id"]
    assert "555-123-4567" not in meta["session_id"]
    assert "[REDACTED_EMAIL]" in meta["session_id"]
    assert "[REDACTED_PHONE]" in meta["session_id"]


def test_safe_start_span_get_tracer_failure_containment():
    """Verify get_tracer() raising inside safe_start_span() is safely caught."""
    with patch(
        "mcp_agent_gateway.observability.tracer.get_tracer",
        side_effect=RuntimeError("OTel registry unavailable"),
    ):
        executed = False
        with safe_start_span("span.get_tracer_fail") as span:
            assert span is None
            executed = True
        assert executed is True


def test_safe_start_span_sanitize_attributes_failure_containment():
    """Verify attribute sanitization raising inside safe_start_span() is safely caught."""
    with patch(
        "mcp_agent_gateway.observability.tracer.sanitize_span_attributes",
        side_effect=TypeError("Corrupt attribute structure"),
    ):
        executed = False
        with safe_start_span(
            "span.sanitize_fail", attributes={"mcp.tool.name": "search_parts"}
        ) as span:
            assert span is None
            executed = True
        assert executed is True


def test_safe_start_span_context_enter_and_exit_failures():
    """Verify safe_start_span() contains both context __enter__ and __exit__ errors."""
    # 1. Context __enter__ raises
    with patch("mcp_agent_gateway.observability.tracer.get_tracer") as mock_get_tracer:
        mock_tracer = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.side_effect = RuntimeError("Context enter failure")
        mock_tracer.start_as_current_span.return_value = mock_cm
        mock_get_tracer.return_value = mock_tracer

        executed_enter = False
        with safe_start_span("span.enter_fail") as span:
            assert span is None
            executed_enter = True
        assert executed_enter is True

    # 2. Context __exit__ raises on clean exit
    with patch("mcp_agent_gateway.observability.tracer.get_tracer") as mock_get_tracer:
        mock_tracer = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock()
        mock_cm.__exit__.side_effect = RuntimeError("Context exit failure")
        mock_tracer.start_as_current_span.return_value = mock_cm
        mock_get_tracer.return_value = mock_tracer

        executed_exit = False
        with safe_start_span("span.exit_fail") as span:
            assert span is not None
            executed_exit = True
        # Should not raise
        assert executed_exit is True


def test_safe_start_span_preserves_application_exceptions():
    """Verify application exceptions propagate completely intact even if telemetry exits fail."""
    with patch("mcp_agent_gateway.observability.tracer.get_tracer") as mock_get_tracer:
        mock_tracer = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock()
        mock_cm.__exit__.side_effect = RuntimeError("Telemetry cleanup crash")
        mock_tracer.start_as_current_span.return_value = mock_cm
        mock_get_tracer.return_value = mock_tracer

        with (
            pytest.raises(ValueError, match="Real business logic error"),
            safe_start_span("span.preserve_app_err"),
        ):
            raise ValueError("Real business logic error")


def test_safe_set_span_attributes_failure_containment():
    """Verify safe_set_span_attributes catches all set_attribute exceptions safely."""
    mock_span = MagicMock()
    mock_span.set_attribute.side_effect = RuntimeError("Span already closed")

    # Should not raise any error
    safe_set_span_attributes(mock_span, {"mcp.tool.name": "search_parts"})
    safe_set_span_attributes(None, {"mcp.tool.name": "search_parts"})
    safe_set_span_attributes(mock_span, None)
