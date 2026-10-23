"""Phase 2 tests for MCP Gateway Proxy, call recording, and gateway-backed agent."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from mcp_agent_gateway.agent.direct_agent import DirectBaselineAgent
from mcp_agent_gateway.agent.gateway_agent import GatewayAgent
from mcp_agent_gateway.agent.scenarios import GATEWAY_DEMO_SCENARIO, run_gateway_scenario
from mcp_agent_gateway.gateway.proxy import GatewayInvocationResult, MCPGatewayProxy
from mcp_agent_gateway.gateway.records import InMemoryCallRecorder, ToolCallRecord


# ---------------------------------------------------------------------------
# 1. Unit Tests for Call Recording
# ---------------------------------------------------------------------------
def test_in_memory_call_recorder_crud():
    """Verify in-memory recorder correctly stores, retrieves, and clears records."""
    recorder = InMemoryCallRecorder()
    assert len(recorder) == 0

    record = ToolCallRecord(
        call_id="gw_call_test123",
        timestamp_utc="2026-10-22T10:00:00Z",
        server_name="parts",
        tool_name="get_inventory",
        arguments={"part_id": "PART-101"},
        outcome="success",
        result={"found": True},
        duration_ms=12.5,
    )
    recorder.record(record)
    assert len(recorder) == 1

    stored = recorder.get_records()
    assert len(stored) == 1
    assert stored[0].call_id == "gw_call_test123"

    found = recorder.find_by_call_id("gw_call_test123")
    assert found is not None
    assert found.tool_name == "get_inventory"

    not_found = recorder.find_by_call_id("nonexistent_id")
    assert not_found is None

    recorder.clear()
    assert len(recorder) == 0


# ---------------------------------------------------------------------------
# 2. Gateway Proxy Unit Tests (Mocked MultiServerMCPClient)
# ---------------------------------------------------------------------------
def test_gateway_forward_valid_call_mocked():
    """Verify gateway forwards valid call to client and records outcome."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock(
        return_value={
            "synthetic": True,
            "found": True,
            "part": {"id": "PART-101", "name": "High-Torque Stepper Motor 24V"},
        }
    )

    recorder = InMemoryCallRecorder()
    gateway = MCPGatewayProxy(mcp_client=mock_client, recorder=recorder)

    res: GatewayInvocationResult = gateway.invoke_tool_sync(
        "get_inventory", {"part_id": "PART-101"}
    )

    assert res.outcome == "success"
    assert res.server_name == "parts"
    assert res.tool_name == "get_inventory"
    assert res.result["found"] is True
    assert res.call_id.startswith("gw_call_")
    assert res.duration_ms >= 0.0

    # Verify call record was created
    records = recorder.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.call_id == res.call_id
    assert rec.outcome == "success"
    assert rec.arguments == {"part_id": "PART-101"}
    assert rec.result["part"]["id"] == "PART-101"


def test_gateway_unknown_tool_rejection():
    """Verify calling an unknown tool produces an unknown_tool outcome without crashing."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {}
    mock_client.discover_tools = AsyncMock(return_value=[])

    recorder = InMemoryCallRecorder()
    gateway = MCPGatewayProxy(mcp_client=mock_client, recorder=recorder)

    res: GatewayInvocationResult = gateway.invoke_tool_sync("unregistered_tool", {"x": 1})

    assert res.outcome == "unknown_tool"
    assert res.server_name == "unknown"
    assert res.result["status"] == "error"
    assert "not found" in res.result["error"]

    records = recorder.get_records()
    assert len(records) == 1
    assert records[0].outcome == "unknown_tool"


def test_gateway_forwarding_exception_handling():
    """Verify transport exceptions during tool invocation are cleanly captured and recorded."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock(
        side_effect=RuntimeError("Subprocess communication pipe broken")
    )

    recorder = InMemoryCallRecorder()
    gateway = MCPGatewayProxy(mcp_client=mock_client, recorder=recorder)

    res: GatewayInvocationResult = gateway.invoke_tool_sync(
        "get_inventory", {"part_id": "PART-101"}
    )

    assert res.outcome == "error"
    assert res.server_name == "parts"
    assert res.result["status"] == "error"
    assert "Subprocess communication pipe broken" in res.error

    records = recorder.get_records()
    assert len(records) == 1
    assert records[0].outcome == "error"
    assert "Subprocess communication pipe broken" in records[0].error_message


# ---------------------------------------------------------------------------
# 3. Gateway Agent Unit Tests
# ---------------------------------------------------------------------------
def test_gateway_agent_routes_through_proxy():
    """Verify GatewayAgent invokes tools strictly through MCPGatewayProxy."""
    mock_gateway = MagicMock()
    mock_gateway.discover_tools = AsyncMock(return_value=[])
    mock_gateway.recorder = InMemoryCallRecorder()
    mock_gateway.invoke_tool = AsyncMock(
        return_value=GatewayInvocationResult(
            call_id="gw_call_agent_mock",
            server_name="parts",
            tool_name="get_inventory",
            outcome="success",
            result={
                "found": True,
                "part": {"name": "High-Torque Stepper Motor 24V", "stock_count": 120},
            },
        )
    )

    agent = GatewayAgent(gateway=mock_gateway)
    state = agent.run_sync("Check stock count and details for part PART-101")

    assert state["is_complete"] is True
    assert len(state["executed_calls"]) >= 1

    # Verify proxy was invoked
    mock_gateway.invoke_tool.assert_called_once()
    call_args = mock_gateway.invoke_tool.call_args
    assert call_args[0][0] == "get_inventory"
    assert call_args[0][1] == {"part_id": "PART-101"}

    # Verify state record contains gateway metadata
    executed = state["executed_calls"][0]
    assert executed["gateway_call_id"] == "gw_call_agent_mock"
    assert executed["gateway_outcome"] == "success"
    assert executed["server_name"] == "parts"


def test_direct_baseline_agent_remains_unmediated():
    """Verify DirectBaselineAgent does not use MCPGatewayProxy or record gateway calls."""
    agent = DirectBaselineAgent()
    # Confirm DirectBaselineAgent does not have a gateway attribute
    assert not hasattr(agent, "gateway")
    assert hasattr(agent, "mcp_client")


# ---------------------------------------------------------------------------
# 4. Integration Tests with Live Local MCP Stdio Servers
# ---------------------------------------------------------------------------
def test_gateway_stdio_integration_parts_server():
    """Integration test: GatewayProxy intercepts real stdio call to parts_server."""

    async def _run():
        gateway = MCPGatewayProxy()
        # 1. Discover tools
        tools = await gateway.discover_tools()
        assert any(t.name == "search_parts" for t in tools)
        assert any(t.name == "get_inventory" for t in tools)

        # 2. Invoke tool through gateway
        inv_res = await gateway.invoke_tool("search_parts", {"query": "relay"})
        assert inv_res.outcome == "success"
        assert inv_res.server_name == "parts"
        assert inv_res.result["count"] >= 1
        assert any(p["id"] == "PART-105" for p in inv_res.result["parts"])

        # 3. Verify record was stored in memory
        records = gateway.recorder.get_records()
        assert len(records) == 1
        assert records[0].call_id == inv_res.call_id
        assert records[0].tool_name == "search_parts"
        assert records[0].server_name == "parts"
        assert records[0].outcome == "success"

    asyncio.run(_run())


def test_gateway_scenario_runner():
    """Verify run_gateway_scenario executes scenario through GatewayAgent and captures records."""
    res = run_gateway_scenario(GATEWAY_DEMO_SCENARIO)

    assert res.scenario_id == "SCENARIO-GW-01-PARTS"
    assert len(res.tool_calls) >= 1
    first_call = res.tool_calls[0]
    assert first_call["tool"] == "get_inventory"
    assert first_call["gateway_call_id"] is not None
    assert first_call["gateway_outcome"] == "success"
    assert res.raw_state.get("gateway_records_count", 0) >= 1
