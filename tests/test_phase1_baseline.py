"""Phase 1 baseline tests: MCP servers, direct LangGraph agent, and security scenarios."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from mcp_agent_gateway.agent.client import MultiServerMCPClient
from mcp_agent_gateway.agent.direct_agent import DirectBaselineAgent
from mcp_agent_gateway.agent.scenarios import (
    BASELINE_SCENARIOS,
    run_scenario,
)
from mcp_agent_gateway.tools.email_server import create_email_server
from mcp_agent_gateway.tools.files_server import create_files_server, validate_path_safety
from mcp_agent_gateway.tools.parts_server import create_parts_server


# ---------------------------------------------------------------------------
# 1. Parts Server Unit Tests
# ---------------------------------------------------------------------------
def test_parts_server_search():
    """Verify parts server search_parts tool returns structured synthetic parts."""
    server = create_parts_server()
    search_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "search_parts":
            search_tool = t.fn
            break

    assert search_tool is not None
    res = search_tool(query="motor")
    assert res["synthetic"] is True
    assert res["count"] >= 1
    assert any(p["id"] == "PART-101" for p in res["parts"])


def test_parts_server_get_inventory():
    """Verify get_inventory returns valid details for existing and missing parts."""
    server = create_parts_server()
    inv_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "get_inventory":
            inv_tool = t.fn
            break

    assert inv_tool is not None

    # Found
    res = inv_tool(part_id="PART-101")
    assert res["found"] is True
    assert res["part"]["stock_count"] == 120
    assert res["in_stock"] is True

    # Not found
    missing = inv_tool(part_id="PART-NONEXISTENT")
    assert missing["found"] is False
    assert "error" in missing


# ---------------------------------------------------------------------------
# 2. Files Server Unit Tests & Path Safety
# ---------------------------------------------------------------------------
def test_files_server_list_and_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify file operations within sandbox directory."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    sample_file = sandbox_dir / "test_doc.txt"
    sample_file.write_text("Hello synthetic canary world!", encoding="utf-8")

    monkeypatch.setenv("SYNTHETIC_DOCS_DIR", str(sandbox_dir))

    server = create_files_server()
    list_tool = None
    read_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "list_files":
            list_tool = t.fn
        elif t.name == "read_file":
            read_tool = t.fn

    assert list_tool is not None
    assert read_tool is not None

    # List files
    list_res = list_tool()
    assert list_res["status"] == "ok"
    assert list_res["count"] == 1
    assert list_res["files"][0]["name"] == "test_doc.txt"

    # Read file
    read_res = read_tool(filename="test_doc.txt")
    assert read_res["status"] == "ok"
    assert "Hello synthetic canary world!" in read_res["content"]

    # Read nonexistent file in sandbox
    missing_res = read_tool(filename="nonexistent_doc.txt")
    assert missing_res["status"] == "not_found"
    assert "not found" in missing_res["error"].lower()


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../outside.txt",
        "../../etc/passwd",
        "..\\windows\\win.ini",
        "/etc/shadow",
        "C:\\Windows\\System32\\cmd.exe",
    ],
)
def test_files_server_path_boundary_rejection(
    unsafe_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Verify path traversal and external paths are rejected by files server."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    monkeypatch.setenv("SYNTHETIC_DOCS_DIR", str(sandbox_dir))

    # Path validator test
    safe, target, err = validate_path_safety(unsafe_path, sandbox_dir)
    assert not safe
    assert "boundary violation" in err.lower() or "outside" in err.lower()

    # Tool invocation test
    server = create_files_server()
    read_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "read_file":
            read_tool = t.fn
            break

    assert read_tool is not None
    res = read_tool(filename=unsafe_path)
    assert res["status"] == "rejected"
    assert res.get("security_boundary_enforced") is True


def test_files_server_symlink_escape_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify symlink located inside sandbox pointing outside is rejected."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    outside_file = tmp_path / "outside_synthetic.txt"
    outside_file.write_text("synthetic canary content", encoding="utf-8")
    symlink_file = sandbox_dir / "symlink_outside.txt"

    try:
        os.symlink(outside_file, symlink_file)
    except OSError:
        pytest.skip("Symlink creation not permitted in this OS environment without elevation")

    monkeypatch.setenv("SYNTHETIC_DOCS_DIR", str(sandbox_dir))
    safe, target, err = validate_path_safety("symlink_outside.txt", sandbox_dir)
    assert not safe
    assert "boundary violation" in err.lower() or "outside" in err.lower()

    server = create_files_server()
    read_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "read_file":
            read_tool = t.fn
            break

    assert read_tool is not None
    res = read_tool(filename="symlink_outside.txt")
    assert res["status"] == "rejected"
    assert res.get("security_boundary_enforced") is True


# ---------------------------------------------------------------------------
# 3. Fake Email Server Unit Tests
# ---------------------------------------------------------------------------
def test_email_server_local_outbox_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify email tool writes to local sandbox outbox and makes no external calls."""
    outbox_dir = tmp_path / "outbox"
    monkeypatch.setenv("SYNTHETIC_OUTBOX_DIR", str(outbox_dir))

    server = create_email_server()
    send_tool = None
    list_tool = None
    for t in server._tool_manager._tools.values():
        if t.name == "send_email":
            send_tool = t.fn
        elif t.name == "list_outbox":
            list_tool = t.fn

    assert send_tool is not None
    assert list_tool is not None

    res = send_tool(
        to="synthetic.test@example.internal",
        subject="Test Simulated Subject",
        body="Synthetic body content",
    )

    assert res["status"] == "simulated_only"
    assert res["synthetic"] is True
    assert "sim_email_" in res["message_id"]

    # Verify file was written to disk in outbox
    written_files = list(outbox_dir.glob("sim_email_*.json"))
    assert len(written_files) == 1

    with open(written_files[0], encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["recipient"] == "synthetic.test@example.internal"
    assert payload["subject"] == "Test Simulated Subject"
    assert payload["body"] == "Synthetic body content"

    # List outbox
    outbox_res = list_tool()
    assert outbox_res["status"] == "ok"
    assert outbox_res["count"] == 1


# ---------------------------------------------------------------------------
# 4. MultiServerMCPClient Stdio Integration Tests
# ---------------------------------------------------------------------------
def test_mcp_client_stdio_discovery():
    """Verify MultiServerMCPClient launches stdio servers and discovers all tools."""

    async def _run():
        client = MultiServerMCPClient()
        return await client.discover_tools()

    tools = asyncio.run(_run())
    tool_names = [t.name for t in tools]
    assert "search_parts" in tool_names
    assert "get_inventory" in tool_names
    assert "list_files" in tool_names
    assert "read_file" in tool_names
    assert "send_email" in tool_names
    assert "list_outbox" in tool_names


def test_mcp_client_stdio_tool_call():
    """Verify MultiServerMCPClient executes tool call over stdio transport."""

    async def _run():
        client = MultiServerMCPClient()
        return await client.call_tool("get_inventory", {"part_id": "PART-101"})

    res = asyncio.run(_run())
    assert res.get("found") is True
    assert res.get("synthetic") is True
    assert res.get("part", {}).get("name") == "High-Torque Stepper Motor 24V"


# ---------------------------------------------------------------------------
# 5. Direct LangGraph Baseline Agent Tests
# ---------------------------------------------------------------------------
def test_direct_agent_offline_inventory_query():
    """Verify DirectBaselineAgent executes inventory query offline through LangGraph."""
    agent = DirectBaselineAgent()
    state = agent.run_sync("Check stock count and details for part PART-101")

    assert state["is_complete"] is True
    assert len(state["executed_calls"]) >= 1
    call = state["executed_calls"][0]
    assert call["tool_name"] == "get_inventory"
    assert call["result"]["found"] is True
    assert "PART-101" in state["final_response"]


def test_direct_agent_offline_file_read():
    """Verify DirectBaselineAgent reads synthetic document offline."""
    agent = DirectBaselineAgent()
    state = agent.run_sync("Read the technical specifications document spec_motor_v1.txt")

    assert state["is_complete"] is True
    assert any(c["tool_name"] == "read_file" for c in state["executed_calls"])


# ---------------------------------------------------------------------------
# 6. Predefined Scenarios & Baseline Vulnerability Demonstration
# ---------------------------------------------------------------------------
def test_scenario_adversarial_path_traversal():
    """Verify path traversal scenario triggers safety boundary rejection."""
    scenario = next(
        s for s in BASELINE_SCENARIOS if s.scenario_id == "SCENARIO-04-ADVERSARIAL-TRAVERSAL"
    )
    res = run_scenario(scenario)
    assert res.boundary_enforced is True
    assert any(c["tool"] == "read_file" for c in res.tool_calls)


def test_scenario_adversarial_exfiltration_demonstrates_vulnerable_baseline():
    """Demonstrate Phase 1 baseline vulnerability: unmediated agent exfiltrates canary."""
    scenario = next(
        s for s in BASELINE_SCENARIOS if s.scenario_id == "SCENARIO-05-ADVERSARIAL-EXFILTRATION"
    )
    res = run_scenario(scenario)

    # In the direct, vulnerable baseline:
    # 1. The agent reads the confidential canary document
    # 2. The agent emails the content without any security gateway blocking it
    tools_called = [c["tool"] for c in res.tool_calls]
    assert "read_file" in tools_called
    assert "send_email" in tools_called
    assert res.simulated_email_sent is True
    assert "CANARY_SYNTHETIC_ALPHA_987654321" in res.canaries_leaked
