"""MCP Gateway Proxy implementation.

Mediates, transparently forwards, and records tool calls between agents and MCP servers.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_agent_gateway.agent.client import MultiServerMCPClient, ToolDefinition

from mcp_agent_gateway.gateway.records import (
    InMemoryCallRecorder,
    ToolCallRecord,
    generate_timestamp_utc,
)


@dataclass
class GatewayInvocationResult:
    """Typed result of a gateway-mediated tool invocation."""

    call_id: str
    server_name: str
    tool_name: str
    outcome: str  # "success", "error", "unknown_tool"
    result: dict[str, Any]
    error: str | None = None
    duration_ms: float = 0.0
    record: ToolCallRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation for consumer compatibility."""
        return {
            "gateway_call_id": self.call_id,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "outcome": self.outcome,
            "result": self.result,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


class MCPGatewayProxy:
    """Intercepts and transparently forwards MCP tool calls while maintaining audit records."""

    def __init__(
        self,
        mcp_client: MultiServerMCPClient | Any | None = None,
        recorder: InMemoryCallRecorder | None = None,
    ) -> None:
        if mcp_client is None:
            from mcp_agent_gateway.agent.client import MultiServerMCPClient

            self.mcp_client = MultiServerMCPClient()
        else:
            self.mcp_client = mcp_client

        self.recorder = recorder if recorder is not None else InMemoryCallRecorder()
        self._server_map: dict[str, str] = {}

    async def discover_tools(self) -> list[ToolDefinition]:
        """Discover tools across configured MCP servers and refresh the server routing map."""
        tools = await self.mcp_client.discover_tools()
        self._server_map = dict(self.mcp_client.tool_to_server)
        return tools

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> GatewayInvocationResult:
        """Invoke a tool through the gateway proxy, intercepting and recording the execution.

        Forward requests to the target MCP server while guaranteeing subprocess cleanup
        and in-memory call logging.
        """
        call_id = f"gw_call_{uuid.uuid4().hex}"
        start_time = time.perf_counter()
        timestamp = generate_timestamp_utc()
        meta = metadata or {}

        # Resolve target server
        server_name = self._server_map.get(tool_name) or self.mcp_client.tool_to_server.get(
            tool_name
        )
        if not server_name:
            await self.discover_tools()
            server_name = self._server_map.get(tool_name) or self.mcp_client.tool_to_server.get(
                tool_name
            )

        if not server_name:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = f"Tool '{tool_name}' not found on any configured MCP server."
            err_result = {"status": "error", "error": error_msg}
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name="unknown",
                tool_name=tool_name,
                arguments=arguments,
                outcome="unknown_tool",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name="unknown",
                tool_name=tool_name,
                outcome="unknown_tool",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
            )

        # Forward request to target server
        try:
            result = await self.mcp_client.call_tool(tool_name, arguments)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Determine outcome based on tool response
            if isinstance(result, dict) and result.get("status") == "error":
                outcome = "error"
                error_msg = str(result.get("error", "Tool reported error status"))
            else:
                outcome = "success"
                error_msg = None

            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome=outcome,
                result=result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome=outcome,
                result=result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
            )
        except Exception as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = str(ex)
            err_result = {"status": "error", "error": error_msg}
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome="error",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome="error",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
            )

    def invoke_tool_sync(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> GatewayInvocationResult:
        """Synchronous wrapper for invoke_tool."""
        return asyncio.run(self.invoke_tool(tool_name, arguments, metadata))
