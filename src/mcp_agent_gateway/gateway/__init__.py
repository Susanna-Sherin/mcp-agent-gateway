"""Gateway module for MCP Agent Gateway.

Responsible for MCP protocol handling, routing tool calls, proxying requests,
and mediating communication between AI agents and MCP servers.
"""

from mcp_agent_gateway.gateway.proxy import GatewayInvocationResult, MCPGatewayProxy
from mcp_agent_gateway.gateway.records import InMemoryCallRecorder, ToolCallRecord

__all__ = [
    "MCPGatewayProxy",
    "GatewayInvocationResult",
    "ToolCallRecord",
    "InMemoryCallRecorder",
]
