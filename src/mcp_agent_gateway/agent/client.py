"""MCP Client Manager for direct, unmediated stdio tool server connections."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@dataclass
class ToolDefinition:
    """Discovered MCP tool metadata."""

    name: str
    description: str
    server_name: str
    input_schema: dict[str, Any]


class MultiServerMCPClient:
    """Manages connections to multiple local MCP stdio servers without gateway mediation."""

    def __init__(self, python_executable: str | None = None) -> None:
        self.python_executable = python_executable or sys.executable
        self.server_modules: dict[str, str] = {
            "parts": "mcp_agent_gateway.tools.parts_server",
            "files": "mcp_agent_gateway.tools.files_server",
            "email": "mcp_agent_gateway.tools.email_server",
        }
        self.tool_to_server: dict[str, str] = {}
        self.discovered_tools: list[ToolDefinition] = []

    def get_server_params(self, server_name: str) -> StdioServerParameters:
        """Create StdioServerParameters for launching a server subprocess."""
        if server_name not in self.server_modules:
            raise ValueError(f"Unknown server: {server_name}")

        mod = self.server_modules[server_name]
        env = dict(os.environ)
        # Ensure PYTHONPATH includes project src
        src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        env["PYTHONPATH"] = src_path + os.pathsep + env.get("PYTHONPATH", "")

        return StdioServerParameters(
            command=self.python_executable,
            args=["-m", mod],
            env=env,
        )

    async def discover_tools(self) -> list[ToolDefinition]:
        """Query all configured stdio servers and return the aggregate list of tools."""
        all_tools: list[ToolDefinition] = []
        self.tool_to_server.clear()

        for server_name in self.server_modules:
            params = self.get_server_params(server_name)
            async with (
                stdio_client(params) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                tool_list = await session.list_tools()
                for t in tool_list.tools:
                    tool_def = ToolDefinition(
                        name=t.name,
                        description=t.description or "",
                        server_name=server_name,
                        input_schema=t.inputSchema if hasattr(t, "inputSchema") else {},
                    )
                    all_tools.append(tool_def)
                    self.tool_to_server[t.name] = server_name

        self.discovered_tools = all_tools
        return all_tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call directly to the target MCP server via stdio transport."""
        server_name = self.tool_to_server.get(tool_name)
        if not server_name:
            # Re-discover tools if not yet mapped
            await self.discover_tools()
            server_name = self.tool_to_server.get(tool_name)

        if not server_name:
            return {
                "status": "error",
                "error": f"Tool '{tool_name}' not found on any configured MCP server.",
            }

        params = self.get_server_params(server_name)
        async with (
            stdio_client(params) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)

            # Parse text content from MCP CallToolResult
            if result.content:
                first_content = result.content[0]
                if hasattr(first_content, "text"):
                    try:
                        return json.loads(first_content.text)
                    except (json.JSONDecodeError, TypeError):
                        return {"text": first_content.text}
            return {"result": str(result)}

    def call_tool_sync(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Synchronous wrapper for call_tool."""
        return asyncio.run(self.call_tool(tool_name, arguments))
