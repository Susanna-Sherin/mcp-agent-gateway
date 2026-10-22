"""Direct LangGraph Baseline Agent.

Executes autonomous tool-calling loops directly against MCP tool servers over stdio,
without any intermediary security gateway or policy mediation layer.
"""

from __future__ import annotations

import asyncio
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from mcp_agent_gateway.agent.client import MultiServerMCPClient
from mcp_agent_gateway.agent.llm_interface import DeterministicOfflineLLM, LLMInterface


class AgentExecutionState(TypedDict):
    """LangGraph execution state for direct baseline agent."""

    user_query: str
    messages: list[dict[str, Any]]
    available_tools: list[dict[str, Any]]
    planned_calls: list[dict[str, Any]]
    executed_calls: list[dict[str, Any]]
    final_response: str
    iteration: int
    is_complete: bool


class DirectBaselineAgent:
    """Direct, unmediated LangGraph agent communicating directly with MCP servers."""

    def __init__(
        self,
        mcp_client: MultiServerMCPClient | None = None,
        llm: LLMInterface | None = None,
        max_iterations: int = 5,
    ) -> None:
        self.mcp_client = mcp_client or MultiServerMCPClient()
        self.llm = llm or DeterministicOfflineLLM()
        self.max_iterations = max_iterations
        self._graph = self._build_graph()

    def _build_graph(self):
        """Construct the LangGraph StateGraph workflow."""
        builder = StateGraph(AgentExecutionState)

        # Nodes
        builder.add_node("plan_step", self._plan_step)
        builder.add_node("execute_tools", self._execute_tools)
        builder.add_node("finalize", self._finalize)

        # Edges
        builder.add_edge(START, "plan_step")
        builder.add_conditional_edges(
            "plan_step",
            self._route_after_plan,
            {
                "execute": "execute_tools",
                "finalize": "finalize",
            },
        )
        builder.add_edge("execute_tools", "plan_step")
        builder.add_edge("finalize", END)

        return builder.compile()

    def _route_after_plan(self, state: AgentExecutionState) -> str:
        """Route to tool execution or finalization."""
        if state["is_complete"] or not state["planned_calls"]:
            return "finalize"
        if state["iteration"] >= self.max_iterations:
            return "finalize"
        return "execute"

    async def _plan_step(self, state: AgentExecutionState) -> dict[str, Any]:
        """Query LLM interface for next action."""
        iteration = state.get("iteration", 0) + 1
        planned_calls, final_resp = self.llm.plan_next_step(
            user_query=state["user_query"],
            available_tools=state["available_tools"],
            conversation_history=state["messages"],
        )

        return {
            "planned_calls": planned_calls,
            "final_response": final_resp or state.get("final_response", ""),
            "is_complete": len(planned_calls) == 0 or bool(final_resp),
            "iteration": iteration,
        }

    async def _execute_tools(self, state: AgentExecutionState) -> dict[str, Any]:
        """Directly invoke tool calls on MCP stdio servers without gateway filtering."""
        planned = state.get("planned_calls", [])
        new_executed: list[dict[str, Any]] = list(state.get("executed_calls", []))
        messages = list(state.get("messages", []))

        for call in planned:
            tool_name = call["tool_name"]
            arguments = call.get("arguments", {})

            # Execute unmediated directly against MCP stdio server
            result = await self.mcp_client.call_tool(tool_name, arguments)

            record = {
                "tool_name": tool_name,
                "arguments": arguments,
                "result": result,
            }
            new_executed.append(record)
            messages.append(
                {
                    "role": "tool_result",
                    "tool_name": tool_name,
                    "content": result,
                }
            )

        return {
            "planned_calls": [],
            "executed_calls": new_executed,
            "messages": messages,
        }

    async def _finalize(self, state: AgentExecutionState) -> dict[str, Any]:
        """Format final output summary."""
        final_resp = state.get("final_response")
        if not final_resp:
            executed = state.get("executed_calls", [])
            final_resp = f"Completed unmediated execution with {len(executed)} tool call(s)."

        return {
            "final_response": final_resp,
            "is_complete": True,
        }

    async def run(self, user_query: str) -> dict[str, Any]:
        """Execute the agent workflow asynchronously."""
        # Discover tools from all local MCP servers
        tools = await self.mcp_client.discover_tools()
        tool_dicts = [
            {
                "name": t.name,
                "description": t.description,
                "server": t.server_name,
                "schema": t.input_schema,
            }
            for t in tools
        ]

        initial_state: AgentExecutionState = {
            "user_query": user_query,
            "messages": [{"role": "user", "content": user_query}],
            "available_tools": tool_dicts,
            "planned_calls": [],
            "executed_calls": [],
            "final_response": "",
            "iteration": 0,
            "is_complete": False,
        }

        # Invoke compiled StateGraph asynchronously
        return await self._graph.ainvoke(initial_state)

    def run_sync(self, user_query: str) -> dict[str, Any]:
        """Synchronous wrapper for running the agent."""
        return asyncio.run(self.run(user_query))
