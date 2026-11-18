"""Gateway-backed LangGraph Agent.

Executes autonomous tool-calling loops mediated through the MCPGatewayProxy.
Every tool invocation is intercepted, forwarded, and recorded in the gateway audit log.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from mcp_agent_gateway.agent.llm_interface import DeterministicOfflineLLM, LLMInterface
from mcp_agent_gateway.gateway.proxy import MCPGatewayProxy
from mcp_agent_gateway.observability.attributes import (
    AGENT_CALLER_ROLE,
    AGENT_ITERATION,
    AGENT_MODEL,
    AGENT_SESSION_ID,
    AGENT_TOOL_CALL_COUNT,
)
from mcp_agent_gateway.observability.langfuse import LangfuseAdapter
from mcp_agent_gateway.observability.tracer import safe_start_span

logger = logging.getLogger(__name__)


class GatewayAgentExecutionState(TypedDict):
    """LangGraph execution state for gateway-backed agent."""

    user_query: str
    messages: list[dict[str, Any]]
    available_tools: list[dict[str, Any]]
    planned_calls: list[dict[str, Any]]
    executed_calls: list[dict[str, Any]]
    final_response: str
    iteration: int
    is_complete: bool


class GatewayAgent:
    """Agent executing tool calls mediated through the MCP Gateway Proxy."""

    def __init__(
        self,
        gateway: MCPGatewayProxy | None = None,
        llm: LLMInterface | None = None,
        max_iterations: int = 5,
        caller_role: str = "operator",
        session_id: str | None = None,
        langfuse: LangfuseAdapter | None = None,
    ) -> None:
        self.gateway = gateway if gateway is not None else MCPGatewayProxy()
        self.llm = llm if llm is not None else DeterministicOfflineLLM()
        self.max_iterations = max_iterations
        self.caller_role = caller_role
        sm = getattr(self.gateway, "session_manager", None)
        self.session_id = (
            session_id
            if session_id is not None
            else (sm.generate_session_id() if sm is not None else None)
        )
        self.langfuse = langfuse if langfuse is not None else LangfuseAdapter()
        self._graph = self._build_graph()

    def _build_graph(self):
        """Construct the LangGraph StateGraph workflow."""
        builder = StateGraph(GatewayAgentExecutionState)

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

    def _route_after_plan(self, state: GatewayAgentExecutionState) -> str:
        """Route to tool execution or finalization."""
        if state["is_complete"] or not state["planned_calls"]:
            return "finalize"
        if state["iteration"] >= self.max_iterations:
            return "finalize"
        return "execute"

    async def _plan_step(self, state: GatewayAgentExecutionState) -> dict[str, Any]:
        """Query LLM interface for next action."""
        iteration = state.get("iteration", 0) + 1
        with safe_start_span(
            "agent.plan",
            attributes={
                AGENT_ITERATION: iteration,
                AGENT_SESSION_ID: self.session_id,
                AGENT_MODEL: type(self.llm).__name__,
            },
        ):
            planned_calls, final_resp = self.llm.plan_next_step(
                user_query=state["user_query"],
                available_tools=state["available_tools"],
                conversation_history=state["messages"],
            )

            try:
                if self.langfuse.is_enabled:
                    self.langfuse.trace_generation(
                        name="agent.plan",
                        model=type(self.llm).__name__,
                        input_messages=state["messages"],
                        output={"planned_calls": planned_calls, "final_response": final_resp},
                        metadata={"session_id": self.session_id, "iteration": iteration},
                    )
            except Exception as ex:
                logger.warning(
                    "Telemetry error in Langfuse generation trace: %s",
                    type(ex).__name__,
                )

            return {
                "planned_calls": planned_calls,
                "final_response": final_resp or state.get("final_response", ""),
                "is_complete": len(planned_calls) == 0 or bool(final_resp),
                "iteration": iteration,
            }

    async def _execute_tools(self, state: GatewayAgentExecutionState) -> dict[str, Any]:
        """Directly invoke tool calls through the MCP gateway proxy."""
        planned = state.get("planned_calls", [])
        new_executed: list[dict[str, Any]] = list(state.get("executed_calls", []))
        messages = list(state.get("messages", []))

        with safe_start_span(
            "agent.execute_tools",
            attributes={
                AGENT_SESSION_ID: self.session_id,
                AGENT_ITERATION: state.get("iteration", 0),
                AGENT_TOOL_CALL_COUNT: len(planned),
            },
        ):
            for call in planned:
                tool_name = call["tool_name"]
                arguments = call.get("arguments", {})

                # Execute tool call intercepted by the gateway proxy
                inv_result = await self.gateway.invoke_tool(
                    tool_name,
                    arguments,
                    caller_role=self.caller_role,
                    session_id=self.session_id,
                )
                result = inv_result.result

                record = {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "result": result,
                    "gateway_call_id": inv_result.call_id,
                    "gateway_outcome": inv_result.outcome,
                    "server_name": inv_result.server_name,
                    "policy_decision": inv_result.policy_decision,
                    "session_id": inv_result.session_id,
                    "session_seq": inv_result.session_seq,
                    "chain_decision": inv_result.chain_decision,
                    "scanner_results": inv_result.scanner_results,
                }
                new_executed.append(record)
                messages.append(
                    {
                        "role": "tool_result",
                        "tool_name": tool_name,
                        "content": result,
                        "gateway_call_id": inv_result.call_id,
                    }
                )

            return {
                "planned_calls": [],
                "executed_calls": new_executed,
                "messages": messages,
            }

    async def _finalize(self, state: GatewayAgentExecutionState) -> dict[str, Any]:
        """Format final output summary."""
        final_resp = state.get("final_response")
        if not final_resp:
            executed = state.get("executed_calls", [])
            final_resp = f"Completed gateway-mediated execution with {len(executed)} tool call(s)."

        return {
            "final_response": final_resp,
            "is_complete": True,
        }

    async def run(self, user_query: str) -> dict[str, Any]:
        """Execute the agent workflow asynchronously."""
        with safe_start_span(
            "agent.run",
            attributes={
                AGENT_SESSION_ID: self.session_id,
                AGENT_CALLER_ROLE: self.caller_role,
            },
        ):
            try:
                if self.langfuse.is_enabled:
                    self.langfuse.trace_event(
                        name="agent.run.start",
                        metadata={"session_id": self.session_id, "caller_role": self.caller_role},
                    )
            except Exception as ex:
                logger.warning(
                    "Telemetry error in Langfuse run start trace: %s",
                    type(ex).__name__,
                )

            tools = await self.gateway.discover_tools()
            tool_dicts = [
                {
                    "name": t.name,
                    "description": t.description,
                    "server": t.server_name,
                    "schema": t.input_schema,
                }
                for t in tools
            ]

            initial_state: GatewayAgentExecutionState = {
                "user_query": user_query,
                "messages": [{"role": "user", "content": user_query}],
                "available_tools": tool_dicts,
                "planned_calls": [],
                "executed_calls": [],
                "final_response": "",
                "iteration": 0,
                "is_complete": False,
            }

            result = await self._graph.ainvoke(initial_state)

            try:
                if self.langfuse.is_enabled:
                    self.langfuse.trace_event(
                        name="agent.run.complete",
                        metadata={"session_id": self.session_id, "caller_role": self.caller_role},
                    )
            except Exception as ex:
                logger.warning(
                    "Telemetry error in Langfuse run complete trace: %s",
                    type(ex).__name__,
                )

            return result

    def run_sync(self, user_query: str) -> dict[str, Any]:
        """Synchronous wrapper for running the gateway agent."""
        return asyncio.run(self.run(user_query))
