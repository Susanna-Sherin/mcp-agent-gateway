"""Agent module for MCP Agent Gateway.

Provides direct unmediated baseline agent, MCP client manager, and benchmarking scenarios.
"""

from mcp_agent_gateway.agent.client import MultiServerMCPClient, ToolDefinition
from mcp_agent_gateway.agent.direct_agent import DirectBaselineAgent
from mcp_agent_gateway.agent.gateway_agent import GatewayAgent
from mcp_agent_gateway.agent.llm_interface import (
    DeterministicOfflineLLM,
    GeminiLiveLLM,
    LLMInterface,
)
from mcp_agent_gateway.agent.scenarios import (
    BASELINE_SCENARIOS,
    GATEWAY_DEMO_SCENARIO,
    ScenarioDefinition,
    ScenarioRunResult,
    run_gateway_scenario,
    run_scenario,
)

__all__ = [
    "MultiServerMCPClient",
    "ToolDefinition",
    "DirectBaselineAgent",
    "GatewayAgent",
    "LLMInterface",
    "DeterministicOfflineLLM",
    "GeminiLiveLLM",
    "BASELINE_SCENARIOS",
    "GATEWAY_DEMO_SCENARIO",
    "ScenarioDefinition",
    "ScenarioRunResult",
    "run_scenario",
    "run_gateway_scenario",
]
