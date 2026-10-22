"""Agent module for MCP Agent Gateway.

Provides direct unmediated baseline agent, MCP client manager, and benchmarking scenarios.
"""

from mcp_agent_gateway.agent.client import MultiServerMCPClient, ToolDefinition
from mcp_agent_gateway.agent.direct_agent import DirectBaselineAgent
from mcp_agent_gateway.agent.llm_interface import (
    DeterministicOfflineLLM,
    GeminiLiveLLM,
    LLMInterface,
)
from mcp_agent_gateway.agent.scenarios import (
    BASELINE_SCENARIOS,
    ScenarioDefinition,
    ScenarioRunResult,
    run_scenario,
)

__all__ = [
    "MultiServerMCPClient",
    "ToolDefinition",
    "DirectBaselineAgent",
    "LLMInterface",
    "DeterministicOfflineLLM",
    "GeminiLiveLLM",
    "BASELINE_SCENARIOS",
    "ScenarioDefinition",
    "ScenarioRunResult",
    "run_scenario",
]
