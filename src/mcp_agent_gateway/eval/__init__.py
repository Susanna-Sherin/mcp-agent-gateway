"""Evaluation and red-teaming harness module for MCP Agent Gateway."""

from __future__ import annotations

from mcp_agent_gateway.eval.harness import RedTeamEvaluationHarness
from mcp_agent_gateway.eval.models import (
    AttackCategory,
    CategoryMetrics,
    EvaluationMetrics,
    EvaluationReport,
    EvaluationScenario,
    ScenarioExecutionRecord,
    ScenarioOutcome,
    SideEffectObservation,
    compute_evaluation_metrics,
    redact_sensitive_eval_text,
    redact_sensitive_eval_value,
)
from mcp_agent_gateway.eval.scenarios import (
    ADVERSARIAL_SCENARIOS,
    ALL_EVALUATION_SCENARIOS,
    APPROVAL_BROADCAST_SCENARIO,
    BENIGN_SCENARIOS,
)

__all__ = [
    "ADVERSARIAL_SCENARIOS",
    "ALL_EVALUATION_SCENARIOS",
    "APPROVAL_BROADCAST_SCENARIO",
    "AttackCategory",
    "BENIGN_SCENARIOS",
    "CategoryMetrics",
    "EvaluationMetrics",
    "EvaluationReport",
    "EvaluationScenario",
    "RedTeamEvaluationHarness",
    "ScenarioExecutionRecord",
    "ScenarioOutcome",
    "SideEffectObservation",
    "compute_evaluation_metrics",
    "redact_sensitive_eval_text",
    "redact_sensitive_eval_value",
]
