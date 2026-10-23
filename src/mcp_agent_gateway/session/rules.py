"""Deterministic chain rule engine for session state and tool-chain enforcement."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_agent_gateway.policy.models import ChainRule
    from mcp_agent_gateway.session.models import SessionState

from mcp_agent_gateway.session.models import ChainRuleDecision

logger = logging.getLogger(__name__)


class ChainRuleEngine:
    """Evaluates declarative tool-chain security constraints against session state.

    Supports:
    1. Forbidden transitions based on session taints (e.g. sensitive read blocks email dispatch).
    2. Prerequisite tool sequences (real registered tools only, requires prior 'success').
    3. Per-session invocation limits (governing forwarded invocations).
    """

    def __init__(self, rules: list[ChainRule] | None = None) -> None:
        self.rules: list[ChainRule] = rules or []

    def _matches_target(
        self,
        rule: ChainRule,
        caller_role: str,
        server: str,
        tool: str,
    ) -> bool:
        """Check if chain rule matches the caller role, target server, and tool."""
        role_matches = "*" in rule.roles or caller_role in rule.roles
        server_matches = rule.server == "*" or rule.server.lower() == server.lower()
        tool_matches = (
            "*" in rule.tools
            or tool in rule.tools
            or tool.lower() in [t.lower() for t in rule.tools]
        )
        return role_matches and server_matches and tool_matches

    def evaluate(
        self,
        session: SessionState,
        caller_role: str,
        server: str,
        tool: str,
    ) -> ChainRuleDecision:
        """Evaluate session state against matching chain rules.

        Evaluation order:
        1. Forbidden transition check (taints).
        2. Prerequisite sequence check.
        3. Invocation limit check.

        Fails closed with CHAIN_EVALUATION_ERROR if an exception occurs.
        """
        try:
            matching = [r for r in self.rules if self._matches_target(r, caller_role, server, tool)]

            for rule in matching:
                # 1. Forbidden Transition based on session taints
                if rule.rule_type == "forbidden_transition":
                    for taint in rule.forbidden_if_tainted:
                        if taint in session.taints:
                            logger.warning(
                                "Chain rule '%s' blocked tool '%s': taint '%s' in session '%s'",
                                rule.id,
                                tool,
                                taint,
                                session.session_id,
                            )
                            return ChainRuleDecision(
                                allowed=False,
                                action="block",
                                rule_id=rule.id,
                                reason_code="CHAIN_FORBIDDEN_TRANSITION",
                                reason=(
                                    f"Transition to tool '{tool}' is forbidden because session "
                                    f"carries security taint '{taint}'."
                                ),
                            )

                # 2. Prerequisite sequence check
                elif rule.rule_type == "prerequisite":
                    req_tool = rule.prerequisite_tool
                    req_server = rule.prerequisite_server

                    # Only prior calls with outcome == 'success' can satisfy prerequisite
                    satisfied = any(
                        call.tool_name == req_tool
                        and call.outcome == "success"
                        and (req_server is None or call.server_name.lower() == req_server.lower())
                        for call in session.history
                    )

                    if not satisfied:
                        logger.warning(
                            "Chain rule '%s' blocked '%s': missing prereq '%s' in '%s'",
                            rule.id,
                            tool,
                            req_tool,
                            session.session_id,
                        )
                        return ChainRuleDecision(
                            allowed=False,
                            action="deny",
                            rule_id=rule.id,
                            reason_code="CHAIN_PREREQUISITE_NOT_MET",
                            reason=(
                                f"Tool '{tool}' requires prior successful execution of "
                                f"prerequisite tool '{req_tool}'."
                            ),
                        )

                # 3. Invocation limit check
                elif rule.rule_type == "invocation_limit":
                    limit = rule.max_invocations
                    if limit is not None:
                        current_count = session.tool_counts.get(tool, 0)
                        if current_count >= limit:
                            logger.warning(
                                "Chain rule '%s' blocked '%s': limit %d reached (%d) in '%s'",
                                rule.id,
                                tool,
                                limit,
                                current_count,
                                session.session_id,
                            )
                            return ChainRuleDecision(
                                allowed=False,
                                action="deny",
                                rule_id=rule.id,
                                reason_code="CHAIN_INVOCATION_LIMIT_EXCEEDED",
                                reason=(
                                    f"Tool '{tool}' has reached maximum session invocation limit "
                                    f"of {limit} (forwarded invocations: {current_count})."
                                ),
                            )

            return ChainRuleDecision(
                allowed=True,
                action="allow",
                rule_id=None,
                reason_code="CHAIN_ALLOWED",
                reason="All applicable chain rules satisfied.",
            )

        except Exception as ex:
            logger.error("Exception during chain rule evaluation: %s", ex, exc_info=True)
            return ChainRuleDecision(
                allowed=False,
                action="deny",
                rule_id=None,
                reason_code="CHAIN_EVALUATION_ERROR",
                reason=f"Chain rule evaluation failure: {ex}",
            )
