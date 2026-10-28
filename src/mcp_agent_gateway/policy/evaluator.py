"""Deterministic policy evaluation engine for MCP Agent Gateway."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_agent_gateway.policy.models import (
    ChainRule,
    PolicyConfig,
    PolicyDecision,
    PolicyRule,
)

logger = logging.getLogger(__name__)


class PolicyConfigError(ValueError):
    """Raised when policy configuration is invalid, malformed, or cannot be parsed."""


class PolicyEngine:
    """Deterministic security policy evaluator enforcing role and argument constraints."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        load_error: str | None = None,
    ) -> None:
        self.config = config
        self.load_error = load_error
        self.is_valid = config is not None and load_error is None

    @property
    def is_loaded(self) -> bool:
        """Indicate whether a valid policy configuration is currently loaded."""
        return self.is_valid

    @property
    def chain_rules(self) -> list[ChainRule]:
        """Return declared chain rules or empty list if no valid config is loaded."""
        if self.config is not None:
            return self.config.chain_rules
        return []

    @classmethod
    def load_from_yaml(cls, path: Path | str, strict: bool = False) -> PolicyEngine:
        """Load and strictly validate policy configuration from a YAML file."""
        file_path = Path(path)
        if not file_path.is_file():
            err_msg = f"Policy file not found: {file_path}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg)
            return cls(config=None, load_error=err_msg)

        try:
            with open(file_path, encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)

            if not isinstance(raw_data, dict):
                err_msg = f"Policy file must contain a YAML mapping, got: {type(raw_data).__name__}"
                if strict:
                    raise PolicyConfigError(err_msg)
                return cls(config=None, load_error=err_msg)

            config = PolicyConfig.model_validate(raw_data)
            return cls(config=config, load_error=None)
        except yaml.YAMLError as ex:
            err_msg = f"Malformed YAML in policy file '{file_path}': {ex}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg) from ex
            return cls(config=None, load_error=err_msg)
        except (ValidationError, ValueError) as ex:
            err_msg = f"Invalid policy configuration in '{file_path}': {ex}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg) from ex
            return cls(config=None, load_error=err_msg)
        except Exception as ex:
            err_msg = f"Unexpected error reading policy file '{file_path}': {ex}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg) from ex
            return cls(config=None, load_error=err_msg)

    @classmethod
    def load_from_dict(cls, data: dict[str, Any], strict: bool = True) -> PolicyEngine:
        """Load and strictly validate policy configuration from a dictionary."""
        try:
            config = PolicyConfig.model_validate(data)
            return cls(config=config, load_error=None)
        except (ValidationError, ValueError) as ex:
            err_msg = f"Invalid policy configuration: {ex}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg) from ex
            return cls(config=None, load_error=err_msg)
        except Exception as ex:
            err_msg = f"Unexpected error loading policy dictionary: {ex}"
            logger.error(err_msg)
            if strict:
                raise PolicyConfigError(err_msg) from ex
            return cls(config=None, load_error=err_msg)

    def _rule_matches_target(
        self,
        rule: PolicyRule,
        caller_role: str,
        server: str,
        tool: str,
    ) -> bool:
        """Check if rule applies to the caller role, server, and tool."""
        role_matches = "*" in rule.roles or caller_role in rule.roles
        server_matches = rule.server == "*" or rule.server.lower() == server.lower()
        tool_matches = (
            "*" in rule.tools
            or tool in rule.tools
            or tool.lower() in [t.lower() for t in rule.tools]
        )
        return role_matches and server_matches and tool_matches

    def _evaluate_block_rule_trigger(
        self,
        rule: PolicyRule,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        """Determine if a matching block rule's constraints trigger a block action."""
        if not rule.argument_constraints:
            return True, f"Unconditional block rule '{rule.id}' matched"

        # If constraints are defined on a block rule, verify if arguments match block criteria
        for arg_name, constraint in rule.argument_constraints.items():
            if arg_name not in arguments:
                continue
            val = arguments[arg_name]

            # Blocked values check
            if constraint.blocked_values is not None and val in constraint.blocked_values:
                return True, f"Argument '{arg_name}' matches prohibited value: '{val}'"

            # Blocked patterns check
            if constraint.blocked_patterns and isinstance(val, str):
                for bp in constraint.blocked_patterns:
                    import re

                    if re.search(bp, val, re.IGNORECASE):
                        return True, f"Argument '{arg_name}' matches prohibited pattern: '{bp}'"

            # Direct pattern on block rule
            if constraint.pattern and isinstance(val, str):
                import re

                if re.search(constraint.pattern, val):
                    msg = f"Argument '{arg_name}' matches block pattern: '{constraint.pattern}'"
                    return True, msg

            # Disallowed values
            if constraint.allowed_values is not None and val not in constraint.allowed_values:
                return True, f"Argument '{arg_name}' value '{val}' is outside permitted values"

        return False, ""

    def _evaluate_allow_rule_satisfaction(
        self,
        rule: PolicyRule,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        """Verify that all argument constraints on an allow rule are satisfied."""
        for arg_name, constraint in rule.argument_constraints.items():
            if arg_name not in arguments or arguments[arg_name] is None:
                if constraint.required:
                    return False, f"Missing required argument: '{arg_name}'"
                continue

            val = arguments[arg_name]
            valid, err = constraint.validate_value(val)
            if not valid:
                return False, f"Argument '{arg_name}' constraint violation: {err}"

        return True, ""

    def evaluate(
        self,
        caller_role: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate an attempted tool call against loaded declarative policies.

        Follows strict security principles:
        1. Fail-closed on missing/invalid policy config.
        2. Fail-closed on unknown caller role.
        3. Mandatory block rule precedence over allow rules.
        4. Default-deny when no explicit allow rule satisfies all constraints.
        """
        # 1. Fail closed if policy is invalid or failed to load
        if not self.is_valid or self.config is None:
            return PolicyDecision(
                allowed=False,
                action="deny",
                rule_id=None,
                reason_code="POLICY_LOAD_ERROR",
                reason=f"Policy configuration is invalid or missing: {self.load_error}",
                caller_role=caller_role,
                server=server,
                tool=tool,
            )

        # 2. Reject undeclared caller roles
        if caller_role not in self.config.roles:
            return PolicyDecision(
                allowed=False,
                action="deny",
                rule_id=None,
                reason_code="UNKNOWN_ROLE",
                reason=(
                    f"Caller role '{caller_role}' is not declared in policy configuration. "
                    f"Declared roles are: {sorted(self.config.roles.keys())}"
                ),
                caller_role=caller_role,
                server=server,
                tool=tool,
            )

        # 3. Collect matching rules
        matching_rules = [
            r for r in self.config.rules if self._rule_matches_target(r, caller_role, server, tool)
        ]

        # 4. Block rule precedence: Evaluate all matching block rules first
        block_rules = [r for r in matching_rules if r.action == "block"]
        for b_rule in block_rules:
            triggers, reason = self._evaluate_block_rule_trigger(b_rule, arguments)
            if triggers:
                return PolicyDecision(
                    allowed=False,
                    action="block",
                    rule_id=b_rule.id,
                    reason_code="RULE_BLOCK",
                    reason=f"Tool call blocked by security rule '{b_rule.id}': {reason}",
                    caller_role=caller_role,
                    server=server,
                    tool=tool,
                )

        # 4.5. Require-approval precedence: Evaluate matching require_approval rules
        approval_rules = [r for r in matching_rules if r.action == "require_approval"]
        for ap_rule in approval_rules:
            satisfied, reason = self._evaluate_allow_rule_satisfaction(ap_rule, arguments)
            if satisfied:
                return PolicyDecision(
                    allowed=False,
                    action="require_approval",
                    rule_id=ap_rule.id,
                    reason_code="REQUIRE_APPROVAL",
                    reason=(
                        f"Tool invocation requires human approval per security rule '{ap_rule.id}'"
                    ),
                    caller_role=caller_role,
                    server=server,
                    tool=tool,
                )

        # 5. Evaluate matching allow rules
        allow_rules = [r for r in matching_rules if r.action == "allow"]
        failed_allow_reasons: list[str] = []

        for a_rule in allow_rules:
            satisfied, reason = self._evaluate_allow_rule_satisfaction(a_rule, arguments)
            if satisfied:
                return PolicyDecision(
                    allowed=True,
                    action="allow",
                    rule_id=a_rule.id,
                    reason_code="ALLOWED",
                    reason=f"Tool call permitted by security rule '{a_rule.id}'",
                    caller_role=caller_role,
                    server=server,
                    tool=tool,
                )
            failed_allow_reasons.append(f"Rule '{a_rule.id}' unsatisfied: {reason}")

        # 6. Default Deny: No allow rule permitted the call
        if failed_allow_reasons:
            detailed_reason = "; ".join(failed_allow_reasons)
            return PolicyDecision(
                allowed=False,
                action="deny",
                rule_id=None,
                reason_code="ARGUMENT_CONSTRAINT_VIOLATION",
                reason=f"Tool call denied: {detailed_reason}",
                caller_role=caller_role,
                server=server,
                tool=tool,
            )

        return PolicyDecision(
            allowed=False,
            action="deny",
            rule_id=None,
            reason_code="DEFAULT_DENY",
            reason=(
                f"Default deny: No matching allow rule for role '{caller_role}', "
                f"server '{server}', tool '{tool}'"
            ),
            caller_role=caller_role,
            server=server,
            tool=tool,
        )
