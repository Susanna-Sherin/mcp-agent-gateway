"""Policy models and declarative schemas for MCP Agent Gateway."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


@dataclass
class PolicyDecision:
    """Result of evaluating an attempted tool invocation against security policies."""

    allowed: bool
    action: Literal["allow", "block", "deny"]
    rule_id: str | None
    reason_code: str
    reason: str
    caller_role: str
    server: str
    tool: str

    def to_dict(self) -> dict[str, Any]:
        """Convert decision to serializable dictionary."""
        return asdict(self)


class ArgumentConstraint(BaseModel):
    """Declarative constraints applied to a single tool argument."""

    model_config = {"extra": "forbid"}

    required: bool = False
    type: Literal["string", "integer", "number", "boolean", "list", "dict"] | None = None
    allowed_values: list[Any] | None = None
    blocked_values: list[Any] | None = None
    pattern: str | None = None
    blocked_patterns: list[str] | None = None
    min_value: float | int | None = None
    max_value: float | int | None = None
    min_length: int | None = None
    max_length: int | None = None

    def validate_value(self, val: Any) -> tuple[bool, str]:
        """Validate argument value against declared constraints."""
        # Type check
        if self.type is not None:
            if self.type == "string" and not isinstance(val, str):
                return False, f"Expected string, got {type(val).__name__}"
            if self.type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                return False, f"Expected integer, got {type(val).__name__}"
            if self.type == "number" and not isinstance(val, (int, float)):
                return False, f"Expected number, got {type(val).__name__}"
            if self.type == "boolean" and not isinstance(val, bool):
                return False, f"Expected boolean, got {type(val).__name__}"
            if self.type == "list" and not isinstance(val, list):
                return False, f"Expected list, got {type(val).__name__}"
            if self.type == "dict" and not isinstance(val, dict):
                return False, f"Expected dict, got {type(val).__name__}"

        # Blocked values
        if self.blocked_values is not None and val in self.blocked_values:
            return False, f"Value '{val}' is explicitly prohibited"

        # Allowed values
        if self.allowed_values is not None and val not in self.allowed_values:
            return False, f"Value '{val}' is not in allowed set: {self.allowed_values}"

        # String-specific checks
        if isinstance(val, str):
            if self.min_length is not None and len(val) < self.min_length:
                return False, f"String length {len(val)} is less than minimum {self.min_length}"
            if self.max_length is not None and len(val) > self.max_length:
                return False, f"String length {len(val)} exceeds maximum {self.max_length}"
            if self.blocked_patterns:
                for bp in self.blocked_patterns:
                    if re.search(bp, val, re.IGNORECASE):
                        return False, f"String matches prohibited pattern '{bp}'"
            if self.pattern is not None and not re.search(self.pattern, val):
                return False, f"String does not match required pattern '{self.pattern}'"

        # Numeric-specific checks
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            if self.min_value is not None and val < self.min_value:
                return False, f"Value {val} is below minimum allowed {self.min_value}"
            if self.max_value is not None and val > self.max_value:
                return False, f"Value {val} exceeds maximum allowed {self.max_value}"

        return True, ""


class PolicyRule(BaseModel):
    """Declarative access control rule governing a tool invocation."""

    model_config = {"extra": "forbid"}

    id: str = Field(..., description="Unique alphanumeric identifier for the rule.")
    description: str = Field(default="", description="Human-readable rationale for the rule.")
    action: Literal["allow", "block"] = Field(..., description="Rule action: allow or block.")
    roles: list[str] = Field(..., description="Roles to which this rule applies, or ['*'].")
    server: str = Field(..., description="Target MCP server name, or '*'.")
    tools: list[str] = Field(..., description="List of tool names, or ['*'].")
    argument_constraints: dict[str, ArgumentConstraint] = Field(
        default_factory=dict,
        description="Argument validation constraints mapped by argument name.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        """Allow rule_id as alias for id, and tool as alias for tools."""
        if isinstance(data, dict):
            new_data = dict(data)
            if "rule_id" in new_data and "id" not in new_data:
                new_data["id"] = new_data.pop("rule_id")
            if "tool" in new_data and "tools" not in new_data:
                tool_val = new_data.pop("tool")
                new_data["tools"] = [tool_val] if isinstance(tool_val, str) else tool_val
            return new_data
        return data


class ChainRule(BaseModel):
    """Declarative rule governing multi-step tool call sequences, taints, and invocation limits."""

    model_config = {"extra": "forbid"}

    id: str = Field(..., description="Unique alphanumeric identifier for the chain rule.")
    description: str = Field(default="", description="Human-readable rationale for the chain rule.")
    rule_type: Literal["forbidden_transition", "prerequisite", "invocation_limit"] = Field(
        ..., description="Type of chain rule."
    )
    server: str = Field(..., description="Target server name, or '*'.")
    tools: list[str] = Field(..., description="Target tool names governed by this rule, or ['*'].")
    roles: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Roles to which this rule applies (defaults to ['*']).",
    )

    # For 'forbidden_transition':
    forbidden_if_tainted: list[str] = Field(
        default_factory=list,
        description="List of session taints that forbid this tool transition.",
    )

    # For 'prerequisite':
    prerequisite_tool: str | None = Field(
        default=None,
        description="Real registered tool name that must have been successfully invoked prior.",
    )
    prerequisite_server: str | None = Field(
        default=None,
        description="Optional server name for the prerequisite tool.",
    )

    # For 'invocation_limit':
    max_invocations: int | None = Field(
        default=None,
        description="Maximum permitted forwarded invocations of the tool in a single session.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        """Allow rule_id as alias for id, and tool as alias for tools."""
        if isinstance(data, dict):
            new_data = dict(data)
            if "rule_id" in new_data and "id" not in new_data:
                new_data["id"] = new_data.pop("rule_id")
            if "tool" in new_data and "tools" not in new_data:
                tool_val = new_data.pop("tool")
                new_data["tools"] = [tool_val] if isinstance(tool_val, str) else tool_val
            return new_data
        return data

    @model_validator(mode="after")
    def validate_rule_fields(self) -> ChainRule:
        """Validate required fields based on rule_type."""
        if self.rule_type == "forbidden_transition" and not self.forbidden_if_tainted:
            raise ValueError(
                f"Chain rule '{self.id}' of type 'forbidden_transition' "
                f"must specify 'forbidden_if_tainted'."
            )
        if self.rule_type == "prerequisite" and (
            not self.prerequisite_tool or not self.prerequisite_tool.strip()
        ):
            raise ValueError(
                f"Chain rule '{self.id}' of type 'prerequisite' must specify 'prerequisite_tool'."
            )
        if self.rule_type == "invocation_limit" and (
            self.max_invocations is None or self.max_invocations < 1
        ):
            raise ValueError(
                f"Chain rule '{self.id}' of type 'invocation_limit' "
                f"must specify 'max_invocations' >= 1."
            )
        return self


class RoleDefinition(BaseModel):
    """Specification of an authorized caller role."""

    model_config = {"extra": "forbid"}

    description: str = Field(default="", description="Role description.")


class PolicyConfig(BaseModel):
    """Root configuration model for declarative security policies."""

    model_config = {"extra": "forbid"}

    version: str = Field(default="1.0", description="Policy schema version.")
    description: str = Field(default="", description="Policy document description.")
    default_action: Literal["deny"] = Field(
        default="deny",
        description="Default fallback action (strictly 'deny').",
    )
    roles: dict[str, RoleDefinition] = Field(
        ...,
        description="Declared authorized caller roles.",
    )
    rules: list[PolicyRule] = Field(
        default_factory=list,
        description="Ordered security policy rules.",
    )
    chain_rules: list[ChainRule] = Field(
        default_factory=list,
        description="Declarative session and tool-chain rules.",
    )

    @model_validator(mode="after")
    def validate_rules_integrity(self) -> PolicyConfig:
        """Validate rule uniqueness and role references."""
        seen_ids: set[str] = set()
        declared_roles: set[str] = set(self.roles.keys())

        for rule in self.rules:
            # Rule ID uniqueness
            if rule.id in seen_ids:
                raise ValueError(f"Duplicate rule ID found in policy configuration: '{rule.id}'")
            seen_ids.add(rule.id)

            # Role references validation
            for role in rule.roles:
                if role != "*" and role not in declared_roles:
                    raise ValueError(
                        f"Rule '{rule.id}' references undeclared role '{role}'. "
                        f"Declared roles are: {sorted(declared_roles)}"
                    )

        seen_chain_ids: set[str] = set()
        for c_rule in self.chain_rules:
            if c_rule.id in seen_ids or c_rule.id in seen_chain_ids:
                raise ValueError(f"Duplicate rule ID found in chain rules: '{c_rule.id}'")
            seen_chain_ids.add(c_rule.id)

            for role in c_rule.roles:
                if role != "*" and role not in declared_roles:
                    raise ValueError(
                        f"Chain rule '{c_rule.id}' references undeclared role '{role}'. "
                        f"Declared roles are: {sorted(declared_roles)}"
                    )

        return self
