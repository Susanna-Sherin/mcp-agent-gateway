"""Allowlisted span attributes and metadata sanitization for OpenTelemetry and Langfuse.

Enforces strict attribute allowlisting and redacts confidential tokens and PII
before any telemetry data is emitted to in-memory, OTLP, or Langfuse exporters.
"""

from __future__ import annotations

import re
from typing import Any

# ==============================================================================
# Attribute Names
# ==============================================================================
# MCP Tool & Server Attributes
MCP_TOOL_NAME = "mcp.tool.name"
MCP_SERVER_NAME = "mcp.server.name"
MCP_TOOL_STATUS = "mcp.tool.status"
MCP_ARGUMENT_KEYS = "mcp.argument_keys"

# Gateway Governance & Correlation Attributes
MCP_GATEWAY_CALL_ID = "mcp.gateway.call_id"
MCP_GATEWAY_SESSION_ID = "mcp.gateway.session_id"
MCP_GATEWAY_SESSION_SEQ = "mcp.gateway.session_seq"
MCP_GATEWAY_CALLER_ROLE = "mcp.gateway.caller_role"
MCP_GATEWAY_OUTCOME = "mcp.gateway.outcome"
MCP_GATEWAY_REASON_CODE = "mcp.gateway.reason_code"
MCP_GATEWAY_DURATION_MS = "mcp.gateway.duration_ms"

# Policy & Chain Rule Attributes
MCP_POLICY_ALLOWED = "mcp.policy.allowed"
MCP_POLICY_RULE_ID = "mcp.policy.rule_id"
MCP_POLICY_REASON_CODE = "mcp.policy.reason_code"
MCP_CHAIN_ALLOWED = "mcp.chain.allowed"
MCP_CHAIN_REASON_CODE = "mcp.chain.reason_code"

# Human Approval Attributes
MCP_APPROVAL_ID = "mcp.approval.id"
MCP_APPROVAL_REQUIRED = "mcp.approval.required"
MCP_APPROVAL_STATUS = "mcp.approval.status"

# Security Scanner Attributes
MCP_SCANNER_CANARY_DETECTED = "mcp.scanner.canary_detected"
MCP_SCANNER_PII_DETECTED = "mcp.scanner.pii_detected"
MCP_SCANNER_INJECTION_DETECTED = "mcp.scanner.injection_detected"
MCP_TOOL_PIN_STATUS = "mcp.tool_pin.status"

# Agent Lifecycle Attributes
AGENT_SESSION_ID = "agent.session_id"
AGENT_CALLER_ROLE = "agent.caller_role"
AGENT_ITERATION = "agent.iteration"
AGENT_COMPLETED = "agent.completed"
AGENT_MODEL = "agent.model"
AGENT_TOOL_CALL_COUNT = "agent.tool_call_count"


# Strict Allowlist of permitted span attributes
ALLOWLISTED_SPAN_ATTRIBUTES: frozenset[str] = frozenset(
    {
        MCP_TOOL_NAME,
        MCP_SERVER_NAME,
        MCP_TOOL_STATUS,
        MCP_ARGUMENT_KEYS,
        MCP_GATEWAY_CALL_ID,
        MCP_GATEWAY_SESSION_ID,
        MCP_GATEWAY_SESSION_SEQ,
        MCP_GATEWAY_CALLER_ROLE,
        MCP_GATEWAY_OUTCOME,
        MCP_GATEWAY_REASON_CODE,
        MCP_GATEWAY_DURATION_MS,
        MCP_POLICY_ALLOWED,
        MCP_POLICY_RULE_ID,
        MCP_POLICY_REASON_CODE,
        MCP_CHAIN_ALLOWED,
        MCP_CHAIN_REASON_CODE,
        MCP_APPROVAL_ID,
        MCP_APPROVAL_REQUIRED,
        MCP_APPROVAL_STATUS,
        MCP_SCANNER_CANARY_DETECTED,
        MCP_SCANNER_PII_DETECTED,
        MCP_SCANNER_INJECTION_DETECTED,
        MCP_TOOL_PIN_STATUS,
        AGENT_SESSION_ID,
        AGENT_CALLER_ROLE,
        AGENT_ITERATION,
        AGENT_COMPLETED,
        AGENT_MODEL,
        AGENT_TOOL_CALL_COUNT,
    }
)

_CANARY_PATTERN = re.compile(r"CANARY_SYNTHETIC_ALPHA[A-Za-z0-9_]*")
_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?=[^A-Za-z0-9]|$)")
_PHONE_PATTERN = re.compile(
    r"(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b|\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b)"
)
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?:bearer\s+[a-z0-9_\-\.]{8,}|(?:api[_-]?key|secret|password|auth_token)\s*[:=]\s*[^\s,;]+)"
)

MAX_TELEMETRY_STRING_LENGTH: int = 500
MAX_RECURSION_DEPTH: int = 10


def sanitize_attribute_value(val: Any, depth: int = 0) -> Any:
    """Sanitize individual attribute value, scrubbing canaries, credentials, and PII.

    Handles primitives, strings, dictionaries, lists, and tuples recursively.
    Prevents unsafe stringification of arbitrary objects.
    Enforces string length limits.
    """
    if depth > MAX_RECURSION_DEPTH:
        return "[MAX_DEPTH_EXCEEDED]"

    if val is None:
        return None

    if isinstance(val, (int, float, bool)):
        return val

    if isinstance(val, str):
        cleaned = val
        truncated = False
        if len(cleaned) > MAX_TELEMETRY_STRING_LENGTH:
            cleaned = cleaned[:MAX_TELEMETRY_STRING_LENGTH]
            truncated = True

        # Redact canaries
        cleaned = _CANARY_PATTERN.sub("[REDACTED_CONFIDENTIAL_TOKEN]", cleaned)
        # Redact credentials & tokens
        cleaned = _CREDENTIAL_PATTERN.sub("[REDACTED_CREDENTIAL]", cleaned)
        # Redact payment card numbers
        cleaned = _CARD_PATTERN.sub("[REDACTED_CARD]", cleaned)
        # Redact SSNs
        cleaned = _SSN_PATTERN.sub("[REDACTED_SSN]", cleaned)
        # Redact email addresses
        cleaned = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", cleaned)
        # Redact phone numbers
        cleaned = _PHONE_PATTERN.sub("[REDACTED_PHONE]", cleaned)

        if truncated:
            cleaned = f"{cleaned}...[TRUNCATED]"
        return cleaned

    if isinstance(val, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in val.items():
            safe_k = (
                sanitize_attribute_value(k, depth=depth + 1)
                if isinstance(k, str)
                else f"<{type(k).__name__}>"
            )
            key_str = str(safe_k) if safe_k is not None else "none"
            sanitized_dict[key_str] = sanitize_attribute_value(v, depth=depth + 1)
        return sanitized_dict

    if isinstance(val, (list, tuple)):
        sanitized_seq = [sanitize_attribute_value(item, depth=depth + 1) for item in val]
        return sanitized_seq if isinstance(val, list) else tuple(sanitized_seq)

    if isinstance(val, (set, frozenset)):
        sanitized_set = [sanitize_attribute_value(item, depth=depth + 1) for item in val]
        try:
            return sorted(sanitized_set, key=lambda x: str(x))
        except Exception:
            return sanitized_set

    # Avoid unsafe stringification of arbitrary unknown objects
    return f"<{type(val).__name__}>"


def sanitize_span_attributes(raw_attrs: dict[str, Any] | None) -> dict[str, Any]:
    """Filter and sanitize attributes against the strict allowlist.

    - Drops any attribute not explicitly listed in ALLOWLISTED_SPAN_ATTRIBUTES.
    - Sanitizes permitted attribute values to prevent accidental canary/PII leakage.
    - Never accepts raw tool arguments, tool outputs, or sensitive credentials.
    """
    if not isinstance(raw_attrs, dict):
        return {}

    sanitized: dict[str, Any] = {}
    for key, value in raw_attrs.items():
        if key in ALLOWLISTED_SPAN_ATTRIBUTES and value is not None:
            sanitized[key] = sanitize_attribute_value(value)
    return sanitized
