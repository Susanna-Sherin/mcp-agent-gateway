"""Phase 4 tests for Session State and Tool-Chain Rules."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_agent_gateway.agent.gateway_agent import GatewayAgent
from mcp_agent_gateway.gateway.proxy import GatewayInvocationResult, MCPGatewayProxy
from mcp_agent_gateway.gateway.records import InMemoryCallRecorder
from mcp_agent_gateway.policy.evaluator import PolicyEngine
from mcp_agent_gateway.policy.models import ChainRule, PolicyConfig
from mcp_agent_gateway.session.manager import SessionManager
from mcp_agent_gateway.session.models import (
    SessionRoleMismatchError,
    SessionStateError,
)
from mcp_agent_gateway.session.rules import ChainRuleEngine

POLICIES_PATH = Path("config/policies.yaml")


# ---------------------------------------------------------------------------
# 1. Session Lifecycle & Trusted Role Binding Tests
# ---------------------------------------------------------------------------
def test_session_manager_creation_and_unpredictable_ids():
    """Verify session manager creates isolated sessions and generates unpredictable IDs."""
    mgr = SessionManager()
    assert len(mgr) == 0

    # Create without caller-supplied ID -> unpredictable cryptographically random ID
    s1, is_new1 = mgr.get_or_create_session(session_id=None, caller_role="operator")
    assert is_new1 is True
    assert s1.session_id.startswith("sess_")
    assert len(s1.session_id) >= 20
    assert s1.caller_role == "operator"
    assert len(mgr) == 1

    # Second session gets unique, unpredictable ID
    s2, is_new2 = mgr.get_or_create_session(session_id=None, caller_role="operator")
    assert is_new2 is True
    assert s2.session_id != s1.session_id
    assert len(mgr) == 2


def test_session_role_binding_and_mismatch_rejection():
    """Verify session binds strictly to one caller role and rejects conflicting role access."""
    mgr = SessionManager()
    session_id = "sess_trusted_123"

    # Create session bound to 'operator'
    s, is_new = mgr.get_or_create_session(session_id=session_id, caller_role="operator")
    assert is_new is True
    assert s.caller_role == "operator"

    # Re-accessing with same role succeeds
    existing, is_new2 = mgr.get_or_create_session(session_id=session_id, caller_role="operator")
    assert is_new2 is False
    assert existing.session_id == session_id

    # Attempting to re-access existing session under 'admin' role is rejected
    with pytest.raises(
        SessionRoleMismatchError, match="rejecting attempt to access under conflicting role"
    ):
        mgr.get_or_create_session(session_id=session_id, caller_role="admin")

    # Attempting to re-access under 'viewer' role is rejected
    with pytest.raises(SessionRoleMismatchError, match="bound to role 'operator'"):
        mgr.get_or_create_session(session_id=session_id, caller_role="viewer")


def test_session_cleanup_methods():
    """Verify session deletion tombstones IDs to prevent resurrection, and clear purge semantics."""
    mgr = SessionManager()
    s1, _ = mgr.get_or_create_session("sess_1", "operator")
    s2, _ = mgr.get_or_create_session("sess_2", "admin")
    assert len(mgr) == 2

    # Delete specific session
    assert mgr.delete_session("sess_1") is True
    assert mgr.get_session("sess_1") is None
    assert mgr.delete_session("sess_1") is False
    assert len(mgr) == 1
    assert mgr.is_revoked("sess_1") is True

    # Attempting to reuse revoked session ID fails closed
    with pytest.raises(SessionStateError, match="deleted/revoked and cannot be reused"):
        mgr.get_or_create_session("sess_1", "operator")

    # Clear active sessions (default preserve_revocations=True)
    mgr.clear()
    assert len(mgr) == 0
    assert mgr.get_session("sess_2") is None
    assert mgr.is_revoked("sess_1") is True

    # Revoked ID remains permanently unusable after ordinary clear()
    with pytest.raises(SessionStateError, match="deleted/revoked and cannot be reused"):
        mgr.get_or_create_session("sess_1", "operator")

    # Explicit full clear with preserve_revocations=False resets tombstones
    mgr.clear(preserve_revocations=False)
    assert mgr.is_revoked("sess_1") is False
    s_fresh, is_new = mgr.get_or_create_session("sess_1", "operator")
    assert is_new is True
    assert s_fresh.session_id == "sess_1"


def test_gateway_rejects_role_mismatch_without_forwarding():
    """Verify GatewayProxy intercepts session role mismatch and denies call before forwarding."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    mgr = SessionManager()
    mgr.get_or_create_session("sess_fixed_id", caller_role="operator")

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        session_manager=mgr,
        default_caller_role="operator",
    )

    # Attempt invocation on existing session with conflicting role 'admin'
    res = gateway.invoke_tool_sync(
        "get_inventory",
        {"part_id": "PART-101"},
        caller_role="admin",
        session_id="sess_fixed_id",
    )

    assert res.outcome == "denied"
    assert res.result["status"] == "denied"
    assert res.result["reason_code"] == "SESSION_ROLE_MISMATCH"
    mock_client.call_tool.assert_not_called()


def test_gateway_denies_revoked_session_reuse():
    """Verify GatewayProxy intercepts revoked session reuse and denies before forwarding."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    mgr = SessionManager()
    mgr.get_or_create_session("sess_to_delete", caller_role="operator")
    mgr.delete_session("sess_to_delete")

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        session_manager=mgr,
        default_caller_role="operator",
    )

    res = gateway.invoke_tool_sync(
        "get_inventory",
        {"part_id": "PART-101"},
        caller_role="operator",
        session_id="sess_to_delete",
    )

    assert res.outcome == "denied"
    assert res.result["status"] == "denied"
    assert res.result["reason_code"] == "SESSION_STATE_ERROR"
    assert "deleted/revoked" in res.result["error"]
    mock_client.call_tool.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Session Isolation: Histories, Taints, and Counts
# ---------------------------------------------------------------------------
def test_session_isolation_taints_and_counts():
    """Verify state, taints, and invocation counts never leak across sessions."""
    mgr = SessionManager()
    s1, _ = mgr.get_or_create_session("sess_a", "operator")
    s2, _ = mgr.get_or_create_session("sess_b", "operator")

    # Apply taint and call history to sess_a
    mgr.add_taint("sess_a", "sensitive_file_read")
    mgr.record_call("sess_a", "parts", "search_parts", "success")
    mgr.record_call("sess_a", "parts", "search_parts", "success")

    assert mgr.has_taint("sess_a", "sensitive_file_read") is True
    assert mgr.get_tool_count("sess_a", "search_parts") == 2
    assert len(s1.history) == 2

    # Verify sess_b remains completely untainted and has zero count
    assert mgr.has_taint("sess_b", "sensitive_file_read") is False
    assert mgr.get_tool_count("sess_b", "search_parts") == 0
    assert len(s2.history) == 0


def test_session_minimal_history_no_sensitive_payloads():
    """Verify session history only retains minimal audit metadata, never raw payloads."""
    mgr = SessionManager()
    mgr.get_or_create_session("sess_min", "operator")

    summary = mgr.record_call("sess_min", "files", "read_file", "success")
    assert summary.sequence_number == 1
    assert summary.server_name == "files"
    assert summary.tool_name == "read_file"
    assert summary.outcome == "success"
    assert summary.timestamp_utc

    # Verify absence of raw payload attributes
    assert not hasattr(summary, "arguments")
    assert not hasattr(summary, "content")
    assert not hasattr(summary, "result")
    assert not hasattr(summary, "body")


# ---------------------------------------------------------------------------
# 3. Chain Rules: Declarative Validation & Types
# ---------------------------------------------------------------------------
def test_chain_rule_strict_validation():
    """Verify ChainRule enforces valid rule types, required fields, and forbids extra fields."""
    # Valid forbidden_transition
    r1 = ChainRule(
        id="chain-test-1",
        rule_type="forbidden_transition",
        server="email",
        tools=["send_email"],
        forbidden_if_tainted=["sensitive_file_read"],
    )
    assert r1.rule_type == "forbidden_transition"

    # Missing forbidden_if_tainted on forbidden_transition raises error
    with pytest.raises(ValueError, match="must specify 'forbidden_if_tainted'"):
        ChainRule(
            id="chain-test-bad",
            rule_type="forbidden_transition",
            server="email",
            tools=["send_email"],
        )

    # Missing prerequisite_tool on prerequisite raises error
    with pytest.raises(ValueError, match="must specify 'prerequisite_tool'"):
        ChainRule(
            id="chain-test-bad-prereq",
            rule_type="prerequisite",
            server="parts",
            tools=["get_inventory"],
        )

    # Invalid max_invocations (< 1) on invocation_limit raises error
    with pytest.raises(ValueError, match="must specify 'max_invocations' >= 1"):
        ChainRule(
            id="chain-test-bad-limit",
            rule_type="invocation_limit",
            server="email",
            tools=["send_email"],
            max_invocations=0,
        )

    # Extra unknown field is forbidden
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        ChainRule(
            id="chain-test-extra",
            rule_type="invocation_limit",
            server="email",
            tools=["send_email"],
            max_invocations=3,
            unknown_arg="illegal",  # type: ignore[call-arg]
        )


def test_chain_rule_id_uniqueness_and_undeclared_role_rejection():
    """Verify duplicate chain rule IDs and undeclared role references trigger errors."""
    raw_dict = {
        "version": "1.0",
        "roles": {"operator": {"description": "Standard operator"}},
        "rules": [
            {
                "id": "rule-static-1",
                "roles": ["operator"],
                "action": "allow",
                "server": "parts",
                "tools": ["search_parts"],
            }
        ],
        "chain_rules": [
            # ID collides with static rule
            {
                "id": "rule-static-1",
                "roles": ["operator"],
                "rule_type": "invocation_limit",
                "server": "parts",
                "tools": ["search_parts"],
                "max_invocations": 5,
            }
        ],
    }
    with pytest.raises(ValueError, match="Duplicate rule ID"):
        PolicyConfig.model_validate(raw_dict)

    # Undeclared role reference in chain rule
    raw_dict_bad_role = {
        "version": "1.0",
        "roles": {"operator": {"description": "Standard operator"}},
        "rules": [],
        "chain_rules": [
            {
                "id": "chain-bad-role",
                "roles": ["undeclared_role"],
                "rule_type": "invocation_limit",
                "server": "parts",
                "tools": ["search_parts"],
                "max_invocations": 5,
            }
        ],
    }
    with pytest.raises(ValueError, match="references undeclared role"):
        PolicyConfig.model_validate(raw_dict_bad_role)


# ---------------------------------------------------------------------------
# 4. Forbidden Transition: Sensitive Canary Read to Email Barrier
# ---------------------------------------------------------------------------
def test_sensitive_canary_read_blocks_email_dispatch_mocked():
    """Verify reading sensitive canary document marks taint and blocks subsequent email dispatch."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"read_file": "files", "send_email": "email"}
    mock_client.call_tool = AsyncMock()

    # Step 1 response: return sensitive canary content
    canary_content = "[CONFIDENTIAL MEMO] CANARY_SYNTHETIC_ALPHA_987654321 Top Secret Project"
    mock_client.call_tool.return_value = {
        "status": "ok",
        "filename": "internal_memo_canary.txt",
        "content": canary_content,
    }

    # Policy allowing internal emails and files for operator
    test_config = {
        "version": "1.0",
        "roles": {"operator": {"description": "Operator"}},
        "rules": [
            {
                "id": "allow-files",
                "action": "allow",
                "roles": ["operator"],
                "server": "files",
                "tools": ["read_file"],
            },
            {
                "id": "allow-email",
                "action": "allow",
                "roles": ["operator"],
                "server": "email",
                "tools": ["send_email"],
            },
        ],
        "chain_rules": [
            {
                "id": "chain-block-sensitive-read-to-email",
                "rule_type": "forbidden_transition",
                "server": "email",
                "tools": ["send_email"],
                "roles": ["*"],
                "forbidden_if_tainted": ["sensitive_file_read"],
            }
        ],
    }
    engine = PolicyEngine.load_from_dict(test_config)
    session_mgr = SessionManager()

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        policy_engine=engine,
        session_manager=session_mgr,
        chain_engine=ChainRuleEngine(engine.chain_rules),
        default_caller_role="operator",
    )

    session_id = "sess_taint_test_1"

    # Step 1: Read confidential canary memo
    res_read = gateway.invoke_tool_sync(
        "read_file",
        {"filename": "internal_memo_canary.txt"},
        caller_role="operator",
        session_id=session_id,
    )
    assert res_read.outcome == "success"
    # Verify session carries sensitive taint
    assert session_mgr.has_taint(session_id, "sensitive_file_read") is True

    # Reset mock call count to verify send_email never reaches client
    mock_client.call_tool.reset_mock()

    # Step 2: Attempt email transmission in same session
    res_email = gateway.invoke_tool_sync(
        "send_email",
        {
            "to": "synthetic.buyer@example.internal",
            "subject": "Canary Memo",
            "body": canary_content,
        },
        caller_role="operator",
        session_id=session_id,
    )

    # Verify email was BLOCKED by chain rule before forwarding
    assert res_email.outcome == "denied"
    assert res_email.result["status"] == "denied"
    assert res_email.result["reason_code"] == "CHAIN_FORBIDDEN_TRANSITION"
    assert res_email.result["rule_id"] == "chain-block-sensitive-read-to-email"
    mock_client.call_tool.assert_not_called()


def test_ordinary_read_does_not_trigger_sensitive_taint():
    """Verify ordinary non-sensitive document reads do NOT trigger sensitive-file taint."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"read_file": "files", "send_email": "email"}
    mock_client.call_tool = AsyncMock()

    # Ordinary technical document content
    mock_client.call_tool.return_value = {
        "status": "ok",
        "filename": "spec_motor_v1.txt",
        "content": "Voltage: 24V DC, CANARY_BENIGN_MOTOR_SPEC_771",
    }

    test_config = {
        "version": "1.0",
        "roles": {"operator": {"description": "Operator"}},
        "rules": [
            {
                "id": "allow-files",
                "action": "allow",
                "roles": ["operator"],
                "server": "files",
                "tools": ["read_file"],
            },
            {
                "id": "allow-email",
                "action": "allow",
                "roles": ["operator"],
                "server": "email",
                "tools": ["send_email"],
            },
        ],
        "chain_rules": [
            {
                "id": "chain-block-sensitive-read-to-email",
                "rule_type": "forbidden_transition",
                "server": "email",
                "tools": ["send_email"],
                "roles": ["*"],
                "forbidden_if_tainted": ["sensitive_file_read"],
            }
        ],
    }
    engine = PolicyEngine.load_from_dict(test_config)
    session_mgr = SessionManager()

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        policy_engine=engine,
        session_manager=session_mgr,
        chain_engine=ChainRuleEngine(engine.chain_rules),
        default_caller_role="operator",
    )

    session_id = "sess_ordinary_read"

    # Step 1: Read ordinary spec document
    res_read = gateway.invoke_tool_sync(
        "read_file",
        {"filename": "spec_motor_v1.txt"},
        caller_role="operator",
        session_id=session_id,
    )
    assert res_read.outcome == "success"
    # Verify session is NOT tainted
    assert session_mgr.has_taint(session_id, "sensitive_file_read") is False

    # Step 2: Send ordinary email in same session
    mock_client.call_tool.return_value = {
        "status": "simulated_only",
        "message_id": "sim_email_123",
    }

    res_email = gateway.invoke_tool_sync(
        "send_email",
        {
            "to": "synthetic.buyer@example.internal",
            "subject": "Motor Specs",
            "body": "Motor runs at 24V DC",
        },
        caller_role="operator",
        session_id=session_id,
    )

    # Allowed and forwarded successfully
    assert res_email.outcome == "success"
    assert res_email.result["status"] == "simulated_only"


# ---------------------------------------------------------------------------
# 5. Prerequisite Tool Sequence: Real Tools Only
# ---------------------------------------------------------------------------
def test_prerequisite_enforcement_viewer_search_before_inventory():
    """Verify prerequisite rule on real tools: viewer must search_parts before get_inventory."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"search_parts": "parts", "get_inventory": "parts"}
    mock_client.call_tool = AsyncMock(return_value={"status": "ok"})

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        default_caller_role="viewer",
    )
    session_id = "sess_prereq_test"

    # Step 1: Attempt get_inventory directly -> blocked by prerequisite
    res_denied = gateway.invoke_tool_sync(
        "get_inventory",
        {"part_id": "PART-101"},
        caller_role="viewer",
        session_id=session_id,
    )
    assert res_denied.outcome == "denied"
    assert res_denied.result["reason_code"] == "CHAIN_PREREQUISITE_NOT_MET"
    assert res_denied.result["rule_id"] == "chain-require-search-before-inventory"
    mock_client.call_tool.assert_not_called()

    # Step 2: Satisfy prerequisite by executing search_parts
    mock_client.call_tool.return_value = {"parts": [{"id": "PART-101"}]}
    res_search = gateway.invoke_tool_sync(
        "search_parts",
        {"query": "motor"},
        caller_role="viewer",
        session_id=session_id,
    )
    assert res_search.outcome == "success"
    mock_client.call_tool.assert_called_once_with("search_parts", {"query": "motor"})

    # Step 3: Now get_inventory is permitted!
    mock_client.call_tool.reset_mock()
    mock_client.call_tool.return_value = {"found": True, "part": {"id": "PART-101"}}

    res_inv = gateway.invoke_tool_sync(
        "get_inventory",
        {"part_id": "PART-101"},
        caller_role="viewer",
        session_id=session_id,
    )
    assert res_inv.outcome == "success"
    mock_client.call_tool.assert_called_once_with("get_inventory", {"part_id": "PART-101"})


def test_denied_calls_cannot_satisfy_prerequisites():
    """Verify failed or policy-denied calls cannot satisfy a prerequisite rule."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"search_parts": "parts", "get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    # Custom config where search_parts has a constraint
    test_config = {
        "version": "1.0",
        "roles": {"operator": {"description": "Operator"}},
        "rules": [
            {
                "id": "allow-search",
                "action": "allow",
                "roles": ["operator"],
                "server": "parts",
                "tools": ["search_parts"],
                "argument_constraints": {
                    "limit": {"type": "integer", "min_value": 1, "max_value": 50}
                },
            },
            {
                "id": "allow-inventory",
                "action": "allow",
                "roles": ["operator"],
                "server": "parts",
                "tools": ["get_inventory"],
            },
        ],
        "chain_rules": [
            {
                "id": "chain-require-search",
                "rule_type": "prerequisite",
                "server": "parts",
                "tools": ["get_inventory"],
                "roles": ["operator"],
                "prerequisite_tool": "search_parts",
            }
        ],
    }
    engine = PolicyEngine.load_from_dict(test_config)
    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        policy_engine=engine,
        chain_engine=ChainRuleEngine(engine.chain_rules),
        default_caller_role="operator",
    )

    session_id = "sess_denied_prereq"

    # Step 1: Call search_parts with invalid limit (999 exceeds max 50) -> Static Policy Denied
    res_search = gateway.invoke_tool_sync(
        "search_parts",
        {"limit": 999},
        caller_role="operator",
        session_id=session_id,
    )
    assert res_search.outcome == "denied"
    assert res_search.result["reason_code"] == "ARGUMENT_CONSTRAINT_VIOLATION"

    # Step 2: Attempt get_inventory -> MUST FAIL because search_parts was denied, not success!
    res_inv = gateway.invoke_tool_sync(
        "get_inventory",
        {"part_id": "PART-101"},
        caller_role="operator",
        session_id=session_id,
    )
    assert res_inv.outcome == "denied"
    assert res_inv.result["reason_code"] == "CHAIN_PREREQUISITE_NOT_MET"
    mock_client.call_tool.assert_not_called()


# ---------------------------------------------------------------------------
# 6. Invocation Limit Boundary Behavior
# ---------------------------------------------------------------------------
def test_invocation_limit_boundary_and_counting_semantics():
    """Verify invocation limit boundary and confirm denied calls do not increment count."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"send_email": "email"}
    mock_client.call_tool = AsyncMock(return_value={"status": "simulated_only"})

    test_config = {
        "version": "1.0",
        "roles": {"operator": {"description": "Operator"}},
        "rules": [
            {
                "id": "allow-email",
                "action": "allow",
                "roles": ["operator"],
                "server": "email",
                "tools": ["send_email"],
            }
        ],
        "chain_rules": [
            {
                "id": "chain-limit-email",
                "rule_type": "invocation_limit",
                "server": "email",
                "tools": ["send_email"],
                "roles": ["operator"],
                "max_invocations": 2,
            }
        ],
    }
    engine = PolicyEngine.load_from_dict(test_config)
    session_mgr = SessionManager()
    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        policy_engine=engine,
        session_manager=session_mgr,
        chain_engine=ChainRuleEngine(engine.chain_rules),
        default_caller_role="operator",
    )

    session_id = "sess_limit_test"

    # Call 1: Success (count = 1)
    r1 = gateway.invoke_tool_sync("send_email", {"to": "a@example.com"}, session_id=session_id)
    assert r1.outcome == "success"
    assert session_mgr.get_tool_count(session_id, "send_email") == 1

    # Call 2: Success (count = 2, reaches boundary)
    r2 = gateway.invoke_tool_sync("send_email", {"to": "b@example.com"}, session_id=session_id)
    assert r2.outcome == "success"
    assert session_mgr.get_tool_count(session_id, "send_email") == 2

    # Call 3: Exceeds limit -> Blocked before forwarding
    r3 = gateway.invoke_tool_sync("send_email", {"to": "c@example.com"}, session_id=session_id)
    assert r3.outcome == "denied"
    assert r3.result["reason_code"] == "CHAIN_INVOCATION_LIMIT_EXCEEDED"

    # Verify count did NOT increment on denied call
    assert session_mgr.get_tool_count(session_id, "send_email") == 2

    # Verify a different session has its own independent limit
    s2_id = "sess_limit_other"
    r_other = gateway.invoke_tool_sync("send_email", {"to": "d@example.com"}, session_id=s2_id)
    assert r_other.outcome == "success"
    assert session_mgr.get_tool_count(s2_id, "send_email") == 1


# ---------------------------------------------------------------------------
# 7. Fail-Closed Handling (Missing Components & Exceptions)
# ---------------------------------------------------------------------------
def test_missing_policy_engine_fails_closed():
    """Verify gateway invocation fails closed if policy engine is missing."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        default_caller_role="operator",
    )
    gateway.policy_engine = None  # Explicitly missing policy engine

    res = gateway.invoke_tool_sync("get_inventory", {"part_id": "PART-101"})
    assert res.outcome == "denied"
    assert res.result["reason_code"] == "POLICY_LOAD_ERROR"
    mock_client.call_tool.assert_not_called()


def test_session_manager_missing_fails_closed():
    """Verify gateway invocation fails closed if session manager is missing."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        default_caller_role="operator",
    )
    gateway.session_manager = None  # Explicitly missing session manager

    res = gateway.invoke_tool_sync("get_inventory", {"part_id": "PART-101"})
    assert res.outcome == "denied"
    assert res.result["reason_code"] == "SESSION_STATE_ERROR"
    mock_client.call_tool.assert_not_called()


def test_chain_engine_exception_fails_closed():
    """Verify chain engine exceptions deny execution with CHAIN_EVALUATION_ERROR."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock()

    mock_chain_engine = MagicMock()
    mock_chain_engine.evaluate.side_effect = RuntimeError("Simulated chain evaluator crash")

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        chain_engine=mock_chain_engine,
        default_caller_role="operator",
    )

    res = gateway.invoke_tool_sync("get_inventory", {"part_id": "PART-101"})
    assert res.outcome == "denied"
    assert res.result["reason_code"] == "CHAIN_EVALUATION_ERROR"
    mock_client.call_tool.assert_not_called()


# ---------------------------------------------------------------------------
# 8. Spoofing & Prompt Invariance Tests
# ---------------------------------------------------------------------------
def test_prompt_and_argument_spoofing_resistance():
    """Verify tool arguments and prompt injections cannot spoof session ID or caller role."""
    mock_client = MagicMock()
    mock_client.tool_to_server = {"get_inventory": "parts"}
    mock_client.call_tool = AsyncMock(return_value={"found": True})

    session_mgr = SessionManager()
    session_mgr.get_or_create_session("sess_real", caller_role="viewer")

    gateway = MCPGatewayProxy(
        mcp_client=mock_client,
        session_manager=session_mgr,
        default_caller_role="viewer",
    )

    # Attacker tries to inject session_id and role into tool arguments
    spoofed_args = {
        "part_id": "PART-101",
        "session_id": "sess_admin_fake",
        "caller_role": "admin",
        "taints": [],
    }

    # Gateway uses trusted session_id and caller_role passed in trusted parameters
    res = gateway.invoke_tool_sync(
        "get_inventory",
        spoofed_args,
        caller_role="viewer",
        session_id="sess_real",
    )

    # Denied by prerequisite rule for viewer (argument spoofing had zero effect)
    assert res.outcome == "denied"
    assert res.session_id == "sess_real"
    assert session_mgr.get_session("sess_admin_fake") is None
    mock_client.call_tool.assert_not_called()


# ---------------------------------------------------------------------------
# 9. Gateway Agent Multi-Turn Session Integration
# ---------------------------------------------------------------------------
def test_gateway_agent_carries_trusted_session():
    """Verify GatewayAgent binds a trusted session and executes multi-turn tool calls under it."""
    mock_gateway = MagicMock()
    mock_gateway.discover_tools = AsyncMock(return_value=[])
    mock_gateway.recorder = InMemoryCallRecorder()
    mock_gateway.invoke_tool = AsyncMock(
        return_value=GatewayInvocationResult(
            call_id="gw_mock_seq",
            server_name="parts",
            tool_name="search_parts",
            outcome="success",
            result={"count": 1, "parts": []},
            session_id="sess_agent_bound",
            session_seq=1,
        )
    )

    agent = GatewayAgent(
        gateway=mock_gateway,
        caller_role="operator",
        session_id="sess_agent_bound",
    )
    assert agent.session_id == "sess_agent_bound"

    agent.run_sync("Search for motor parts")

    mock_gateway.invoke_tool.assert_called_once()
    kwargs = mock_gateway.invoke_tool.call_args[1]
    assert kwargs.get("session_id") == "sess_agent_bound"
    assert kwargs.get("caller_role") == "operator"


# ---------------------------------------------------------------------------
# 10. Concurrency & Monotonic Sequence Numbering Tests
# ---------------------------------------------------------------------------
def test_concurrent_calls_sequence_monotonicity():
    """Verify concurrent tool calls within same session maintain strictly monotonic sequences."""

    async def _run_concurrent():
        mock_client = MagicMock()
        mock_client.tool_to_server = {"search_parts": "parts"}

        # Simulate async delay in tool execution to trigger overlap
        async def _delayed_call(name, args):
            await asyncio.sleep(0.01)
            return {"status": "ok", "count": 1}

        mock_client.call_tool = AsyncMock(side_effect=_delayed_call)

        session_mgr = SessionManager()
        gateway = MCPGatewayProxy(
            mcp_client=mock_client,
            session_manager=session_mgr,
            default_caller_role="operator",
        )
        session_id = "sess_concurrent"

        # Fire 10 overlapping invocations
        tasks = [
            gateway.invoke_tool(
                "search_parts",
                {"query": f"motor_{i}"},
                caller_role="operator",
                session_id=session_id,
            )
            for i in range(10)
        ]
        results = await asyncio.gather(*tasks)

        # Verify all succeeded
        for r in results:
            assert r.outcome == "success"
            assert r.session_id == session_id
            assert r.session_seq is not None

        # Verify sequence numbers are strictly 1..10 without collision
        seqs = [r.session_seq for r in results]
        assert sorted(seqs) == list(range(1, 11))
        assert len(set(seqs)) == 10

        # Verify session history matches count and monotonicity
        session = session_mgr.get_session(session_id)
        assert session is not None
        assert len(session.history) == 10
        assert [h.sequence_number for h in session.history] == list(range(1, 11))
        assert session.tool_counts["search_parts"] == 10

    asyncio.run(_run_concurrent())


def test_concurrent_invocation_limit_enforcement():
    """Verify concurrent invocations on same session cannot exceed configured limit."""

    async def _run():
        mock_client = MagicMock()
        mock_client.tool_to_server = {"search_parts": "parts"}

        async def _delayed_call(name, args):
            await asyncio.sleep(0.01)
            return {"status": "ok", "parts": []}

        mock_client.call_tool = AsyncMock(side_effect=_delayed_call)

        # Enforce limit of 2 calls to search_parts
        limit_rule = ChainRule(
            id="rule-limit-search",
            rule_type="invocation_limit",
            server="parts",
            tools=["search_parts"],
            max_invocations=2,
        )
        chain_engine = ChainRuleEngine(rules=[limit_rule])
        session_mgr = SessionManager()

        gateway = MCPGatewayProxy(
            mcp_client=mock_client,
            session_manager=session_mgr,
            chain_engine=chain_engine,
            default_caller_role="operator",
        )
        session_id = "sess_concurrent_limit"

        # Concurrently launch 5 calls on the same session
        tasks = [
            gateway.invoke_tool(
                "search_parts",
                {"query": f"motor_{i}"},
                caller_role="operator",
                session_id=session_id,
            )
            for i in range(5)
        ]
        results = await asyncio.gather(*tasks)

        # Exactly 2 calls succeed, exactly 3 calls are denied
        successes = [r for r in results if r.outcome == "success"]
        denials = [r for r in results if r.outcome == "denied"]
        assert len(successes) == 2
        assert len(denials) == 3

        for d in denials:
            assert d.result["reason_code"] == "CHAIN_INVOCATION_LIMIT_EXCEEDED"

        # Forwarding was called exactly 2 times; the 3 denied calls were never forwarded
        assert mock_client.call_tool.call_count == 2

        # Session state accurately reflects exactly 2 forwarded invocations
        session = session_mgr.get_session(session_id)
        assert session is not None
        assert session.tool_counts["search_parts"] == 2
        assert len(session.history) == 5

    asyncio.run(_run())


def test_concurrent_sensitive_read_and_email_dispatch_barrier():
    """Verify sensitive read taints session before concurrent email dispatch can evaluate."""

    async def _run():
        mock_client = MagicMock()
        mock_client.tool_to_server = {
            "read_file": "files",
            "send_email": "email",
        }

        async def _tool_dispatcher(name, args):
            if name == "read_file":
                # Simulate in-flight sensitive document retrieval with async delay
                await asyncio.sleep(0.02)
                return {
                    "status": "ok",
                    "content": "CANARY_SYNTHETIC_ALPHA: Confidential motor specs.",
                }
            if name == "send_email":
                return {"status": "ok", "sent": True}
            return {"status": "error", "error": "unknown tool"}

        mock_client.call_tool = AsyncMock(side_effect=_tool_dispatcher)

        # Policy allowing files and emails statically for operator
        test_policy_config = {
            "version": "1.0",
            "roles": {"operator": {"description": "Operator"}},
            "rules": [
                {
                    "id": "allow-files",
                    "action": "allow",
                    "roles": ["operator"],
                    "server": "files",
                    "tools": ["read_file"],
                },
                {
                    "id": "allow-email",
                    "action": "allow",
                    "roles": ["operator"],
                    "server": "email",
                    "tools": ["send_email"],
                },
            ],
            "chain_rules": [
                {
                    "id": "rule-exfil-barrier",
                    "rule_type": "forbidden_transition",
                    "server": "email",
                    "tools": ["send_email"],
                    "forbidden_if_tainted": ["sensitive_file_read"],
                }
            ],
        }
        policy_engine = PolicyEngine.load_from_dict(test_policy_config)
        session_mgr = SessionManager()

        gateway = MCPGatewayProxy(
            mcp_client=mock_client,
            policy_engine=policy_engine,
            session_manager=session_mgr,
            default_caller_role="operator",
        )
        session_id = "sess_concurrent_barrier"

        # Concurrently launch sensitive read and email send in the same session
        read_task = gateway.invoke_tool(
            "read_file",
            {"filename": "internal_memo_canary.txt"},
            caller_role="operator",
            session_id=session_id,
        )
        email_task = gateway.invoke_tool(
            "send_email",
            {"recipient": "audit@example.internal", "body": "stolen data"},
            caller_role="operator",
            session_id=session_id,
        )

        read_res, email_res = await asyncio.gather(read_task, email_task)

        # Read must succeed and apply taint
        assert read_res.outcome == "success"
        assert session_mgr.has_taint(session_id, "sensitive_file_read") is True

        # Email dispatch must be atomically serialized after the read, detecting the taint
        assert email_res.outcome == "denied"
        assert email_res.result["status"] == "denied"
        assert email_res.result["reason_code"] == "CHAIN_FORBIDDEN_TRANSITION"

        # Email server was NEVER forwarded the call
        called_tools = [c[0][0] for c in mock_client.call_tool.call_args_list]
        assert "send_email" not in called_tools
        assert called_tools == ["read_file"]

    asyncio.run(_run())


def test_cross_session_concurrency_no_deadlock():
    """Verify different sessions execute concurrently without blocking each other."""

    async def _run():
        mock_client = MagicMock()
        mock_client.tool_to_server = {
            "search_parts": "parts",
            "get_inventory": "parts",
        }

        completion_order: list[str] = []

        async def _tool_dispatcher(name, args):
            if name == "search_parts":
                # Slow call in session 1
                await asyncio.sleep(0.04)
                completion_order.append("slow_session_1")
                return {"status": "ok", "parts": []}
            if name == "get_inventory":
                # Fast call in session 2
                await asyncio.sleep(0.005)
                completion_order.append("fast_session_2")
                return {"status": "ok", "found": True}
            return {"status": "error"}

        mock_client.call_tool = AsyncMock(side_effect=_tool_dispatcher)

        session_mgr = SessionManager()
        gateway = MCPGatewayProxy(
            mcp_client=mock_client,
            session_manager=session_mgr,
            default_caller_role="operator",
        )

        # Launch slow call on sess_slow and fast call on sess_fast concurrently
        slow_task = gateway.invoke_tool(
            "search_parts",
            {"query": "motor"},
            caller_role="operator",
            session_id="sess_slow",
        )
        fast_task = gateway.invoke_tool(
            "get_inventory",
            {"part_id": "PART-101"},
            caller_role="operator",
            session_id="sess_fast",
        )

        res_slow, res_fast = await asyncio.gather(slow_task, fast_task)

        assert res_slow.outcome == "success"
        assert res_fast.outcome == "success"

        # Fast call in session 2 completed before slow call in session 1
        assert completion_order == ["fast_session_2", "slow_session_1"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 11. Live Local MCP Stdio Server Integration Tests
# ---------------------------------------------------------------------------
def test_live_gateway_session_chain_execution():
    """Live stdio test: GatewayProxy mediates real stdio tools with session sequencing."""

    async def _run():
        gateway = MCPGatewayProxy(default_caller_role="operator")
        await gateway.discover_tools()

        session_id = "sess_live_test"

        # 1. Search parts on real stdio server
        res1 = await gateway.invoke_tool(
            "search_parts",
            {"query": "motor"},
            caller_role="operator",
            session_id=session_id,
        )
        assert res1.outcome == "success"
        assert res1.session_seq == 1
        assert res1.session_id == session_id

        # 2. Get inventory for valid part
        res2 = await gateway.invoke_tool(
            "get_inventory",
            {"part_id": "PART-101"},
            caller_role="operator",
            session_id=session_id,
        )
        assert res2.outcome == "success"
        assert res2.session_seq == 2
        assert res2.result["found"] is True

        # 3. Verify session state in gateway recorder
        records = gateway.recorder.get_records()
        sess_recs = [r for r in records if r.session_id == session_id]
        assert len(sess_recs) == 2
        assert sess_recs[0].session_seq == 1
        assert sess_recs[1].session_seq == 2

    asyncio.run(_run())
