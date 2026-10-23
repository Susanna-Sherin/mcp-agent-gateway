"""MCP Gateway Proxy implementation.

Mediates, transparently forwards, and records tool calls between agents and MCP servers.
Enforces deterministic access control policies and session tool-chain rules.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_agent_gateway.agent.client import MultiServerMCPClient, ToolDefinition
    from mcp_agent_gateway.policy.evaluator import PolicyEngine
    from mcp_agent_gateway.session.manager import SessionManager
    from mcp_agent_gateway.session.rules import ChainRuleEngine

from mcp_agent_gateway.gateway.records import (
    InMemoryCallRecorder,
    ToolCallRecord,
    generate_timestamp_utc,
)
from mcp_agent_gateway.session.models import (
    ChainRuleDecision,
    SessionRoleMismatchError,
    SessionStateError,
)

logger = logging.getLogger(__name__)


@dataclass
class GatewayInvocationResult:
    """Typed result of a gateway-mediated tool invocation."""

    call_id: str
    server_name: str
    tool_name: str
    outcome: str  # "success", "error", "unknown_tool", "denied"
    result: dict[str, Any]
    error: str | None = None
    duration_ms: float = 0.0
    record: ToolCallRecord | None = None
    policy_decision: dict[str, Any] | None = None
    session_id: str | None = None
    session_seq: int | None = None
    chain_decision: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation for consumer compatibility."""
        return {
            "gateway_call_id": self.call_id,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "outcome": self.outcome,
            "result": self.result,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "policy_decision": self.policy_decision,
            "session_id": self.session_id,
            "session_seq": self.session_seq,
            "chain_decision": self.chain_decision,
        }


class MCPGatewayProxy:
    """Intercepts and transparently forwards MCP tool calls while maintaining audit records."""

    def __init__(
        self,
        mcp_client: MultiServerMCPClient | Any | None = None,
        recorder: InMemoryCallRecorder | None = None,
        policy_engine: PolicyEngine | Any | None = None,
        session_manager: SessionManager | Any | None = None,
        chain_engine: ChainRuleEngine | Any | None = None,
        default_caller_role: str = "operator",
    ) -> None:
        if mcp_client is None:
            from mcp_agent_gateway.agent.client import MultiServerMCPClient

            self.mcp_client = MultiServerMCPClient()
        else:
            self.mcp_client = mcp_client

        self.recorder = recorder if recorder is not None else InMemoryCallRecorder()
        self.default_caller_role = default_caller_role

        # Phase 3: Static Policy Engine
        if policy_engine is not None:
            self.policy_engine = policy_engine
        else:
            from mcp_agent_gateway.config.settings import get_settings
            from mcp_agent_gateway.policy.evaluator import PolicyEngine

            settings = get_settings()
            self.policy_engine = PolicyEngine.load_from_yaml(settings.policy_config_path)

        # Phase 4: Session Manager and Chain Engine
        if session_manager is not None:
            self.session_manager = session_manager
        else:
            from mcp_agent_gateway.session.manager import SessionManager

            self.session_manager = SessionManager()

        if chain_engine is not None:
            self.chain_engine = chain_engine
        elif self.policy_engine is not None and getattr(self.policy_engine, "chain_rules", None):
            from mcp_agent_gateway.session.rules import ChainRuleEngine

            self.chain_engine = ChainRuleEngine(rules=self.policy_engine.chain_rules)
        else:
            from mcp_agent_gateway.session.rules import ChainRuleEngine

            self.chain_engine = ChainRuleEngine(rules=[])

        self._server_map: dict[str, str] = {}

    async def discover_tools(self) -> list[ToolDefinition]:
        """Discover tools across configured MCP servers and refresh the server routing map."""
        tools = await self.mcp_client.discover_tools()
        self._server_map = dict(self.mcp_client.tool_to_server)
        return tools

    @staticmethod
    def _is_sensitive_file_read(arguments: dict[str, Any], result: Any) -> bool:
        """Deterministic condition identifying sensitive document or canary reads.

        Taints only reads meeting an explicit, deterministic sensitive-file condition.
        Ordinary document reads (such as spec_motor_v1.txt or supplier_catalog.txt)
        do not trigger the taint.
        """
        filename = str(arguments.get("filename", "")).lower()
        if (
            "internal_memo" in filename
            or "canary" in filename
            or "confidential" in filename
            or "restricted" in filename
        ):
            return True

        if isinstance(result, dict) and result.get("status") == "ok":
            content = str(result.get("content", ""))
            if "CANARY_SYNTHETIC_ALPHA" in content or "CONFIDENTIAL" in content:
                return True

        return False

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        caller_role: str | None = None,
        session_id: str | None = None,
    ) -> GatewayInvocationResult:
        """Invoke a tool through the gateway proxy, intercepting and recording the execution.

        Invocation sequence:
        1. Resolve and validate the registered tool.
        2. Resolve or create the trusted session and verify the bound role.
        3. Evaluate Phase 3 static policy under per-session lock.
        4. Evaluate chain rules before any MCP subprocess or side effect.
        5. Forward only when all mandatory checks pass.
        6. Update successful-call history, relevant taints, and invocation counts.
        7. Record the final decision and session sequence metadata.
        """
        call_id = f"gw_call_{uuid.uuid4().hex}"
        start_time = time.perf_counter()
        timestamp = generate_timestamp_utc()
        meta = metadata or {}
        role = caller_role or meta.get("caller_role") or self.default_caller_role

        # ------------------------------------------------------------------
        # Step 1: Resolve and validate the registered tool
        # ------------------------------------------------------------------
        server_name = self._server_map.get(tool_name) or self.mcp_client.tool_to_server.get(
            tool_name
        )
        if not server_name:
            await self.discover_tools()
            server_name = self._server_map.get(tool_name) or self.mcp_client.tool_to_server.get(
                tool_name
            )

        if not server_name:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = f"Tool '{tool_name}' not found on any configured MCP server."
            err_result = {"status": "error", "error": error_msg}
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name="unknown",
                tool_name=tool_name,
                arguments=arguments,
                outcome="unknown_tool",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
                session_id=session_id,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name="unknown",
                tool_name=tool_name,
                outcome="unknown_tool",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
                session_id=session_id,
            )

        # ------------------------------------------------------------------
        # Step 2: Resolve or create trusted session & verify bound role
        # ------------------------------------------------------------------
        if self.session_manager is None:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = "Session manager is uninitialized; failing closed."
            err_result = {
                "status": "denied",
                "error": error_msg,
                "reason_code": "SESSION_STATE_ERROR",
            }
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome="denied",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
                session_id=session_id,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome="denied",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
                session_id=session_id,
            )

        try:
            session, _ = self.session_manager.get_or_create_session(
                session_id=session_id,
                caller_role=role,
            )
            resolved_session_id = session.session_id
        except SessionRoleMismatchError as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = str(ex)
            err_result = {
                "status": "denied",
                "error": error_msg,
                "reason_code": "SESSION_ROLE_MISMATCH",
            }
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome="denied",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
                session_id=session_id,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome="denied",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
                session_id=session_id,
            )
        except SessionStateError as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = str(ex)
            err_result = {
                "status": "denied",
                "error": error_msg,
                "reason_code": "SESSION_STATE_ERROR",
            }
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome="denied",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
                session_id=session_id,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome="denied",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
                session_id=session_id,
            )
        except Exception as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_msg = f"Session state resolution error: {ex}"
            err_result = {
                "status": "denied",
                "error": error_msg,
                "reason_code": "SESSION_STATE_ERROR",
            }
            rec = ToolCallRecord(
                call_id=call_id,
                timestamp_utc=timestamp,
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                outcome="denied",
                result=err_result,
                error_message=error_msg,
                duration_ms=duration_ms,
                metadata=meta,
                session_id=session_id,
            )
            self.recorder.record(rec)
            return GatewayInvocationResult(
                call_id=call_id,
                server_name=server_name,
                tool_name=tool_name,
                outcome="denied",
                result=err_result,
                error=error_msg,
                duration_ms=duration_ms,
                record=rec,
                session_id=session_id,
            )

        # ------------------------------------------------------------------
        # Acquire per-session serialization lock
        # ------------------------------------------------------------------
        if hasattr(self.session_manager, "get_async_lock"):
            session_lock = self.session_manager.get_async_lock(resolved_session_id)
        else:
            session_lock = asyncio.Lock()

        async with session_lock:
            # Re-verify session is not revoked or deactivated while waiting for lock
            if (
                hasattr(self.session_manager, "is_revoked")
                and self.session_manager.is_revoked(resolved_session_id)
            ) or not session.is_active:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                error_msg = (
                    f"Session '{resolved_session_id}' has been deleted/revoked or is inactive."
                )
                err_result = {
                    "status": "denied",
                    "error": error_msg,
                    "reason_code": "SESSION_STATE_ERROR",
                }
                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="denied",
                    result=err_result,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    metadata=meta,
                    session_id=resolved_session_id,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                    result=err_result,
                    error=error_msg,
                    duration_ms=duration_ms,
                    record=rec,
                    session_id=resolved_session_id,
                )

            # ------------------------------------------------------------------
            # Step 3: Evaluate Phase 3 static policy. Static denial takes precedence.
            # ------------------------------------------------------------------
            if self.policy_engine is None:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                error_msg = "Security policy engine is missing; failing closed."
                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                )
                err_result = {
                    "status": "denied",
                    "error": error_msg,
                    "reason_code": "POLICY_LOAD_ERROR",
                }
                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="denied",
                    result=err_result,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    metadata=meta,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                    result=err_result,
                    error=error_msg,
                    duration_ms=duration_ms,
                    record=rec,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )

            decision = self.policy_engine.evaluate(
                caller_role=role,
                server=server_name,
                tool=tool_name,
                arguments=arguments,
            )
            if not decision.allowed:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                )
                err_result = {
                    "status": "denied",
                    "error": decision.reason,
                    "rule_id": decision.rule_id,
                    "reason_code": decision.reason_code,
                }
                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="denied",
                    result=err_result,
                    error_message=decision.reason,
                    duration_ms=duration_ms,
                    policy_decision=decision.to_dict(),
                    metadata={
                        **meta,
                        "policy": decision.to_dict(),
                    },
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                    result=err_result,
                    error=decision.reason,
                    duration_ms=duration_ms,
                    record=rec,
                    policy_decision=decision.to_dict(),
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )

            # ------------------------------------------------------------------
            # Step 4: Evaluate chain rules before any MCP subprocess or side effect
            # ------------------------------------------------------------------
            if self.chain_engine is None:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                error_msg = "Chain rule engine is missing; failing closed."
                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                )
                err_result = {
                    "status": "denied",
                    "error": error_msg,
                    "reason_code": "CHAIN_EVALUATION_ERROR",
                }
                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="denied",
                    result=err_result,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    policy_decision=decision.to_dict(),
                    metadata=meta,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                    result=err_result,
                    error=error_msg,
                    duration_ms=duration_ms,
                    record=rec,
                    policy_decision=decision.to_dict(),
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )

            try:
                chain_decision = self.chain_engine.evaluate(
                    session=session,
                    caller_role=role,
                    server=server_name,
                    tool=tool_name,
                )
            except Exception as ex:
                chain_decision = ChainRuleDecision(
                    allowed=False,
                    action="deny",
                    rule_id=None,
                    reason_code="CHAIN_EVALUATION_ERROR",
                    reason=f"Chain rule evaluation exception: {ex}",
                )

            if not chain_decision.allowed:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                )
                err_result = {
                    "status": "denied",
                    "error": chain_decision.reason,
                    "rule_id": chain_decision.rule_id,
                    "reason_code": chain_decision.reason_code,
                }
                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="denied",
                    result=err_result,
                    error_message=chain_decision.reason,
                    duration_ms=duration_ms,
                    policy_decision=decision.to_dict(),
                    chain_decision=chain_decision.to_dict(),
                    metadata={
                        **meta,
                        "policy": decision.to_dict(),
                        "chain": chain_decision.to_dict(),
                    },
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="denied",
                    result=err_result,
                    error=chain_decision.reason,
                    duration_ms=duration_ms,
                    record=rec,
                    policy_decision=decision.to_dict(),
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                    chain_decision=chain_decision.to_dict(),
                )

            # ------------------------------------------------------------------
            # Step 5: Forward only when all mandatory checks pass
            # ------------------------------------------------------------------
            try:
                result = await self.mcp_client.call_tool(tool_name, arguments)
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                if isinstance(result, dict) and result.get("status") == "error":
                    outcome = "error"
                    error_msg = str(result.get("error", "Tool reported error status"))
                else:
                    outcome = "success"
                    error_msg = None

                # --------------------------------------------------------------
                # Step 6: Update call history, relevant taints, and invocation counts
                # --------------------------------------------------------------
                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome=outcome,
                )

                # Apply sensitive read taint if explicit deterministic condition is met
                if (
                    outcome == "success"
                    and server_name == "files"
                    and tool_name == "read_file"
                    and self._is_sensitive_file_read(arguments, result)
                ):
                    self.session_manager.add_taint(resolved_session_id, "sensitive_file_read")

                # --------------------------------------------------------------
                # Step 7: Record final decision and session sequence metadata
                # --------------------------------------------------------------
                call_metadata = dict(meta)
                decision_dict = decision.to_dict()
                chain_dict = chain_decision.to_dict()
                call_metadata["policy"] = decision_dict
                call_metadata["chain"] = chain_dict

                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome=outcome,
                    result=result,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    policy_decision=decision_dict,
                    chain_decision=chain_dict,
                    metadata=call_metadata,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome=outcome,
                    result=result,
                    error=error_msg,
                    duration_ms=duration_ms,
                    record=rec,
                    policy_decision=decision_dict,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                    chain_decision=chain_dict,
                )
            except Exception as ex:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                error_msg = str(ex)
                err_result = {"status": "error", "error": error_msg}

                summary = self.session_manager.record_call(
                    session_id=resolved_session_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="error",
                )

                call_metadata = dict(meta)
                decision_dict = decision.to_dict()
                chain_dict = chain_decision.to_dict()
                call_metadata["policy"] = decision_dict
                call_metadata["chain"] = chain_dict

                rec = ToolCallRecord(
                    call_id=call_id,
                    timestamp_utc=timestamp,
                    server_name=server_name,
                    tool_name=tool_name,
                    arguments=arguments,
                    outcome="error",
                    result=err_result,
                    error_message=error_msg,
                    duration_ms=duration_ms,
                    policy_decision=decision_dict,
                    chain_decision=chain_dict,
                    metadata=call_metadata,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                )
                self.recorder.record(rec)
                return GatewayInvocationResult(
                    call_id=call_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    outcome="error",
                    result=err_result,
                    error=error_msg,
                    duration_ms=duration_ms,
                    record=rec,
                    policy_decision=decision_dict,
                    session_id=resolved_session_id,
                    session_seq=summary.sequence_number,
                    chain_decision=chain_dict,
                )

    def invoke_tool_sync(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        caller_role: str | None = None,
        session_id: str | None = None,
    ) -> GatewayInvocationResult:
        """Synchronous wrapper for invoke_tool."""
        return asyncio.run(
            self.invoke_tool(
                tool_name=tool_name,
                arguments=arguments,
                metadata=metadata,
                caller_role=caller_role,
                session_id=session_id,
            )
        )
