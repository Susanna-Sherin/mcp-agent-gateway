# MCP Agent Gateway

[![CI](https://github.com/placeholder-org/mcp-agent-gateway/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A security, governance, and observability gateway for **Model Context Protocol (MCP)** agents.

MCP Agent Gateway acts as an intelligent intermediary between autonomous AI agents and MCP server tools, enforcing granular policy constraints, PII/secret scanning, human-in-the-loop approvals, and audit trails.

---

## Current Status: Phase 4 (Session State and Tool-Chain Rules)

Phase 0 (Foundations), Phase 1 (Vulnerable Baseline), Phase 2 (Gateway Proxy & Call Recording), Phase 3 (Deterministic Policy Engine), and Phase 4 (Session State & Tool-Chain Rules) are implemented. Subsequent phases will introduce scanners, approval workflows, and persistent audit storage.

### Project Layout

```text
MCP-Agent-Gateway/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI workflow (lint + tests)
├── src/
│   └── mcp_agent_gateway/       # Core package
│       ├── __init__.py          # Package entrypoint & version definition
│       ├── config/              # Environment & application settings (Pydantic)
│       ├── gateway/             # MCP protocol routing & dispatching (Phase 1+)
│       ├── policy/              # Declarative policy engine & RBAC (Phase 2+)
│       ├── session/             # Session state & context tracker (Phase 2+)
│       ├── scanners/            # PII, prompt injection & secret scanners (Phase 3+)
│       ├── approval/            # Human-in-the-loop approval workflows (Phase 3+)
│       ├── audit/               # Immutable audit logging & compliance (Phase 4+)
│       ├── tools/               # MCP tool adapters & sandbox demo tools (Phase 1+)
│       ├── api/                 # FastAPI HTTP endpoints & management dashboard
│       ├── agent/               # Agent framework integration (Phase 5+)
│       └── observability/       # Tracing, metrics & OpenTelemetry hooks (Phase 4+)
├── tests/
│   ├── __init__.py
│   └── test_smoke.py            # Phase 0 verification & import smoke tests
├── .env.example                 # Template for environment variables (no secrets)
├── .gitignore                   # Git ignore patterns
├── pyproject.toml               # Package build metadata, Ruff & pytest configs
├── requirements.txt             # Pinned direct dependencies
├── requirements.lock            # Exact reproducible locked dependency tree
└── README.md                    # Project documentation
```

---

## Getting Started

### Prerequisites

- **Python 3.13+** (Verified on Python 3.13.7)
- **PowerShell / Bash**
- **Git**

### Installation

1. Activate your virtual environment (e.g., `.venv`):
   ```powershell
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   ```

2. Install reproducible locked dependencies and package in editable mode:
   ```powershell
   python -m pip install -r requirements.lock
   python -m pip install --no-deps -e .
   ```

3. Setup environment configuration:
   ```powershell
   Copy-Item .env.example .env
   ```

---

## Verification & Quality Assurance

### Run Tests
```powershell
pytest
```

### Run Linter & Formatter
```powershell
# Check for lint violations
ruff check .

# Check formatting without modifying files
ruff format --check .

# Auto-format files
ruff format .
```

---

---

## Phase 1 Baseline: Direct Tool Servers & Demo Agent

Phase 1 provides three isolated synthetic MCP tool servers and an unmediated direct LangGraph agent used as a baseline for measuring future security gateway effectiveness.

> [!NOTE]
> **Synthetic Sandbox Guarantee:** All parts, documents, and emails are strictly synthetic. The email tool writes simulated messages to a local folder (`data/synthetic/outbox/`) and never connects to SMTP or external networks. The file server strictly rejects path traversal attempts outside `data/synthetic/docs/`.

### 1. Running the MCP Servers Directly (stdio)

Each server communicates using the standard Model Context Protocol over stdio:

```powershell
# Synthetic Parts & Inventory Server
python -m mcp_agent_gateway.tools.parts_server

# Isolated File Operations Server (data/synthetic/docs/)
python -m mcp_agent_gateway.tools.files_server

# Fake Email Server (writes to data/synthetic/outbox/)
python -m mcp_agent_gateway.tools.email_server
```

### 2. Running the Direct Baseline Agent (Offline Mode)

The baseline LangGraph agent can discover and invoke tools across all three servers directly over stdio without requiring an external LLM API key:

```powershell
python -c "from mcp_agent_gateway.agent import DirectBaselineAgent; print(DirectBaselineAgent().run_sync('Check stock count and details for part PART-101')['final_response'])"
```

To run a multi-step adversarial canary baseline exfiltration experiment:
```powershell
python -c "from mcp_agent_gateway.agent.scenarios import BASELINE_SCENARIOS, run_scenario; res = run_scenario(BASELINE_SCENARIOS[4]); print('Canary leaked in baseline:', res.canaries_leaked)"
```

---

## Phase 2: MCP Gateway Proxy & Call Recording

The MCP Gateway Proxy (`MCPGatewayProxy`) mediates between agents and MCP tool servers over stdio, intercepting calls and recording in-memory audit logs.

```python
from mcp_agent_gateway.gateway.proxy import MCPGatewayProxy

gateway = MCPGatewayProxy(default_caller_role="operator")
result = gateway.invoke_tool_sync("get_inventory", {"part_id": "PART-101"})
print("Outcome:", result.outcome)
print("Call Record:", result.record.to_dict())
```

---

## Phase 3: Deterministic Policy Engine

Phase 3 introduces declarative security policies and a deterministic policy engine that acts as the security authority over all tool invocations before they reach MCP servers.

### Policy Configuration (`config/policies.yaml`)

Policies are configured declaratively in YAML with strict validation via Pydantic:

- **Authorized Roles:** `admin`, `operator`, `viewer`, `untrusted`.
- **Default Deny:** Any invocation not explicitly permitted by a matching allow rule is denied (`DEFAULT_DENY`).
- **Block Precedence:** Matching block rules always take absolute precedence over allow rules (`RULE_BLOCK`).
- **Argument Constraints:** Granular validation on argument types, allowed/blocked values, string regex patterns, and numeric ranges (`ARGUMENT_CONSTRAINT_VIOLATION`).
- **Subprocess Isolation:** Denied calls are terminated immediately within the gateway proxy; target MCP server processes are never spawned or called, preventing disk/network side effects.
- **Fail-Closed Security:** Missing or malformed policy files immediately fail closed, denying all tool calls (`POLICY_LOAD_ERROR`).

### Offline Policy Evaluation Example

```python
from pathlib import Path
from mcp_agent_gateway.policy import PolicyEngine

engine = PolicyEngine.load_from_yaml(Path("config/policies.yaml"))
decision = engine.evaluate(
    caller_role="operator",
    server="email",
    tool="send_email",
    arguments={
        "to": "attacker@external.darkweb.invalid",
        "subject": "Test",
        "body": "Data",
    },
)

print("Allowed:", decision.allowed)  # False
print("Reason Code:", decision.reason_code)  # RULE_BLOCK
print("Rule ID:", decision.rule_id)  # rule-block-external-exfiltration
```

---

## Phase 4: Session State and Tool-Chain Rules

Phase 4 introduces stateful, multi-step tool sequence governance through isolated session state and deterministic declarative chain rules.

### 1. Session State Architecture (`mcp_agent_gateway.session`)

- **Thread-Safe In-Memory Session Manager:** Manages isolated agent execution contexts synchronized via reentrant locking (`SessionManager`).
- **Cryptographic Unpredictability:** Generates unpredictable, cryptographically random session IDs (`sess_<token>`) in trusted application code when not caller-supplied.
- **Strict Role Binding:** Binds each session strictly to a single trusted caller role on creation. Re-access attempts with a conflicting role are immediately rejected (`SESSION_ROLE_MISMATCH`).
- **Revocation Tombstones:** Deleted sessions are permanently tombstoned so deleted session IDs cannot be reused to resurrect clean, untainted sessions (`SESSION_STATE_ERROR`). Calling `clear()` purges active session state while deliberately preserving revocation tombstones by default (`preserve_revocations=True`).
- **Prompt/Argument Spoofing Invariance:** Session identity and caller roles are never taken from LLM-generated output, tool arguments, or untrusted prompt text.
- **Minimal Audit History:** Retains strictly minimal call metadata: `sequence_number`, `server_name`, `tool_name`, `outcome`, and `timestamp_utc`. Never stores raw tool arguments, outputs, document contents, email bodies, or confidential payloads in session memory.
- **Session Isolation:** Histories, taints, and invocation counts are completely isolated per session with zero cross-session leakage.
- **Atomic Monotonic Ordering & Per-Session Locking:** Calls within the same session are serialized atomically using per-session async locks scoped to the running event loop. This prevents race conditions against invocation limits or sensitive-read taints while allowing calls across distinct sessions to run concurrently without deadlocks.

### 2. Declarative Chain Rules Schema (`config/policies.yaml`)

Chain rules extend the YAML policy document under `chain_rules:` with strict Pydantic validation (`extra="forbid"`):

| Rule Type | Description | Mandatory Schema Fields | Reason Code on Violation |
| :--- | :--- | :--- | :--- |
| `forbidden_transition` | Forbids invoking a target tool if the session carries an active taint. | `server`, `tools`, `forbidden_if_tainted` | `CHAIN_FORBIDDEN_TRANSITION` |
| `prerequisite` | Requires prior successful execution (`outcome == "success"`) of a real registered prerequisite tool. | `server`, `tools`, `prerequisite_tool` | `CHAIN_PREREQUISITE_NOT_MET` |
| `invocation_limit` | Restricts total forwarded tool invocations in a single session. | `server`, `tools`, `max_invocations` (>= 1) | `CHAIN_INVOCATION_LIMIT_EXCEEDED` |

### 3. Invocation Evaluation Sequence

`MCPGatewayProxy.invoke_tool` strictly enforces this 7-step sequence:

```text
1. Resolve and Validate Registered Tool
   └── If unknown tool: record unknown_tool outcome, return immediately.
2. Resolve or Create Trusted Session & Verify Bound Role
   ├── Fail closed if session manager is missing or ID is revoked (SESSION_STATE_ERROR).
   └── Reject if session is bound to a conflicting role (SESSION_ROLE_MISMATCH).
[Per-Session Async Lock Acquired]
3. Evaluate Phase 3 Static Policy
   ├── Fail closed if policy engine is missing (POLICY_LOAD_ERROR).
   └── Static policy denial takes strict precedence (RULE_BLOCK, DEFAULT_DENY, etc.).
4. Evaluate Phase 4 Chain Rules
   ├── Fail closed if chain engine is missing or errors (CHAIN_EVALUATION_ERROR).
   └── Evaluate taints, prerequisites, and invocation limits before any MCP subprocess.
5. Forward to MCP Client
   └── Subprocess invocation occurs ONLY if all prior checks passed.
6. Update Session State
   ├── Record call outcome ("success", "error", "denied") in minimal history.
   ├── Increment forwarded tool counts for successful/forwarded executions.
   └── Apply security taints on explicit sensitive file read conditions.
7. Record Audit Entry
   └── Append ToolCallRecord with session_id, session_seq, and chain_decision.
```

### 4. Sensitive Read to Email Barrier & Taint Semantics

- **Explicit Deterministic Taint:** Only reads meeting an explicit, deterministic sensitive-file condition (e.g. `internal_memo_canary.txt`, sensitive memo filenames, or containing benchmark canary token `CANARY_SYNTHETIC_ALPHA`) trigger `sensitive_file_read` taint.
- **Ordinary Document Protection:** Ordinary non-sensitive technical document reads (`spec_motor_v1.txt`, `supplier_catalog.txt`) do NOT taint the session.
- **Prerequisite Semantics:** Only prior calls with `outcome == "success"` satisfy prerequisites. Denied or failed calls cannot satisfy prerequisites.
- **Invocation Counting Semantics:** Invocation limits govern forwarded calls (calls that reached Step 5). Denied calls do not consume invocation quotas.

### 5. In-Memory State Limitations

- **Process Lifetime Scope:** Session state is held in-memory and is transient; restarting the gateway process resets all active sessions and counts.
- **Single-Node Deployment:** In-memory session tracking is designed for single gateway instances. Multi-instance distributed deployments require shared state backends (e.g., Redis).

---

## Security Guidelines

- **Never commit `.env` or real credentials to version control.**
- Use `.env.example` solely as a documentation template for configuration keys.
- Input/output security scanning (e.g., Presidio, prompt guards) will be enabled in Phase 5.

---

## Roadmap

- **Phase 0:** Project foundations, CI, environment, and package skeleton *(Done)*
- **Phase 1:** Vulnerable MCP baseline (parts, files, fake email, direct LangGraph agent) *(Done)*
- **Phase 2:** MCP Gateway proxy and call recording *(Done)*
- **Phase 3:** Deterministic policy engine and RBAC enforcement *(Done)*
- **Phase 4:** Session state, trusted role binding, and tool-chain rules *(Done)*
- **Phase 5:** PII/secret scanners, prompt guards, and human-in-the-loop approvals
- **Phase 6:** Immutable audit storage, OpenTelemetry tracing, and observability
- **Phase 7:** Multi-agent orchestration and management dashboard
