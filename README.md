# MCP Agent Gateway

[![CI](https://github.com/placeholder-org/mcp-agent-gateway/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A security, governance, and observability gateway for **Model Context Protocol (MCP)** agents.

MCP Agent Gateway acts as an intelligent intermediary between autonomous AI agents and MCP server tools, enforcing granular policy constraints, PII/secret scanning, human-in-the-loop approvals, and audit trails.

---

## Current Status: Phase 6 (Human Approval Queue & Persistent SQLite Audit Log)

Phase 0 (Foundations), Phase 1 (Vulnerable Baseline), Phase 2 (Gateway Proxy & Call Recording), Phase 3 (Deterministic Policy Engine), Phase 4 (Session State & Tool-Chain Rules), Phase 5 (Security Scanners & Tool Description Pinning), and Phase 6 (Human Approval Queue & Persistent SQLite Audit Log) are fully implemented.

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

## Phase 5: Security Scanners & Tool Description Pinning

Phase 5 introduces comprehensive pre-forwarding input filtering, post-execution output redaction, and cryptographic tool-definition verification.

### 1. Deterministic PII Scanner & Luhn Validator (`mcp_agent_gateway.scanners.pii`)

- **Deterministic Pattern Recognizers:** Detects US Social Security Numbers (`US_SSN`, strictly SSA-compliant excluding area numbers 000, 666, 900–999), RFC-compliant email addresses (`EMAIL`), and international/North American phone numbers (`PHONE`).
- **Payment Card Detection with Luhn (Mod 10) Checksum:** Candidate payment card numbers (13–19 digits matching major card issuer patterns) must pass a full Luhn verification algorithm. Numbers failing the mod 10 checksum are preserved as non-sensitive strings to prevent overblocking.
- **Pure-Python Offline Engine:** Operates 100% offline with zero mandatory external NLP models or heavy dependencies. Microsoft Presidio Analyzer is supported as an optional pluggable backend when installed.
- **Safe Reverse-Index Redaction:** Replaces detected entities in text with `[REDACTED_{ENTITY_TYPE}]` using reverse-index substitution to maintain offset integrity without corrupting adjacent text.
- **Recursive Structural Traversal:** Recursively inspects and redacts arbitrarily nested dictionaries, lists, sets, and strings across tool arguments and outputs.

### 2. Prompt-Injection Scanner & Conditional Gemini Judge (`mcp_agent_gateway.scanners.prompt_injection`)

- **Tier 1 (Deterministic Signatures & Suspicion Scoring):** Weighted regular expression patterns detect system prompt overrides, instruction resets, jailbreak personas (DAN/developer mode), raw chat template markup (`<|im_start|>`), and confidential exfiltration directives.
- **Immediate Heuristic Denial:** High-confidence attacks (suspicion score >= 0.85) are blocked deterministically without making an LLM call.
- **Benign Query Protection:** Standard motor parts catalog queries (`search_parts`, part numbers, inventory counts) evaluate with low suspicion scores (< 0.40) and pass without interruption.
- **Tier 2 (Conditional Gemini Judge):** Ambiguous suspicious inputs (0.40 <= score < 0.85) are routed to a structured Gemini model classification call ONLY when `scanner_gemini_judge_enabled` is explicitly configured and an API key is present.
- **Security Boundaries:** The Gemini judge NEVER makes role or tool authorization decisions, and CANNOT override static policy or chain rule denials. If the judge is unavailable or raises an error, the gateway fails closed (`SCANNER_PROMPT_INJECTION`).

### 3. Tool Description & Schema Pinning (`mcp_agent_gateway.scanners.tool_pinning`)

- **Rug-Pulling & Tampering Defense:** Protects against compromised or rogue MCP servers dynamically altering tool descriptions, instructions, or input schemas at runtime.
- **Canonical Hash Generation:** Normalizes tool name, description, and input schema using deterministic JSON sorting and whitespace suppression, generating canonical SHA-256 digests.
- **Administrative Enrollment:** Discovered tool definitions are explicitly enrolled via `enroll_tool_pins()` and saved to `config/tool_pins.json`. Runtime execution NEVER silently enrolls or mutates pins.
- **Strict Verification:** Un-enrolled tools or mismatched hash digests are immediately denied (`TOOL_DESCRIPTION_PIN_MISMATCH` or `TOOL_DESCRIPTION_UNKNOWN_PIN`).
- **Security Scope Notice:** A local JSON pin file is not cryptographically signed or protected against an attacker with local file-write privileges who can modify application files. Its security guarantee is specifically defending against external or subprocess MCP servers tampering with tools at runtime.

### 4. Comprehensive 9-Step Gateway Invocation Pipeline

`MCPGatewayProxy.invoke_tool` strictly enforces this 9-step execution flow:

```text
1. Resolve Registered Tool & Verify Description Pin
   ├── If unknown tool: return unknown_tool outcome immediately.
   └── If tool_pinning_enabled: verify live tool against enrolled SHA-256 hash pins.
       └── Fail closed if unknown or mismatched (TOOL_DESCRIPTION_PIN_MISMATCH).
2. Resolve or Create Trusted Session & Verify Bound Role
   ├── Fail closed if session manager missing or session revoked (SESSION_STATE_ERROR).
   └── Reject if session bound to conflicting role (SESSION_ROLE_MISMATCH).
[Per-Session Async Lock Acquired]
3. Evaluate Phase 3 Static Policy
   ├── Fail closed if policy engine is missing (POLICY_LOAD_ERROR).
   └── Static policy denial takes strict precedence (RULE_BLOCK, DEFAULT_DENY, etc.).
4. Evaluate Phase 4 Chain Rules
   ├── Fail closed if chain engine missing or errors (CHAIN_EVALUATION_ERROR).
   └── Enforce taints, prerequisites, and invocation limits before any MCP subprocess.
4.5. Evaluate Pre-Forwarding Input Scanners
   ├── Block confidential canary token exfiltration (SCANNER_CANARY_LEAKAGE).
   ├── Block input PII in tool arguments (SCANNER_PII_DETECTED).
   ├── Block input prompt injections (SCANNER_PROMPT_INJECTION).
   └── Scanner exceptions fail closed and release session lock (SCANNER_ERROR).
5. Forward to MCP Client
   └── Subprocess invocation occurs ONLY if all prior checks passed.
5.5. Evaluate Post-Execution Output Scanners
   ├── Detect synthetic benchmark canary token in output (canary_leakage_detected).
   └── Redact discovered PII entities from output ([REDACTED_{ENTITY_TYPE}]).
6. Update Session State
   ├── Record minimal call history ("success", "error", "denied").
   ├── Increment forwarded tool counts for forwarded executions.
   └── Apply security taints on explicit sensitive document reads.
7. Record Audit Entry
   └── Append ToolCallRecord with scanner_results, redacting sensitive arguments.
```

### 5. Phase 5 Configuration Settings

| Setting | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `scanner_pii_enabled` | `SCANNER_PII_ENABLED` | `true` | Scan tool arguments for PII and redact output PII. |
| `scanner_injection_enabled` | `SCANNER_INJECTION_ENABLED` | `true` | Evaluate input arguments for prompt injection signatures. |
| `scanner_gemini_judge_enabled` | `SCANNER_GEMINI_JUDGE_ENABLED` | `false` | Enable Tier 2 Gemini judge for ambiguous inputs. |
| `tool_pinning_enabled` | `TOOL_PINNING_ENABLED` | `true` | Enforce SHA-256 hash pinning for tool descriptions/schemas. |
| `tool_pins_path` | `TOOL_PINS_PATH` | `config/tool_pins.json` | Path to enrolled tool description pins configuration. |

---

## Phase 6: Human Approval Queue & Persistent SQLite Audit Log

Phase 6 introduces asynchronous human-in-the-loop authorization gates and tamper-evident persistent compliance logging backed by SQLite.

### 1. Human Approval State Machine (`mcp_agent_gateway.approval`)

```text
                  ┌──────────────┐
                  │   PENDING    │
                  └──────┬───────┘
          ┌──────────────┼──────────────┐
          │ (approve)    │ (reject)     │ (TTL expired)
          ▼              ▼              ▼
   ┌─────────────┐ ┌────────────┐ ┌───────────┐
   │  APPROVED   │ │  REJECTED  │ │  EXPIRED  │
   └──────┬──────┘ └────────────┘ └───────────┘
          │ (claimed by gateway)
          ▼
   ┌─────────────┐
   │  CONSUMED   │ (irreversible, single-use)
   └─────────────┘
```

- **Atomic Single-Use Claim:** Transition from `APPROVED` to `CONSUMED` occurs atomically in SQLite immediately before any tool forwarding. Only one claimant may succeed; any subsequent replay attempts are denied (`APPROVAL_ALREADY_CONSUMED`).
- **Irreversible Consumption:** Once consumed, an approval is never restored—even if downstream MCP execution times out, raises an exception, or the gateway restarts. Retrying requires submitting a fresh approval request.
- **Cryptographic Request Binding:** Approvals are bound to a deterministic SHA-256 fingerprint computed across gateway-resolved caller identity, role, session ID, server, tool, and canonical sorted arguments. Modifying any parameter causes claim rejection (`APPROVAL_BINDING_MISMATCH`).
- **Current-State Revalidation:** Upon claim, the gateway revalidates session activity, role match, static block rules, chain rules (taints/limits), and pre-forwarding scanners. Explicit block rules always take absolute precedence.

### 2. Persistent SQLite Audit Storage (`mcp_agent_gateway.audit`)

- **Durable Source of Truth:** Every terminal invocation outcome (`success`, `error`, `unknown_tool`, `denied`), policy decision, chain decision, scanner result, and approval identifier is durably recorded in SQLite (`data/gateway.db`).
- **Privacy Sanitization Guarantee:** Only sanitized argument and result representations (PII redacted, canary tokens replaced) are persisted to disk. Raw unsanitized arguments and raw stack traces are never written to SQLite.
- **Fail-Closed Persistence Semantics:** If pre-execution audit storage is unavailable, protected operations fail closed (`AUDIT_PERSISTENCE_ERROR`). If post-execution audit persistence fails, the error is returned to the caller and the tool is never retried automatically.
- **High Concurrency Support:** Operates using SQLite Write-Ahead Logging (`WAL`), synchronous normal, and a 5000ms busy timeout.

### 3. Reviewer Authentication & FastAPI Endpoints (`mcp_agent_gateway.api`)

- **Fail-Closed Administrative Auth:** All administrative and reviewer endpoints require `GATEWAY_ADMIN_API_KEY` to be explicitly configured. If absent or empty, administrative endpoints fail closed (`503 Service Unavailable`).
- **Reviewer Identity Header:** Requests must provide constant-time verified credentials via `X-Admin-Key` (or `Authorization: Bearer <key>`) alongside mandatory `X-Reviewer-Id` header identifying the human reviewer.
- **Available Endpoints:**
  - `GET /healthz`: Public system health check.
  - `GET /approvals/pending`: List active pending approval requests (paginated).
  - `GET /approvals/{id}`: Inspect details of an approval request.
  - `POST /approvals/{id}/approve`: Authorized reviewer approves pending request (body: `{"reason": "..."}`).
  - `POST /approvals/{id}/reject`: Authorized reviewer rejects pending request (body: `{"reason": "..."}`).
  - `GET /audit/records`: Query durable audit log with filtering (`session_id`, `tool_name`, `outcome`) and pagination (`limit`, `offset`).
  - `GET /audit/records/{call_id}`: Retrieve full audit record for a specific call ID.

### 4. Phase 6 Configuration Settings

| Setting | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `audit_db_path` | `AUDIT_DB_PATH` | `data/gateway.db` | Persistent SQLite database path for audit logs and approval queue. |
| `approval_timeout_seconds` | `APPROVAL_TIMEOUT_SECONDS` | `300` | Approval request time-to-live in seconds before auto-expiring. |
| `audit_retention_days` | `AUDIT_RETENTION_DAYS` | `90` | Audit record retention period in days. |
| `admin_api_key` | `GATEWAY_ADMIN_API_KEY` | `null` | Pre-shared administrative API key. If unset, reviewer endpoints fail closed. |

---

## Security Guidelines

- **Never commit `.env` or real credentials to version control.**
- Use `.env.example` solely as a documentation template for configuration keys.
- Scanners run pre-forwarding on inputs and post-execution on outputs to prevent data leakage.
- Approvals are single-use, non-transferable, and cryptographically bound to request context.

---

## Roadmap

- **Phase 0:** Project foundations, CI, environment, and package skeleton *(Done)*
- **Phase 1:** Vulnerable MCP baseline (parts, files, fake email, direct LangGraph agent) *(Done)*
- **Phase 2:** MCP Gateway proxy and call recording *(Done)*
- **Phase 3:** Deterministic policy engine and RBAC enforcement *(Done)*
- **Phase 4:** Session state, trusted role binding, and tool-chain rules *(Done)*
- **Phase 5:** PII scanning, prompt injection guards, and tool description pinning *(Done)*
- **Phase 6:** Human approval queue and persistent SQLite audit logging *(Done)*
- **Phase 7:** Multi-agent orchestration and management dashboard
