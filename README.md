# MCP Agent Gateway

[![CI](https://github.com/placeholder-org/mcp-agent-gateway/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A security, governance, and observability gateway for **Model Context Protocol (MCP)** agents.

MCP Agent Gateway acts as an intelligent intermediary between autonomous AI agents and MCP server tools, enforcing granular policy constraints, PII/secret scanning, human-in-the-loop approvals, and audit trails.

---

## Current Status: Phase 0 (Foundations)

Phase 0 establishes the package scaffolding, environment baselines, CI automation, and code standards. Subsequent phases will introduce the MCP proxy protocol, policy engine, scanners, and agent orchestrators.

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

## Security Guidelines

- **Never commit `.env` or real credentials to version control.**
- Use `.env.example` solely as a documentation template for configuration keys.
- Input/output security scanning (e.g., Presidio, prompt guards) will be enabled in Phase 3.

---

## Roadmap

- **Phase 0:** Project foundations, CI, environment, and package skeleton *(Current)*
- **Phase 1:** Core MCP gateway protocol mediator and demo tool sandbox
- **Phase 2:** Declarative policy engine and session state management
- **Phase 3:** PII/secret scanners and human-in-the-loop approval gates
- **Phase 4:** Immutable audit logging, OpenTelemetry tracing, and observability
- **Phase 5:** End-to-end multi-agent orchestration and management dashboard
