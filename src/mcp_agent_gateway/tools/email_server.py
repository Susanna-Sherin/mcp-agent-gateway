"""Fake Email MCP Server.

Provides a tool to write simulated outgoing messages to a local sandbox outbox directory.
Never connects to SMTP, external email networks, or cloud delivery services.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer


def get_outbox_dir() -> Path:
    """Resolve and ensure the dedicated simulated email outbox directory exists."""
    env_dir = os.getenv("SYNTHETIC_OUTBOX_DIR")
    if env_dir:
        outbox = Path(env_dir).resolve()
    else:
        repo_root = Path(__file__).parents[3]
        outbox = (repo_root / "data" / "synthetic" / "outbox").resolve()

    outbox.mkdir(parents=True, exist_ok=True)
    return outbox


def create_email_server() -> MCPServer:
    """Create and configure the fake email MCP server."""
    server = MCPServer("fake-email-server")

    @server.tool(
        name="send_email",
        description="Simulate sending an email by writing message payload to local sandbox outbox.",
    )
    def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
        """Simulate sending an email to a recipient."""
        outbox_dir = get_outbox_dir()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:8]
        msg_id = f"sim_email_{timestamp}_{unique_suffix}"

        payload = {
            "message_id": msg_id,
            "status": "simulated_only",
            "synthetic": True,
            "recipient": to.strip(),
            "subject": subject.strip(),
            "body": body,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "delivery_mechanism": "local_disk_sandbox",
        }

        outbox_file = outbox_dir / f"{msg_id}.json"
        try:
            with open(outbox_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as ex:
            return {
                "synthetic": True,
                "status": "error",
                "error": f"Failed writing to local outbox: {ex}",
            }

        return {
            "synthetic": True,
            "status": "simulated_only",
            "message_id": msg_id,
            "recipient": payload["recipient"],
            "subject": payload["subject"],
            "outbox_file": outbox_file.name,
            "note": "No external network transmission was made; simulated sandbox delivery only.",
        }

    @server.tool(
        name="list_outbox",
        description="List all simulated messages currently recorded in the local sandbox outbox.",
    )
    def list_outbox() -> dict[str, Any]:
        """List messages stored in the simulated outbox."""
        outbox_dir = get_outbox_dir()
        messages: list[dict[str, Any]] = []

        for p in sorted(outbox_dir.glob("sim_email_*.json")):
            try:
                with open(p, encoding="utf-8") as f:
                    messages.append(json.load(f))
            except Exception:
                continue

        return {
            "synthetic": True,
            "status": "ok",
            "count": len(messages),
            "messages": messages,
        }

    return server


if __name__ == "__main__":
    app = create_email_server()
    app.run("stdio")
