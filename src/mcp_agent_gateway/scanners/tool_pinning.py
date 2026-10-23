"""Tool description and schema hash pinning for MCP Agent Gateway.

Protects against dynamic tool rug-pulling and schema tampering attacks where a compromised
or rogue MCP server mutates tool descriptions, parameter schemas, or instruction semantics
after deployment to induce prompt injection or illicit agent behavior.

Security Limitations:
    This mechanism computes and validates canonical SHA-256 hashes stored in a local JSON
    configuration file. A local JSON file is NOT cryptographically signed or protected
    against an attacker with local file-write privileges who can alter both application code
    and pin configuration files. Its security guarantee is specifically defending against
    external/subprocess MCP servers dynamically tampering with tool descriptions or schemas
    at runtime.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def canonicalize_tool_definition(
    tool_name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
) -> str:
    """Produce a deterministic, canonical JSON representation of a tool definition.

    Ensures consistent key ordering and whitespace suppression so equivalent definitions
    always produce identical SHA-256 digests across platforms.

    Args:
        tool_name: Registered name of the tool.
        description: Declared description string.
        input_schema: Declared JSON Schema for arguments.

    Returns:
        Deterministic UTF-8 canonical JSON string.
    """
    normalized = {
        "name": str(tool_name).strip(),
        "description": str(description or "").strip(),
        "inputSchema": input_schema or {},
    }
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def compute_tool_hash(
    tool_name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
) -> str:
    """Compute the SHA-256 hex digest of a canonicalized tool definition."""
    canonical = canonicalize_tool_definition(tool_name, description, input_schema)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ToolPinVerificationResult:
    """Structured result of verifying a live tool definition against enrolled pins."""

    tool_key: str
    verified: bool
    status: str  # "matched", "mismatched", "unknown_pin", "disabled"
    expected_hash: str | None = None
    actual_hash: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to serializable dictionary."""
        return asdict(self)


class ToolDescriptionPinner:
    """Enforces and verifies cryptographic hash pins for MCP tool definitions.

    Invariants:
    1. Runtime operations never silently auto-enroll or mutate existing pins.
    2. Unknown tools or mismatched hash fingerprints fail closed when enforcement is enabled.
    """

    def __init__(
        self,
        pins_path: Path | str | None = None,
        enforce_pinning: bool = True,
    ) -> None:
        self.enforce_pinning = enforce_pinning
        self.pins_path = Path(pins_path) if pins_path else None
        self._pins: dict[str, str] = {}

        if self.pins_path and self.pins_path.exists():
            self.load_pins(self.pins_path)

    @staticmethod
    def make_tool_key(server_name: str, tool_name: str) -> str:
        """Construct standard scoped key format: 'server_name:tool_name'."""
        return f"{server_name}:{tool_name}"

    def load_pins(self, path: Path | str) -> None:
        """Load enrolled tool pins from a JSON file.

        Args:
            path: Path to the JSON configuration file containing tool pins.

        Raises:
            ValueError: If the pin file is malformed or missing the required 'tools' map.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Tool pins file not found at: {p}")

        with open(p, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict) or "tools" not in data or not isinstance(data["tools"], dict):
            raise ValueError(
                f"Malformed tool pins file at {p}: must contain top-level 'tools' dictionary."
            )

        self._pins = {str(k): str(v).lower() for k, v in data["tools"].items()}
        self.pins_path = p
        logger.info("Loaded %d tool hash pins from %s", len(self._pins), p)

    def enroll_tools(
        self,
        tools_by_server: list[tuple[str, Any]],
        output_path: Path | str,
    ) -> dict[str, str]:
        """Explicitly enroll discovered tool definitions and write them to a pins file.

        This is a deliberate administrative action and is never called implicitly during
        live tool dispatch.

        Args:
            tools_by_server: List of (server_name, ToolDefinition) tuples.
            output_path: Target path to write the JSON pins document.

        Returns:
            Dictionary of enrolled tool keys mapping to their SHA-256 hashes.
        """
        enrolled: dict[str, str] = {}
        for server_name, tool in tools_by_server:
            name = getattr(tool, "name", str(tool))
            description = getattr(tool, "description", None)
            input_schema = getattr(tool, "input_schema", getattr(tool, "inputSchema", None))
            key = self.make_tool_key(server_name, name)
            digest = compute_tool_hash(name, description, input_schema)
            enrolled[key] = digest

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0",
            "description": "Enrolled canonical SHA-256 hashes of MCP tool descriptions and schemas",
            "security_notice": (
                "A local JSON file is not cryptographically signed or protected against "
                "local file-write attacks. Its guarantee is defending against runtime "
                "MCP server tampering or rug-pulling."
            ),
            "tools": enrolled,
        }

        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)

        self._pins = dict(enrolled)
        self.pins_path = out
        logger.info("Explicitly enrolled %d tool pins into %s", len(enrolled), out)
        return enrolled

    def verify_tool(
        self,
        server_name: str,
        tool_name: str,
        description: str | None,
        input_schema: dict[str, Any] | None,
    ) -> ToolPinVerificationResult:
        """Verify a live tool definition against the enrolled pin dictionary.

        Args:
            server_name: Declared hosting MCP server name.
            tool_name: Registered tool name.
            description: Live description string provided by the server.
            input_schema: Live argument schema provided by the server.

        Returns:
            ToolPinVerificationResult indicating match status, expected hash, and actual hash.
        """
        key = self.make_tool_key(server_name, tool_name)
        actual_hash = compute_tool_hash(tool_name, description, input_schema)

        if not self.enforce_pinning:
            return ToolPinVerificationResult(
                tool_key=key,
                verified=True,
                status="disabled",
                actual_hash=actual_hash,
            )

        if key not in self._pins:
            return ToolPinVerificationResult(
                tool_key=key,
                verified=False,
                status="unknown_pin",
                actual_hash=actual_hash,
                error_message=f"Tool '{key}' is not enrolled in trusted tool pins configuration.",
            )

        expected_hash = self._pins[key]
        if actual_hash != expected_hash:
            return ToolPinVerificationResult(
                tool_key=key,
                verified=False,
                status="mismatched",
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                error_message=(
                    f"Tool description/schema pin mismatch for '{key}'. "
                    f"Expected: {expected_hash}, Live: {actual_hash}"
                ),
            )

        return ToolPinVerificationResult(
            tool_key=key,
            verified=True,
            status="matched",
            expected_hash=expected_hash,
            actual_hash=actual_hash,
        )

    def get_enrolled_count(self) -> int:
        """Return the count of currently enrolled tool pins."""
        return len(self._pins)
