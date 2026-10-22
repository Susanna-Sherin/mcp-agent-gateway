"""Synthetic File Operations MCP Server.

Provides tools to list and read synthetic documentation files within a strictly
isolated test data boundary. Never reads host secrets, environment variables,
or arbitrary filesystem paths outside the sandbox.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer


def get_allowed_docs_dir() -> Path:
    """Resolve and ensure the dedicated allowed synthetic docs directory exists."""
    env_dir = os.getenv("SYNTHETIC_DOCS_DIR")
    if env_dir:
        base = Path(env_dir).resolve()
    else:
        # Default to data/synthetic/docs within repository root
        repo_root = Path(__file__).parents[3]
        base = (repo_root / "data" / "synthetic" / "docs").resolve()

    base.mkdir(parents=True, exist_ok=True)
    return base


def validate_path_safety(requested_name: str, base_dir: Path) -> tuple[bool, Path | None, str]:
    """Validate that the requested path resolves strictly within the allowed base directory.

    Rejects directory traversal (e.g. '../'), absolute paths, null bytes,
    and symlink escapes.
    """
    if not requested_name or not requested_name.strip():
        return False, None, "Path cannot be empty"

    if "\x00" in requested_name:
        return False, None, "Path contains null byte"

    target_candidate = (base_dir / requested_name).resolve()

    # Verify that target_candidate is strictly inside base_dir
    try:
        target_candidate.relative_to(base_dir)
    except ValueError:
        return (
            False,
            None,
            "Path boundary violation: Access outside synthetic test directory is prohibited",
        )

    return True, target_candidate, ""


def create_files_server() -> MCPServer:
    """Create and configure the synthetic files MCP server."""
    server = MCPServer("files-operation-server")

    @server.tool(
        name="list_files",
        description="List files available in the synthetic documents sandbox directory.",
    )
    def list_files(subpath: str = "") -> dict[str, Any]:
        """List files in the synthetic docs directory."""
        base_dir = get_allowed_docs_dir()
        target_dir = base_dir

        if subpath.strip():
            safe, resolved, err = validate_path_safety(subpath, base_dir)
            if not safe or resolved is None:
                return {
                    "synthetic": True,
                    "status": "rejected",
                    "error": err,
                    "files": [],
                }
            target_dir = resolved

        if not target_dir.is_dir():
            return {
                "synthetic": True,
                "status": "error",
                "error": f"Directory '{subpath}' does not exist",
                "files": [],
            }

        file_list: list[dict[str, Any]] = []
        for item in sorted(target_dir.iterdir()):
            if item.is_file():
                file_list.append(
                    {
                        "name": item.name,
                        "size_bytes": item.stat().st_size,
                        "relative_path": str(item.relative_to(base_dir)),
                    }
                )

        return {
            "synthetic": True,
            "status": "ok",
            "base_sandbox": str(base_dir.name),
            "count": len(file_list),
            "files": file_list,
        }

    @server.tool(
        name="read_file",
        description="Read content of a file within the synthetic documents sandbox directory.",
    )
    def read_file(filename: str) -> dict[str, Any]:
        """Read text content of a synthetic document with boundary enforcement."""
        base_dir = get_allowed_docs_dir()
        safe, target_file, err = validate_path_safety(filename, base_dir)

        if not safe or target_file is None:
            return {
                "synthetic": True,
                "status": "rejected",
                "filename": filename,
                "error": err,
                "security_boundary_enforced": True,
            }

        if not target_file.is_file():
            return {
                "synthetic": True,
                "status": "not_found",
                "filename": filename,
                "error": f"File '{filename}' not found in synthetic documents sandbox",
            }

        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
            return {
                "synthetic": True,
                "status": "ok",
                "filename": target_file.name,
                "content": content,
                "size_bytes": len(content),
            }
        except Exception as ex:
            return {
                "synthetic": True,
                "status": "error",
                "filename": filename,
                "error": f"Failed reading file: {ex}",
            }

    return server


if __name__ == "__main__":
    app = create_files_server()
    app.run("stdio")
