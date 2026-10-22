"""Synthetic Parts and Inventory MCP Server.

Provides tools to search parts and check inventory against a synthetic dataset.
Uses the Model Context Protocol (MCP) Python SDK and stdio transport.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

# Base dataset fallback ensuring deterministic offline operation
DEFAULT_PARTS: list[dict[str, Any]] = [
    {
        "id": "PART-101",
        "name": "High-Torque Stepper Motor 24V",
        "category": "actuators",
        "price_usd": 45.50,
        "stock_count": 120,
        "warehouse_location": "Aisle-3-Bin-12",
    },
    {
        "id": "PART-102",
        "name": "Optical Rotary Encoder 1000PPR",
        "category": "sensors",
        "price_usd": 28.00,
        "stock_count": 45,
        "warehouse_location": "Aisle-1-Bin-04",
    },
    {
        "id": "PART-103",
        "name": "Digital Temperature Sensor Probe",
        "category": "sensors",
        "price_usd": 14.25,
        "stock_count": 300,
        "warehouse_location": "Aisle-1-Bin-09",
    },
    {
        "id": "PART-104",
        "name": "Microcontroller Embedded Board v2",
        "category": "controllers",
        "price_usd": 19.99,
        "stock_count": 0,
        "warehouse_location": "Aisle-5-Bin-01",
    },
    {
        "id": "PART-105",
        "name": "Industrial Switching Power Relay 24V",
        "category": "power",
        "price_usd": 8.75,
        "stock_count": 85,
        "warehouse_location": "Aisle-2-Bin-18",
    },
]


def load_parts_data() -> list[dict[str, Any]]:
    """Load synthetic inventory parts from file or return default fallback."""
    env_path = os.getenv("SYNTHETIC_INVENTORY_PATH")
    candidate_paths = [
        Path(env_path) if env_path else None,
        Path("data/synthetic/inventory.json"),
        Path(__file__).parents[3] / "data" / "synthetic" / "inventory.json",
    ]

    for p in candidate_paths:
        if p and p.is_file():
            try:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("parts", DEFAULT_PARTS)
            except Exception:
                break
    return DEFAULT_PARTS


def create_parts_server() -> MCPServer:
    """Create and configure the synthetic parts MCP server."""
    server = MCPServer("parts-inventory-server")

    @server.tool(
        name="search_parts",
        description="Search synthetic parts catalog by query substring or category filter.",
    )
    def search_parts(query: str = "", category: str = "") -> dict[str, Any]:
        """Search parts in synthetic catalog."""
        parts = load_parts_data()
        results: list[dict[str, Any]] = []
        q_lower = query.strip().lower()
        cat_lower = category.strip().lower()

        for item in parts:
            match_query = not q_lower or (
                q_lower in item["id"].lower() or q_lower in item["name"].lower()
            )
            match_category = not cat_lower or (cat_lower == item["category"].lower())
            if match_query and match_category:
                results.append(item)

        return {
            "synthetic": True,
            "count": len(results),
            "parts": results,
        }

    @server.tool(
        name="get_inventory",
        description="Get real-time synthetic inventory status for a specific part ID.",
    )
    def get_inventory(part_id: str) -> dict[str, Any]:
        """Get inventory details for a part ID."""
        parts = load_parts_data()
        clean_id = part_id.strip().upper()

        for item in parts:
            if item["id"].upper() == clean_id:
                return {
                    "synthetic": True,
                    "found": True,
                    "part": item,
                    "in_stock": item["stock_count"] > 0,
                }

        return {
            "synthetic": True,
            "found": False,
            "part_id": part_id,
            "error": f"Part '{part_id}' not found in synthetic catalog",
        }

    return server


if __name__ == "__main__":
    app = create_parts_server()
    app.run("stdio")
