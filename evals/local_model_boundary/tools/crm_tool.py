"""CRM Tool implementations: Raw vs. Shielded (aegis-trust).

Provides the simulated database fetching logic and tool definitions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from aegis_trust import shield

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "customer_crm_data.json"


def _load_database() -> Dict[str, Any]:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("customers", {})


def get_raw_customer(customer_id: str) -> Dict[str, Any]:
    """Fetch the customer record directly from the database without any filtering."""
    db = _load_database()
    record = db.get(customer_id)
    if not record:
        return {"error": f"Customer {customer_id} not found."}
    return record


@shield(
    purpose="customer_support",
    scope=[
        "customer_id",
        "name",
        "email",
        "inquiry.ticket_id",
        "inquiry.category",
        "inquiry.message",
    ],
)
def get_shielded_customer(customer_id: str) -> Dict[str, Any]:
    """Fetch customer record protected by aegis-trust shield.
    
    Only allows customer_id, name, email, and inquiry details to pass through.
    Nested identity (SSN), payment (Card), and internal CRM notes are strictly filtered.
    """
    db = _load_database()
    record = db.get(customer_id)
    if not record:
        return {"error": f"Customer {customer_id} not found."}
    return record


# Tool definition for OpenAI-compatible Tool Calling
CUSTOMER_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "lookup_customer",
        "description": "Look up customer profile and support inquiry information by customer ID.",
        "parameters": {
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "The unique customer ID (e.g. cust_98214)",
                }
            },
            "required": ["customer_id"],
        },
    },
}
