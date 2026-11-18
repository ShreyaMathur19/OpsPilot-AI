
"""
OpsPilot AI - Tool Registry and Execution

Features:
- 11 registered AI tools
- Device and alert retrieval
- Employee ownership lookup
- Internal policy search
- Incident management
- Simulated notifications
- Simulated device quarantine
- Device status verification
- Historical investigation memory

All actions operate on local simulated data.
No real devices are modified.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import store


ROOT = Path(__file__).resolve().parent.parent


# ============================================================
# TOOL SCHEMAS - AVAILABLE TO THE LLM
# ============================================================

SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "get_device",
            "description": (
                "Retrieve current information about a "
                "specific device from the internal database."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Unique device ID"
                    }
                },
                "required": ["device_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_devices",
            "description": (
                "List company devices. Optionally filter "
                "by compliance or operational status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "compliance": {
                        "type": "string"
                    },
                    "status": {
                        "type": "string"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": (
                "Retrieve security alerts and optionally "
                "filter by device ID or severity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    },
                    "severity": {
                        "type": "string"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_owner",
            "description": (
                "Retrieve the employee responsible "
                "for a specific device."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    }
                },
                "required": ["device_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_knowledge",
            "description": (
                "Search internal security policies and "
                "incident response playbooks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_incidents",
            "description": (
                "Retrieve previously created security "
                "incidents, optionally filtered by device."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_incident",
            "description": (
                "Create a simulated security incident "
                "when supported by evidence and policy. "
                "Avoid duplicate open incidents."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    },
                    "severity": {
                        "type": "string",
                        "enum": [
                            "low",
                            "medium",
                            "high",
                            "critical"
                        ]
                    },
                    "title": {
                        "type": "string"
                    },
                    "details": {
                        "type": "string"
                    }
                },
                "required": [
                    "device_id",
                    "severity",
                    "title",
                    "details"
                ]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "notify_owner",
            "description": (
                "Queue a simulated notification "
                "to the owner of a device. "
                "Does not send a real email."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    },
                    "message": {
                        "type": "string"
                    }
                },
                "required": [
                    "device_id",
                    "message"
                ]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "quarantine_device",
            "description": (
                "Request human approval for simulated "
                "device quarantine. This is a sensitive "
                "operation and must not be executed "
                "without authorization."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    },
                    "reason": {
                        "type": "string"
                    }
                },
                "required": [
                    "device_id",
                    "reason"
                ]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_device_status",
            "description": (
                "Verify a device's current operational "
                "status using the internal SQLite database."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string"
                    }
                },
                "required": ["device_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_past_cases",
            "description": (
                "Retrieve relevant historical completed "
                "investigations. Historical findings must "
                "not be treated as current device evidence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"]
            }
        }
    }
]


# ============================================================
# TOOL ACCESS CONTROL
# ============================================================

SENSITIVE = {
    "quarantine_device"
}

ALLOWED = {
    schema["function"]["name"]
    for schema in SCHEMAS
}


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _require_device(device_id):
    """Return a device or raise an error."""

    records = store.query(
        "SELECT * FROM devices WHERE device_id=?",
        (device_id,)
    )

    if not records:
        raise ValueError(
            f"Unknown device ID: {device_id}"
        )

    return records[0]


def _owner(device_id):
    """Retrieve employee ownership from employees.csv."""

    device = _require_device(device_id)

    path = ROOT / "data" / "employees.csv"

    with path.open(
        newline="",
        encoding="utf-8"
    ) as file:

        return next(
            (
                row
                for row in csv.DictReader(file)
                if row["employee_id"] == device["owner_id"]
            ),
            None
        )


# ============================================================
# TOOL EXECUTION ENGINE
# ============================================================

def execute_tool(name, args):
    """
    Execute an allowed internal tool.

    Important:
    The Agent class is responsible for requiring human
    approval before invoking sensitive tools.

    Direct calls to execute_tool("quarantine_device", ...)
    bypass that Agent-level approval queue. Keep this
    function internal and do not expose it as an
    unrestricted API endpoint.
    """

    if name not in ALLOWED:
        raise ValueError(
            f"Tool not available: {name}"
        )

    if not isinstance(args, dict):
        raise ValueError(
            "Tool arguments must be a JSON object"
        )

    # --------------------------------------------------------
    # 1. GET DEVICE
    # --------------------------------------------------------

    if name == "get_device":

        return _require_device(
            args["device_id"]
        )

    # --------------------------------------------------------
    # 2. LIST DEVICES
    # --------------------------------------------------------

    if name == "list_devices":

        sql = "SELECT * FROM devices WHERE 1=1"

        values = []

        for field in ("compliance", "status"):

            if args.get(field):
                sql += f" AND {field}=?"
                values.append(args[field])

        sql += " ORDER BY device_id LIMIT 50"

        return store.query(
            sql,
            values
        )

    # --------------------------------------------------------
    # 3. GET ALERTS
    # --------------------------------------------------------

    if name == "get_alerts":

        sql = "SELECT * FROM alerts WHERE 1=1"

        values = []

        for field in ("device_id", "severity"):

            if args.get(field):
                sql += f" AND {field}=?"
                values.append(args[field])

        sql += " ORDER BY observed_at DESC LIMIT 100"

        return store.query(
            sql,
            values
        )

    # --------------------------------------------------------
    # 4. GET OWNER
    # --------------------------------------------------------

    if name == "get_owner":

        owner = _owner(
            args["device_id"]
        )

        return owner or {
            "error": (
                "No owner record exists. "
                "Do not assume an owner."
            )
        }

    # --------------------------------------------------------
    # 5. SEARCH INTERNAL KNOWLEDGE
    # --------------------------------------------------------

    if name == "search_knowledge":

        policy_path = (
            ROOT / "data" / "security_policy.md"
        )

        playbook_path = (
            ROOT / "data" / "response_playbooks.json"
        )

        text = policy_path.read_text(
            encoding="utf-8"
        )

        policy_entries = [
            section.strip()
            for section in text.split("\n## ")
            if section.strip()
        ]

        playbooks = json.loads(
            playbook_path.read_text(
                encoding="utf-8"
            )
        )

        terms = {
            word.strip(".,:!?").lower()
            for word in args["query"].split()
            if len(word) > 3
        }

        scored = []

        for entry in policy_entries:

            score = sum(
                term in entry.lower()
                for term in terms
            )

            if score > 0:
                scored.append({
                    "score": score,
                    "source": "security_policy.md",
                    "excerpt": entry[:1100]
                })

        for playbook in playbooks:

            entry = json.dumps(
                playbook,
                ensure_ascii=False
            )

            score = sum(
                term in entry.lower()
                for term in terms
            )

            if score > 0:
                scored.append({
                    "score": score,
                    "source": "response_playbooks.json",
                    "excerpt": entry[:1100]
                })

        scored.sort(
            key=lambda item: item["score"],
            reverse=True
        )

        results = [
            {
                "source": entry["source"],
                "excerpt": entry["excerpt"]
            }
            for entry in scored[:5]
        ]

        return results or [
            {
                "source": "internal knowledge",
                "finding": (
                    "No matching rule found. "
                    "Escalate uncertainty rather "
                    "than invent policy."
                )
            }
        ]

    # --------------------------------------------------------
    # 6. LIST INCIDENTS
    # --------------------------------------------------------

    if name == "list_incidents":

        if args.get("device_id"):

            return store.query(
                """
                SELECT *
                FROM incidents
                WHERE device_id=?
                ORDER BY created_at DESC
                """,
                (args["device_id"],)
            )

        return store.query(
            """
            SELECT *
            FROM incidents
            ORDER BY created_at DESC
            LIMIT 50
            """
        )

    # --------------------------------------------------------
    # 7. CREATE INCIDENT
    # --------------------------------------------------------

    if name == "create_incident":

        _require_device(
            args["device_id"]
        )

        severity = args["severity"]

        if severity not in {
            "low",
            "medium",
            "high",
            "critical"
        }:
            raise ValueError(
                "Invalid incident severity"
            )

        title = args["title"][:140]
        details = args["details"][:1500]

        existing = store.query(
            """
            SELECT *
            FROM incidents
            WHERE device_id=?
              AND title=?
              AND state='open'
            """,
            (
                args["device_id"],
                title
            )
        )

        if existing:

            return {
                "status": "already_exists",
                "incident": existing[0]
            }

        incident_id = store.new_id("INC")

        store.execute(
            """
            INSERT INTO incidents
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                args["device_id"],
                severity,
                title,
                details,
                "open",
                store.now()
            )
        )

        return {
            "status": "created",
            "incident_id": incident_id
        }

    # --------------------------------------------------------
    # 8. NOTIFY OWNER
    # --------------------------------------------------------

    if name == "notify_owner":

        owner = _owner(
            args["device_id"]
        )

        if not owner:

            return {
                "error": (
                    "Owner missing. "
                    "Notification not created."
                )
            }

        notification_id = store.new_id("NTF")

        store.execute(
            """
            INSERT INTO notifications
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                notification_id,
                args["device_id"],
                owner["email"],
                args["message"][:1000],
                store.now()
            )
        )

        return {
            "status": "queued_locally",
            "notification_id": notification_id,
            "recipient": owner["email"],
            "delivery": "simulation_only"
        }

    # --------------------------------------------------------
    # 9. QUARANTINE DEVICE (SIMULATED)
    # --------------------------------------------------------

    if name == "quarantine_device":

        device = _require_device(
            args["device_id"]
        )

        if device["status"] == "quarantined":

            return {
                "status": "already_quarantined",
                "device_id": device["device_id"]
            }

        store.execute(
            """
            UPDATE devices
            SET status='quarantined'
            WHERE device_id=?
            """,
            (args["device_id"],)
        )

        return {
            "status": "quarantined",
            "device_id": args["device_id"],
            "simulation_only": True
        }

    # --------------------------------------------------------
    # 10. VERIFY DEVICE STATUS
    # --------------------------------------------------------

    if name == "verify_device_status":

        device = _require_device(
            args["device_id"]
        )

        return {
            "device_id": device["device_id"],
            "status": device["status"],
            "verified_against": "sqlite_devices"
        }

    # --------------------------------------------------------
    # 11. SEARCH HISTORICAL INVESTIGATIONS
    # --------------------------------------------------------

    if name == "search_past_cases":

        from .memory import similar_cases

        return similar_cases(
            args["query"]
        )

    # --------------------------------------------------------
    # UNKNOWN TOOL
    # --------------------------------------------------------

    raise ValueError(
        f"Unsupported tool: {name}"
    )
