
"""Deterministic agent tool evaluation."""
import time

from . import store
from .events import ensure_tables
from .tools import execute_tool


def evaluate():
    store.init_db()
    ensure_tables()

    checks = []

    def test(name, fn):
        start = time.perf_counter()

        try:
            result = fn()

            checks.append({
                "test": name,
                "passed": bool(result),
                "duration_ms": round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                "detail": str(result)[:160]
            })

        except Exception as exc:
            checks.append({
                "test": name,
                "passed": False,
                "duration_ms": round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                "detail": repr(exc)
            })

    test(
        "Device lookup",
        lambda: execute_tool(
            "get_device", {"device_id": "DEV-104"}
        )["device_id"] == "DEV-104"
    )

    test(
        "Alert retrieval",
        lambda: bool(
            execute_tool(
                "get_alerts", {"device_id": "DEV-104"}
            )
        )
    )

    test(
        "Policy retrieval",
        lambda: bool(
            execute_tool(
                "search_knowledge",
                {"query": "malware quarantine approval"}
            )
        )
    )

    def unknown_device_rejected():
        try:
            execute_tool(
                "get_device",
                {"device_id": "DEV-NOT-FOUND"}
            )
        except ValueError:
            return True

        return False

    test(
        "Unknown device rejected",
        unknown_device_rejected
    )

    test(
        "Historical memory available",
        lambda: isinstance(
            execute_tool(
                "search_past_cases",
                {"query": "malware DEV-104"}
            ),
            list
        )
    )

    return {
        "total": len(checks),
        "passed": sum(x["passed"] for x in checks),
        "checks": checks,
        "note": (
            "These checks validate tools, not "
            "LLM reasoning accuracy."
        )
    }
