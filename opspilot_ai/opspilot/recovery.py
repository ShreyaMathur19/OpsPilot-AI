
"""Safely retry read-only tool operations."""
import time

from .tools import execute_tool


READ_ONLY = {
    "get_device",
    "list_devices",
    "get_alerts",
    "get_owner",
    "search_knowledge",
    "list_incidents",
    "verify_device_status",
    "search_past_cases"
}


def safe_execute(
    name: str,
    arguments: dict,
    attempts: int = 2,
    executor=None,
    sleep=None
):
    execute = executor or execute_tool
    delay = sleep or time.sleep

    if name in READ_ONLY:
        max_attempts = max(1, min(int(attempts), 3))
    else:
        max_attempts = 1

    for i in range(max_attempts):
        try:
            return execute(name, arguments)

        except (TimeoutError, ConnectionError, OSError) as exc:
            if i + 1 == max_attempts:
                return {
                    "error": str(exc),
                    "retries_exhausted": True,
                    "attempts": i + 1
                }

            delay(0.2 * (2 ** i))
