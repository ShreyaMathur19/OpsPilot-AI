
"""Retrieve relevant historical investigations."""
import re

from . import store


def similar_cases(query: str, limit: int = 4):
    words = set(
        re.findall(r"[a-z0-9-]{4,}", query.lower())
    )

    records = store.query("""
        SELECT id, objective, status, result, created_at
        FROM runs
        WHERE status='completed'
        ORDER BY created_at DESC
        LIMIT 150
    """)

    ranked = []

    for record in records:
        text = (
            record["objective"] + " " + record["result"]
        ).lower()

        score = sum(
            1 for word in words
            if word in text
        )

        if score:
            ranked.append((score, record))

    ranked.sort(
        key=lambda item: item[0],
        reverse=True
    )

    results = []

    for score, record in ranked[:max(1, min(limit, 10))]:
        results.append({
            "run_id": record["id"],
            "objective": record["objective"],
            "summary": record["result"][:800],
            "created_at": record["created_at"],
            "match_score": score,
            "historical_only": True
        })

    return results
