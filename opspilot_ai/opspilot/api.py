
"""Authenticated local security event API."""
import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import store, events


app = FastAPI(
    title="OpsPilot AI Event API",
    version="1.0"
)


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100)
    device_id: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=80)
    severity: str
    description: str = Field(min_length=1, max_length=1500)
    observed_at: str | None = None


@app.on_event("startup")
def startup():
    store.init_db()
    events.ensure_tables()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "mode": "simulated"
    }


@app.post("/events")
def post_event(
    event: SecurityEvent,
    x_api_key: str | None = Header(default=None)
):
    secret = os.getenv("OPSPILOT_INGEST_KEY", "")

    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Configure OPSPILOT_INGEST_KEY"
        )

    if not x_api_key or not hmac.compare_digest(
        x_api_key, secret
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    try:
        return events.ingest(
            event.model_dump(exclude_none=True)
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        ) from exc
