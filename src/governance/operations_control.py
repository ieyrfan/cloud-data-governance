"""Deterministic governance control-plane primitives.

These helpers contain no storage or AWS assumptions, which keeps policy,
incident, retention and checkpoint behaviour independently testable.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

INCIDENT_TRANSITIONS = {
    "OPEN": {"TRIAGED"},
    "TRIAGED": {"CONTAINED", "OPEN"},
    "CONTAINED": {"RESOLVED", "TRIAGED"},
    "RESOLVED": set(),
}


def transition_incident(current: str, requested: str) -> str:
    current = current.upper()
    requested = requested.upper()
    if requested not in INCIDENT_TRANSITIONS.get(current, set()):
        raise ValueError(f"Incident cannot transition from {current} to {requested}")
    return requested


def retention_control(*, resource_id: str, retention_days: int, legal_hold: bool, actor: str) -> dict:
    now = datetime.now(UTC)
    return {
        "resource_id": resource_id,
        "retention_days": retention_days,
        "retain_until": (now + timedelta(days=retention_days)).isoformat(),
        "legal_hold": legal_hold,
        "deletion_blocked": legal_hold,
        "updated_at": now.isoformat(),
        "updated_by": actor,
    }


def sign_checkpoint(*, head_hash: str, event_count: int, generated_at: str, secret: str) -> str:
    payload = json.dumps(
        {"event_count": event_count, "generated_at": generated_at, "head_hash": head_hash},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def verify_checkpoint(checkpoint: dict, secret: str) -> bool:
    expected = sign_checkpoint(
        head_hash=checkpoint["head_hash"],
        event_count=int(checkpoint["event_count"]),
        generated_at=checkpoint["generated_at"],
        secret=secret,
    )
    return hmac.compare_digest(expected, str(checkpoint.get("signature", "")))
