"""Optional external audit-checkpoint anchoring.

The normal audit ledger remains application-level and tamper-evident. When a
separately governed S3 bucket is configured, this module publishes a compact,
content-free checkpoint object with retention controls. It never copies
document bytes or raw PII into the anchor boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import boto3


def publish_checkpoint(*, head_hash: str, event_count: int, generated_at: str | None = None,
                       bucket: str | None = None, s3_client=None, retention_days: int = 365) -> dict:
    """Publish a content-free checkpoint, or explicitly report it disabled."""
    bucket = bucket or os.environ.get("AUDIT_ANCHOR_BUCKET", "").strip()
    generated_at = generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    checkpoint = {
        "schema": "datasentinel.audit-checkpoint.v1",
        "head_hash": str(head_hash),
        "event_count": int(event_count),
        "generated_at": generated_at,
        "release_id": os.environ.get("RELEASE_ID", ""),
    }
    if not bucket:
        return {"active": False, "reason": "AUDIT_ANCHOR_BUCKET_NOT_CONFIGURED", "checkpoint": checkpoint}
    body = json.dumps(checkpoint, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    key = f"checkpoints/{generated_at.replace(':', '').replace('-', '')}-{digest}.json"
    client = s3_client or boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"),
                                      endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"))
    client.put_object(
        Bucket=bucket, Key=key, Body=body, ContentType="application/json",
        ServerSideEncryption="aws:kms" if os.environ.get("AUDIT_ANCHOR_KMS_KEY_ID") else "AES256",
        **({"SSEKMSKeyId": os.environ["AUDIT_ANCHOR_KMS_KEY_ID"]}
           if os.environ.get("AUDIT_ANCHOR_KMS_KEY_ID") else {}),
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=max(1, retention_days)),
        Metadata={"checkpoint-sha256": digest, "content-free": "true"},
    )
    return {"active": True, "bucket": bucket, "key": key, "sha256": digest, "checkpoint": checkpoint}

