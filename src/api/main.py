import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlparse

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from mangum import Mangum
from pydantic import BaseModel, Field

from src.classifiers.document_type_classifier import DOCUMENT_TYPES, classify_document_type
from src.governance.operations_control import (
    retention_control,
    sign_checkpoint,
    transition_incident,
    verify_checkpoint,
)
from src.governance.policy_engine import PROFILE_ALIASES, PROFILES, public_profiles, simulate_policy
from src.governance.redaction_policy import (
    RedactionPolicyError,
    normalize_policy,
    public_policy_metadata,
)
from src.integrations.webhook_dispatcher import validate_webhook_url

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "data-governance-results-dev")
AUDIT_TABLE_NAME = os.environ.get("AUDIT_TABLE", "data-governance-audit-dev")
ACCESS_REQUESTS_TABLE_NAME = os.environ.get(
    "ACCESS_REQUESTS_TABLE", "data-governance-access-requests-dev"
)
RAW_BUCKET = os.environ.get("RAW_BUCKET", "")
CLEAN_BUCKET = os.environ.get("CLEAN_BUCKET", "")
EPHEMERAL_PROCESSING_MODE = os.environ.get("EPHEMERAL_PROCESSING_MODE", "false").lower() == "true"
STRICT_TRANSIENT_MODE = os.environ.get("STRICT_TRANSIENT_MODE", "false").lower() == "true"
PUBLIC_FREE_API_ENABLED = (
    STRICT_TRANSIENT_MODE and os.environ.get("PUBLIC_FREE_API_ENABLED", "false").lower() == "true"
)
def _legacy_original_access_enabled() -> bool:
    return os.environ.get("ENABLE_LEGACY_ORIGINAL_ACCESS", "false").lower() == "true"
CLASSIFIER_FUNCTION_NAME = os.environ.get("CLASSIFIER_FUNCTION_NAME", "")
CLASSIFICATION_RULE_NAME = os.environ.get("CLASSIFICATION_RULE_NAME", "")
CLASSIFICATION_DLQ_URL = os.environ.get("CLASSIFICATION_DLQ_URL", "")
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
PRESENTATION_MODE = (
    DEMO_MODE and os.environ.get("PRESENTATION_MODE", "false").lower() == "true"
)

app = FastAPI(
    title="DataSentinel Governance API",
    description=(
        "API-first document protection, classification, governed access, risk, "
        "audit evidence, and security posture."
    ),
    version="2.8.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


@app.middleware("http")
async def add_browser_security_headers(request: Request, call_next):
    if request.url.path == "/api/v1/protect":
        request.state.correlation_id = uuid.uuid4().hex
    if STRICT_TRANSIENT_MODE:
        path = request.url.path
        allowed = {
            "/", "/customer", "/favicon.svg", "/health", "/config",
            "/api/v1/protect", "/api/v1/docs",
        }
        if not PUBLIC_FREE_API_ENABLED:
            allowed.update({"/auth/login", "/auth/logout", "/api/docs", "/api/openapi.json"})
        if path not in allowed and not path.startswith("/static/"):
            return JSONResponse(status_code=410, content={"detail": "Stored-document workflows are disabled."})
    # Optional production-edge lock.  Learner Lab leaves this unset so the
    # direct custom domain continues to work; a CloudFront deployment sets the
    # same secret as an origin custom header and rejects direct API bypass.
    edge_secret = os.environ.get("EDGE_SHARED_SECRET", "")
    if edge_secret and not hmac.compare_digest(
        request.headers.get("x-datasentinel-edge-secret", ""), edge_secret
    ):
        return JSONResponse(status_code=403, content={"detail": "Edge authentication required."})
    csrf_cookie = request.cookies.get("ds_csrf") or secrets.token_urlsafe(32)
    state_changing = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
    cookie_session = bool(request.cookies.get("dashboard_session"))
    if (state_changing and cookie_session and request.url.path != "/auth/login"
            and not (PUBLIC_FREE_API_ENABLED and request.url.path == "/api/v1/protect")):
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), csrf_cookie):
            return JSONResponse(status_code=403, content={"detail": "CSRF validation failed."})
    response = await call_next(request)
    response.set_cookie(
        "ds_csrf",
        csrf_cookie,
        secure=True,
        httponly=False,
        samesite="strict",
        max_age=SESSION_SECONDS,
        path="/",
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net "
        "'sha256-eV3QMumkWxytVHa/LDvu+mnW+PcSAEI4SfFu0iIlbDc='; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "connect-src 'self' https://*.amazonaws.com; "
        "font-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = (
        "public, max-age=31536000, immutable"
        if request.url.path.startswith("/static/")
        else "no-store"
    )
    if request.url.path == "/api/v1/protect":
        response.headers["X-Correlation-ID"] = request.state.correlation_id
    return response


if (FRONTEND_DIR / "static").is_dir():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")

_dynamodb = None
_s3 = None
_events = None
_lambda = None
_sqs = None
_kms = None
_demo_access_requests = []
_demo_access_events = []
_demo_integration_records = {}
_login_attempts = {}
_revoked_sessions = {}

# Presentation mode is deliberately opt-in and only available together with
# DEMO_MODE. It keeps the local event walkthrough from expiring mid-demo while
# preserving the normal 30-minute session for Learner Lab and production paths.
SESSION_SECONDS = 8 * 60 * 60 if PRESENTATION_MODE else 1800
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
UPLOAD_CONTENT_TYPES = {
    ".csv": "text/csv",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".json": "application/json",
    ".log": "text/plain",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".ini": "text/plain",
    ".cfg": "text/plain",
}


class UploadRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=180)
    content_type: str = Field(default="text/plain", max_length=100)
    redaction_policy: dict[str, str] = Field(default_factory=dict)
    policy_confirmed: bool = False


def _upload_redaction_policy(request: UploadRequest) -> tuple[dict[str, str], dict]:
    try:
        policy = normalize_policy(request.redaction_policy, confirmed=request.policy_confirmed)
    except RedactionPolicyError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return policy, public_policy_metadata(policy, confirmed=request.policy_confirmed)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=128)


class AccessRequestCreate(BaseModel):
    resource_id: str = Field(min_length=6, max_length=1024)
    justification: str = Field(min_length=12, max_length=500)


class AccessRequestDecision(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    note: str = Field(default="", max_length=500)


class IntegrationDocumentCreate(BaseModel):
    filename: str = Field(min_length=1, max_length=180)
    content_type: str = Field(max_length=100)
    purpose: str = Field(min_length=3, max_length=120)
    subject_reference: str = Field(default="", max_length=160)
    protection_profile: str = Field(default="malaysia-general", min_length=3, max_length=80)
    redaction_policy: dict[str, str] = Field(default_factory=dict)
    policy_confirmed: bool = False


class PolicySimulationRequest(BaseModel):
    profile: str = Field(default="malaysia-general", min_length=3, max_length=80)
    signal_types: list[str] = Field(default_factory=list, max_length=30)
    extraction_complete: bool = True


class ReprocessRequest(BaseModel):
    resource_id: str = Field(min_length=6, max_length=1024)
    reason: str = Field(min_length=12, max_length=300)


class ApiClientCreate(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    client_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    label: str = Field(min_length=3, max_length=100)
    scopes: list[Literal["documents:create", "documents:read", "protected-copy:read"]]
    expires_in_days: int = Field(default=30, ge=1, le=365)


class WebhookRegistration(BaseModel):
    url: str = Field(min_length=12, max_length=500)


class ClassificationReviewDecision(BaseModel):
    resource_id: str = Field(min_length=6, max_length=1024)
    decision: Literal["CONFIRM", "ESCALATE", "REPROCESS"]
    note: str = Field(min_length=12, max_length=500)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=5, max_length=160)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    resource_id: str = Field(default="", max_length=1024)
    summary: str = Field(min_length=12, max_length=1000)


class IncidentTransition(BaseModel):
    status: Literal["OPEN", "TRIAGED", "CONTAINED", "RESOLVED"]
    note: str = Field(min_length=8, max_length=500)


class RetentionControlRequest(BaseModel):
    resource_id: str = Field(min_length=6, max_length=1024)
    retention_days: int = Field(ge=1, le=3650)
    legal_hold: bool = False


def _region():
    return os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def _dynamodb_resource():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource(
            "dynamodb",
            endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"),
            region_name=_region(),
        )
    return _dynamodb


def _s3_client():
    global _s3
    if _s3 is None:
        _s3 = boto3.client(
            "s3",
            endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"),
            region_name=_region(),
        )
    return _s3


def _events_client():
    global _events
    if _events is None:
        _events = boto3.client("events", region_name=_region())
    return _events


def _lambda_client():
    global _lambda
    if _lambda is None:
        _lambda = boto3.client("lambda", region_name=_region())
    return _lambda


def _sqs_client():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client("sqs", region_name=_region())
    return _sqs


def _kms_client():
    global _kms
    if _kms is None:
        _kms = boto3.client("kms", region_name=_region())
    return _kms


def _json_safe(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _query_all(table, **query):
    items = []
    response = table.query(**query)
    items.extend(response.get("Items", []))
    while response.get("LastEvaluatedKey"):
        response = table.query(**query, ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


def _classification_inventory():
    return _query_all(
        _dynamodb_resource().Table(TABLE_NAME),
        IndexName="InventoryByTimestamp",
        KeyConditionExpression=Key("inventory_scope").eq("CLASSIFICATION"),
        ScanIndexForward=False,
    )


def _access_records(record_type: str):
    return _query_all(
        _access_requests_table(),
        IndexName="AccessByTypeAndTime",
        KeyConditionExpression=Key("record_type").eq(record_type),
        ScanIndexForward=False,
    )


def _audit_records():
    return _query_all(
        _dynamodb_resource().Table(AUDIT_TABLE_NAME),
        IndexName="AuditByTimestamp",
        KeyConditionExpression=Key("ledger_scope").eq("AUDIT"),
        ScanIndexForward=True,
    )


def _newest_classifications(items):
    newest = {}
    for item in items:
        resource_id = item.get("resource_id")
        if not resource_id:
            continue
        current = newest.get(resource_id)
        item_order = (item.get("timestamp") or item.get("version_id", ""), item.get("version_id", ""))
        current_order = (
            current.get("timestamp") or current.get("version_id", ""),
            current.get("version_id", ""),
        ) if current else ("", "")
        if current is None or item_order > current_order:
            newest[resource_id] = item
    visible_items = (
        item
        for item in newest.values()
        if "/acceptance/" not in str(item.get("resource_id", "")).casefold()
    )
    return sorted(
        (_normalise_classification_item(item) for item in visible_items),
        key=lambda item: item.get("timestamp", ""),
        reverse=True,
    )


def _normalise_classification_item(item):
    """Fail closed when a legacy result has no positive classification evidence."""
    normalised = dict(item)
    findings = normalised.get("findings")
    findings = dict(findings) if isinstance(findings, dict) else {}
    document_type = findings.get("document_type")
    if not isinstance(document_type, dict) or document_type.get("key") not in DOCUMENT_TYPES:
        document_type = classify_document_type("", normalised.get("resource_id", ""))
        findings["document_type"] = document_type
    normalised["document_type"] = document_type["key"]
    normalised["document_type_label"] = document_type["label"]
    normalised["findings"] = findings
    try:
        confidence = float(normalised.get("confidence_score", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    matches = int(findings.get("pattern_matches_count", 0) or 0)
    if (
        str(normalised.get("sensitivity_level", "")).upper() == "PUBLIC"
        and confidence <= 0
        and matches == 0
    ):
        normalised["sensitivity_level"] = "UNKNOWN"
        normalised["risk_level"] = "HIGH"
        normalised["risk_score"] = max(float(normalised.get("risk_score", 0) or 0), 60)
        normalised["classification_status"] = "REVIEW_REQUIRED_UNREADABLE_OR_UNPROVEN"
        findings = dict(findings)
        findings["review_reason"] = "No positive text-classification evidence was recorded."
        normalised["findings"] = findings
    return normalised


def _classification_explanation(item):
    """Return a deterministic, evidence-backed explanation without exposing values."""
    sensitivity = str(item.get("sensitivity_level", "UNKNOWN")).upper()
    findings = item.get("findings")
    findings = findings if isinstance(findings, dict) else {}
    detected = [
        str(value).replace("_", " ").upper()
        for value in findings.get("pattern_types_detected", [])
        if value
    ]
    count = int(findings.get("pattern_matches_count", 0) or 0)
    policy_by_sensitivity = {
        "RESTRICTED": "DS-MY-PII-004",
        "CONFIDENTIAL": "DS-DATA-003",
        "INTERNAL": "DS-DATA-002",
        "PUBLIC": "DS-DATA-001",
        "UNKNOWN": "DS-FAIL-CLOSED-001",
    }
    if sensitivity == "UNKNOWN":
        rationale = (
            "The content could not be positively proven safe, so DataSentinel failed closed "
            "and requires human review."
        )
    elif detected:
        signals = ", ".join(detected[:4])
        rationale = (
            f"DataSentinel assigned {sensitivity} after detecting {count} validated "
            f"pattern{'s' if count != 1 else ''} across: {signals}."
        )
    elif sensitivity == "PUBLIC":
        rationale = "No supported sensitive-data pattern was detected in the extracted text."
    else:
        rationale = (
            f"DataSentinel assigned {sensitivity} from the recorded classifier evidence and "
            "requires the protected-copy policy."
        )
    return {
        "policy_id": findings.get("policy_id")
        or policy_by_sensitivity.get(sensitivity, "DS-FAIL-CLOSED-001"),
        "policy_version": findings.get("policy_version", "2026.10-r1"),
        "classifier_id": findings.get("classifier_id", "DS-CLASSIFIER-MY-PII"),
        "classifier_version": findings.get("classifier_version", "legacy-unversioned"),
        "decision": sensitivity,
        "rationale": rationale,
        "detected_signal_types": detected,
        "validated_signal_count": count,
        "human_review_required": sensitivity in {"RESTRICTED", "CONFIDENTIAL", "UNKNOWN"},
        "original_values_disclosed": False,
    }


def _demo_payload(name):
    path = FRONTEND_DIR / "demo-data.json"
    if not path.is_file():
        raise HTTPException(status_code=503, detail="Demo data is unavailable.")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data[name]


def _session_secret():
    return os.environ.get("ADMIN_DASHBOARD_TOKEN", "")


def _create_session(username: str, role: str):
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "role": role,
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=SESSION_SECONDS)).timestamp()),
    }
    encoded = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(_session_secret().encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"dg1.{encoded}.{signature}"


def _read_session(token: str):
    if not token.startswith("dg1.") or not _session_secret():
        return None
    try:
        _, encoded, supplied_signature = token.split(".", 2)
        expected_signature = hmac.new(
            _session_secret().encode(), encoded.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
        now = int(datetime.now(UTC).timestamp())
        if int(payload.get("exp", 0)) <= now:
            return None
        if payload.get("role") not in {"ADMIN", "DATA_OWNER", "REVIEWER", "AUDITOR"}:
            return None
        jti = str(payload.get("jti", ""))
        if not jti or _is_session_revoked(jti, now):
            return None
        return {
            "username": str(payload.get("sub", "user")),
            "role": payload["role"],
            "jti": jti,
            "exp": int(payload["exp"]),
        }
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
        return None


def require_dashboard_token(
    x_dashboard_token: str | None = Header(default=None),
    dashboard_session: str | None = Cookie(default=None),
):
    reviewer_token = os.environ.get("DASHBOARD_TOKEN", "")
    admin_token = os.environ.get("ADMIN_DASHBOARD_TOKEN", "")
    if not reviewer_token and not admin_token:
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")
    x_dashboard_token = x_dashboard_token or dashboard_session
    if not x_dashboard_token:
        raise HTTPException(status_code=401, detail="A valid dashboard access token is required.")
    session = _read_session(x_dashboard_token)
    if session:
        return session
    if os.environ.get("ALLOW_LEGACY_DASHBOARD_TOKENS", "true").lower() == "true":
        if admin_token and hmac.compare_digest(x_dashboard_token, admin_token):
            return {"username": "administrator", "role": "ADMIN"}
        if reviewer_token and hmac.compare_digest(x_dashboard_token, reviewer_token):
            return {"username": "reviewer", "role": "REVIEWER"}
    raise HTTPException(status_code=401, detail="A valid dashboard access token is required.")


def require_direct_protect_access(
    x_dashboard_token: str | None = Header(default=None),
    dashboard_session: str | None = Cookie(default=None),
):
    """Keep other dashboard routes private while allowing the bounded public API."""
    if PUBLIC_FREE_API_ENABLED:
        return {"role": "PUBLIC", "username": "anonymous"}
    return require_dashboard_token(x_dashboard_token, dashboard_session)


def _claim_public_free_slot() -> None:
    """Atomically reserve one daily slot without recording caller or document data."""
    table_name = os.environ.get("PUBLIC_USAGE_TABLE", "")
    if not table_name:
        raise HTTPException(status_code=503, detail="Public processing is temporarily unavailable.")
    try:
        limit = int(os.environ.get("PUBLIC_FREE_DAILY_LIMIT", "200"))
    except ValueError:
        raise HTTPException(status_code=503, detail="Public processing is temporarily unavailable.") from None
    if limit < 1 or limit > 10000:
        raise HTTPException(status_code=503, detail="Public processing is temporarily unavailable.")
    now = datetime.now(UTC)
    day = now.strftime("%Y-%m-%d")
    next_day = datetime.combine(now.date() + timedelta(days=1), datetime.min.time(), UTC)
    retry_after = max(1, int((next_day - now).total_seconds()))
    try:
        boto3.resource("dynamodb", region_name=_region()).Table(table_name).update_item(
            Key={"usage_day": day},
            UpdateExpression="SET #count = if_not_exists(#count, :zero) + :one, expires_epoch = :expiry",
            ConditionExpression="attribute_not_exists(#count) OR #count < :limit",
            ExpressionAttributeNames={"#count": "request_count"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":limit": limit,
                ":expiry": int((next_day + timedelta(days=2)).timestamp()),
            },
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=429,
                detail="Today's free processing limit has been reached. Try again tomorrow.",
                headers={"Retry-After": str(retry_after)},
            ) from error
        raise HTTPException(status_code=503, detail="Public processing is temporarily unavailable.") from error
    except BotoCoreError as error:
        raise HTTPException(status_code=503, detail="Public processing is temporarily unavailable.") from error


def require_integration_client(x_api_key: str | None = Header(default=None)):
    """Authenticate a machine client without storing its raw API key in CloudFormation."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="A valid integration API key is required.")
    supplied_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    managed = _integration_record(f"INTEGRATION_CLIENT_KEY#{supplied_hash}")
    if managed:
        summary = _integration_record(
            _client_summary_id(str(managed.get("tenant_id", "")), str(managed.get("client_id", "")))
        )
        if (
            managed.get("status") != "ACTIVE"
            or not summary
            or summary.get("status") != "ACTIVE"
            or int(managed.get("expires_epoch", 0)) <= int(time.time())
        ):
            raise HTTPException(status_code=401, detail="A valid integration API key is required.")
        return {
            "tenant_id": managed["tenant_id"],
            "client_id": managed["client_id"],
            "scopes": set(managed.get("scopes", [])),
            "auth_type": "MANAGED_API_KEY_SHA256",
        }
    expected_hash = os.environ.get("INTEGRATION_API_KEY_HASH", "").strip().lower()
    if not expected_hash or not hmac.compare_digest(supplied_hash, expected_hash):
        raise HTTPException(status_code=401, detail="A valid integration API key is required.")
    scopes = {
        value.strip()
        for value in os.environ.get(
            "INTEGRATION_API_SCOPES",
            "documents:create,documents:read,protected-copy:read",
        ).split(",")
        if value.strip()
    }
    return {
        "tenant_id": os.environ.get("INTEGRATION_TENANT_ID", "ifhx-demo"),
        "client_id": os.environ.get("INTEGRATION_CLIENT_ID", "booth-client"),
        "scopes": scopes,
        "auth_type": "API_KEY_SHA256",
    }


def _require_integration_scope(client: dict, scope: str):
    if scope not in client["scopes"]:
        raise HTTPException(status_code=403, detail=f"The client lacks the {scope} scope.")


def _integration_record(record_id: str):
    if DEMO_MODE:
        return _demo_integration_records.get(record_id)
    return (
        _access_requests_table()
        .get_item(Key={"request_id": record_id}, ConsistentRead=True)
        .get("Item")
    )


def _put_integration_record(item: dict, *, create_only: bool = False):
    # AccessByTypeAndTime only indexes records that carry its range key.  Keep
    # this invariant at the storage boundary so every control-plane record is
    # listable immediately after its consistent primary-key write.
    item.setdefault("created_at", datetime.now(UTC).isoformat())
    if DEMO_MODE:
        if create_only and item["request_id"] in _demo_integration_records:
            return False
        _demo_integration_records[item["request_id"]] = item
        return True
    arguments = {"Item": item}
    if create_only:
        arguments["ConditionExpression"] = "attribute_not_exists(request_id)"
    try:
        _access_requests_table().put_item(**arguments)
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _list_integration_records(record_type: str) -> list[dict]:
    if DEMO_MODE:
        return [
            item
            for item in _demo_integration_records.values()
            if item.get("record_type") == record_type
        ]
    return _access_records(record_type)


def _integration_document_record(client: dict, document_id: str):
    item = _integration_record(f"INTEGRATION_DOCUMENT#{client['tenant_id']}#{document_id}")
    if not item or item.get("client_id") != client["client_id"]:
        raise HTTPException(status_code=404, detail="Document not found for this API client.")
    return item


def _public_signal_type(value: str):
    return {
        "MY_IC": "MALAYSIAN_NRIC",
        "MALAYSIAN_NRIC": "MALAYSIAN_NRIC",
        "MY_PHONE": "MALAYSIAN_PHONE",
        "EMAIL": "EMAIL_ADDRESS",
        "CREDIT_CARD": "PAYMENT_CARD",
        "GOVERNMENT_ID": "GOVERNMENT_IDENTIFIER",
        "FINANCIAL_ACCOUNT": "FINANCIAL_ACCOUNT",
        "MATRIC_NUMBER": "MATRIC_NUMBER",
        "DOB": "DATE_OF_BIRTH",
        "NAME": "NAME",
        "ADDRESS": "ADDRESS",
    }.get(str(value).upper(), str(value).upper())


def _integration_status(item: dict):
    classification = _latest_file(item["resource_id"])
    if not classification:
        return {
            "document_id": item["document_id"],
            "job_id": item["job_id"],
            "status": "processing" if item.get("uploaded") else "awaiting_upload",
            "created_at": item["created_at"],
            "purpose": item["purpose"],
            "protection_profile": item["protection_profile"],
        }
    findings = classification.get("findings", {})
    findings = classification.get("findings", {})
    if findings.get("processing_status") == "FAILED":
        return {
            "document_id": item["document_id"],
            "job_id": item["job_id"],
            "status": "failed",
            "created_at": item["created_at"],
            "failed_at": classification.get("timestamp"),
            "failure_code": findings.get("failure_code", "CLASSIFICATION_FAILED"),
            "retryable": bool(findings.get("retryable", True)),
        }
    actions = classification.get("governance_actions", {})
    evidence_ready = bool(
        actions.get("protected_copy_created") or actions.get("redacted_copy_created")
    )
    status = "completed" if evidence_ready else "review_required"
    return {
        "document_id": item["document_id"],
        "job_id": item["job_id"],
        "status": status,
        "created_at": item["created_at"],
        "completed_at": classification.get("timestamp"),
        "purpose": item["purpose"],
        "protection_profile": item["protection_profile"],
        "classification": {
            "sensitivity": classification.get("sensitivity_level", "UNKNOWN"),
            "document_type": classification.get("document_type", "OTHER"),
            "confidence": float(classification.get("confidence_score", 0) or 0),
            "risk_level": classification.get("risk_level", "INFO"),
            "review_required": classification.get("sensitivity_level")
            in {"RESTRICTED", "CONFIDENTIAL", "UNKNOWN"},
        },
        "detected_signals": [
            {"type": _public_signal_type(signal), "values_disclosed": False}
            for signal in findings.get("pattern_types_detected", [])
        ],
        "protected_copy": {"available": evidence_ready},
        "policy_decision": {
            "default_access": "PROTECTED_ONLY",
            "original_access": "MANAGEMENT_APPROVAL_REQUIRED",
            "policy_id": _classification_explanation(classification)["policy_id"],
            "policy_version": _classification_explanation(classification)["policy_version"],
        },
    }


def _derived_role_password(role_name: str):
    return hashlib.sha256(f"{role_name}:{_session_secret()}".encode()).hexdigest()[:24]


def _login_attempt_key(request: Request, username: str):
    client_host = request.client.host if request.client else "unknown"
    return f"{client_host}:{username.casefold()}"


def _auth_record_id(prefix: str, value: str):
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"{prefix}#{digest}"


def _login_failure_state(attempt_key: str, now: int):
    if DEMO_MODE:
        failures = [
            stamp
            for stamp in _login_attempts.get(attempt_key, [])
            if now - stamp < LOGIN_WINDOW_SECONDS
        ]
        return failures
    try:
        item = (
            _access_requests_table()
            .get_item(
                Key={"request_id": _auth_record_id("AUTH_RATE", attempt_key)},
                ConsistentRead=True,
            )
            .get("Item")
        )
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="Sign-in protection is unavailable.") from error
    if not item or int(item.get("expires_epoch", 0)) <= now:
        return []
    return [float(stamp) for stamp in item.get("failure_times", [])]


def _record_login_failure(attempt_key: str, failures: list[float], now: int):
    failures = [*failures, float(now)]
    if DEMO_MODE:
        _login_attempts[attempt_key] = failures
        return
    try:
        _access_requests_table().put_item(
            Item={
                "request_id": _auth_record_id("AUTH_RATE", attempt_key),
                "record_type": "LOGIN_THROTTLE",
                "failure_times": [Decimal(str(stamp)) for stamp in failures],
                "expires_epoch": now + LOGIN_WINDOW_SECONDS,
            }
        )
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="Sign-in protection is unavailable.") from error


def _clear_login_failures(attempt_key: str):
    if DEMO_MODE:
        _login_attempts.pop(attempt_key, None)
        return
    try:
        _access_requests_table().delete_item(
            Key={"request_id": _auth_record_id("AUTH_RATE", attempt_key)}
        )
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="Sign-in protection is unavailable.") from error


def _is_session_revoked(jti: str, now: int):
    if DEMO_MODE:
        expired = [key for key, expiry in _revoked_sessions.items() if expiry <= now]
        for key in expired:
            _revoked_sessions.pop(key, None)
        return jti in _revoked_sessions
    try:
        item = (
            _access_requests_table()
            .get_item(
                Key={"request_id": _auth_record_id("SESSION_REVOCATION", jti)},
                ConsistentRead=True,
            )
            .get("Item")
        )
    except (BotoCoreError, ClientError):
        return True
    return bool(item and int(item.get("expires_epoch", 0)) > now)


def _revoke_session(session: dict):
    if DEMO_MODE:
        _revoked_sessions[session["jti"]] = session["exp"]
        return
    try:
        _access_requests_table().put_item(
            Item={
                "request_id": _auth_record_id("SESSION_REVOCATION", session["jti"]),
                "record_type": "SESSION_REVOCATION",
                "expires_epoch": session["exp"],
            }
        )
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="Session revocation is unavailable.") from error


@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request):
    """Exchange the Learner Lab administrator login for the internal session token."""
    accounts = {
        os.environ.get("ADMIN_USERNAME", "admin"): (os.environ.get("ADMIN_PASSWORD", ""), "ADMIN"),
        os.environ.get("OWNER_USERNAME", "owner"): (
            os.environ.get("OWNER_PASSWORD", _derived_role_password("owner")),
            "DATA_OWNER",
        ),
        os.environ.get("REVIEWER_USERNAME", "reviewer"): (
            os.environ.get("REVIEWER_PASSWORD", _derived_role_password("reviewer")),
            "REVIEWER",
        ),
        os.environ.get("AUDITOR_USERNAME", "auditor"): (
            os.environ.get("AUDITOR_PASSWORD", _derived_role_password("auditor")),
            "AUDITOR",
        ),
    }
    now = int(time.time())
    attempt_key = _login_attempt_key(request, credentials.username)
    failures = _login_failure_state(attempt_key, now)
    if len(failures) >= LOGIN_MAX_FAILURES:
        retry_after = max(1, int(LOGIN_WINDOW_SECONDS - (now - failures[0])))
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    account = accounts.get(credentials.username)
    if not account or not account[0] or not hmac.compare_digest(credentials.password, account[0]):
        _record_login_failure(attempt_key, failures, now)
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    if not _session_secret():
        raise HTTPException(status_code=503, detail="Administrator login is not configured.")
    role = account[1]
    _clear_login_failures(attempt_key)
    session_token = _create_session(credentials.username, role)
    content = {
        "access_role": role,
        "username": credentials.username,
        "expires_in_seconds": SESSION_SECONDS,
    }
    # Demo-mode tests and local API clients may still use the legacy header;
    # deployed browser consoles never receive the bearer token in JSON.
    if DEMO_MODE:
        content["session_token"] = session_token
    response = JSONResponse(content=content)
    response.set_cookie(
        "dashboard_session",
        session_token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/auth/logout")
def logout(
    x_dashboard_token: str | None = Header(default=None),
    dashboard_session: str | None = Cookie(default=None),
):
    x_dashboard_token = x_dashboard_token or dashboard_session
    if not x_dashboard_token:
        raise HTTPException(status_code=401, detail="A valid dashboard session is required.")
    session = _read_session(x_dashboard_token)
    if not session:
        raise HTTPException(status_code=401, detail="A valid dashboard session is required.")
    _revoke_session(session)
    response = JSONResponse(content={"revoked": True})
    response.delete_cookie("dashboard_session", path="/")
    return response


def _classification_summary(items):
    breakdown = {
        "RESTRICTED": 0,
        "CONFIDENTIAL": 0,
        "INTERNAL": 0,
        "PUBLIC": 0,
        "UNKNOWN": 0,
    }
    risk_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    evidence_checks_passed = 0
    evidence_checks_total = 0
    document_type_breakdown = {key: 0 for key in DOCUMENT_TYPES}
    for item in items:
        sensitivity = str(item.get("sensitivity_level", "UNKNOWN")).upper()
        breakdown[sensitivity if sensitivity in breakdown else "UNKNOWN"] += 1
        risk = str(item.get("risk_level", "INFO")).upper()
        if risk in risk_breakdown:
            risk_breakdown[risk] += 1
        document_type = str(item.get("document_type", "OTHER")).upper()
        document_type_breakdown[document_type if document_type in DOCUMENT_TYPES else "OTHER"] += 1

        actions = item.get("governance_actions")
        actions = actions if isinstance(actions, dict) else {}
        required_actions = [
            "source_private_by_design",
            "protected_copy_created",
            "protected_format_preserved",
            "retention_tags_applied",
            "audit_event_created",
        ]
        if sensitivity in {"RESTRICTED", "CONFIDENTIAL", "INTERNAL"}:
            required_actions.append("redacted_copy_created")
        evidence_checks_total += len(required_actions)
        evidence_checks_passed += sum(bool(actions.get(action)) for action in required_actions)

    review_count = breakdown["RESTRICTED"] + breakdown["CONFIDENTIAL"]
    readiness = (
        round(evidence_checks_passed / evidence_checks_total * 100) if evidence_checks_total else 0
    )
    return {
        "total_files_scanned": len(items),
        "sensitivity_breakdown": breakdown,
        "risk_breakdown": risk_breakdown,
        "document_type_breakdown": document_type_breakdown,
        "review_required": review_count,
        "governance_readiness_score": readiness,
        "readiness_checks_passed": evidence_checks_passed,
        "readiness_checks_total": evidence_checks_total,
        "readiness_basis": "recorded_governance_actions",
        "records_with_unknown_classification": breakdown["UNKNOWN"],
        "last_classification_at": items[0].get("timestamp") if items else None,
    }


def _normalise_audit_details(event):
    details = event.get("details", {})
    if isinstance(details, str):
        try:
            return json.loads(details)
        except json.JSONDecodeError:
            return {"raw": details}
    return details if isinstance(details, dict) else {"value": details}


def _verify_audit_events(events):
    """Recompute every hash and link across the complete retrieved ledger."""
    ordered = sorted(
        events, key=lambda event: (event.get("timestamp", ""), event.get("log_id", ""))
    )
    expected_previous = "0" * 64
    for event in ordered:
        if event.get("previous_hash") != expected_previous:
            return {
                "verified": False,
                "checked_events": len(ordered),
                "scope": "complete_retrieved_ledger",
                "message": "Chain linkage mismatch detected.",
            }
        payload = {
            "timestamp": event.get("timestamp"),
            "action": event.get("action"),
            "actor": event.get("actor"),
            "resource": event.get("resource"),
            "details": _normalise_audit_details(event),
            "previous_hash": event.get("previous_hash"),
        }
        calculated = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(calculated, str(event.get("current_hash", ""))):
            return {
                "verified": False,
                "checked_events": len(ordered),
                "scope": "complete_retrieved_ledger",
                "message": "Event hash mismatch detected.",
            }
        expected_previous = calculated
    return {
        "verified": bool(ordered),
        "checked_events": len(ordered),
        "scope": "complete_retrieved_ledger",
        "message": "Every retrieved event hash and chain link was recomputed."
        if ordered
        else "No events are available to verify.",
    }


@app.get("/", include_in_schema=False)
def dashboard():
    index = FRONTEND_DIR / ("customer.html" if STRICT_TRANSIENT_MODE else "index.html")
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Dashboard assets are unavailable.")
    return FileResponse(index)


@app.get("/customer", include_in_schema=False)
def customer_portal():
    page = FRONTEND_DIR / "customer.html"
    if not page.is_file():
        raise HTTPException(status_code=404, detail="Customer portal assets are unavailable.")
    return FileResponse(page)


@app.get("/api/v1/docs", include_in_schema=False)
def direct_api_guide():
    page = FRONTEND_DIR / "api.html"
    if not page.is_file():
        raise HTTPException(status_code=404, detail="API guide is unavailable.")
    return FileResponse(page)


@app.get("/favicon.svg", include_in_schema=False)
def favicon():
    icon = FRONTEND_DIR / "favicon.svg"
    if not icon.is_file():
        raise HTTPException(status_code=404, detail="Favicon is unavailable.")
    return FileResponse(icon, media_type="image/svg+xml")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cloud-data-governance-api",
        "version": app.version,
        "mode": "demo" if DEMO_MODE else "aws",
        "release_id": os.environ.get("RELEASE_ID", "local"),
        "time": datetime.now(UTC).isoformat(),
    }


@app.get("/config", include_in_schema=False)
def public_config():
    return {
        "project_name": "DataSentinel" if STRICT_TRANSIENT_MODE else "Cloud Data Governance",
        "environment": os.environ.get("ENVIRONMENT", "local"),
        "region": _region(),
        "demo_mode": DEMO_MODE,
        "upload_enabled": not DEMO_MODE and (STRICT_TRANSIENT_MODE or bool(RAW_BUCKET)),
        "service_mode": "direct_redaction" if STRICT_TRANSIENT_MODE else (
            "ephemeral_redaction" if EPHEMERAL_PROCESSING_MODE else "governed_storage"
        ),
        "max_direct_bytes": 3 * 1024 * 1024 if STRICT_TRANSIENT_MODE else None,
        "public_free_api": PUBLIC_FREE_API_ENABLED,
        "public_daily_limit": int(os.environ.get("PUBLIC_FREE_DAILY_LIMIT", "200"))
        if PUBLIC_FREE_API_ENABLED else None,
        "privacy_statement": (
            "The application processes document bytes in memory and does not create a document inventory. AWS service handling and operational logs remain subject to AWS policies."
            if STRICT_TRANSIENT_MODE else (
                "Original uploads are deleted after processing. The sender remains responsible for the unredacted source."
                if EPHEMERAL_PROCESSING_MODE
                else "Uploads follow the configured governed-storage retention policy."
            )
        ),
        "release_id": os.environ.get("RELEASE_ID", "local"),
    }


@app.post("/api/v1/protect")
async def protect_document_direct(
    request: Request,
    x_filename: str = Header(default=""),
    x_redaction_policy: str = Header(default=""),
    x_policy_confirmed: str = Header(default="false"),
    auth: dict = Depends(require_direct_protect_access),
):
    """Return a downloadable file without writing customer content to S3 or DynamoDB."""
    if not STRICT_TRANSIENT_MODE:
        raise HTTPException(status_code=409, detail="Direct processing is unavailable.")
    if auth.get("role") not in {"ADMIN", "DATA_OWNER", "PUBLIC"}:
        raise HTTPException(status_code=403, detail="This account cannot process documents.")
    from src.api.transient_process import MAX_DIRECT_INPUT_BYTES, protect_in_memory
    started = time.monotonic()

    if int(request.headers.get("content-length", "0") or "0") > MAX_DIRECT_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="Files must be 3 MB or smaller.")
    filename = Path(unquote(x_filename)).name
    if not filename or len(filename) > 180:
        raise HTTPException(status_code=422, detail="A valid filename is required.")
    if PUBLIC_FREE_API_ENABLED:
        _claim_public_free_slot()
    try:
        policy = json.loads(x_redaction_policy) if x_redaction_policy else {}
        if not isinstance(policy, dict):
            raise ValueError("Invalid redaction policy")
        protected, content_type, evidence = protect_in_memory(
            await request.body(),
            filename,
            boto3.client("textract", region_name=_region()),
            redaction_policy=policy,
            policy_confirmed=x_policy_confirmed.lower() == "true",
        )
    except (ValueError, RedactionPolicyError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="OCR is unavailable; no file was issued.") from error
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", filename).strip(".-")
    return Response(
        content=protected,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="protected-{safe_name}"',
            "X-Detected-Categories": ",".join(evidence["detected_categories"]),
            "X-Redacted-Categories": ",".join(evidence["redacted_categories"]),
            "X-Kept-Categories": ",".join(evidence["kept_categories"]),
            "X-Redaction-Hits": str(evidence["redaction_hits"]),
            "X-OCR-Used": str(evidence["ocr_used"]).lower(),
            "X-Output-Verified": str(evidence["output_verified"]).lower(),
            "X-Processing-Ms": str(round((time.monotonic() - started) * 1000)),
            "X-Document-Type": evidence["document_type"],
            "X-Suggested-Classification": evidence["suggested_classification"],
            "Cache-Control": "no-store",
        },
    )


@app.get("/system/status")
def get_system_status(auth: dict = Depends(require_dashboard_token)):
    """Return authenticated, live dependency checks without leaking provider errors."""
    if DEMO_MODE:
        checks = [
            {
                "id": check_id,
                "label": label,
                "status": "SNAPSHOT",
                "detail": "Demo evidence only; no live AWS dependency was queried.",
            }
            for check_id, label in [
                ("raw-storage", "Private intake"),
                ("event-pipeline", "Automatic trigger"),
                ("classification", "Classification"),
                ("protected-storage", "Protection"),
                ("evidence-store", "Proof and review"),
            ]
        ]
        return {
            "overall": "SNAPSHOT",
            "mode": "demo",
            "checked_at": datetime.now(UTC).isoformat(),
            "checks": checks,
            "access_role": auth["role"],
        }

    checks = []

    def check_dependency(check_id, label, operation, operational_detail):
        try:
            operation()
            status = "OPERATIONAL"
            detail = operational_detail
        except Exception:  # noqa: BLE001 - boundary intentionally hides provider internals
            status = "DEGRADED"
            detail = "The dependency did not answer the live readiness check."
        checks.append({"id": check_id, "label": label, "status": status, "detail": detail})

    check_dependency(
        "raw-storage",
        "Private intake",
        lambda: _s3_client().head_bucket(Bucket=RAW_BUCKET),
        "The private raw-data bucket is reachable.",
    )

    def check_event_rule():
        response = _events_client().describe_rule(Name=CLASSIFICATION_RULE_NAME)
        if response.get("State") != "ENABLED":
            raise RuntimeError("Classification event rule is not enabled")
        queue = _sqs_client().get_queue_attributes(
            QueueUrl=CLASSIFICATION_DLQ_URL,
            AttributeNames=["ApproximateNumberOfMessages"],
        )
        if int(queue.get("Attributes", {}).get("ApproximateNumberOfMessages", "0")):
            raise RuntimeError("Classification dead-letter queue is not empty")

    check_dependency(
        "event-pipeline",
        "Automatic trigger",
        check_event_rule,
        "The S3 classification event rule is enabled and its failure queue is empty.",
    )

    def check_classifier():
        response = _lambda_client().get_function_configuration(
            FunctionName=CLASSIFIER_FUNCTION_NAME
        )
        if response.get("State") != "Active" or response.get("LastUpdateStatus") != "Successful":
            raise RuntimeError("Classifier function is not ready")
        _dynamodb_resource().Table(TABLE_NAME).load()

    check_dependency(
        "classification",
        "Classification",
        check_classifier,
        "The classifier function and evidence table are ready.",
    )
    check_dependency(
        "protected-storage",
        "Protection",
        lambda: _s3_client().head_bucket(Bucket=CLEAN_BUCKET),
        "The protected-output bucket is reachable.",
    )

    def check_evidence_stores():
        _dynamodb_resource().Table(AUDIT_TABLE_NAME).load()
        _dynamodb_resource().Table(ACCESS_REQUESTS_TABLE_NAME).load()

    check_dependency(
        "evidence-store",
        "Proof and review",
        check_evidence_stores,
        "Audit and access-decision stores are active.",
    )
    overall = (
        "OPERATIONAL" if all(check["status"] == "OPERATIONAL" for check in checks) else "DEGRADED"
    )
    return {
        "overall": overall,
        "mode": "aws",
        "checked_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "access_role": auth["role"],
    }


@app.get("/dashboard/summary")
def get_dashboard_summary(auth: dict = Depends(require_dashboard_token)):
    if DEMO_MODE:
        summary = _classification_summary(
            [_normalise_classification_item(item) for item in _demo_payload("files")]
        )
        summary["access_role"] = auth["role"]
        summary["username"] = auth["username"]
        return summary
    try:
        items = _newest_classifications(_classification_inventory())
        summary = _classification_summary(items)
        summary["access_role"] = auth["role"]
        summary["username"] = auth["username"]
        return _json_safe(summary)
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to load the dashboard summary."
        ) from error


@app.get("/files", dependencies=[Depends(require_dashboard_token)])
def list_files(
    limit: int = Query(default=100, ge=1, le=250),
    sensitivity: str | None = Query(default=None),
):
    if DEMO_MODE:
        items = [_normalise_classification_item(item) for item in _demo_payload("files")]
    else:
        try:
            items = _newest_classifications(_classification_inventory())
        except Exception as error:
            raise HTTPException(
                status_code=500, detail="Unable to load classified files."
            ) from error

    if sensitivity:
        sensitivity = sensitivity.upper()
        if sensitivity not in {"RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC", "UNKNOWN"}:
            raise HTTPException(status_code=422, detail="Unknown sensitivity filter.")
        items = [item for item in items if item.get("sensitivity_level") == sensitivity]
    returned = items[:limit]
    return {
        "items": _json_safe(returned),
        "count": len(returned),
        "total_count": len(items),
        "truncated": len(returned) < len(items),
    }


def _latest_file(resource_id):
    if DEMO_MODE:
        item = next(
            (item for item in _demo_payload("files") if item["resource_id"] == resource_id), None
        )
        return _normalise_classification_item(item) if item else None
    items = _query_all(
        _dynamodb_resource().Table(TABLE_NAME),
        KeyConditionExpression=Key("resource_id").eq(resource_id),
        ScanIndexForward=False,
    )
    if not items:
        return None
    latest = max(
        items,
        key=lambda item: (
            item.get("timestamp") or item.get("version_id", ""),
            item.get("version_id", ""),
        ),
    )
    return _normalise_classification_item(latest)


@app.get("/files/risk")
def get_file_risk_score(
    resource_id: str = Query(min_length=6, max_length=1024),
    auth: dict = Depends(require_dashboard_token),
):
    try:
        item = _latest_file(resource_id)
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to load the classification record."
        ) from error
    if not item:
        raise HTTPException(status_code=404, detail="File classification not found.")
    sensitivity = item.get("sensitivity_level", "UNKNOWN")
    actions = item.get("governance_actions", {})
    protected_available = bool(
        actions.get("protected_copy_created") or actions.get("redacted_copy_created")
    )
    can_access_original = (
        _legacy_original_access_enabled()
        and not EPHEMERAL_PROCESSING_MODE
        and (
            auth["role"] in {"ADMIN", "DATA_OWNER"}
            or _has_approved_access(auth["username"], item["resource_id"])
        )
    )
    return _json_safe(
        {
            "resource_id": item["resource_id"],
            "sensitivity": sensitivity,
            "confidence_score": item.get("confidence_score", "0"),
            "risk_score": item.get("risk_score", 0),
            "risk_level": item.get("risk_level", "INFO"),
            "risk_basis": "sensitivity_baseline",
            "findings": item.get("findings", {}),
            "document_type": item.get("document_type", "OTHER"),
            "document_type_label": item.get("document_type_label", DOCUMENT_TYPES["OTHER"]),
            "explanation": _classification_explanation(item),
            "governance_actions": actions,
            "timestamp": item.get("timestamp"),
            "compliance_status": "REVIEW_REQUIRED"
            if sensitivity in {"RESTRICTED", "CONFIDENTIAL", "UNKNOWN"}
            else "NO_SENSITIVE_DATA_DETECTED",
            "access_role": auth["role"],
            "protected_copy_available": protected_available,
            "can_access_original": can_access_original,
            "original_access_requires_approval": (
                False
                if EPHEMERAL_PROCESSING_MODE or not _legacy_original_access_enabled()
                else auth["role"] not in {"ADMIN", "DATA_OWNER"}
            ),
        }
    )


def _evidence_pack_filename(resource_id: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(resource_id).name).strip(".-")
    return f"DataSentinel-Evidence-{name or 'resource'}.zip"


@app.get("/files/evidence-pack")
def create_evidence_pack(
    resource_id: str = Query(min_length=6, max_length=1024),
    auth: dict = Depends(require_dashboard_token),
):
    """Export decision evidence only; original or protected document bytes are excluded."""
    try:
        item = _latest_file(resource_id)
        access_events = [
            event for event in _list_access_events() if event.get("resource_id") == resource_id
        ]
        requests = [
            request
            for request in _list_access_requests()
            if request.get("resource_id") == resource_id
        ]
        if auth["role"] == "REVIEWER":
            access_events = [
                event for event in access_events if event.get("actor") == auth["username"]
            ]
            requests = [
                request for request in requests if request.get("requester") == auth["username"]
            ]
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to assemble the evidence pack."
        ) from error
    if not item:
        raise HTTPException(status_code=404, detail="File classification not found.")

    generated_at = datetime.now(UTC).isoformat()
    classification = {
        "resource_id": item.get("resource_id"),
        "version_id": item.get("version_id"),
        "timestamp": item.get("timestamp"),
        "sensitivity_level": item.get("sensitivity_level", "UNKNOWN"),
        "confidence_score": item.get("confidence_score", 0),
        "risk_score": item.get("risk_score", 0),
        "risk_level": item.get("risk_level", "INFO"),
        "findings": item.get("findings", {}),
        "governance_actions": item.get("governance_actions", {}),
        "explanation": _classification_explanation(item),
    }
    manifest = {
        "product": "DataSentinel",
        "schema_version": "1.0",
        "generated_at": generated_at,
        "generated_by": auth["username"],
        "generated_by_role": auth["role"],
        "resource_id": resource_id,
        "contents": [
            "manifest.json",
            "classification-decision.json",
            "access-history.json",
            "approval-history.json",
            "README.txt",
        ],
        "documents_included": False,
        "notice": "Evidence export only. No original or protected document content is included.",
    }
    readme = (
        "DataSentinel governance evidence pack\n"
        f"Generated: {generated_at}\n"
        f"Resource: {resource_id}\n\n"
        "This pack records the classification decision, policy explanation, retrieval-link "
        "issuance and approval history visible to the requesting role. It is evidence output, "
        "not a compliance certification. Original and protected document bytes are excluded.\n"
    )
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("manifest.json", json.dumps(_json_safe(manifest), indent=2))
        bundle.writestr(
            "classification-decision.json", json.dumps(_json_safe(classification), indent=2)
        )
        bundle.writestr("access-history.json", json.dumps(_json_safe(access_events), indent=2))
        bundle.writestr("approval-history.json", json.dumps(_json_safe(requests), indent=2))
        bundle.writestr("README.txt", readme)
    archive.seek(0)
    filename = _evidence_pack_filename(resource_id)
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _raw_object_key(resource_id: str) -> str:
    prefix = f"s3://{RAW_BUCKET}/"
    if not RAW_BUCKET or not resource_id.startswith(prefix):
        raise HTTPException(status_code=422, detail="Resource is outside the governed raw zone.")
    object_key = resource_id[len(prefix) :]
    if not object_key:
        raise HTTPException(status_code=422, detail="Resource object key is missing.")
    return object_key


def _access_requests_table():
    return _dynamodb_resource().Table(ACCESS_REQUESTS_TABLE_NAME)


def _list_access_requests():
    if DEMO_MODE:
        return list(_demo_access_requests)
    return _access_records("ACCESS_REQUEST")


def _approved_access_request(username: str, resource_id: str):
    now = datetime.now(UTC)
    try:
        requests = _list_access_requests()
    except (BotoCoreError, ClientError):
        return None
    for item in requests:
        if (
            item.get("requester") != username
            or item.get("resource_id") != resource_id
            or item.get("status") != "APPROVED"
            or not item.get("access_expires_at")
        ):
            continue
        try:
            expires_at = datetime.fromisoformat(
                str(item["access_expires_at"]).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            continue
        if expires_at > now:
            return item
    return None


def _has_approved_access(username: str, resource_id: str):
    return _approved_access_request(username, resource_id) is not None


def _list_access_events():
    if DEMO_MODE:
        return list(_demo_access_events)
    return _access_records("FILE_ACCESS_EVENT")


def _record_access_event(
    *,
    auth: dict,
    resource_id: str,
    variant: str,
    disposition: str,
    access_basis: str,
    approved_request_id: str = "",
):
    now = datetime.now(UTC)
    correlation_id = str(uuid.uuid4())
    item = {
        "request_id": f"access-event-{uuid.uuid4()}",
        "record_type": "FILE_ACCESS_EVENT",
        "correlation_id": correlation_id,
        "action": "DOWNLOAD_LINK_ISSUED",
        "resource_id": resource_id,
        "actor": auth["username"],
        "actor_role": auth["role"],
        "variant": variant.upper(),
        "disposition": disposition.upper(),
        "access_basis": access_basis,
        "approved_request_id": approved_request_id,
        "created_at": now.isoformat(),
        "link_expires_at": (now + timedelta(seconds=120)).isoformat(),
        "expires_epoch": int((now + timedelta(days=90)).timestamp()),
    }
    if DEMO_MODE:
        _demo_access_events.append(item)
    else:
        _access_requests_table().put_item(Item=item)
    return item


@app.post("/access-requests")
def create_access_request(
    request: AccessRequestCreate,
    auth: dict = Depends(require_dashboard_token),
):
    if EPHEMERAL_PROCESSING_MODE or not _legacy_original_access_enabled():
        raise HTTPException(
            status_code=410,
            detail="Original access is sender-controlled; server-side original retrieval is disabled.",
        )
    if auth["role"] == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot request original files.")
    if not _latest_file(request.resource_id):
        raise HTTPException(status_code=404, detail="File classification not found.")
    now = datetime.now(UTC)
    item = {
        "request_id": str(uuid.uuid4()),
        "record_type": "ACCESS_REQUEST",
        "resource_id": request.resource_id,
        "requester": auth["username"],
        "requester_role": auth["role"],
        "justification": request.justification.strip(),
        "status": "APPROVED" if auth["role"] in {"ADMIN", "DATA_OWNER"} else "PENDING",
        "created_at": now.isoformat(),
        "decided_at": now.isoformat() if auth["role"] in {"ADMIN", "DATA_OWNER"} else "",
        "decided_by": auth["username"] if auth["role"] in {"ADMIN", "DATA_OWNER"} else "",
        "decision_note": "Privileged role auto-approved for the live demonstration."
        if auth["role"] in {"ADMIN", "DATA_OWNER"}
        else "",
        "access_expires_at": (now + timedelta(minutes=15)).isoformat()
        if auth["role"] in {"ADMIN", "DATA_OWNER"}
        else "",
        "expires_epoch": int((now + timedelta(days=90)).timestamp()),
    }
    try:
        if DEMO_MODE:
            _demo_access_requests.append(item)
        else:
            _access_requests_table().put_item(Item=item)
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to record the access request."
        ) from error
    return _json_safe(item)


@app.get("/access-requests")
def list_access_requests(auth: dict = Depends(require_dashboard_token)):
    try:
        items = _list_access_requests()
    except Exception as error:
        raise HTTPException(status_code=500, detail="Unable to load access requests.") from error
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        items = [item for item in items if item.get("requester") == auth["username"]]
    items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    pending = sum(item.get("status") == "PENDING" for item in items)
    return {"items": _json_safe(items[:100]), "count": len(items), "pending": pending}


@app.get("/access-events")
def list_access_events(auth: dict = Depends(require_dashboard_token)):
    try:
        items = _list_access_events()
    except Exception as error:
        raise HTTPException(status_code=500, detail="Unable to load file access events.") from error
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        items = [item for item in items if item.get("actor") == auth["username"]]
    items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {"items": _json_safe(items[:100]), "count": len(items)}


@app.patch("/access-requests/{request_id}")
def decide_access_request(
    request_id: str,
    decision: AccessRequestDecision,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(
            status_code=403, detail="Only an administrator or data owner can decide requests."
        )
    items = _list_access_requests()
    item = next((entry for entry in items if entry.get("request_id") == request_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Access request not found.")
    if item.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail="This request has already been decided.")
    now = datetime.now(UTC)
    status = "APPROVED" if decision.decision == "APPROVE" else "REJECTED"
    updates = {
        "status": status,
        "decided_at": now.isoformat(),
        "decided_by": auth["username"],
        "decision_note": decision.note.strip(),
        "access_expires_at": (now + timedelta(minutes=15)).isoformat()
        if status == "APPROVED"
        else "",
    }
    if DEMO_MODE:
        item.update(updates)
    else:
        try:
            _access_requests_table().update_item(
                Key={"request_id": request_id},
                UpdateExpression=(
                    "SET #status=:status, decided_at=:decided_at, decided_by=:decided_by, "
                    "decision_note=:decision_note, access_expires_at=:access_expires_at"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": updates["status"],
                    ":decided_at": updates["decided_at"],
                    ":decided_by": updates["decided_by"],
                    ":decision_note": updates["decision_note"],
                    ":access_expires_at": updates["access_expires_at"],
                    ":pending": "PENDING",
                },
                ConditionExpression="#status = :pending",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise HTTPException(
                    status_code=409, detail="This request has already been decided."
                ) from error
            raise HTTPException(status_code=500, detail="Unable to decide this request.") from error
        item.update(updates)
    return _json_safe(item)


@app.get("/capabilities", dependencies=[Depends(require_dashboard_token)])
def get_capabilities():
    return {
        "implemented": [
            "Role-based signed sessions",
            "Original-file approval workflow",
            "Format-preserving redaction",
            "Post-protection action evidence",
            "Hash-linked audit verification",
            "S3 posture assessment",
            "Event-driven classification",
            "Short-lived file access",
            "File retrieval correlation evidence",
            "Downloadable per-resource evidence packs",
            "Lambda and dead-letter queue failure alarms",
            "Amazon Textract OCR for single-page scanned PDFs and asynchronous multi-page scans",
            "Versioned external Integration API",
            "Hashed machine-client authentication and explicit scopes",
            "Tenant/client namespacing and idempotent document jobs",
            "Audited protected-copy delivery for external applications",
            "Versioned policy profiles and value-free decision simulation",
            "Fail-closed reprocessing with immutable classification history",
            "Operational classification and review analytics",
            "Managed tenant API clients with one-time keys, rotation and revocation",
            "KMS-encrypted signed webhooks with retries, delivery evidence and dead-letter isolation",
            "Recorded classification-review decisions without PII disclosure",
            "Security incident lifecycle with constrained state transitions",
            "Per-resource retention and legal-hold control records",
            "Application-signed audit-head checkpoints with signature verification",
            "Versioned classifier identity in new classification evidence",
            "Federated-identity claim adapter for an upstream verified authorizer",
            "Fail-closed GuardDuty malware-status gate boundary",
            "Dependency-free Python SDK for the Integration API",
        ],
        "integration_ready": [
            "Amazon Cognito federation",
            "GuardDuty Malware Protection for S3",
            "AWS WAF rate controls",
            "Externally anchored KMS audit checkpoints",
            "Cross-region disaster-recovery replication",
        ],
        "statement": (
            "Integration boundaries and local control evidence are implemented. External AWS "
            "services listed as integration-ready are not represented as active in this Learner Lab release."
        ),
    }


@app.get("/policies", dependencies=[Depends(require_dashboard_token)])
def list_policy_profiles():
    """List versioned protection profiles without exposing detected values."""
    return {"items": public_profiles(), "count": len(PROFILES)}


@app.post("/policies/simulate")
def simulate_policy_decision(
    request: PolicySimulationRequest,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(
            status_code=403,
            detail="Only administrators and data owners can simulate policy changes.",
        )
    try:
        return simulate_policy(request.profile, request.signal_types, request.extraction_complete)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Protection profile not found.") from error


@app.get("/analytics")
def get_operational_analytics(auth: dict = Depends(require_dashboard_token)):
    try:
        items = (
            [_normalise_classification_item(item) for item in _demo_payload("files")]
            if DEMO_MODE
            else _newest_classifications(_classification_inventory())
        )
        requests = _list_access_requests()
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to calculate operational analytics."
        ) from error
    if auth["role"] == "REVIEWER":
        requests = [item for item in requests if item.get("requester") == auth["username"]]
    total = len(items)
    reviewed = sum(item.get("sensitivity_level") != "UNKNOWN" for item in items)
    protected = sum(
        bool((item.get("governance_actions") or {}).get("protected_copy_created")) for item in items
    )
    return {
        "documents": total,
        "classification_coverage_percent": round(reviewed / total * 100) if total else 0,
        "protected_copy_coverage_percent": round(protected / total * 100) if total else 0,
        "review_queue": sum(
            item.get("sensitivity_level") in {"RESTRICTED", "CONFIDENTIAL", "UNKNOWN"}
            for item in items
        ),
        "access_requests": len(requests),
        "pending_access_requests": sum(item.get("status") == "PENDING" for item in requests),
        "metric_scope": "latest visible classification per resource",
        "values_disclosed": False,
    }


@app.get("/reviews")
def list_classification_reviews(auth: dict = Depends(require_dashboard_token)):
    items = _list_integration_records("CLASSIFICATION_REVIEW")
    if auth["role"] == "REVIEWER":
        items = [item for item in items if item.get("reviewed_by") == auth["username"]]
    items.sort(key=lambda item: item.get("reviewed_at", ""), reverse=True)
    return {"items": _json_safe(items), "count": len(items)}


@app.post("/reviews", status_code=201)
def record_classification_review(
    request: ClassificationReviewDecision,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "REVIEWER"}:
        raise HTTPException(status_code=403, detail="This role cannot decide classification reviews.")
    now = datetime.now(UTC).isoformat()
    record = {
        "request_id": f"CLASSIFICATION_REVIEW#{uuid.uuid4()}",
        "record_type": "CLASSIFICATION_REVIEW",
        "resource_id": request.resource_id,
        "decision": request.decision,
        "note": request.note,
        "reviewed_at": now,
        "reviewed_by": auth["username"],
        "reviewed_by_role": auth["role"],
        "values_disclosed": False,
    }
    _put_integration_record(record)
    return _json_safe(record)


@app.get("/incidents")
def list_incidents(auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect incidents.")
    items = _list_integration_records("SECURITY_INCIDENT")
    items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {"items": _json_safe(items), "count": len(items)}


@app.post("/incidents", status_code=201)
def create_incident(request: IncidentCreate, auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot create incidents.")
    now = datetime.now(UTC).isoformat()
    incident_id = f"inc_{uuid.uuid4().hex}"
    record = {
        "request_id": f"SECURITY_INCIDENT#{incident_id}",
        "record_type": "SECURITY_INCIDENT",
        "incident_id": incident_id,
        "title": request.title,
        "severity": request.severity,
        "resource_id": request.resource_id,
        "summary": request.summary,
        "status": "OPEN",
        "created_at": now,
        "updated_at": now,
        "created_by": auth["username"],
        "history": [{"status": "OPEN", "at": now, "by": auth["username"]}],
    }
    _put_integration_record(record)
    return _json_safe(record)


@app.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    request: IncidentTransition,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(status_code=403, detail="Only administrators and data owners can transition incidents.")
    record_id = f"SECURITY_INCIDENT#{incident_id}"
    current = _integration_record(record_id)
    if not current:
        raise HTTPException(status_code=404, detail="Incident not found.")
    try:
        status = transition_incident(str(current.get("status", "OPEN")), request.status)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    now = datetime.now(UTC).isoformat()
    history = list(current.get("history") or [])
    history.append({"status": status, "note": request.note, "at": now, "by": auth["username"]})
    updated = {**current, "status": status, "updated_at": now, "updated_by": auth["username"], "history": history}
    _put_integration_record(updated)
    return _json_safe(updated)


@app.get("/retention-controls")
def list_retention_controls(auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect retention controls.")
    items = _list_integration_records("RETENTION_CONTROL")
    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return {"items": _json_safe(items), "count": len(items)}


@app.put("/retention-controls")
def put_retention_control(
    request: RetentionControlRequest,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(status_code=403, detail="Only administrators and data owners can change retention.")
    control = retention_control(
        resource_id=request.resource_id,
        retention_days=request.retention_days,
        legal_hold=request.legal_hold,
        actor=auth["username"],
    )
    record = {
        "request_id": f"RETENTION_CONTROL#{hashlib.sha256(request.resource_id.encode()).hexdigest()}",
        "record_type": "RETENTION_CONTROL",
        **control,
    }
    _put_integration_record(record)
    if not DEMO_MODE and RAW_BUCKET and request.resource_id.startswith(f"s3://{RAW_BUCKET}/"):
        try:
            object_key = _raw_object_key(request.resource_id)
            current = _s3_client().get_object_tagging(Bucket=RAW_BUCKET, Key=object_key)
            tags = {tag["Key"]: tag["Value"] for tag in current.get("TagSet", [])}
            tags.update(
                {
                    "LegalHold": "true" if request.legal_hold else "false",
                    "RetentionDays": str(request.retention_days),
                    "GovernanceStatus": "LEGAL_HOLD" if request.legal_hold else "RETENTION_CONTROLLED",
                }
            )
            _s3_client().put_object_tagging(
                Bucket=RAW_BUCKET,
                Key=object_key,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]},
            )
        except Exception as error:
            raise HTTPException(
                status_code=503,
                detail="Retention control was recorded but storage enforcement could not be applied.",
            ) from error
    return _json_safe(record)


def _checkpoint_secret() -> str:
    return os.environ.get("CHECKPOINT_SIGNING_SECRET") or _session_secret()


@app.get("/audit/checkpoints")
def list_audit_checkpoints(auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect audit checkpoints.")
    items = _list_integration_records("AUDIT_CHECKPOINT")
    secret = _checkpoint_secret()
    public = []
    for item in sorted(items, key=lambda value: value.get("generated_at", ""), reverse=True):
        public.append({**item, "signature_valid": verify_checkpoint(item, secret)})
    return {"items": _json_safe(public), "count": len(public), "external_anchor_active": False}


@app.post("/audit/checkpoints", status_code=201)
def create_audit_checkpoint(auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot create audit checkpoints.")
    events = _demo_payload("audit") if DEMO_MODE else _audit_records()
    integrity = _verify_audit_events(events)
    if not integrity.get("verified"):
        raise HTTPException(status_code=409, detail="Audit chain integrity must be valid before checkpointing.")
    head_hash = str(events[-1].get("current_hash", "")) if events else "0" * 64
    generated_at = datetime.now(UTC).isoformat()
    checkpoint_id = f"chk_{uuid.uuid4().hex}"
    record = {
        "request_id": f"AUDIT_CHECKPOINT#{checkpoint_id}",
        "record_type": "AUDIT_CHECKPOINT",
        "checkpoint_id": checkpoint_id,
        "head_hash": head_hash,
        "event_count": len(events),
        "generated_at": generated_at,
        "generated_by": auth["username"],
        "signature_algorithm": "HMAC-SHA256",
        "trust_boundary": "DATASENTINEL_APPLICATION",
        "external_anchor_active": False,
    }
    record["signature"] = sign_checkpoint(
        head_hash=head_hash,
        event_count=len(events),
        generated_at=generated_at,
        secret=_checkpoint_secret(),
    )
    _put_integration_record(record)
    return _json_safe(record | {"signature_valid": True})


def _client_summary_id(tenant_id: str, client_id: str) -> str:
    return f"INTEGRATION_CLIENT#{tenant_id}#{client_id}"


def _create_managed_api_client(request: ApiClientCreate, actor: str) -> dict:
    now = datetime.now(UTC)
    summary_id = _client_summary_id(request.tenant_id, request.client_id)
    existing = _integration_record(summary_id)
    if existing and existing.get("status") == "ACTIVE":
        raise HTTPException(
            status_code=409, detail="An active API client already uses this identity."
        )
    api_key = f"ds_live_{request.client_id}_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    expires_at = now + timedelta(days=request.expires_in_days)
    summary = {
        "request_id": summary_id,
        "record_type": "INTEGRATION_CLIENT",
        "tenant_id": request.tenant_id,
        "client_id": request.client_id,
        "label": request.label.strip(),
        "scopes": sorted(set(request.scopes)),
        "status": "ACTIVE",
        "key_fingerprint": key_hash[:12],
        "key_hash": key_hash,
        "created_at": now.isoformat(),
        "created_by": actor,
        "expires_at": expires_at.isoformat(),
        "expires_epoch": int(expires_at.timestamp()),
    }
    key_record = {
        **summary,
        "request_id": f"INTEGRATION_CLIENT_KEY#{key_hash}",
        "record_type": "INTEGRATION_CLIENT_KEY",
    }
    if not _put_integration_record(key_record, create_only=True):
        raise HTTPException(status_code=409, detail="API key collision; retry client creation.")
    _put_integration_record(summary)
    return {**summary, "api_key": api_key, "api_key_returned_once": True}


def _set_managed_client_status(summary: dict, status: str, actor: str) -> dict:
    now = datetime.now(UTC).isoformat()
    updated = {**summary, "status": status, "updated_at": now, "updated_by": actor}
    _put_integration_record(updated)
    key_hash = str(summary.get("key_hash", ""))
    if key_hash:
        key_record = _integration_record(f"INTEGRATION_CLIENT_KEY#{key_hash}")
        if key_record:
            _put_integration_record(
                {**key_record, "status": status, "updated_at": now, "updated_by": actor}
            )
    return updated


def _public_client(item: dict) -> dict:
    return {
        key: _json_safe(value)
        for key, value in item.items()
        if key not in {"api_key", "key_hash", "request_id", "expires_epoch"}
    }


def _webhook_id(tenant_id: str, client_id: str) -> str:
    return f"INTEGRATION_WEBHOOK#{tenant_id}#{client_id}"


def _public_webhook(item: dict) -> dict:
    return {
        key: _json_safe(value)
        for key, value in item.items()
        if key not in {"request_id", "secret_ciphertext"}
    }


def _managed_client_or_404(tenant_id: str, client_id: str) -> dict:
    client = _integration_record(_client_summary_id(tenant_id, client_id))
    if not client:
        raise HTTPException(status_code=404, detail="API client not found.")
    return client


@app.get("/api-clients")
def list_managed_api_clients(auth: dict = Depends(require_dashboard_token)):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect API clients.")
    items = sorted(
        _list_integration_records("INTEGRATION_CLIENT"),
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )
    return {"items": [_public_client(item) for item in items], "count": len(items)}


@app.post("/api-clients", status_code=201)
def create_managed_api_client(
    request: ApiClientCreate,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Only administrators can create API clients.")
    created = _create_managed_api_client(request, auth["username"])
    return _public_client(created) | {
        "api_key": created["api_key"],
        "api_key_returned_once": True,
    }


@app.post("/api-clients/{tenant_id}/{client_id}/rotate", status_code=201)
def rotate_managed_api_client(
    tenant_id: str,
    client_id: str,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Only administrators can rotate API keys.")
    current = _integration_record(_client_summary_id(tenant_id, client_id))
    if not current:
        raise HTTPException(status_code=404, detail="API client not found.")
    _set_managed_client_status(current, "ROTATED", auth["username"])
    request = ApiClientCreate(
        tenant_id=tenant_id,
        client_id=client_id,
        label=current["label"],
        scopes=current.get("scopes", []),
        expires_in_days=30,
    )
    created = _create_managed_api_client(request, auth["username"])
    return _public_client(created) | {"api_key": created["api_key"]}


@app.delete("/api-clients/{tenant_id}/{client_id}")
def revoke_managed_api_client(
    tenant_id: str,
    client_id: str,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Only administrators can revoke API clients.")
    current = _integration_record(_client_summary_id(tenant_id, client_id))
    if not current:
        raise HTTPException(status_code=404, detail="API client not found.")
    revoked = _set_managed_client_status(current, "REVOKED", auth["username"])
    webhook = _integration_record(_webhook_id(tenant_id, client_id))
    if webhook and webhook.get("status") == "ACTIVE":
        _put_integration_record(
            {
                **webhook,
                "status": "DISABLED",
                "updated_at": datetime.now(UTC).isoformat(),
                "updated_by": auth["username"],
                "disabled_reason": "API_CLIENT_REVOKED",
            }
        )
    return _public_client(revoked)


@app.get("/api-clients/{tenant_id}/{client_id}/webhook")
def get_client_webhook(
    tenant_id: str,
    client_id: str,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect webhooks.")
    _managed_client_or_404(tenant_id, client_id)
    webhook = _integration_record(_webhook_id(tenant_id, client_id))
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found.")
    return _public_webhook(webhook)


@app.put("/api-clients/{tenant_id}/{client_id}/webhook", status_code=201)
def register_client_webhook(
    tenant_id: str,
    client_id: str,
    registration: WebhookRegistration,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Only administrators can manage webhooks.")
    client = _managed_client_or_404(tenant_id, client_id)
    if client.get("status") != "ACTIVE":
        raise HTTPException(status_code=409, detail="The API client is not active.")
    try:
        destination = validate_webhook_url(registration.url.strip())
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    key_id = os.environ.get("WEBHOOK_KMS_KEY_ID", "").strip()
    if not key_id:
        raise HTTPException(status_code=503, detail="Webhook encryption is not configured.")
    secret = f"whsec_{secrets.token_urlsafe(32)}"
    context = {"tenant_id": tenant_id, "client_id": client_id}
    try:
        encrypted = _kms_client().encrypt(
            KeyId=key_id,
            Plaintext=secret.encode(),
            EncryptionContext=context,
        )["CiphertextBlob"]
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status_code=503, detail="Webhook secret encryption failed.") from error
    now = datetime.now(UTC).isoformat()
    record = {
        "request_id": _webhook_id(tenant_id, client_id),
        "record_type": "INTEGRATION_WEBHOOK",
        "tenant_id": tenant_id,
        "client_id": client_id,
        "url": destination,
        "destination_host": urlparse(destination).hostname,
        "status": "ACTIVE",
        "secret_ciphertext": base64.b64encode(encrypted).decode(),
        "secret_fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:12],
        "created_at": now,
        "updated_at": now,
        "updated_by": auth["username"],
    }
    _put_integration_record(record)
    return _public_webhook(record) | {"signing_secret": secret, "secret_returned_once": True}


@app.delete("/api-clients/{tenant_id}/{client_id}/webhook")
def disable_client_webhook(
    tenant_id: str,
    client_id: str,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Only administrators can manage webhooks.")
    webhook = _integration_record(_webhook_id(tenant_id, client_id))
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found.")
    updated = {
        **webhook,
        "status": "DISABLED",
        "updated_at": datetime.now(UTC).isoformat(),
        "updated_by": auth["username"],
    }
    _put_integration_record(updated)
    return _public_webhook(updated)


@app.get("/webhook-deliveries")
def list_webhook_deliveries(
    tenant_id: str | None = Query(default=None, max_length=63),
    client_id: str | None = Query(default=None, max_length=63),
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER", "AUDITOR"}:
        raise HTTPException(status_code=403, detail="This role cannot inspect webhook delivery.")
    items = _list_integration_records("WEBHOOK_DELIVERY")
    if tenant_id:
        items = [item for item in items if item.get("tenant_id") == tenant_id]
    if client_id:
        items = [item for item in items if item.get("client_id") == client_id]
    items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {
        "items": [
            {
                key: _json_safe(value)
                for key, value in item.items()
                if key not in {"request_id", "expires_epoch"}
            }
            for item in items[:100]
        ],
        "count": min(len(items), 100),
    }


@app.post("/files/reprocess", status_code=202)
def reprocess_file(
    request: ReprocessRequest,
    auth: dict = Depends(require_dashboard_token),
):
    if auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(
            status_code=403,
            detail="Only administrators and data owners can reprocess documents.",
        )
    if DEMO_MODE:
        raise HTTPException(status_code=409, detail="Reprocessing requires the AWS mode.")
    item = _latest_file(request.resource_id)
    if not item:
        raise HTTPException(status_code=404, detail="File classification not found.")
    object_key = _raw_object_key(request.resource_id)
    try:
        metadata = _s3_client().head_object(Bucket=RAW_BUCKET, Key=object_key)
        _s3_client().copy_object(
            Bucket=RAW_BUCKET,
            Key=object_key,
            CopySource={"Bucket": RAW_BUCKET, "Key": object_key},
            MetadataDirective="COPY",
            TaggingDirective="COPY",
            ContentType=metadata.get("ContentType", "application/octet-stream"),
        )
    except Exception as error:
        raise HTTPException(
            status_code=503, detail="The document could not be queued for reprocessing."
        ) from error
    return {
        "status": "REPROCESSING_QUEUED",
        "resource_id": request.resource_id,
        "requested_by": auth["username"],
        "reason_recorded": bool(request.reason.strip()),
        "history_preserved": True,
    }


@app.get("/files/download")
def create_download_url(
    resource_id: str = Query(min_length=6, max_length=1024),
    variant: Literal["protected", "original"] = Query(default="protected"),
    disposition: Literal["inline", "attachment"] = Query(default="inline"),
    auth: dict = Depends(require_dashboard_token),
):
    if DEMO_MODE:
        raise HTTPException(status_code=409, detail="Downloads are unavailable in demo mode.")
    if variant == "original" and (EPHEMERAL_PROCESSING_MODE or not _legacy_original_access_enabled()):
        raise HTTPException(
            status_code=410,
            detail="Original-file server access is disabled. Request the sender's source copy.",
        )
    approved_request = None
    if variant == "original" and auth["role"] not in {"ADMIN", "DATA_OWNER"}:
        approved_request = _approved_access_request(auth["username"], resource_id)
        if not approved_request:
            raise HTTPException(
                status_code=403,
                detail="Approved original-file access is required for this resource.",
            )
    try:
        item = _latest_file(resource_id)
    except Exception as error:
        raise HTTPException(status_code=500, detail="Unable to authorize this resource.") from error
    if not item:
        raise HTTPException(status_code=404, detail="File classification not found.")

    object_key = _raw_object_key(resource_id)
    actions = item.get("governance_actions", {})
    if variant == "protected" and not (
        actions.get("protected_copy_created") or actions.get("redacted_copy_created")
    ):
        raise HTTPException(
            status_code=409,
            detail="A protected copy is not available yet. Reprocess the file first.",
        )

    bucket = RAW_BUCKET if variant == "original" else CLEAN_BUCKET
    if not bucket:
        raise HTTPException(status_code=503, detail="The requested storage zone is not configured.")
    filename = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(object_key).name).strip(".-") or "document"
    try:
        metadata = _s3_client().head_object(Bucket=bucket, Key=object_key)
        version_id = (
            item.get("findings", {}).get("source_version_id")
            if variant == "original"
            else item.get("findings", {}).get("protected_version_id")
        )
        params = {
            "Bucket": bucket,
            "Key": object_key,
            "ResponseContentDisposition": f'{disposition}; filename="{filename}"',
        }
        if version_id and version_id != "unknown":
            params["VersionId"] = version_id
        url = _s3_client().generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=120,
        )
    except Exception as error:
        raise HTTPException(
            status_code=404, detail="The requested file copy is unavailable."
        ) from error

    access_basis = (
        "PROTECTED_DEFAULT"
        if variant == "protected"
        else "PRIVILEGED_ROLE"
        if auth["role"] in {"ADMIN", "DATA_OWNER"}
        else "APPROVED_REQUEST"
    )
    try:
        event = _record_access_event(
            auth=auth,
            resource_id=resource_id,
            variant=variant,
            disposition=disposition,
            access_basis=access_basis,
            approved_request_id=str(approved_request.get("request_id", ""))
            if approved_request
            else "",
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="The secure file link could not be issued and audited.",
        ) from error
    return {
        "url": url,
        "variant": variant,
        "access_role": auth["role"],
        "content_type": metadata.get("ContentType", "application/octet-stream"),
        "filename": filename,
        "expires_in_seconds": 120,
        "correlation_id": event["correlation_id"],
        "access_basis": event["access_basis"],
        "access_event": _json_safe(event),
    }


@app.get("/audit", dependencies=[Depends(require_dashboard_token)])
def list_audit_events(limit: int = Query(default=50, ge=1, le=200)):
    if DEMO_MODE:
        events = _demo_payload("audit")
    else:
        try:
            chain = _audit_records()
            events = list(reversed(chain))
        except Exception as error:
            raise HTTPException(status_code=500, detail="Unable to load audit events.") from error
    integrity = _verify_audit_events(list(reversed(events)))
    for event in events:
        event["details"] = _normalise_audit_details(event)
    returned = events[:limit]
    return {
        "items": _json_safe(returned),
        "count": len(returned),
        "total_count": len(events),
        "integrity": integrity,
    }


@app.get("/posture", dependencies=[Depends(require_dashboard_token)])
def get_security_posture():
    if DEMO_MODE:
        return _demo_payload("posture")
    if not RAW_BUCKET or not CLEAN_BUCKET:
        raise HTTPException(status_code=503, detail="Governed bucket names are not configured.")
    try:
        from src.governance.cspm_scanner import CSPMScanner

        return CSPMScanner().scan_buckets([RAW_BUCKET, CLEAN_BUCKET])
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to evaluate the S3 security posture."
        ) from error


@app.post("/uploads/presign")
def create_upload_url(
    request: UploadRequest,
    auth: dict = Depends(require_dashboard_token),
):
    if DEMO_MODE:
        raise HTTPException(status_code=409, detail="Uploads are disabled in local demo mode.")
    if auth.get("role") not in {"ADMIN", "DATA_OWNER"}:
        raise HTTPException(
            status_code=403,
            detail="Only administrators and data owners can upload governed documents.",
        )
    if not RAW_BUCKET:
        raise HTTPException(status_code=503, detail="The raw data bucket is not configured.")

    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(request.filename).name).strip(".-")
    extension = Path(safe_name).suffix.lower()
    if not safe_name or extension not in UPLOAD_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Upload a supported document, image, markup, or configuration file.",
        )

    supplied_content_type = request.content_type.split(";", 1)[0].strip().lower()
    expected_content_type = UPLOAD_CONTENT_TYPES[extension]
    if supplied_content_type != expected_content_type:
        raise HTTPException(
            status_code=422,
            detail=f"The declared content type does not match the {extension} file extension.",
        )
    _, policy_metadata = _upload_redaction_policy(request)
    policy_token = base64.urlsafe_b64encode(
        json.dumps(policy_metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    object_key = f"uploads/{uuid.uuid4().hex}{extension}"
    try:
        upload = _s3_client().generate_presigned_post(
            Bucket=RAW_BUCKET,
            Key=object_key,
            Fields={
                "Content-Type": expected_content_type,
                "x-amz-meta-original-filename": safe_name,
                "x-amz-meta-redaction-policy": policy_token,
            },
            Conditions=[
                {"Content-Type": expected_content_type},
                {"x-amz-meta-original-filename": safe_name},
                {"x-amz-meta-redaction-policy": policy_token},
                ["content-length-range", 1, 5 * 1024 * 1024],
            ],
            ExpiresIn=300,
        )
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to create the secure upload URL."
        ) from error
    return {
        "upload_url": upload["url"],
        "form_fields": upload["fields"],
        "object_key": object_key,
        "resource_id": f"s3://{RAW_BUCKET}/{object_key}",
        "expires_in_seconds": 300,
        "max_bytes": 5 * 1024 * 1024,
        "display_filename": safe_name,
        "redaction_policy": policy_metadata,
    }


def _integration_upload_contract(item: dict):
    policy_token = base64.urlsafe_b64encode(
        json.dumps(item.get("redaction_policy", {}), separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    upload = _s3_client().generate_presigned_post(
        Bucket=RAW_BUCKET,
        Key=item["object_key"],
        Fields={
            "Content-Type": item["content_type"],
            "x-amz-meta-original-filename": item["display_filename"],
            "x-amz-meta-tenant-id": item["tenant_id"],
            "x-amz-meta-client-id": item["client_id"],
            "x-amz-meta-document-id": item["document_id"],
            "x-amz-meta-protection-profile": item["protection_profile"],
            "x-amz-meta-redaction-policy": policy_token,
        },
        Conditions=[
            {"Content-Type": item["content_type"]},
            {"x-amz-meta-original-filename": item["display_filename"]},
            {"x-amz-meta-tenant-id": item["tenant_id"]},
            {"x-amz-meta-client-id": item["client_id"]},
            {"x-amz-meta-document-id": item["document_id"]},
            {"x-amz-meta-protection-profile": item["protection_profile"]},
            {"x-amz-meta-redaction-policy": policy_token},
            ["content-length-range", 1, 5 * 1024 * 1024],
        ],
        ExpiresIn=300,
    )
    return {
        "method": "POST",
        "url": upload["url"],
        "form_fields": upload["fields"],
        "expires_in_seconds": 300,
        "max_bytes": 5 * 1024 * 1024,
    }


@app.get("/api/v1/whoami", tags=["Integration API"])
def integration_whoami(client: dict = Depends(require_integration_client)):
    """Return the machine identity and scopes attached to the supplied API key."""
    return {
        "tenant_id": client["tenant_id"],
        "client_id": client["client_id"],
        "scopes": sorted(client["scopes"]),
        "authentication": client["auth_type"],
    }


@app.post("/api/v1/documents", status_code=202, tags=["Integration API"])
def create_integration_document(
    request: IntegrationDocumentCreate,
    client: dict = Depends(require_integration_client),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    """Create an isolated asynchronous document job for an external application."""
    _require_integration_scope(client, "documents:create")
    if DEMO_MODE or not RAW_BUCKET:
        raise HTTPException(status_code=409, detail="Integration uploads require the AWS mode.")
    if not idempotency_key or not 8 <= len(idempotency_key) <= 180:
        raise HTTPException(
            status_code=400,
            detail="Provide an Idempotency-Key between 8 and 180 characters.",
        )
    if request.protection_profile.strip() not in PROFILES and request.protection_profile.strip() not in PROFILE_ALIASES:
        raise HTTPException(status_code=422, detail="Unknown protection profile.")
    try:
        _, policy_metadata = _upload_redaction_policy(
            UploadRequest(
                filename=request.filename,
                content_type=request.content_type,
                redaction_policy=request.redaction_policy,
                policy_confirmed=request.policy_confirmed,
            )
        )
    except HTTPException:
        raise
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(request.filename).name).strip(".-")
    extension = Path(safe_name).suffix.lower()
    if not safe_name or extension not in UPLOAD_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Upload a supported document, image, markup, or configuration file.",
        )
    supplied_content_type = request.content_type.split(";", 1)[0].strip().lower()
    if supplied_content_type != UPLOAD_CONTENT_TYPES[extension]:
        raise HTTPException(
            status_code=422,
            detail=f"The declared content type does not match the {extension} file extension.",
        )

    digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    request_fingerprint = hashlib.sha256(
        json.dumps(request.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    idempotency_id = f"INTEGRATION_IDEMPOTENCY#{client['tenant_id']}#{client['client_id']}#{digest}"
    existing = _integration_record(idempotency_id)
    replayed = bool(existing)
    if existing:
        if existing.get("request_fingerprint") != request_fingerprint:
            raise HTTPException(
                status_code=409,
                detail="The Idempotency-Key was already used with a different request.",
            )
        document_id = existing["document_id"]
        try:
            item = _integration_document_record(client, document_id)
        except HTTPException as error:
            if error.status_code != 404:
                raise
            # Recover a claim that survived a transient failure before its
            # dependent document/job records were written. The matching
            # fingerprint proves that this is the same idempotent request.
            now = datetime.now(UTC)
            job_id = existing["job_id"]
            object_key = (
                f"integrations/{client['tenant_id']}/{client['client_id']}/"
                f"{document_id}/{safe_name}"
            )
            item = {
                "request_id": f"INTEGRATION_DOCUMENT#{client['tenant_id']}#{document_id}",
                "record_type": "INTEGRATION_DOCUMENT",
                "tenant_id": client["tenant_id"],
                "client_id": client["client_id"],
                "document_id": document_id,
                "job_id": job_id,
                "object_key": object_key,
                "resource_id": f"s3://{RAW_BUCKET}/{object_key}",
                "display_filename": safe_name,
                "content_type": supplied_content_type,
                "purpose": request.purpose.strip(),
                "subject_reference": request.subject_reference.strip(),
                "protection_profile": request.protection_profile.strip(),
                "redaction_policy": policy_metadata,
                "created_at": existing.get("created_at", now.isoformat()),
                "expires_epoch": int((now + timedelta(days=90)).timestamp()),
            }
            _put_integration_record(item, create_only=True)
            _put_integration_record(
                {
                    **item,
                    "request_id": f"INTEGRATION_JOB#{client['tenant_id']}#{job_id}",
                    "record_type": "INTEGRATION_JOB",
                },
                create_only=True,
            )
            item = _integration_document_record(client, document_id)
    else:
        now = datetime.now(UTC)
        document_id = f"doc_{uuid.uuid4().hex}"
        job_id = f"job_{uuid.uuid4().hex}"
        object_key = (
            f"integrations/{client['tenant_id']}/{client['client_id']}/{document_id}/{safe_name}"
        )
        item = {
            "request_id": f"INTEGRATION_DOCUMENT#{client['tenant_id']}#{document_id}",
            "record_type": "INTEGRATION_DOCUMENT",
            "tenant_id": client["tenant_id"],
            "client_id": client["client_id"],
            "document_id": document_id,
            "job_id": job_id,
            "object_key": object_key,
            "resource_id": f"s3://{RAW_BUCKET}/{object_key}",
            "display_filename": safe_name,
            "content_type": supplied_content_type,
            "purpose": request.purpose.strip(),
            "subject_reference": request.subject_reference.strip(),
            "protection_profile": request.protection_profile.strip(),
            "redaction_policy": policy_metadata,
            "created_at": now.isoformat(),
            "expires_epoch": int((now + timedelta(days=90)).timestamp()),
        }
        claim = {
            "request_id": idempotency_id,
            "record_type": "INTEGRATION_IDEMPOTENCY",
            "tenant_id": client["tenant_id"],
            "client_id": client["client_id"],
            "document_id": document_id,
            "job_id": job_id,
            "created_at": now.isoformat(),
            "expires_epoch": int((now + timedelta(hours=24)).timestamp()),
            "request_fingerprint": request_fingerprint,
        }
        if not _put_integration_record(claim, create_only=True):
            existing = _integration_record(idempotency_id)
            item = _integration_document_record(client, existing["document_id"])
            replayed = True
        else:
            _put_integration_record(item, create_only=True)
            _put_integration_record(
                {
                    **item,
                    "request_id": f"INTEGRATION_JOB#{client['tenant_id']}#{job_id}",
                    "record_type": "INTEGRATION_JOB",
                },
                create_only=True,
            )
    try:
        upload = _integration_upload_contract(item)
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Unable to create the secure upload URL."
        ) from error
    return {
        "document_id": item["document_id"],
        "job_id": item["job_id"],
        "status": "awaiting_upload",
        "replayed": replayed,
        "upload": upload,
        "links": {
            "document": f"/api/v1/documents/{item['document_id']}",
            "job": f"/api/v1/jobs/{item['job_id']}",
        },
    }


@app.get("/api/v1/documents/{document_id}", tags=["Integration API"])
def get_integration_document(
    document_id: str,
    client: dict = Depends(require_integration_client),
):
    _require_integration_scope(client, "documents:read")
    item = _integration_document_record(client, document_id)
    try:
        _s3_client().head_object(Bucket=RAW_BUCKET, Key=item["object_key"])
        item = {**item, "uploaded": True}
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") not in {"404", "NoSuchKey"}:
            raise HTTPException(
                status_code=503, detail="Document status is temporarily unavailable."
            ) from error
    return _json_safe(_integration_status(item))


@app.get("/api/v1/jobs/{job_id}", tags=["Integration API"])
def get_integration_job(
    job_id: str,
    client: dict = Depends(require_integration_client),
):
    _require_integration_scope(client, "documents:read")
    job = _integration_record(f"INTEGRATION_JOB#{client['tenant_id']}#{job_id}")
    if not job or job.get("client_id") != client["client_id"]:
        raise HTTPException(status_code=404, detail="Job not found for this API client.")
    return get_integration_document(job["document_id"], client)


@app.get(
    "/api/v1/documents/{document_id}/protected-copy",
    tags=["Integration API"],
)
def get_integration_protected_copy(
    document_id: str,
    disposition: Literal["inline", "attachment"] = Query(default="inline"),
    client: dict = Depends(require_integration_client),
):
    _require_integration_scope(client, "protected-copy:read")
    item = _integration_document_record(client, document_id)
    classification = _latest_file(item["resource_id"])
    if not classification:
        raise HTTPException(status_code=409, detail="Document processing is not complete.")
    actions = classification.get("governance_actions", {})
    if not (actions.get("protected_copy_created") or actions.get("redacted_copy_created")):
        raise HTTPException(status_code=409, detail="A protected copy is not available.")
    correlation_id = str(uuid.uuid4())
    try:
        metadata = _s3_client().head_object(Bucket=CLEAN_BUCKET, Key=item["object_key"])
        protected_version = classification.get("findings", {}).get("protected_version_id")
        params = {
            "Bucket": CLEAN_BUCKET,
            "Key": item["object_key"],
            "ResponseContentDisposition": (
                f'{disposition}; filename="{item["display_filename"]}"'
            ),
        }
        if protected_version and protected_version != "unknown":
            params["VersionId"] = protected_version
        url = _s3_client().generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=120,
        )
        now = datetime.now(UTC)
        _put_integration_record(
            {
                "request_id": f"INTEGRATION_ACCESS#{correlation_id}",
                "record_type": "INTEGRATION_ACCESS_EVENT",
                "tenant_id": client["tenant_id"],
                "client_id": client["client_id"],
                "document_id": document_id,
                "action": "PROTECTED_LINK_ISSUED",
                "correlation_id": correlation_id,
                "created_at": now.isoformat(),
                "expires_epoch": int((now + timedelta(days=90)).timestamp()),
            }
        )
    except Exception as error:
        raise HTTPException(status_code=404, detail="The protected copy is unavailable.") from error
    return {
        "document_id": document_id,
        "variant": "protected",
        "url": url,
        "content_type": metadata.get("ContentType", "application/octet-stream"),
        "filename": item["display_filename"],
        "expires_in_seconds": 120,
        "correlation_id": correlation_id,
    }


_mangum_handler = None


def handler(event, context):
    """Create the Lambda adapter lazily so source imports remain side-effect free."""
    global _mangum_handler
    if _mangum_handler is None:
        _mangum_handler = Mangum(app)
    return _mangum_handler(event, context)
