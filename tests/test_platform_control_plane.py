import importlib

import pytest
from fastapi.testclient import TestClient

from src.governance.identity_adapter import principal_from_verified_claims
from src.governance.operations_control import sign_checkpoint, verify_checkpoint
from src.integrations.malware_gate import evaluate_scan_status


def _client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "platform-reviewer-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "platform-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "platform-admin-password")
    monkeypatch.setenv("OWNER_PASSWORD", "platform-owner-password")
    monkeypatch.setenv("REVIEWER_PASSWORD", "platform-reviewer-password")
    monkeypatch.setenv("AUDITOR_PASSWORD", "platform-auditor-password")
    monkeypatch.setenv("SESSION_SIGNING_SECRET", "platform-session-secret")
    monkeypatch.setenv("CHECKPOINT_SIGNING_SECRET", "platform-checkpoint-secret")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._demo_integration_records.clear()
    return TestClient(api_main.app)


def _login(client, username, password):
    token = client.post("/auth/login", json={"username": username, "password": password})
    assert token.status_code == 200
    return {"X-Dashboard-Token": token.json()["session_token"]}


def test_malware_gate_fails_closed_only_when_enforcement_is_active():
    assert evaluate_scan_status({}, enforced=False)["allowed"] is True
    pending = evaluate_scan_status({}, enforced=True)
    assert pending == {
        "allowed": False,
        "status": "NOT_SCANNED",
        "mode": "ENFORCED",
        "quarantine_required": True,
    }
    assert evaluate_scan_status(
        {"GuardDutyMalwareScanStatus": "NO_THREATS_FOUND"}, enforced=True
    )["allowed"] is True
    assert evaluate_scan_status(
        {"GuardDutyMalwareScanStatus": "THREATS_FOUND"}, enforced=True
    )["allowed"] is False


def test_federated_claim_adapter_requires_one_role_tenant_and_trusted_issuer():
    claims = {
        "iss": "https://identity.example.test/pool",
        "sub": "person-123",
        "preferred_username": "operator@example.test",
        "custom:tenant_id": "faculty-demo",
        "cognito:groups": ["datasentinel-owner"],
    }
    principal = principal_from_verified_claims(
        claims, trusted_issuer="https://identity.example.test/pool"
    )
    assert principal.role == "DATA_OWNER"
    assert principal.tenant_id == "faculty-demo"
    with pytest.raises(ValueError, match="not trusted"):
        principal_from_verified_claims(claims, trusted_issuer="https://attacker.example")
    with pytest.raises(ValueError, match="exactly one"):
        principal_from_verified_claims(
            {**claims, "cognito:groups": ["datasentinel-owner", "datasentinel-admin"]},
            trusted_issuer=claims["iss"],
        )


def test_checkpoint_signature_detects_tampering():
    checkpoint = {
        "head_hash": "a" * 64,
        "event_count": 12,
        "generated_at": "2026-10-18T00:00:00+00:00",
    }
    checkpoint["signature"] = sign_checkpoint(**checkpoint, secret="checkpoint-secret")
    assert verify_checkpoint(checkpoint, "checkpoint-secret") is True
    assert verify_checkpoint({**checkpoint, "event_count": 13}, "checkpoint-secret") is False


def test_review_incident_retention_and_checkpoint_workflows(monkeypatch):
    client = _client(monkeypatch)
    admin = _login(client, "admin", "platform-admin-password")
    auditor = _login(client, "auditor", "platform-auditor-password")

    review = client.post(
        "/reviews",
        headers=admin,
        json={
            "resource_id": "s3://raw/uploads/result.pdf",
            "decision": "CONFIRM",
            "note": "Verified protected output against the source evidence.",
        },
    )
    assert review.status_code == 201
    assert review.json()["values_disclosed"] is False
    assert review.json()["created_at"]

    created = client.post(
        "/incidents",
        headers=auditor,
        json={
            "title": "Unexpected original access",
            "severity": "HIGH",
            "resource_id": "s3://raw/uploads/result.pdf",
            "summary": "Audit correlation requires containment and owner review.",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]
    triaged = client.patch(
        f"/incidents/{incident_id}",
        headers=admin,
        json={"status": "TRIAGED", "note": "Correlation checked and owner notified."},
    )
    assert triaged.status_code == 200
    invalid = client.patch(
        f"/incidents/{incident_id}",
        headers=admin,
        json={"status": "RESOLVED", "note": "Attempted to skip containment."},
    )
    assert invalid.status_code == 409

    hold = client.put(
        "/retention-controls",
        headers=admin,
        json={
            "resource_id": "s3://raw/uploads/result.pdf",
            "retention_days": 365,
            "legal_hold": True,
        },
    )
    assert hold.status_code == 200
    assert hold.json()["deletion_blocked"] is True

    checkpoint = client.post("/audit/checkpoints", headers=auditor)
    assert checkpoint.status_code == 201
    assert checkpoint.json()["signature_valid"] is True
    assert checkpoint.json()["created_at"]
    assert checkpoint.json()["external_anchor_active"] is False
    listed = client.get("/audit/checkpoints", headers=auditor)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["signature_valid"] is True


def test_classifier_evidence_declares_version_and_malware_boundary():
    source = open("src/handlers/s3_classifier.py", encoding="utf-8").read()
    template = open("cloudformation/learner-lab.yml", encoding="utf-8").read()
    assert 'CLASSIFIER_VERSION = "2026.10-r7"' in source
    assert '"classifier_version": CLASSIFIER_VERSION' in source
    assert "evaluate_scan_status" in source
    assert 'ENFORCE_MALWARE_GATE: "false"' in template
    assert "GuardDuty Malware Protection is not available" in template
