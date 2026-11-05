import hashlib
import importlib

import pytest
from fastapi.testclient import TestClient


class IntegrationS3:
    def __init__(self):
        self.posts = []

    def generate_presigned_post(self, **kwargs):
        self.posts.append(kwargs)
        return {
            "url": "https://raw.example.com/",
            "fields": {"key": kwargs["Key"], **kwargs["Fields"]},
        }

    def head_object(self, **kwargs):
        return {"ContentType": "application/pdf"}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        assert operation == "get_object"
        assert ExpiresIn == 120
        return f"https://protected.example.com/{Params['Key']}"


def integration_client(monkeypatch, scopes=None):
    api_key = "ds_test_integration_key"
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("RAW_BUCKET", "raw-zone")
    monkeypatch.setenv("CLEAN_BUCKET", "protected-zone")
    monkeypatch.setenv("INTEGRATION_API_KEY_HASH", hashlib.sha256(api_key.encode()).hexdigest())
    monkeypatch.setenv("INTEGRATION_TENANT_ID", "tenant-a")
    monkeypatch.setenv("INTEGRATION_CLIENT_ID", "student-portal")
    monkeypatch.setenv(
        "INTEGRATION_API_SCOPES",
        scopes or "documents:create,documents:read,protected-copy:read",
    )

    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    records = {}

    def get_record(record_id):
        return records.get(record_id)

    def put_record(item, *, create_only=False):
        if create_only and item["request_id"] in records:
            return False
        records[item["request_id"]] = item
        return True

    monkeypatch.setattr(api_main, "_integration_record", get_record)
    monkeypatch.setattr(api_main, "_put_integration_record", put_record)
    monkeypatch.setattr(api_main, "_s3", IntegrationS3())
    return TestClient(api_main.app), api_main, records, api_key


def create_document(client, api_key, idempotency_key="student-case-10042"):
    return client.post(
        "/api/v1/documents",
        headers={"X-API-Key": api_key, "Idempotency-Key": idempotency_key},
        json={
            "filename": "result-slip.pdf",
            "content_type": "application/pdf",
            "purpose": "student-record-verification",
            "subject_reference": "STUDENT-10042",
            "protection_profile": "malaysia-academic-record",
        },
    )


def test_machine_identity_requires_hashed_api_key(monkeypatch):
    client, _, _, api_key = integration_client(monkeypatch)

    assert client.get("/api/v1/whoami").status_code == 401
    assert client.get("/api/v1/whoami", headers={"X-API-Key": "wrong"}).status_code == 401
    response = client.get("/api/v1/whoami", headers={"X-API-Key": api_key})

    assert response.status_code == 200
    assert response.json() == {
        "tenant_id": "tenant-a",
        "client_id": "student-portal",
        "scopes": ["documents:create", "documents:read", "protected-copy:read"],
        "authentication": "API_KEY_SHA256",
    }


def test_document_creation_is_idempotent_and_tenant_namespaced(monkeypatch):
    client, api_main, records, api_key = integration_client(monkeypatch)

    first = create_document(client, api_key)
    second = create_document(client, api_key)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["document_id"] == second.json()["document_id"]
    assert first.json()["job_id"] == second.json()["job_id"]
    assert first.json()["replayed"] is False
    assert second.json()["replayed"] is True
    assert first.json()["upload"]["expires_in_seconds"] == 300
    assert first.json()["upload"]["max_bytes"] == 5 * 1024 * 1024
    document = next(
        value for key, value in records.items() if key.startswith("INTEGRATION_DOCUMENT#")
    )
    assert document["tenant_id"] == "tenant-a"
    assert document["client_id"] == "student-portal"
    assert document["object_key"].startswith("integrations/tenant-a/student-portal/doc_")
    assert api_main._s3.posts[0]["Fields"]["x-amz-meta-tenant-id"] == "tenant-a"


def test_idempotency_replay_recovers_claim_without_document(monkeypatch):
    client, api_main, records, api_key = integration_client(monkeypatch)
    original_put = api_main._put_integration_record
    failed_once = False

    def fail_after_claim(item, *, create_only=False):
        nonlocal failed_once
        if item.get("record_type") == "INTEGRATION_DOCUMENT" and not failed_once:
            failed_once = True
            raise RuntimeError("simulated transient document write failure")
        return original_put(item, create_only=create_only)

    monkeypatch.setattr(api_main, "_put_integration_record", fail_after_claim)
    with pytest.raises(RuntimeError, match="simulated transient"):
        create_document(client, api_key)

    replay = create_document(client, api_key)

    assert replay.status_code == 202
    assert replay.json()["replayed"] is True
    document_id = replay.json()["document_id"]
    assert f"INTEGRATION_DOCUMENT#tenant-a#{document_id}" in records
    assert any(key.startswith("INTEGRATION_JOB#tenant-a#") for key in records)


def test_status_discloses_signal_types_but_not_sensitive_values(monkeypatch):
    client, api_main, _, api_key = integration_client(monkeypatch)
    created = create_document(client, api_key).json()
    resource_id = api_main._integration_document_record(
        {
            "tenant_id": "tenant-a",
            "client_id": "student-portal",
        },
        created["document_id"],
    )["resource_id"]
    monkeypatch.setattr(
        api_main,
        "_latest_file",
        lambda candidate: {
            "resource_id": resource_id,
            "timestamp": "2026-10-16T12:00:00Z",
            "sensitivity_level": "RESTRICTED",
            "confidence_score": "0.97",
            "risk_level": "CRITICAL",
            "document_type": "ACADEMIC_RESULT",
            "findings": {
                "pattern_types_detected": ["malaysian_nric", "address"],
                "pattern_matches_count": 2,
            },
            "governance_actions": {"protected_copy_created": True},
        }
        if candidate == resource_id
        else None,
    )

    response = client.get(
        f"/api/v1/documents/{created['document_id']}", headers={"X-API-Key": api_key}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["classification"]["sensitivity"] == "RESTRICTED"
    assert payload["classification"]["document_type"] == "ACADEMIC_RESULT"
    assert payload["detected_signals"] == [
        {"type": "MALAYSIAN_NRIC", "values_disclosed": False},
        {"type": "ADDRESS", "values_disclosed": False},
    ]
    assert "900101" not in response.text


def test_protected_copy_is_scoped_and_audited(monkeypatch):
    client, api_main, records, api_key = integration_client(monkeypatch)
    created = create_document(client, api_key).json()
    monkeypatch.setattr(
        api_main,
        "_latest_file",
        lambda resource_id: {
            "resource_id": resource_id,
            "governance_actions": {"protected_copy_created": True},
        },
    )

    response = client.get(
        f"/api/v1/documents/{created['document_id']}/protected-copy",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200
    assert response.json()["variant"] == "protected"
    assert response.json()["expires_in_seconds"] == 120
    assert response.json()["url"].startswith("https://protected.example.com/")
    events = [
        value for key, value in records.items() if key.startswith("INTEGRATION_ACCESS#")
    ]
    assert len(events) == 1
    assert events[0]["tenant_id"] == "tenant-a"
    assert events[0]["client_id"] == "student-portal"


def test_scope_enforcement_blocks_document_creation(monkeypatch):
    client, _, _, api_key = integration_client(
        monkeypatch, scopes="documents:read,protected-copy:read"
    )

    response = create_document(client, api_key)

    assert response.status_code == 403
    assert "documents:create" in response.json()["detail"]


def test_internal_pattern_names_are_normalised_for_external_clients(monkeypatch):
    _, api_main, _, _ = integration_client(monkeypatch)

    assert api_main._public_signal_type("my_ic") == "MALAYSIAN_NRIC"
    assert api_main._public_signal_type("my_phone") == "MALAYSIAN_PHONE"
    assert api_main._public_signal_type("email") == "EMAIL_ADDRESS"
    assert api_main._public_signal_type("credit_card") == "PAYMENT_CARD"
