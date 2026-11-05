import importlib

from fastapi.testclient import TestClient


def _client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "client-reviewer-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "client-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "client-admin-password")
    monkeypatch.setenv("OWNER_PASSWORD", "client-owner-password")
    monkeypatch.setenv("REVIEWER_PASSWORD", "client-reviewer-password")
    monkeypatch.setenv("AUDITOR_PASSWORD", "client-auditor-password")
    monkeypatch.setenv("SESSION_SIGNING_SECRET", "client-session-secret")
    monkeypatch.setenv("INTEGRATION_API_KEY_HASH", "")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._demo_integration_records.clear()
    return TestClient(api_main.app)


def _login(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"X-Dashboard-Token": response.json()["session_token"]}


def _definition():
    return {
        "tenant_id": "faculty-demo",
        "client_id": "student-portal",
        "label": "Student portal",
        "scopes": ["documents:create", "documents:read", "protected-copy:read"],
        "expires_in_days": 30,
    }


def test_api_key_is_returned_once_hashed_and_resolves_machine_identity(monkeypatch):
    client = _client(monkeypatch)
    admin = _login(client, "admin", "client-admin-password")

    created = client.post("/api-clients", headers=admin, json=_definition())
    assert created.status_code == 201
    api_key = created.json()["api_key"]
    assert api_key.startswith("ds_live_student-portal_")

    listed = client.get("/api-clients", headers=admin)
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert "api_key" not in listed.json()["items"][0]
    assert "key_hash" not in listed.json()["items"][0]

    whoami = client.get("/api/v1/whoami", headers={"X-API-Key": api_key})
    assert whoami.status_code == 200
    assert whoami.json()["tenant_id"] == "faculty-demo"
    assert whoami.json()["client_id"] == "student-portal"
    assert whoami.json()["authentication"] == "MANAGED_API_KEY_SHA256"


def test_rotation_immediately_revokes_old_key_and_revoke_blocks_new_key(monkeypatch):
    client = _client(monkeypatch)
    admin = _login(client, "admin", "client-admin-password")
    old_key = client.post("/api-clients", headers=admin, json=_definition()).json()["api_key"]

    rotated = client.post("/api-clients/faculty-demo/student-portal/rotate", headers=admin)
    assert rotated.status_code == 201
    new_key = rotated.json()["api_key"]
    assert new_key != old_key
    assert client.get("/api/v1/whoami", headers={"X-API-Key": old_key}).status_code == 401
    assert client.get("/api/v1/whoami", headers={"X-API-Key": new_key}).status_code == 200

    revoked = client.delete("/api-clients/faculty-demo/student-portal", headers=admin)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "REVOKED"
    assert client.get("/api/v1/whoami", headers={"X-API-Key": new_key}).status_code == 401


def test_client_management_is_role_restricted(monkeypatch):
    client = _client(monkeypatch)
    reviewer = _login(client, "reviewer", "client-reviewer-password")
    owner = _login(client, "owner", "client-owner-password")
    auditor = _login(client, "auditor", "client-auditor-password")

    assert client.post("/api-clients", headers=reviewer, json=_definition()).status_code == 403
    assert client.post("/api-clients", headers=owner, json=_definition()).status_code == 403
    assert client.get("/api-clients", headers=reviewer).status_code == 403
    assert client.get("/api-clients", headers=auditor).status_code == 200
