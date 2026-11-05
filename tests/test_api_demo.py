import importlib

from fastapi.testclient import TestClient


def demo_client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "demo-access-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin123")
    monkeypatch.setenv("OWNER_PASSWORD", "owner123")
    monkeypatch.setenv("REVIEWER_PASSWORD", "reviewer123")
    monkeypatch.setenv("AUDITOR_PASSWORD", "auditor123")
    import src.api.main as api_main

    return TestClient(importlib.reload(api_main).app)


def test_health_and_dashboard_assets(monkeypatch):
    client = demo_client(monkeypatch)
    assert client.get("/health").json()["mode"] == "demo"
    assert client.get("/").status_code == 200
    assert "Governance overview" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200


def test_demo_system_status_is_truthfully_labelled_as_snapshot(monkeypatch):
    client = demo_client(monkeypatch)
    response = client.get(
        "/system/status", headers={"X-Dashboard-Token": "demo-access-token"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall"] == "SNAPSHOT"
    assert payload["mode"] == "demo"
    assert len(payload["checks"]) == 5
    assert {check["status"] for check in payload["checks"]} == {"SNAPSHOT"}


def test_protected_routes_require_valid_token(monkeypatch):
    client = demo_client(monkeypatch)
    assert client.get("/dashboard/summary").status_code == 401
    assert (
        client.get("/dashboard/summary", headers={"X-Dashboard-Token": "wrong"}).status_code == 401
    )
    response = client.get("/dashboard/summary", headers={"X-Dashboard-Token": "demo-access-token"})
    assert response.status_code == 200
    assert response.json()["total_files_scanned"] == 8


def test_admin_login_creates_an_internal_session(monkeypatch):
    client = demo_client(monkeypatch)
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_token"].startswith("dg1.")
    assert payload["access_role"] == "ADMIN"
    assert payload["username"] == "admin"
    assert payload["expires_in_seconds"] == 1800
    session = payload["session_token"]
    summary = client.get("/dashboard/summary", headers={"X-Dashboard-Token": session})
    assert summary.status_code == 200
    assert summary.json()["access_role"] == "ADMIN"


def test_admin_login_rejects_incorrect_credentials(monkeypatch):
    client = demo_client(monkeypatch)
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    response = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password."


def test_login_is_rate_limited_and_logout_revokes_session(monkeypatch):
    client = demo_client(monkeypatch)
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-password")

    for _ in range(5):
        assert client.post(
            "/auth/login", json={"username": "admin", "password": "wrong"}
        ).status_code == 401
    limited = client.post(
        "/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0

    api_main = importlib.import_module("src.api.main")
    api_main._login_attempts.clear()
    login = client.post(
        "/auth/login", json={"username": "admin", "password": "correct-password"}
    )
    token = login.json()["session_token"]
    headers = {"X-Dashboard-Token": token}
    assert client.get("/files", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).json() == {"revoked": True}
    assert client.get("/files", headers=headers).status_code == 401


def test_zero_confidence_public_record_fails_closed(monkeypatch):
    client = demo_client(monkeypatch)
    headers = {"X-Dashboard-Token": "demo-access-token"}
    files = client.get("/files", headers=headers).json()["items"]
    uncertain = [item for item in files if float(item.get("confidence_score", 0)) == 0]
    assert uncertain
    assert {item["sensitivity_level"] for item in uncertain} == {"UNKNOWN"}
    resource = uncertain[0]["resource_id"]
    detail = client.get("/files/risk", params={"resource_id": resource}, headers=headers)
    assert detail.json()["compliance_status"] == "REVIEW_REQUIRED"


def test_frontend_navigation_logout_and_login_hint_contracts():
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    app_source = (project_root / "frontend" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    page = (project_root / "frontend" / "index.html").read_text(encoding="utf-8")

    assert 'historyMode = "push"' in app_source
    assert 'history[method]({ view: name }, "", `#${name}`)' in app_source
    assert 'window.addEventListener("popstate"' in app_source
    assert 'fetch("/auth/logout"' in app_source
    assert "admin / admin123" not in app_source
    assert "app.js?v=20261101&hardened=1" in page


def test_inventory_filters_and_risk_details(monkeypatch):
    client = demo_client(monkeypatch)
    headers = {"X-Dashboard-Token": "demo-access-token"}
    files = client.get("/files?sensitivity=RESTRICTED", headers=headers).json()
    assert files["count"] == 2
    resource = files["items"][0]["resource_id"]
    detail = client.get("/files/risk", params={"resource_id": resource}, headers=headers)
    assert detail.status_code == 200
    assert detail.json()["compliance_status"] == "REVIEW_REQUIRED"
    assert client.get("/files?sensitivity=SECRET", headers=headers).status_code == 422


def test_demo_upload_is_safely_disabled(monkeypatch):
    client = demo_client(monkeypatch)
    response = client.post(
        "/uploads/presign",
        headers={"X-Dashboard-Token": "demo-access-token"},
        json={"filename": "sample.txt", "content_type": "text/plain"},
    )
    assert response.status_code == 409


def login_as(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"X-Dashboard-Token": response.json()["session_token"]}


def test_reviewer_access_request_owner_approval_flow(monkeypatch):
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    client = demo_client(monkeypatch)
    reviewer = login_as(client, "reviewer", "reviewer123")
    resource = client.get("/files", headers=reviewer).json()["items"][0]["resource_id"]

    before = client.get("/files/risk", params={"resource_id": resource}, headers=reviewer)
    assert before.json()["can_access_original"] is False
    request = client.post(
        "/access-requests",
        headers=reviewer,
        json={
            "resource_id": resource,
            "justification": "Validate the original evidence for an approved investigation.",
        },
    )
    assert request.status_code == 410
    after = client.get("/files/risk", params={"resource_id": resource}, headers=reviewer)
    assert after.json()["can_access_original"] is False


def test_role_boundaries_and_capability_truth(monkeypatch):
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    client = demo_client(monkeypatch)
    auditor = login_as(client, "auditor", "auditor123")
    resource = client.get("/files", headers=auditor).json()["items"][0]["resource_id"]
    denied = client.post(
        "/access-requests",
        headers=auditor,
        json={"resource_id": resource, "justification": "Audit requires the original document."},
    )
    assert denied.status_code == 410
    capabilities = client.get("/capabilities", headers=auditor).json()
    assert "Role-based signed sessions" in capabilities["implemented"]
    assert "File retrieval correlation evidence" in capabilities["implemented"]
    assert "Lambda and dead-letter queue failure alarms" in capabilities["implemented"]
    assert any(
        item.startswith("Amazon Textract OCR for single-page scanned PDFs")
        and "multi-page" in item
        for item in capabilities["implemented"]
    )
    assert "Amazon Textract OCR" not in capabilities["integration_ready"]
    assert "Amazon Cognito federation" in capabilities["integration_ready"]
    assert "not represented as active" in capabilities["statement"]


def test_tampered_signed_session_is_rejected(monkeypatch):
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    client = demo_client(monkeypatch)
    token = login_as(client, "admin", "admin123")["X-Dashboard-Token"]
    tampered = f"{token[:-1]}{'0' if token[-1] != '0' else '1'}"
    assert client.get(
        "/dashboard/summary", headers={"X-Dashboard-Token": tampered}
    ).status_code == 401
