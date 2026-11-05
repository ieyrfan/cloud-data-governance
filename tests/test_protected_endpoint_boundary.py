import importlib

from fastapi.testclient import TestClient


def _demo_client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "boundary-test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "boundary-test-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "boundary-test-admin-password")
    monkeypatch.setenv("SESSION_SIGNING_SECRET", "boundary-test-session-signing-secret")
    import src.api.main as api_main

    return TestClient(importlib.reload(api_main).app)


def test_every_management_data_endpoint_rejects_anonymous_access(monkeypatch):
    client = _demo_client(monkeypatch)
    resource = "s3://private-zone/uploads/example.pdf"

    checks = [
        client.get("/system/status"),
        client.get("/dashboard/summary"),
        client.get("/files"),
        client.get("/files/risk", params={"resource_id": resource}),
        client.get("/files/evidence-pack", params={"resource_id": resource}),
        client.get("/access-requests"),
        client.get("/access-events"),
        client.get("/capabilities"),
        client.get("/policies"),
        client.get("/analytics"),
        client.get("/api-clients"),
        client.get(
            "/files/download",
            params={"resource_id": resource, "variant": "protected"},
        ),
        client.get("/audit"),
        client.get("/posture"),
        client.post(
            "/uploads/presign",
            json={"filename": "example.pdf", "content_type": "application/pdf"},
        ),
        client.post(
            "/access-requests",
            json={"resource_id": resource, "justification": "Required for review."},
        ),
        client.post(
            "/policies/simulate",
            json={"profile": "malaysia-general", "signal_types": []},
        ),
        client.post(
            "/files/reprocess",
            json={"resource_id": resource, "reason": "Retry the current classifier."},
        ),
        client.post(
            "/api-clients",
            json={
                "tenant_id": "tenant-demo",
                "client_id": "client-demo",
                "label": "Demo client",
                "scopes": ["documents:read"],
                "expires_in_days": 30,
            },
        ),
        client.put(
            "/api-clients/faculty-demo/student-portal/webhook",
            json={"url": "https://hooks.example.com/events"},
        ),
        client.get("/webhook-deliveries"),
    ]

    assert all(response.status_code == 401 for response in checks)
