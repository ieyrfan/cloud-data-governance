import importlib

from fastapi.testclient import TestClient


class PresignedPostS3:
    def __init__(self):
        self.request = None

    def generate_presigned_post(self, **kwargs):
        self.request = kwargs
        return {
            "url": "https://example-bucket.s3.amazonaws.com/",
            "fields": {"key": kwargs["Key"], "Content-Type": kwargs["Fields"]["Content-Type"]},
        }


def test_upload_contract_enforces_size_at_s3(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    fake_s3 = PresignedPostS3()
    monkeypatch.setattr(api_main, "_s3", fake_s3)
    client = TestClient(api_main.app)

    response = client.post(
        "/uploads/presign",
        headers={"X-Dashboard-Token": "test-admin-token"},
        json={"filename": "evidence.txt", "content_type": "text/plain"},
    )

    assert response.status_code == 200
    assert response.json()["max_bytes"] == 5 * 1024 * 1024
    assert response.json()["form_fields"]["Content-Type"] == "text/plain"
    assert ["content-length-range", 1, 5 * 1024 * 1024] in fake_s3.request["Conditions"]
    assert fake_s3.request["ExpiresIn"] == 300


def test_upload_rejects_unsupported_extension(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    response = client.post(
        "/uploads/presign",
        headers={"X-Dashboard-Token": "test-admin-token"},
        json={"filename": "payload.exe", "content_type": "application/octet-stream"},
    )

    assert response.status_code == 422


def test_upload_rejects_mime_type_spoofing(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("ALLOW_LEGACY_DASHBOARD_TOKENS", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    response = client.post(
        "/uploads/presign",
        headers={"X-Dashboard-Token": "test-admin-token"},
        json={"filename": "evidence.pdf", "content_type": "text/html"},
    )

    assert response.status_code == 422
    assert "does not match" in response.json()["detail"]


def test_upload_accepts_ic_photo_formats(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    fake_s3 = PresignedPostS3()
    monkeypatch.setattr(api_main, "_s3", fake_s3)
    client = TestClient(api_main.app)

    for filename, content_type in (
        ("ic-photo.jpg", "image/jpeg"),
        ("ic-scan.jpeg", "image/jpeg"),
        ("ic-copy.png", "image/png"),
    ):
        response = client.post(
            "/uploads/presign",
            headers={"X-Dashboard-Token": "test-admin-token"},
            json={"filename": filename, "content_type": content_type},
        )
        assert response.status_code == 200


def test_upload_accepts_markup_and_configuration_formats(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-dashboard-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    monkeypatch.setattr(api_main, "_s3", PresignedPostS3())
    client = TestClient(api_main.app)
    for filename, content_type in (
        ("record.html", "text/html"),
        ("record.xml", "application/xml"),
        ("record.yaml", "application/yaml"),
        ("record.ini", "text/plain"),
        ("record.cfg", "text/plain"),
    ):
        response = client.post(
            "/uploads/presign",
            headers={"X-Dashboard-Token": "test-admin-token"},
            json={"filename": filename, "content_type": content_type},
        )
        assert response.status_code == 200


def test_reviewer_cannot_create_upload(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "test-reviewer-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "test-admin-token")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")

    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    response = client.post(
        "/uploads/presign",
        headers={"X-Dashboard-Token": "test-reviewer-token"},
        json={"filename": "evidence.pdf", "content_type": "application/pdf"},
    )

    assert response.status_code == 403
    assert "administrators and data owners" in response.json()["detail"]
