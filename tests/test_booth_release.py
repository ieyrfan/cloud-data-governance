import importlib
import io
import zipfile

from fastapi.testclient import TestClient


def _client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "demo-reviewer-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "temporary-test-password")
    import src.api.main as api_main

    return TestClient(importlib.reload(api_main).app)


def test_risk_response_explains_policy_without_sensitive_values(monkeypatch):
    client = _client(monkeypatch)
    resource_id = "s3://cloud-data-governance-raw-dev/evidence/payroll-september.csv"
    response = client.get(
        "/files/risk",
        params={"resource_id": resource_id},
        headers={"X-Dashboard-Token": "demo-admin-token"},
    )

    assert response.status_code == 200
    explanation = response.json()["explanation"]
    assert explanation["policy_id"] == "DS-MY-PII-004"
    assert explanation["decision"] == "RESTRICTED"
    assert explanation["human_review_required"] is True
    assert explanation["original_values_disclosed"] is False
    assert "900101-14-5555" not in explanation["rationale"]


def test_evidence_pack_contains_proof_but_not_document_content(monkeypatch):
    client = _client(monkeypatch)
    resource_id = "s3://cloud-data-governance-raw-dev/evidence/payroll-september.csv"
    response = client.get(
        "/files/evidence-pack",
        params={"resource_id": resource_id},
        headers={"X-Dashboard-Token": "demo-admin-token"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {
            "README.txt",
            "access-history.json",
            "approval-history.json",
            "classification-decision.json",
            "manifest.json",
        }
        manifest = archive.read("manifest.json").decode()
        assert '"documents_included": false' in manifest
        assert "temporary-test-password" not in "".join(
            archive.read(name).decode() for name in archive.namelist()
        )


def test_booth_ui_has_accurate_session_and_guided_story():
    page = open("frontend/index.html", encoding="utf-8").read()
    script = open("frontend/static/app.js", encoding="utf-8").read()

    assert "Your 30-minute session" in page
    assert "four-hour session" not in page
    assert "Tell the DataSentinel story in five moves" in page
    assert "styles.css?v=34" in page
    assert "data-evidence-pack" in script
    assert "/files/evidence-pack" in script
    assert "DataGuard" not in page
    assert "DataGuard" not in script
