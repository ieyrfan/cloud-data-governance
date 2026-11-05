"""Regression coverage for issues found during the 2026-10-12 exhaustive QA run."""

import importlib
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeS3:
    def head_object(self, **_kwargs):
        return {"ContentType": "application/pdf"}

    def generate_presigned_url(self, _operation, Params, ExpiresIn):
        assert ExpiresIn == 120
        return f"https://signed.example/{Params['Bucket']}/{Params['Key']}"


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class FakeDynamoDB:
    def __init__(self):
        self.table = FakeTable()

    def Table(self, _name):
        return self.table


def test_download_response_returns_the_exact_persisted_access_event(monkeypatch):
    """Regression: ISSUE-001 - Audit view stayed stale after issuing a file link.

    Found by /qa on 2026-10-12.
    Report: .gstack/qa-reports/qa-report-dataguard-ifhx-my-2026-10-12.md
    """
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "reviewer-token-1234")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "administrator-token-1234")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")
    monkeypatch.setenv("CLEAN_BUCKET", "governed-clean")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._s3 = FakeS3()
    api_main._dynamodb = FakeDynamoDB()
    monkeypatch.setattr(
        api_main,
        "_latest_file",
        lambda resource_id: {
            "resource_id": resource_id,
            "governance_actions": {"protected_copy_created": True},
        },
    )
    client = TestClient(api_main.app)
    resource = "s3://governed-raw/uploads/qa-evidence.pdf"

    response = client.get(
        "/files/download",
        params={"resource_id": resource, "variant": "protected"},
        headers={"X-Dashboard-Token": "reviewer-token-1234"},
    )

    assert response.status_code == 200
    payload = response.json()
    event = payload["access_event"]
    assert event["correlation_id"] == payload["correlation_id"]
    assert event["resource_id"] == resource
    assert event["variant"] == "PROTECTED"
    assert event["access_basis"] == "PROTECTED_DEFAULT"
    assert api_main._dynamodb.table.items == [event]


def test_browser_inserts_new_retrieval_evidence_without_a_full_refresh():
    """Regression: ISSUE-001 - New evidence must appear immediately in Audit."""
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert "if (payload.access_event)" in app
    assert "renderAccessEvents({ items: [payload.access_event, ...current]" in app


def test_mobile_section_intro_stacks_instead_of_squeezing_request_status():
    """Regression: ISSUE-002 - The pending-request summary wrapped into a thin column."""
    styles = (PROJECT_ROOT / "frontend" / "static" / "styles.css").read_text(
        encoding="utf-8"
    )

    assert ".section-intro { display: grid; grid-template-columns: minmax(0, 1fr);" in styles
    assert ".request-summary { width: 100%; min-width: 0; justify-items: start; }" in styles
