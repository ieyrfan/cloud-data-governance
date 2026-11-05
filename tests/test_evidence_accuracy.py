import copy
import importlib

from fastapi.testclient import TestClient


def _api(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "demo-access-token")
    import src.api.main as api_main

    return importlib.reload(api_main)


def test_internal_acceptance_fixtures_are_not_shown_as_user_documents(monkeypatch):
    api_main = _api(monkeypatch)
    items = [
        {
            "resource_id": "s3://raw/acceptance/synthetic-ic-photo.jpg",
            "version_id": "2026-10-14T00:00:00Z#1",
            "sensitivity_level": "RESTRICTED",
        },
        {
            "resource_id": "s3://raw/uploads/real-id.jpg",
            "version_id": "2026-10-14T00:00:01Z#2",
            "sensitivity_level": "RESTRICTED",
        },
    ]

    visible = api_main._newest_classifications(items)

    assert [item["resource_id"] for item in visible] == ["s3://raw/uploads/real-id.jpg"]


def test_newest_classification_uses_timestamp_not_lexical_failure_prefix(monkeypatch):
    api_main = _api(monkeypatch)
    resource_id = "s3://raw/uploads/recovered-document.pdf"
    items = [
        {
            "resource_id": resource_id,
            "version_id": "zzfailure#older",
            "timestamp": "2026-10-25T08:00:00Z",
            "sensitivity_level": "UNKNOWN",
            "findings": {"processing_status": "FAILED"},
        },
        {
            "resource_id": resource_id,
            "version_id": "source#newer",
            "timestamp": "2026-10-27T03:00:00Z",
            "sensitivity_level": "RESTRICTED",
            "findings": {"pattern_matches_count": 2},
        },
    ]

    visible = api_main._newest_classifications(items)

    assert visible[0]["sensitivity_level"] == "RESTRICTED"
    assert visible[0]["version_id"] == "source#newer"


def test_readiness_is_derived_from_recorded_actions(monkeypatch):
    api_main = _api(monkeypatch)
    items = api_main._demo_payload("files")
    summary = api_main._classification_summary(items)
    assert summary["governance_readiness_score"] == 100
    assert summary["readiness_checks_passed"] == summary["readiness_checks_total"] == 45
    assert summary["readiness_basis"] == "recorded_governance_actions"

    incomplete = copy.deepcopy(items[:1])
    incomplete[0]["governance_actions"]["audit_event_created"] = False
    incomplete_summary = api_main._classification_summary(incomplete)
    assert incomplete_summary["governance_readiness_score"] == 83


def test_unknown_classification_is_not_silently_counted_as_public(monkeypatch):
    api_main = _api(monkeypatch)
    summary = api_main._classification_summary([{"resource_id": "s3://bucket/key"}])
    assert summary["sensitivity_breakdown"]["PUBLIC"] == 0
    assert summary["sensitivity_breakdown"]["UNKNOWN"] == 1


def test_api_recomputes_hashes_across_complete_demo_ledger(monkeypatch):
    api_main = _api(monkeypatch)
    headers = {"X-Dashboard-Token": "demo-access-token"}
    response = TestClient(api_main.app).get("/audit?limit=2", headers=headers)
    payload = response.json()
    assert payload["count"] == 2
    assert payload["total_count"] == 3
    assert payload["integrity"] == {
        "verified": True,
        "checked_events": 3,
        "scope": "complete_retrieved_ledger",
        "message": "Every retrieved event hash and chain link was recomputed.",
    }


def test_hash_recomputation_detects_modified_event(monkeypatch):
    api_main = _api(monkeypatch)
    events = copy.deepcopy(api_main._demo_payload("audit"))
    events[0]["details"]["confidence"] = 0.01
    result = api_main._verify_audit_events(events)
    assert result["verified"] is False
    assert result["message"] == "Event hash mismatch detected."


def test_files_endpoint_reports_truncation_truthfully(monkeypatch):
    api_main = _api(monkeypatch)
    headers = {"X-Dashboard-Token": "demo-access-token"}
    payload = TestClient(api_main.app).get("/files?limit=2", headers=headers).json()
    assert payload["count"] == 2
    assert payload["total_count"] == 8
    assert payload["truncated"] is True
