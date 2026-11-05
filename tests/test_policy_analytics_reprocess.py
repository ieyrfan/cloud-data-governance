import importlib

import pytest
from fastapi.testclient import TestClient

from src.governance.policy_engine import public_profiles, simulate_policy


def _client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "policy-reviewer-token")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "policy-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "policy-admin-password")
    monkeypatch.setenv("OWNER_PASSWORD", "policy-owner-password")
    monkeypatch.setenv("REVIEWER_PASSWORD", "policy-reviewer-password")
    monkeypatch.setenv("SESSION_SIGNING_SECRET", "policy-session-secret")
    import src.api.main as api_main

    return TestClient(importlib.reload(api_main).app)


def _login(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"X-Dashboard-Token": response.json()["session_token"]}


def test_policy_engine_is_versioned_value_free_and_fail_closed():
    profiles = public_profiles()
    assert {item["key"] for item in profiles} == {"malaysia-general", "external-review"}
    assert all(item["values_disclosed"] is False for item in profiles)

    restricted = simulate_policy("malaysia-general", ["MALAYSIAN_NRIC"], True)
    incomplete = simulate_policy("malaysia-general", [], False)
    assert restricted["decision"] == "RESTRICTED"
    assert restricted["values_disclosed"] is False
    assert incomplete["decision"] == "UNKNOWN"
    assert incomplete["human_review_required"] is True

    with pytest.raises(KeyError):
        simulate_policy("missing-profile", [], True)


def test_policy_simulation_and_analytics_follow_role_boundaries(monkeypatch):
    client = _client(monkeypatch)
    admin = _login(client, "admin", "policy-admin-password")
    reviewer = _login(client, "reviewer", "policy-reviewer-password")

    assert client.get("/policies", headers=reviewer).status_code == 200
    assert client.get("/analytics", headers=reviewer).status_code == 200
    denied = client.post(
        "/policies/simulate",
        headers=reviewer,
        json={"profile": "malaysia-general", "signal_types": ["ADDRESS"]},
    )
    assert denied.status_code == 403
    allowed = client.post(
        "/policies/simulate",
        headers=admin,
        json={"profile": "external-review", "signal_types": ["EMAIL"]},
    )
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "RESTRICTED"
    assert allowed.json()["values_disclosed"] is False


def test_reprocessing_is_unavailable_in_demo_and_requires_privilege(monkeypatch):
    client = _client(monkeypatch)
    admin = _login(client, "admin", "policy-admin-password")
    reviewer = _login(client, "reviewer", "policy-reviewer-password")
    payload = {
        "resource_id": "s3://raw/uploads/example.pdf",
        "reason": "Retry with the current classifier policy.",
    }
    assert client.post("/files/reprocess", headers=reviewer, json=payload).status_code == 403
    assert client.post("/files/reprocess", headers=admin, json=payload).status_code == 409
