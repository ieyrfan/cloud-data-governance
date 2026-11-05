"""Regression coverage for browser-facing response hardening."""

import importlib

from fastapi.testclient import TestClient


def test_browser_security_headers_are_applied(monkeypatch):
    # Regression: ISSUE-008 — browser responses lacked defense-in-depth headers.
    # Found by /qa on 2026-09-14.
    # Report: .gstack/qa-reports/qa-report-dataguard-live-2026-09-14.md
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "demo-access-token")
    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert (
        "sha256-eV3QMumkWxytVHa/LDvu+mnW+PcSAEI4SfFu0iIlbDc="
        in response.headers["content-security-policy"]
    )
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["cache-control"] == "no-store"


def test_versioned_static_assets_are_cacheable(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "demo-access-token")
    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    response = client.get("/static/app.js?v=4")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert response.headers["x-content-type-options"] == "nosniff"
