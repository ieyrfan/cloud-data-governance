from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]


def test_integration_hub_exposes_managed_clients_webhooks_and_delivery_evidence():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="integration-management"' in page
    assert 'id="api-client-form"' in page
    assert 'id="api-secret-reveal"' in page
    assert 'id="webhook-dialog"' in page
    assert 'id="webhook-delivery-panel"' in page
    assert 'api("/api-clients")' in app
    assert 'api("/webhook-deliveries")' in app
    assert "signing_secret" in app
    assert "api_key" in app


def test_integration_management_respects_role_and_never_persists_one_time_secrets():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'const canManage = state.role === "ADMIN"' in app
    assert '["ADMIN", "DATA_OWNER", "AUDITOR"].includes(state.role)' in app
    assert 'sessionStorage.setItem("api' not in app
    assert 'localStorage.setItem("api' not in app
    assert 'sessionStorage.setItem("webhook' not in app
    assert 'localStorage.setItem("webhook' not in app


def test_presentation_copy_matches_current_multi_page_ocr_capability():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "multi-page scanned PDFs" in page
    assert "unsupported multi-page OCR" not in page
    assert "Mixed or multi-page scans stop" not in page
    assert "/static/app.js?v=20261101&hardened=1" in page
    assert "/static/styles.css?v=34" in page


def test_mobile_navigation_keeps_readable_touch_targets_for_all_role_tabs():
    styles = (PROJECT_ROOT / "frontend" / "static" / "styles.css").read_text(
        encoding="utf-8"
    )

    assert "overflow-x: auto" in styles
    assert "flex: 0 0 78px" in styles
    assert ".nav-list::-webkit-scrollbar" in styles

