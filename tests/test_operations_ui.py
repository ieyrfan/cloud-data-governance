from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_operations_console_exposes_connected_control_workflows():
    page = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    styles = (ROOT / "frontend" / "static" / "styles.css").read_text(encoding="utf-8")

    assert 'data-view="operations"' in page
    assert 'id="operations-view"' in page
    assert 'id="incident-form"' in page
    assert 'id="retention-form"' in page
    assert 'id="checkpoint-create"' in page
    assert 'id="incidents-body"' in page
    assert 'api("/incidents")' in app
    assert 'api("/retention-controls")' in app
    assert 'api("/audit/checkpoints"' in app
    assert "transitionIncident" in app
    assert ".operations-control-grid" in styles
    assert 'sessionStorage.setItem("incident' not in app
    assert 'localStorage.setItem("incident' not in app


def test_operations_console_is_role_specific():
    app = (ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    assert '["overview", "inventory", "audit", "posture", "requests", "policies", "operations", "integrations"]' in app
    assert '["overview", "inventory", "requests", "policies", "operations", "integrations"]' in app
    assert '["overview", "inventory", "audit", "posture", "requests", "operations", "integrations"]' in app
    assert '["overview", "inventory", "requests", "integrations"]' in app
