from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_signal_types_use_clear_public_labels_in_activity_and_evidence():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'my_ic: "Malaysian NRIC"' in app
    assert 'address: "Postal address"' in app
    assert 'email_address: "Email address"' in app
    assert "escapeHtml(signalLabel(signal))" in app


def test_mobile_inventory_filters_reserve_a_full_width_count_row():
    styles = (PROJECT_ROOT / "frontend" / "static" / "styles.css").read_text(
        encoding="utf-8"
    )

    assert ".inventory-toolbar .count-badge" in styles
    assert "flex: 1 0 100%" in styles


def test_release_31_assets_are_cache_busted_together():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "styles.css?v=34" in page
    assert "app.js?v=20261101&hardened=1" in page


def test_policy_studio_has_value_free_simulation_and_operational_metrics():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="policies-view"' in page
    assert 'id="policy-form"' in page
    assert 'id="analytics-protection"' in page
    assert 'api("/policies/simulate"' in app
    assert 'const policies = await api("/policies")' in app
    assert 'const analytics = await api("/analytics")' in app
    assert 'data-reprocess data-resource=' in app
    assert 'api("/files/reprocess"' in app

