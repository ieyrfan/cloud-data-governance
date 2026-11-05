from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_upload_waits_for_classification_and_reports_protected_copy():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "Date.now() + 60000" in app
    assert "error.status !== 404" in app
    assert "Protected copy is ready" in app
    assert 'id="upload-stage"' in page
    assert 'aria-live="polite"' in page


def test_processing_map_binds_every_live_dependency_status():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert 'api("/system/status")' in app
    for check_id in [
        "raw-storage",
        "event-pipeline",
        "classification",
        "protected-storage",
        "evidence-store",
    ]:
        assert f'data-system-check="{check_id}"' in page


def test_login_explains_product_company_team_and_honest_scope():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert "Student-led cloud security team" in page
    assert "Muhammad Irfan bin Rizal" in page
    assert "Project lead · Cloud architecture" in page
    assert "CEO, IFHX Technology" not in page
    assert "Muhammad Faris Irfan bin Dzulkifli" in page
    assert "Muhammad Ihsan bin Kamarulzaman" in page
    assert "How DataSentinel works" in page
    assert "Amazon Textract OCR is active" in page
    assert "Multi-page scanned-PDF OCR is active" in page


def test_file_retrieval_evidence_is_visible_in_the_audit_view():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert 'api("/access-events")' in app
    assert "correlation_id" in app
    assert 'id="access-events-body"' in page
    assert "Protected links issued" in page


def test_audit_sequence_numbers_use_full_ledger_position():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'String(total - index).padStart(2, "0")' in app
    assert 'String(events.length - index).padStart(2, "0")' not in app


def test_management_console_explains_the_external_integration_product():
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    assert 'data-view="integrations"' in page
    assert "Connect your application to DataSentinel" in page
    assert "POST /api/v1/documents" in page
    assert "Originals stay customer-controlled" in page
    assert 'integrations: "Developer access"' in app
