from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_inventory_has_document_catalogue_and_filter():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="document-type-filter"' in page
    assert 'id="document-type-summary"' in page
    assert "ACADEMIC_RESULT" in page
    assert "documentTypeTag(item)" in app
    assert "matchesType" in app


def test_each_governance_role_has_a_distinct_workspace():
    page = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="role-workspace"' in page
    for role in ["ADMIN", "DATA_OWNER", "REVIEWER", "AUDITOR"]:
        assert f"{role}:" in app
    assert "Full operational control" in app
    assert "Upload and access decisions" in app
    assert "Protected-copy access" in app
    assert "Read-only assurance" in app
