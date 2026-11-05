import importlib

from fastapi.testclient import TestClient


def test_customer_portal_and_passport_demo_are_served(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    page = client.get("/customer")
    assert page.status_code == 200
    assert "Protect and download" in page.text
    assert "DEMO PASSPORT" in page.text
    assert "synthetic illustration" in page.text.lower()
    assert "No document inventory" in page.text
    assert "3 MB" in page.text
    assert 'id="api"' in page.text
    assert "https://datasentinel.ifhx.my/api/v1/protect" in page.text
    assert "--data-binary @sample.pdf" in page.text

    asset = client.get("/static/demo-passport.svg")
    assert asset.status_code == 200
    assert "SYNTHETIC DATA" in asset.text


def test_passport_is_a_distinct_inventory_type():
    from src.classifiers.document_type_classifier import classify_document_type

    result = classify_document_type(
        "PASSPORT NATIONALITY DATE OF BIRTH ISSUING AUTHORITY", "passport-demo.jpg"
    )
    assert result["key"] == "PASSPORT"


def test_personal_details_alone_do_not_imply_passport():
    from src.classifiers.document_type_classifier import classify_document_type

    assert classify_document_type("Nationality Malaysian Date of birth 1 January 2000", "document.txt")["key"] == "OTHER"
    assert classify_document_type("Work experience Technical skills Nationality Date of birth", "document.txt")["key"] == "RESUME"
