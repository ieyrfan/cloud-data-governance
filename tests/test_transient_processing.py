import importlib
import io

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi.testclient import TestClient
from PIL import Image

from src.api.transient_process import _mykad_name_from_ocr, protect_in_memory


def test_mykad_ocr_fallback_finds_unlabelled_name_after_ic():
    lines = [
        {"Text": "900101-14-5555"},
        {
            "Text": "SYNTHETIC TEST PERSON",
            "Geometry": {"BoundingBox": {"Left": 0.08, "Top": 0.58, "Height": 0.04}},
        },
        {
            "Text": "NO 73 JALAN CONTOH",
            "Geometry": {"BoundingBox": {"Left": 0.08, "Top": 0.68, "Height": 0.04}},
        },
    ]

    assert _mykad_name_from_ocr(
        "KAD PENGENALAN MALAYSIA", lines, {"my_ic": ["900101-14-5555"]}
    ) == "SYNTHETIC TEST PERSON"


@pytest.mark.parametrize(
    ("text", "lines", "matches", "message"),
    [
        ("KAD PENGENALAN MALAYSIA", [], {}, "could not be confidently read"),
        (
            "KAD PENGENALAN MALAYSIA",
            [{"Text": "900101145555"}],
            {"my_ic": ["900101-14-5555"]},
            "could not be confidently located",
        ),
    ],
)
def test_mykad_ocr_fallback_fails_closed(text, lines, matches, message):
    with pytest.raises(ValueError, match=message):
        _mykad_name_from_ocr(text, lines, matches)


def test_direct_protection_returns_bytes_without_s3_or_dynamodb(monkeypatch):
    monkeypatch.setenv("STRICT_TRANSIENT_MODE", "true")
    monkeypatch.setenv("ALLOW_LEGACY_DASHBOARD_TOKENS", "true")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "synthetic-admin-token-long-enough")
    monkeypatch.setenv("DASHBOARD_TOKEN", "synthetic-reviewer-token-long-enough")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    calls = []

    def fake_client(service, **_kwargs):
        calls.append(service)
        if service != "textract":
            raise AssertionError("Direct protection must not call a persistence service")
        return object()

    monkeypatch.setattr(api_main.boto3, "client", fake_client)
    client = TestClient(api_main.app)
    page = client.get("/")
    assert "Protect and download" in page.text
    assert "Data inventory" not in page.text
    assert client.get("/files/risk?resource_id=test").status_code == 410

    response = client.post(
        "/api/v1/protect",
        content=b"NRIC: 900101-14-5555\nEmail: learner@example.com",
        headers={
            "X-Dashboard-Token": "synthetic-admin-token-long-enough",
            "X-Filename": "sample.txt",
            "Content-Type": "text/plain",
        },
    )
    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="protected-sample.txt"'
    assert response.headers["x-document-type"] == "OTHER"
    assert response.headers["x-suggested-classification"] == "RESTRICTED"
    assert response.headers["x-detected-categories"] == "email,my_ic"
    assert response.headers["x-redacted-categories"] == "email,my_ic"
    assert response.headers["x-ocr-used"] == "false"
    assert response.headers["x-output-verified"] == "true"
    assert response.headers["x-processing-ms"].isdigit()
    assert len(response.headers["x-correlation-id"]) == 32
    assert "900101-14-5555" not in str(response.headers)
    assert b"900101-14-5555" not in response.content
    assert b"learner@example.com" not in response.content
    assert calls == ["textract"]


def test_uncertain_input_fails_without_returning_original_bytes(monkeypatch):
    monkeypatch.setenv("STRICT_TRANSIENT_MODE", "true")
    monkeypatch.setenv("ALLOW_LEGACY_DASHBOARD_TOKENS", "true")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "synthetic-admin-token-long-enough")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    monkeypatch.setattr(api_main.boto3, "client", lambda *_args, **_kwargs: object())
    response = TestClient(api_main.app).post(
        "/api/v1/protect",
        content=b"No reliably detected field here",
        headers={"X-Dashboard-Token": "synthetic-admin-token-long-enough", "X-Filename": "sample.txt"},
    )
    assert response.status_code == 422
    assert len(response.headers["x-correlation-id"]) == 32
    assert b"No reliably detected field here" not in response.content


def test_keep_only_policy_does_not_issue_an_unchanged_file():
    with pytest.raises(ValueError, match="No supported field was protected"):
        protect_in_memory(
            b"Name: Alice Example", "name.txt", object(),
            redaction_policy={"name": "KEEP"}, policy_confirmed=True,
        )


def test_mixed_keep_and_redact_policy_returns_content_free_receipt():
    protected, content_type, receipt = protect_in_memory(
        b"NRIC: 900101-14-5555\nEmail: learner@example.com",
        "synthetic.txt", object(),
        redaction_policy={"email": "KEEP"}, policy_confirmed=True,
    )
    assert content_type.startswith("text/plain")
    assert b"900101-14-5555" not in protected
    assert b"learner@example.com" in protected
    assert receipt["kept_categories"] == ["email"]
    assert receipt["redacted_categories"] == ["my_ic"]
    assert receipt["output_verified"] is True
    assert "learner@example.com" not in str(receipt)


def test_invalid_direct_inputs_never_issue_a_file():
    for source, filename in [
        (b"x" * (3 * 1024 * 1024 + 1), "synthetic.txt"),
        (b"not an image", "synthetic.png"),
        (b"{invalid", "synthetic.json"),
    ]:
        with pytest.raises(ValueError):
            protect_in_memory(source, filename, object())


def test_output_size_limit_blocks_result(monkeypatch):
    import src.api.transient_process as direct

    monkeypatch.setattr(direct, "MAX_DIRECT_OUTPUT_BYTES", 8)
    with pytest.raises(ValueError, match="output exceeds"):
        direct.protect_in_memory(b"NRIC: 900101-14-5555", "sample.txt", object())


def test_textract_network_failure_returns_no_file(monkeypatch):
    monkeypatch.setenv("STRICT_TRANSIENT_MODE", "true")
    monkeypatch.setenv("PUBLIC_FREE_API_ENABLED", "false")
    monkeypatch.setenv("ALLOW_LEGACY_DASHBOARD_TOKENS", "true")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "synthetic-admin-token-long-enough")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)

    class FailingTextract:
        def detect_document_text(self, **_kwargs):
            raise EndpointConnectionError(endpoint_url="https://textract.us-east-1.amazonaws.com")

    monkeypatch.setattr(api_main.boto3, "client", lambda *_args, **_kwargs: FailingTextract())
    source = io.BytesIO()
    Image.new("RGB", (120, 80), "white").save(source, format="PNG")
    response = TestClient(api_main.app).post(
        "/api/v1/protect",
        content=source.getvalue(),
        headers={
            "X-Dashboard-Token": "synthetic-admin-token-long-enough",
            "X-Filename": "synthetic.png",
            "Content-Type": "image/png",
        },
    )
    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/json")
    assert len(response.headers["x-correlation-id"]) == 32
    assert source.getvalue() not in response.content


def test_public_direct_protection_needs_no_login_and_uses_aggregate_quota(monkeypatch):
    monkeypatch.setenv("STRICT_TRANSIENT_MODE", "true")
    monkeypatch.setenv("PUBLIC_FREE_API_ENABLED", "true")
    monkeypatch.setenv("PUBLIC_USAGE_TABLE", "synthetic-public-usage")
    monkeypatch.setenv("PUBLIC_FREE_DAILY_LIMIT", "200")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    quota_calls = []

    class FakeTable:
        def update_item(self, **kwargs):
            quota_calls.append(kwargs)

    class FakeResource:
        def Table(self, table_name):
            assert table_name == "synthetic-public-usage"
            return FakeTable()

    monkeypatch.setattr(api_main.boto3, "resource", lambda service, **_kw: FakeResource())
    monkeypatch.setattr(api_main.boto3, "client", lambda service, **_kw: object())
    client = TestClient(api_main.app)
    page = client.get("/")
    assert "no account needed" in page.text
    assert 'id="customer-login"' not in page.text
    assert client.get("/api/v1/docs").status_code == 200
    assert client.get("/api/docs").status_code == 410
    assert client.post("/auth/login", json={"username": "admin", "password": "invalid"}).status_code == 410
    response = client.post(
        "/api/v1/protect",
        content=b"NRIC: 900101-14-5555\nEmail: learner@example.com",
        headers={"X-Filename": "sample.txt", "Content-Type": "text/plain"},
    )
    assert response.status_code == 200
    assert b"900101-14-5555" not in response.content
    assert len(quota_calls) == 1
    assert set(quota_calls[0]["Key"]) == {"usage_day"}
    assert "request_count" in quota_calls[0]["ExpressionAttributeNames"].values()
    assert client.get("/files/risk?resource_id=test").status_code == 410


def test_public_quota_fail_closed_before_ocr(monkeypatch):
    monkeypatch.setenv("STRICT_TRANSIENT_MODE", "true")
    monkeypatch.setenv("PUBLIC_FREE_API_ENABLED", "true")
    monkeypatch.setenv("PUBLIC_USAGE_TABLE", "synthetic-public-usage")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)

    class FakeTable:
        def update_item(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "quota"}},
                "UpdateItem",
            )

    class FakeResource:
        def Table(self, _name):
            return FakeTable()

    monkeypatch.setattr(api_main.boto3, "resource", lambda _service, **_kw: FakeResource())
    monkeypatch.setattr(api_main.boto3, "client", lambda *_args, **_kw: pytest.fail("OCR called"))
    response = TestClient(api_main.app).post(
        "/api/v1/protect",
        content=b"NRIC: 900101-14-5555",
        headers={"X-Filename": "sample.txt"},
    )
    assert response.status_code == 429
    assert response.headers["retry-after"]
    assert b"900101-14-5555" not in response.content


@pytest.mark.parametrize("residual_visible", [False, True])
def test_direct_image_rereads_protected_pixels_and_rejects_residual_text(residual_visible):
    source = io.BytesIO()
    Image.new("RGB", (400, 200), "white").save(source, format="PNG")

    class FakeTextract:
        calls = 0

        def detect_document_text(self, **_kwargs):
            self.calls += 1
            if self.calls == 2 and not residual_visible:
                return {"Blocks": []}
            return {"Blocks": [{
                "BlockType": "LINE", "Text": "NRIC: 900101145555", "Confidence": 99,
                "Geometry": {"BoundingBox": {
                    "Left": 0.1, "Top": 0.2, "Width": 0.5, "Height": 0.1,
                }},
            }]}

    textract = FakeTextract()
    if residual_visible:
        with pytest.raises(ValueError, match="still exposes"):
            protect_in_memory(source.getvalue(), "identity.png", textract)
    else:
        protected, content_type, evidence = protect_in_memory(
            source.getvalue(), "identity.png", textract
        )
        assert protected.startswith(b"\x89PNG")
        assert content_type == "image/png"
        assert evidence["ocr_used"] is True
    assert textract.calls == 2


def test_direct_image_covers_low_confidence_lines_and_retries_ocr():
    source = io.BytesIO()
    Image.new("RGB", (400, 200), "white").save(source, format="JPEG")

    class FakeTextract:
        calls = 0

        def detect_document_text(self, **_kwargs):
            self.calls += 1
            if self.calls == 3:
                return {"Blocks": []}
            return {"Blocks": [
                {
                    "BlockType": "LINE", "Text": "NRIC: 900101145555", "Confidence": 99,
                    "Geometry": {"BoundingBox": {
                        "Left": 0.1, "Top": 0.2, "Width": 0.5, "Height": 0.1,
                    }},
                },
                {
                    "BlockType": "LINE", "Text": "Uncertain printed field", "Confidence": 55,
                    "Geometry": {"BoundingBox": {
                        "Left": 0.1, "Top": 0.6, "Width": 0.5, "Height": 0.1,
                    }},
                },
            ]}

    textract = FakeTextract()
    protected, content_type, evidence = protect_in_memory(
        source.getvalue(), "identity.jpg", textract
    )
    assert textract.calls == 3
    assert content_type == "image/jpeg"
    # Generic uncertain text is not automatically private; the identified
    # value still has to be covered without turning the card into a black panel.
    assert evidence["redaction_hits"] >= 1
    with Image.open(io.BytesIO(protected)) as image:
        assert max(image.getpixel((100, 50))) < 20
        assert min(image.getpixel((100, 130))) > 240


def test_low_confidence_only_still_issues_no_file():
    source = io.BytesIO()
    Image.new("RGB", (400, 200), "white").save(source, format="JPEG")

    class FakeTextract:
        def detect_document_text(self, **_kwargs):
            return {"Blocks": [{
                "BlockType": "LINE", "Text": "Unreadable text", "Confidence": 52,
                "Geometry": {"BoundingBox": {
                    "Left": 0.1, "Top": 0.2, "Width": 0.5, "Height": 0.1,
                }},
            }]}

    with pytest.raises(ValueError, match="No sensitive field was reliably detected"):
        protect_in_memory(source.getvalue(), "unreadable.jpg", FakeTextract())


def test_passport_expiry_date_is_covered_even_without_a_detector_hit():
    from src.utils.format_redactor import _ocr_blocks_to_redact

    lines = [
        {"Text": "PASSPORT MALAYSIA"},
        {"Text": "Date of Expiry"},
        {"Text": "31 AUG 2024"},
    ]
    selected = _ocr_blocks_to_redact({"government_id": []}, lines)
    assert lines[1] in selected
    assert lines[2] in selected
