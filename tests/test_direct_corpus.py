"""Small synthetic direct-mode corpus; no customer documents or AWS calls."""

import io
import json

import pymupdf
import pytest

from src.api.transient_process import protect_in_memory


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("sample.txt", b"NRIC: 900101-14-5555\nEmail: demo@example.com"),
        ("sample.csv", b"NRIC,Email\n900101-14-5555,demo@example.com\n"),
        ("sample.md", b"# Sample\nNRIC: 900101-14-5555\nEmail: demo@example.com"),
        ("sample.json", b'{"nric":"900101-14-5555","email":"demo@example.com"}'),
    ],
    ids=["txt", "csv", "markdown", "json"],
)
def test_synthetic_text_formats_protect_both_values(filename, source):
    protected, _, receipt = protect_in_memory(source, filename, object())
    assert b"900101-14-5555" not in protected
    assert b"demo@example.com" not in protected
    assert receipt["redacted_categories"] == ["email", "my_ic"]
    assert receipt["ocr_used"] is False
    assert receipt["output_verified"] is True
    if filename.endswith(".json"):
        assert isinstance(json.loads(protected), dict)


def test_synthetic_two_page_text_pdf_protects_every_page():
    document = pymupdf.open()
    for _ in range(2):
        page = document.new_page()
        page.insert_text((72, 72), "NRIC: 900101-14-5555")
    source = document.tobytes()
    document.close()
    protected, content_type, receipt = protect_in_memory(source, "sample.pdf", object())
    assert content_type == "application/pdf"
    with pymupdf.open(stream=io.BytesIO(protected), filetype="pdf") as result:
        assert result.page_count == 2
        assert all("900101-14-5555" not in page.get_text() for page in result)
    assert receipt["output_verified"] is True
