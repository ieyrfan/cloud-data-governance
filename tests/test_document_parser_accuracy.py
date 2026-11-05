import io

import pytest
from PIL import Image
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from src.utils.document_parser import (
    extract_text_from_file,
    extract_text_from_textract,
    extract_text_from_textract_async,
)


def test_malformed_structured_input_falls_back_to_text_for_security_scanning():
    malformed_json = b'{"passport_number":"ZX928173" trailing'
    malformed_csv = b'passport_number,name\n"ZX928173,Synthetic Person'

    assert "ZX928173" in extract_text_from_file(malformed_json, "record.json")
    assert "ZX928173" in extract_text_from_file(malformed_csv, "record.csv")


def test_valid_utf8_json_is_normalised_without_data_loss():
    text = extract_text_from_file('{"name":"José"}'.encode(), "record.json")
    assert '"José"' in text


def test_csv_headers_are_preserved_as_field_context_for_ambiguous_identifiers():
    text = extract_text_from_file(
        b"employee_number,full_name\nEMP-10291,Synthetic Person\n",
        "employees.csv",
    )

    assert "employee_number: EMP-10291" in text
    assert "full_name: Synthetic Person" in text


@pytest.mark.parametrize("extension", ["html", "htm", "xml", "yaml", "yml", "ini", "cfg"])
def test_markup_and_configuration_text_formats_are_accepted(extension):
    text = extract_text_from_file(b"employee_id: EMP-10291", f"record.{extension}")

    assert text == "employee_id: EMP-10291"


@pytest.mark.parametrize(
    ("content", "filename", "message"),
    [
        (b"", "empty.txt", "is empty"),
        (b"\xff\xfe\x00", "binary.txt", "not valid UTF-8"),
        (b'{"broken":', "broken.json", "Unable to parse"),
        (b"content", "archive.bin", "Unsupported document type"),
    ],
)
def test_unreliable_input_is_rejected_instead_of_classified_public(content, filename, message):
    with pytest.raises(ValueError, match=message):
        extract_text_from_file(content, filename)


def test_textract_ocr_preserves_text_and_line_geometry():
    class FakeTextract:
        def detect_document_text(self, **kwargs):
            assert kwargs["Document"]["S3Object"] == {"Bucket": "raw", "Name": "scan.pdf"}
            return {
                "Blocks": [
                    {"BlockType": "PAGE", "Page": 1},
                    {
                        "BlockType": "LINE",
                        "Page": 1,
                        "Text": "NRIC : 900101145555",
                        "Geometry": {
                            "BoundingBox": {"Left": 0.1, "Top": 0.1, "Width": 0.3, "Height": 0.04}
                        },
                    },
                ]
            }

    text, lines = extract_text_from_textract(FakeTextract(), "raw", "scan.pdf")

    assert text == "NRIC : 900101145555"
    assert len(lines) == 1


def test_low_confidence_ocr_fails_closed_for_human_review():
    class FakeTextract:
        def detect_document_text(self, **_kwargs):
            return {
                "Blocks": [
                    {
                        "BlockType": "LINE",
                        "Page": 1,
                        "Text": "NRIC : O4O5O2O2O2O1",
                        "Confidence": 62.0,
                    }
                ]
            }

    with pytest.raises(ValueError, match="requires human review"):
        extract_text_from_textract(FakeTextract(), "raw", "blurred-ic.jpg")


def test_mixed_multi_page_pdf_fails_closed_instead_of_skipping_scanned_page():
    output = io.BytesIO()
    document = canvas.Canvas(output)
    document.drawString(72, 720, "Text page")
    document.showPage()
    image = io.BytesIO()
    Image.new("RGB", (200, 100), "white").save(image, format="PNG")
    document.drawImage(ImageReader(io.BytesIO(image.getvalue())), 72, 600, 200, 100)
    document.save()

    with pytest.raises(ValueError, match="asynchronous multi-page OCR"):
        extract_text_from_file(output.getvalue(), "mixed.pdf")


def test_async_textract_collects_every_page_and_pagination_token():
    class FakeTextract:
        def __init__(self):
            self.calls = []

        def start_document_text_detection(self, **kwargs):
            assert kwargs["DocumentLocation"]["S3Object"] == {
                "Bucket": "raw",
                "Name": "multi.pdf",
            }
            return {"JobId": "job-1"}

        def get_document_text_detection(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                return {
                    "JobStatus": "SUCCEEDED",
                    "NextToken": "page-2",
                    "Blocks": [
                        {
                            "BlockType": "LINE",
                            "Page": 1,
                            "Text": "NRIC: 900101145555",
                            "Confidence": 99,
                        }
                    ],
                }
            assert kwargs["NextToken"] == "page-2"
            return {
                "JobStatus": "SUCCEEDED",
                "Blocks": [
                    {
                        "BlockType": "LINE",
                        "Page": 2,
                        "Text": "ADDRESS: 8 Jalan Demo",
                        "Confidence": 98,
                    }
                ],
            }

    fake = FakeTextract()
    text, lines = extract_text_from_textract_async(fake, "raw", "multi.pdf", poll_seconds=0)

    assert "NRIC" in text
    assert "ADDRESS" in text
    assert [line["Page"] for line in lines] == [1, 2]


@pytest.mark.parametrize("status", ["FAILED", "PARTIAL_SUCCESS"])
def test_async_textract_fails_closed_when_job_is_not_complete(status):
    class FakeTextract:
        def start_document_text_detection(self, **_kwargs):
            return {"JobId": "job-1"}

        def get_document_text_detection(self, **_kwargs):
            return {"JobStatus": status, "StatusMessage": "synthetic failure"}

    with pytest.raises(ValueError, match="human review"):
        extract_text_from_textract_async(FakeTextract(), "raw", "multi.pdf", poll_seconds=0)
