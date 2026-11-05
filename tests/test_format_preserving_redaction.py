import io
import json

import pymupdf
from PIL import Image
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from src.classifiers.pattern_matcher import find_sensitive_patterns
from src.utils.format_redactor import redact_document


def _sample_pdf() -> bytes:
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=(612, 792))
    document.setTitle("Payroll evidence")
    document.drawString(72, 730, "Payroll evidence")
    document.drawString(72, 700, "NRIC: 900101-14-5555")
    document.drawString(72, 680, "Email: payroll@example.com")
    document.rect(65, 650, 300, 100)
    document.save()
    return output.getvalue()


def test_pdf_remains_pdf_and_sensitive_text_is_removed():
    source = _sample_pdf()
    original = pymupdf.open(stream=source, filetype="pdf")
    try:
        source_text = "\n".join(page.get_text() for page in original)
        original_size = (original[0].rect.width, original[0].rect.height)
    finally:
        original.close()

    matches = find_sensitive_patterns(source_text)
    protected, content_type, evidence = redact_document(
        source, "payroll.pdf", source_text, matches
    )

    result = pymupdf.open(stream=protected, filetype="pdf")
    try:
        result_text = "\n".join(page.get_text() for page in result)
        result_size = (result[0].rect.width, result[0].rect.height)
        assert result.page_count == 1
        assert not result.metadata.get("title")
        assert result.xref_xml_metadata() == 0
    finally:
        result.close()

    assert protected.startswith(b"%PDF")
    assert content_type == "application/pdf"
    assert evidence["format_preserved"] is True
    assert evidence["protected_extension"] == ".pdf"
    assert evidence["redaction_hits"] == 2
    assert result_size == original_size
    assert "Payroll evidence" in result_text
    assert "900101-14-5555" not in result_text
    assert "payroll@example.com" not in result_text


def test_pdf_with_embedded_attachment_is_removed_from_protected_output():
    document = pymupdf.open(stream=_sample_pdf(), filetype="pdf")
    document.embfile_add("private.txt", b"sensitive attachment")
    source = document.tobytes()
    text = document[0].get_text()
    document.close()
    protected, _, _ = redact_document(source, "with-attachment.pdf", text, find_sensitive_patterns(text))
    result = pymupdf.open(stream=protected, filetype="pdf")
    try:
        assert result.embfile_count() == 0
    finally:
        result.close()


def test_protected_jpeg_does_not_carry_source_exif():
    image = Image.new("RGB", (360, 120), "white")
    exif = Image.Exif()
    exif[270] = "synthetic private camera note"
    source = io.BytesIO()
    image.save(source, format="JPEG", exif=exif)
    line = {"Text": "Email: demo@example.com", "Geometry": {"BoundingBox": {
        "Left": .1, "Top": .3, "Width": .5, "Height": .2,
    }}}
    protected, _, _ = redact_document(
        source.getvalue(), "synthetic.jpg", line["Text"],
        {"email": ["demo@example.com"]}, ocr_lines=[line],
    )
    with Image.open(io.BytesIO(protected)) as result:
        assert not result.getexif()
    assert b"synthetic private camera note" not in protected


def test_birth_dates_are_redacted_from_every_pdf_page():
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=(612, 792))
    document.drawString(72, 700, "Tarikh Lahir")
    document.drawString(260, 700, "14/02/1998")
    document.showPage()
    document.drawString(72, 700, "Date of Birth")
    document.drawString(260, 700, "2000-07-23")
    document.showPage()
    document.drawString(72, 700, "Non-sensitive page remains readable")
    document.save()
    source = output.getvalue()

    original = pymupdf.open(stream=source, filetype="pdf")
    try:
        source_text = "\n".join(page.get_text() for page in original)
    finally:
        original.close()
    matches = find_sensitive_patterns(source_text)

    protected, content_type, evidence = redact_document(
        source, "multi-page-profile.pdf", source_text, matches
    )

    result = pymupdf.open(stream=protected, filetype="pdf")
    try:
        result_text = "\n".join(page.get_text() for page in result)
        assert result.page_count == 3
    finally:
        result.close()
    assert content_type == "application/pdf"
    assert evidence["redaction_hits"] == 2
    assert "14/02/1998" not in result_text
    assert "2000-07-23" not in result_text
    assert "Non-sensitive page remains readable" in result_text


def test_malaysian_address_continuation_line_is_redacted():
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=(612, 792))
    document.drawString(72, 700, "Alamat Rumah")
    document.drawString(72, 680, "No. 21, Jalan Anggerik 1/1, Taman Rekaan 1, 40000 Shah Alam,")
    document.drawString(72, 660, "Selangor")
    document.save()
    source = output.getvalue()
    original = pymupdf.open(stream=source, filetype="pdf")
    try:
        source_text = original[0].get_text()
    finally:
        original.close()

    matches = find_sensitive_patterns(source_text)
    assert "Selangor" in matches["address"]
    protected, _, _ = redact_document(source, "address.pdf", source_text, matches)
    result = pymupdf.open(stream=protected, filetype="pdf")
    try:
        result_text = result[0].get_text()
    finally:
        result.close()
    assert "No. 21, Jalan Anggerik" not in result_text
    assert "Selangor" not in result_text


def test_scanned_pdf_uses_ocr_geometry_for_visual_redaction():
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=(612, 792))
    scan = io.BytesIO()
    Image.new("RGB", (612, 792), "white").save(scan, format="PNG")
    document.drawImage(ImageReader(io.BytesIO(scan.getvalue())), 0, 0, 612, 792)
    document.save()
    source = output.getvalue()
    patterns = find_sensitive_patterns("NRIC : 900101145555")
    ocr_lines = [
        {
            "BlockType": "LINE",
            "Page": 1,
            "Text": "NRIC : 900101145555",
            "Geometry": {
                "BoundingBox": {"Left": 0.1, "Top": 0.08, "Width": 0.35, "Height": 0.04}
            },
        }
    ]

    protected, content_type, evidence = redact_document(
        source, "scan.pdf", "NRIC : 900101145555", patterns, ocr_lines=ocr_lines
    )

    assert protected.startswith(b"%PDF")
    assert content_type == "application/pdf"
    assert evidence["ocr_used"] is True
    assert evidence["redaction_hits"] == 1

    original = pymupdf.open(stream=source, filetype="pdf")
    redacted = pymupdf.open(stream=protected, filetype="pdf")
    try:
        original_images = {
            original.extract_image(xref)["image"]
            for page in original
            for xref, *_ in page.get_images(full=True)
        }
        redacted_images = {
            redacted.extract_image(xref)["image"]
            for page in redacted
            for xref, *_ in page.get_images(full=True)
        }
        assert original_images.isdisjoint(redacted_images)
    finally:
        original.close()
        redacted.close()


def test_ic_photo_keeps_image_format_and_blacks_out_detected_line():
    source_buffer = io.BytesIO()
    Image.new("RGB", (600, 360), "white").save(source_buffer, format="JPEG")
    source = source_buffer.getvalue()
    text = "NRIC : 900101145555"
    patterns = find_sensitive_patterns(text)
    ocr_lines = [
        {
            "BlockType": "LINE",
            "Page": 1,
            "Text": text,
            "Geometry": {
                "BoundingBox": {"Left": 0.2, "Top": 0.25, "Width": 0.5, "Height": 0.1}
            },
        }
    ]

    protected, content_type, evidence = redact_document(
        source, "ic-photo.jpg", text, patterns, ocr_lines=ocr_lines
    )

    assert protected.startswith(b"\xff\xd8\xff")
    assert content_type == "image/jpeg"
    assert evidence["format_preserved"] is True
    assert evidence["ocr_used"] is True
    assert evidence["redaction_hits"] == 1
    with Image.open(io.BytesIO(protected)) as image:
        red, green, blue = image.convert("RGB").getpixel((300, 105))
        assert max(red, green, blue) < 20


def test_identity_postcode_and_state_line_is_always_selected_for_redaction():
    from src.utils.format_redactor import _ocr_blocks_to_redact

    lines = [
        {"Text": "KAD PENGENALAN MALAYSIA", "Geometry": {"BoundingBox": {}}},
        {"Text": "NAME: Example Person", "Geometry": {"BoundingBox": {}}},
        {"Text": "80000 KENINGAU SABAH", "Geometry": {"BoundingBox": {}}},
        {"Text": "WARGANEGARA", "Geometry": {"BoundingBox": {}}},
    ]

    selected = _ocr_blocks_to_redact({}, lines)

    assert [block["Text"] for block in selected] == [
        "80000 KENINGAU SABAH", "WARGANEGARA"
    ]


def test_name_is_redacted_with_other_personal_fields():
    source = (
        b"NAME: Synthetic Student\n"
        b"ADDRESS: 8 Jalan Demo, 75400 Melaka\n"
        b"NRIC: 900101145555\n"
        b"MATRIC NO: DEMO1234"
    )
    text = source.decode()
    patterns = find_sensitive_patterns(text)

    protected, _, evidence = redact_document(source, "identity.txt", text, patterns)
    rendered = protected.decode()

    assert "Synthetic Student" not in rendered
    assert "900101145555" not in rendered
    assert "8 Jalan Demo" not in rendered
    assert "DEMO1234" not in rendered
    assert evidence["redaction_hits"] >= 3


def test_csv_and_json_keep_their_native_formats():
    csv_source = b"name,email\nIrfan,irfan@example.com\n"
    csv_text = csv_source.decode()
    csv_output, csv_type, csv_evidence = redact_document(
        csv_source, "people.csv", csv_text, find_sensitive_patterns(csv_text)
    )
    assert csv_type == "text/csv; charset=utf-8"
    assert csv_output.decode().splitlines()[0] == "name,email"
    assert "[REDACTED - EMAIL]" in csv_output.decode()
    assert csv_evidence["protected_extension"] == ".csv"

    json_source = b'{\n  "email": "irfan@example.com",\n  "active": true\n}'
    json_text = json_source.decode()
    json_output, json_type, json_evidence = redact_document(
        json_source, "record.json", json_text, find_sensitive_patterns(json_text)
    )
    parsed = json.loads(json_output)
    assert json_type == "application/json"
    assert parsed["email"] == "[REDACTED - EMAIL]"
    assert parsed["active"] is True
    assert json_evidence["protected_extension"] == ".json"


def test_json_escaped_values_are_redacted_after_parsing():
    source = b'{"email":"person\\u0040example.com"}'
    text = source.decode()
    protected, _, evidence = redact_document(
        source, "record.json", text, find_sensitive_patterns("email: person@example.com")
    )
    parsed = json.loads(protected)
    assert parsed["email"] == "[REDACTED - EMAIL]"
    assert evidence["redaction_hits"] == 1


def test_json_numeric_identifier_is_redacted_without_breaking_json():
    source = b'{"nric":900101145555}'
    text = source.decode()
    protected, _, evidence = redact_document(
        source, "record.json", text, find_sensitive_patterns("NRIC: 900101-14-5555")
    )
    parsed = json.loads(protected)
    assert parsed["nric"] == "[REDACTED - NRIC]"
    assert evidence["redaction_hits"] == 1
