"""Direct document protection with no application-side document persistence."""

from __future__ import annotations

import io
import re
from pathlib import Path

import pymupdf
from PIL import Image, ImageEnhance, ImageFilter, ImageOps

from src.classifiers.document_type_classifier import classify_document_type
from src.classifiers.pattern_matcher import discover_sensitive_data, find_sensitive_patterns
from src.governance.redaction_policy import apply_policy, normalize_policy
from src.utils.document_parser import extract_text_from_file, extract_text_from_textract_bytes
from src.utils.format_redactor import CONTENT_TYPES, redact_document

MAX_DIRECT_INPUT_BYTES = 3 * 1024 * 1024
MAX_DIRECT_OUTPUT_BYTES = 3 * 1024 * 1024
MAX_SCANNED_PAGES = 3
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
MAX_IMAGE_PIXELS = 25_000_000
RESTRICTED_CATEGORIES = {
    "my_ic", "credit_card", "government_id", "passport_number", "financial_account",
    "aws_access_key", "secret", "private_key", "patient_id",
}
PASSPORT_DATE_PATTERN = re.compile(
    r"(?i)\b\d{1,2}[\s./-]+(?:\d{1,2}|jan|feb|mar|apr|may|mei|jun|jul|aug|sep|oct|okt|nov|dec|dis)[\s./-]+\d{2,4}\b"
)
MYKAD_HEADER_PATTERN = re.compile(r"(?i)\b(?:mykad|kad\s+pengenalan)\b")
MYKAD_ADDRESS_START_PATTERN = re.compile(
    r"(?i)^\s*(?:alamat|address|no\.?\s*\d|jalan|jln\.?|lorong|persiaran|"
    r"taman|kampung|kg\.?|pangsapuri|apartment|blok|block)\b"
)
MYKAD_NON_NAME_PATTERN = re.compile(
    r"(?i)\b(?:mykad|kad|pengenalan|malaysia|identity|card|nama|name|"
    r"warganegara|citizen|lelaki|perempuan|male|female|wanita|johor|kedah|"
    r"kelantan|melaka|pahang|perak|perlis|sabah|sarawak|selangor|terengganu|"
    r"putrajaya|labuan)\b"
)
MYKAD_NAME_TOKEN_PATTERN = re.compile(r"^[^\W\d_]+(?:['\u2019.-][^\W\d_]+)*$", re.UNICODE)


def _ocr_image(file_bytes: bytes, textract_client) -> tuple[str, list[dict]]:
    """Retry small/uncertain images and cover every uncertain OCR line."""
    try:
        with Image.open(io.BytesIO(file_bytes)) as source:
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed the direct-processing limit")
            image = ImageOps.exif_transpose(source).convert("RGB")
    except (OSError, Image.DecompressionBombError) as error:
        raise ValueError("Image could not be safely decoded") from error

    def read(candidate: Image.Image) -> tuple[str, list[dict]]:
        encoded = io.BytesIO()
        candidate.save(encoded, format="JPEG", quality=90)
        if len(encoded.getvalue()) > MAX_DIRECT_INPUT_BYTES:
            raise ValueError("Prepared image exceeds the direct-processing limit")
        return extract_text_from_textract_bytes(
            textract_client, encoded.getvalue(), "uploaded image",
            cover_uncertain_lines=True,
        )

    baseline = read(image)
    if not any(line.get("CoverUncertain") for line in baseline[1]):
        return baseline

    scale = min(3, 2400 / max(image.size))
    if scale <= 1:
        return baseline
    enlarged = image.resize(
        (round(image.width * scale), round(image.height * scale)), Image.Resampling.LANCZOS
    )
    enhanced = ImageEnhance.Contrast(enlarged).enhance(1.25).filter(
        ImageFilter.UnsharpMask(radius=1.5, percent=140, threshold=2)
    )
    try:
        retry = read(enhanced)
    except ValueError:
        return baseline

    def quality(result: tuple[str, list[dict]]) -> tuple[int, int, int]:
        matches = find_sensitive_patterns(result[0])
        detected = sum(len(values) for category, values in matches.items() if category != "name")
        uncertain = sum(bool(line.get("CoverUncertain")) for line in result[1])
        return detected, -uncertain, len(result[1])

    chosen, other = (retry, baseline) if quality(retry) > quality(baseline) else (baseline, retry)
    # A second pass can hallucinate a watermark as a huge OCR line. Use its
    # sensitive findings as a cross-check, but never draw its unrelated boxes
    # over the original image. A value present only there needs review.
    chosen_values = {
        re.sub(r"[^\w]", "", value.casefold())
        for category, values in find_sensitive_patterns(chosen[0]).items()
        if category != "name"
        for value in values
    }
    for category, values in find_sensitive_patterns(other[0]).items():
        if category == "name":
            continue
        for value in values:
            compact = re.sub(r"[^\w]", "", value.casefold())
            if compact and compact not in chosen_values:
                raise ValueError("OCR passes disagree on a sensitive value; no file was issued")
    return chosen


def _verify_protected_pixels(
    protected: bytes, extension: str, selected: dict[str, list[str]], textract_client
) -> None:
    """Re-read raster output and reject a detected value that remains visible."""
    values = {
        re.sub(r"[^\w]", "", str(value).casefold())
        for matches in selected.values()
        for value in matches
    }
    values.discard("")
    if not values:
        return
    if extension in IMAGE_EXTENSIONS:
        pages = [protected]
    else:
        pages = []
        with pymupdf.open(stream=protected, filetype="pdf") as document:
            for page in document:
                pages.append(page.get_pixmap(dpi=150, alpha=False).tobytes("jpeg", jpg_quality=85))
    for image in pages:
        response = textract_client.detect_document_text(Document={"Bytes": image})
        visible = re.sub(
            r"[^\w]", "",
            "".join(
                str(block.get("Text", ""))
                for block in response.get("Blocks", [])
                if block.get("BlockType") == "LINE"
            ).casefold(),
        )
        if any(value in visible for value in values):
            raise ValueError("Protected output still exposes a detected sensitive value")


def _ocr_pdf(file_bytes: bytes, textract_client) -> tuple[str, list[dict]]:
    lines = []
    texts = []
    with pymupdf.open(stream=file_bytes, filetype="pdf") as document:
        if document.needs_pass:
            raise ValueError("Encrypted PDFs cannot be protected")
        if document.page_count > MAX_SCANNED_PAGES:
            raise ValueError("Scanned PDFs are limited to three pages in direct processing")
        for page_number, page in enumerate(document, start=1):
            if page.rotation:
                raise ValueError("Rotated PDF pages need manual review before protection")
            image = page.get_pixmap(dpi=150, alpha=False).tobytes("jpeg", jpg_quality=85)
            text, page_lines = extract_text_from_textract_bytes(
                textract_client, image, "scanned PDF page"
            )
            for block in page_lines:
                block["Page"] = page_number
            lines.extend(page_lines)
            texts.append(text)
    return "\n".join(texts), lines


def _mykad_name_from_ocr(text: str, ocr_lines: list[dict], matches: dict) -> str | None:
    """Recover the unlabelled name row on a recognised MyKad from OCR layout."""
    if not MYKAD_HEADER_PATTERN.search(text):
        return None
    ic_values = [re.sub(r"\D", "", value) for value in matches.get("my_ic", [])]
    if not ic_values:
        raise ValueError(
            "This MyKad could not be confidently read. No protected file was issued; "
            "use a clearer image or add a manual cover area."
        )

    ic_line_index = None
    for index, line in enumerate(ocr_lines):
        line_digits = re.sub(r"\D", "", str(line.get("Text", "")))
        if any(value and value in line_digits for value in ic_values):
            ic_line_index = index
            break
    if ic_line_index is None:
        raise ValueError(
            "The MyKad number and OCR layout did not align. No protected file was issued; "
            "use a clearer image or add a manual cover area."
        )

    for line in ocr_lines[ic_line_index + 1:]:
        value = re.sub(r"\s+", " ", str(line.get("Text", ""))).strip()
        if not value:
            continue
        if MYKAD_ADDRESS_START_PATTERN.match(value):
            break
        box = line.get("Geometry", {}).get("BoundingBox", {})
        try:
            left = float(box["Left"])
            top = float(box["Top"])
            height = float(box["Height"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (0 <= left < 0.72 and 0 <= top <= 1 and 0 < height <= 0.2):
            continue
        words = value.split()
        if not 2 <= len(words) <= 5:
            continue
        if not all(MYKAD_NAME_TOKEN_PATTERN.fullmatch(word) for word in words):
            continue
        if MYKAD_NON_NAME_PATTERN.search(value):
            continue
        return value

    raise ValueError(
        "The name on this MyKad could not be confidently located. No protected file was issued; "
        "add a manual cover area or use a clearer image."
    )


def protect_in_memory(
    file_bytes: bytes,
    filename: str,
    textract_client,
    *,
    redaction_policy: dict[str, str] | None = None,
    policy_confirmed: bool = False,
) -> tuple[bytes, str, dict]:
    """Return protected bytes without uploading or recording customer content."""
    extension = Path(filename).suffix.lower()
    if extension not in CONTENT_TYPES:
        raise ValueError("Unsupported document format")
    if not file_bytes or len(file_bytes) > MAX_DIRECT_INPUT_BYTES:
        raise ValueError("Choose a non-empty file no larger than 3 MB")
    policy = normalize_policy(redaction_policy, confirmed=policy_confirmed)
    ocr_lines = None
    if extension in IMAGE_EXTENSIONS:
        text, ocr_lines = _ocr_image(file_bytes, textract_client)
    else:
        try:
            text = extract_text_from_file(file_bytes, filename)
        except ValueError as error:
            if extension != ".pdf" or not (
                "asynchronous multi-page OCR" in str(error)
                or "contains no extractable text" in str(error)
            ):
                raise
            text, ocr_lines = _ocr_pdf(file_bytes, textract_client)
    # Use the context-aware redaction map for the release decision.  The
    # compatibility matcher remains useful for discovery and OCR quality
    # scoring, but its broad legacy candidates must not become covers by
    # themselves in the direct report workflow.
    matches = discover_sensitive_data(text).redaction_map()
    # MyKad prints its cardholder name as an unlabelled OCR line. Keep the
    # existing regex/OCR/PII engines unchanged; this card-layout fallback only
    # feeds a confidently located name through the normal policy and redactor.
    if (
        ocr_lines
        and policy.get("name") == "REDACT"
        and not matches.get("name")
        and MYKAD_HEADER_PATTERN.search(text)
        and matches.get("my_ic")
    ):
        try:
            mykad_name = _mykad_name_from_ocr(text, ocr_lines, matches)
        except ValueError:
            # Keep the safe portrait/card fallback below when the photograph
            # has enough header evidence but its text layout is unreadable.
            mykad_name = None
        if mykad_name:
            matches["name"] = [mykad_name]
    # A partially covered or blurred MyKad can lose every printed value in
    # OCR while the card header remains recognisable.  Do not issue the image
    # unchanged: create an internal portrait-cover finding so the image
    # redactor produces a safe, visibly protected result instead of a false
    # "no sensitive data" rejection.
    if ocr_lines and MYKAD_HEADER_PATTERN.search(text) and not any(matches.values()):
        matches["mykad_portrait"] = ["MYKAD portrait"]
    if not any(matches.values()):
        raise ValueError("No sensitive field was reliably detected; no unprotected file was issued")
    selected, kept = apply_policy(matches, policy)
    if ocr_lines and re.search(r"(?i)\b(?:passport|pasport)\b|P<", text):
        # Passport issue/expiry dates are sensitive even when a generic DOB
        # detector does not classify them. Include them in output verification.
        selected["passport_date"] = list(dict.fromkeys(PASSPORT_DATE_PATTERN.findall(text)))
    protected, content_type, evidence = redact_document(
        file_bytes, filename, text, selected, ocr_lines=ocr_lines,
        kept_categories=set(kept),
    )
    if evidence["redaction_hits"] < 1:
        raise ValueError("No supported field was protected; no file was issued")
    if len(protected) > MAX_DIRECT_OUTPUT_BYTES:
        raise ValueError("Protected output exceeds the 3 MB direct-download limit")
    if ocr_lines:
        _verify_protected_pixels(protected, extension, selected, textract_client)
    detected_categories = sorted(category for category, values in matches.items() if values)
    document_type = classify_document_type(text, filename)
    suggested_classification = (
        "RESTRICTED"
        if RESTRICTED_CATEGORIES.intersection(detected_categories)
        else "CONFIDENTIAL" if detected_categories else "REVIEW_REQUIRED"
    )
    return protected, content_type, {
        "detected_categories": detected_categories,
        "redacted_categories": sorted(set(detected_categories) - set(kept)),
        "kept_categories": kept,
        "redaction_hits": evidence["redaction_hits"],
        "ocr_used": bool(ocr_lines),
        "output_verified": True,
        "document_type": document_type["key"],
        "suggested_classification": suggested_classification,
    }
