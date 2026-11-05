import hashlib
import io
import json
import math
import re
from pathlib import Path

import pymupdf
from PIL import Image, ImageDraw, ImageOps

from src.classifiers.pattern_matcher import redact_sensitive_data

CONTENT_TYPES = {
    ".csv": "text/csv; charset=utf-8",
    ".json": "application/json",
    ".log": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
    ".html": "text/plain; charset=utf-8",
    ".htm": "text/plain; charset=utf-8",
    ".xml": "text/plain; charset=utf-8",
    ".yaml": "text/plain; charset=utf-8",
    ".yml": "text/plain; charset=utf-8",
    ".ini": "text/plain; charset=utf-8",
    ".cfg": "text/plain; charset=utf-8",
}

MASKS = {
    "my_ic": "[REDACTED - NRIC]",
    "credit_card": "[REDACTED - CC]",
    "email": "[REDACTED - EMAIL]",
    "my_phone": "[REDACTED - PHONE]",
    "name": "[REDACTED - NAME]",
    # The transient policy adapter uses this private key so that names follow
    # the same automatic redaction path as every other detected PII field.
    "person_name": "[REDACTED - NAME]",
    "address": "[REDACTED - ADDRESS]",
    "matric_number": "[REDACTED - ID]",
    "government_id": "[REDACTED - ID]",
    "financial_account": "[REDACTED - FINANCIAL]",
    "date_of_birth": "[REDACTED - DOB]",
    "aws_access_key": "[REDACTED - CREDENTIAL]",
    "secret": "[REDACTED - SECRET]",
    "private_key": "[REDACTED - PRIVATE KEY]",
    "ip_address": "[REDACTED - NETWORK ID]",
    "mac_address": "[REDACTED - DEVICE ID]",
    "gps_coordinates": "[REDACTED - LOCATION]",
    "patient_id": "[REDACTED - HEALTH ID]",
    "customer_id": "[REDACTED - ID]",
    "user_identifier": "[REDACTED - USER ID]",
}
# Names are personal data too.  Older reviewer-copy behaviour kept them
# visible, which produced outputs that still identified the person.  The
# current protection path must close every detected PII field by default.
VISIBLE_REVIEW_TYPES: set[str] = set()
MALAYSIAN_STATES = (
    "johor|kedah|kelantan|melaka|negeri sembilan|pahang|perak|perlis|pulau pinang|"
    "penang|sabah|sarawak|selangor|terengganu|kuala lumpur|putrajaya|labuan"
)


def _identity_document(ocr_lines: list[dict]) -> bool:
    text = " ".join(str(block.get("Text", "")) for block in ocr_lines).casefold()
    return any(
        marker in text
        for marker in (
            "kad pengenalan", "mykad", "national registration", "passport", "pasport", "p<"
        )
    )


def _mykad_document(ocr_lines: list[dict]) -> bool:
    """Return true only for a Malaysian MyKad, not every identity document."""
    text = " ".join(str(block.get("Text", "")) for block in ocr_lines).casefold()
    compact = re.sub(r"[^a-z0-9]+", " ", text)
    return bool(
        re.search(r"\bmykad\b", compact)
        or re.search(r"\bkad pengenalan(?: malaysia)?\b", compact)
        or ("malaysia" in compact and "pengenalan" in compact)
    )


def _mykad_portrait_region(ocr_lines: list[dict], pattern_matches: dict) -> dict | None:
    """Cover the portrait area on the standard landscape MyKad layout.

    Textract returns geometry for text, not a face region. Once the card header
    and a Malaysian identity number are recognised, use a conservative fixed
    right-hand portrait region. This is deliberately fail-closed: a recognised
    MyKad with no usable IC match is rejected by the caller rather than issuing
    a copy that may leave the portrait exposed.
    """
    card_text = " ".join(str(block.get("Text", "")) for block in ocr_lines).casefold()
    likely_card = (
        _mykad_document(ocr_lines)
        or (
            pattern_matches.get("government_id")
            and not re.search(r"\b(?:passport|pasport|p<)\b", card_text)
        )
    )
    if not likely_card:
        return None
    # OCR may miss the IC digits when the card is blurred, partly covered, or
    # photographed at an angle.  A confidently recognised MyKad plus any
    # detected identity field is still enough to cover the portrait; otherwise
    # the face would remain exposed even though the text was protected.
    if not any(
        pattern_matches.get(category)
        for category in (
            "my_ic", "name", "person_name", "date_of_birth", "address", "my_phone",
            "government_id", "mykad_portrait",
        )
    ):
        return None
    return {
        "Page": 1,
        "ExactRegion": True,
        "PortraitRegion": True,
        "Geometry": {"BoundingBox": {
            "Left": 0.66,
            "Top": 0.22,
            "Width": 0.33,
            "Height": 0.74,
        }},
    }


def _mykad_secondary_portrait_region(
    ocr_lines: list[dict], pattern_matches: dict
) -> dict | None:
    """Cover the alternate MyKad photo placement seen in angled captures.

    Malaysian identity-card captures may be mirrored/cropped or show the
    portrait on the opposite side of the card.  Covering both conservative
    portrait candidates is safer than trusting orientation inferred from a
    partial OCR result.
    """
    primary = _mykad_portrait_region(ocr_lines, pattern_matches)
    if primary is None:
        return None
    return {
        "Page": 1,
        "ExactRegion": True,
        "PortraitRegion": True,
        "Geometry": {"BoundingBox": {
            "Left": 0.24,
            "Top": 0.28,
            "Width": 0.24,
            "Height": 0.52,
        }},
    }


def _identity_address_line(text: str, identity_document: bool) -> bool:
    if not identity_document:
        return False
    normalised = re.sub(r"\s+", " ", text.casefold()).strip()
    return bool(
        re.search(r"\b\d{5}\b", normalised)
        or re.search(rf"\b(?:{MALAYSIAN_STATES})\b", normalised)
    )


def _passport_mrz_line(text: str, identity_document: bool) -> bool:
    if not identity_document:
        return False
    compact = re.sub(r"\s+", "", text.upper())
    return bool(
        re.fullmatch(r"P<[A-Z0-9<]{23,42}", compact)
        or (re.fullmatch(r"[A-Z0-9<]{30,44}", compact) and any(c.isdigit() for c in compact))
    )


def _identity_sensitive_field(text: str, identity_document: bool) -> bool:
    """Mask identity fields even when OCR separates a label from its value."""
    return bool(
        identity_document
        and re.match(
            r"(?i)^\s*(?:date\s+of\s+(?:birth|issue|expiry|expiration)|birth\s+date|"
            r"place\s+of\s+birth|tarikh\s+(?:lahir|dikeluarkan|luput|tamat)|"
            r"tempat\s+lahir|nationality|citizenship|warganegara|"
            r"sex|gender|jantina|passport\s*(?:no\.?|number)|"
            r"nric|no\.?\s*kad\s*pengenalan)\b",
            text,
        )
    )


def _identity_date_line(text: str, identity_document: bool) -> bool:
    """Cover issue/expiry dates even if OCR separated them from their labels."""
    return bool(
        identity_document
        and re.search(
            r"(?i)\b\d{1,2}[\s./-]+(?:\d{1,2}|jan|feb|mar|apr|may|mei|jun|jul|aug|sep|oct|okt|nov|dec|dis)[\s./-]+\d{2,4}\b",
            text,
        )
    )


def _expanded_box(
    box: dict, width: float, height: float, polygon: list[dict] | None = None
) -> tuple[float, float, float, float]:
    """Cover the full skewed OCR polygon and reject unusable geometry."""
    try:
        if polygon is not None and len(polygon) != 4:
            raise ValueError("OCR line has invalid redaction geometry")
        x = float(box["Left"])
        y = float(box["Top"])
        w = float(box["Width"])
        h = float(box["Height"])
        points = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
        if polygon:
            points.extend((float(point["X"]), float(point["Y"])) for point in polygon)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("OCR line has invalid redaction geometry") from error
    if (
        not all(math.isfinite(value) and -0.001 <= value <= 1.001 for point in points for value in point)
        or w <= 0
        or h <= 0
        or width <= 0
        or height <= 0
    ):
        raise ValueError("OCR line has invalid redaction geometry")
    left = min(point[0] for point in points) * width
    top = min(point[1] for point in points) * height
    right = max(point[0] for point in points) * width
    bottom = max(point[1] for point in points) * height
    # Estimate glyph height from the polygon's short edge. The enclosing box
    # can be very tall for a diagonal line and would hide neighbouring fields.
    thickness = min(right - left, bottom - top)
    if polygon and len(polygon) >= 4:
        polygon_points = points[4:]
        thickness = min(
            math.hypot(
                (polygon_points[index][0] - polygon_points[(index + 1) % len(polygon_points)][0])
                * width,
                (polygon_points[index][1] - polygon_points[(index + 1) % len(polygon_points)][1])
                * height,
            )
            for index in range(len(polygon_points))
        )
    margin = max(5.0, thickness * 0.35)
    return (
        max(0.0, left - margin),
        max(0.0, top - margin),
        min(width, right + margin),
        min(height, bottom + margin),
    )


def _redactable_matches(pattern_matches: dict) -> dict:
    return {
        data_type: [
            match for match in matches
            if not (
                data_type in {"name", "person_name"}
                and str(match).strip().casefold() in {
                    "name", "nama", "email", "e-mail", "phone", "telefon",
                    "address", "alamat", "nric", "ic", "dob", "date of birth",
                }
            )
        ]
        for data_type, matches in pattern_matches.items()
        if data_type not in VISIBLE_REVIEW_TYPES
    }


def _ocr_value_lines(pattern_matches: dict, ocr_lines: list[dict]) -> set[int]:
    """Locate each detected value, including values split across OCR lines."""
    values = {
        re.sub(r"[^\w]", "", str(value).casefold())
        for matches in _redactable_matches(pattern_matches).values()
        for value in matches
    }
    values.discard("")
    compact_lines = [re.sub(r"[^\w]", "", str(line.get("Text", "")).casefold()) for line in ocr_lines]
    selected = set()
    for value in values:
        candidates = []
        for start in range(len(ocr_lines)):
            combined = ""
            for end in range(start, min(start + 4, len(ocr_lines))):
                if ocr_lines[end].get("Page", 1) != ocr_lines[start].get("Page", 1):
                    break
                combined += compact_lines[end]
                if value in combined:
                    candidates.append(tuple(range(start, end + 1)))
                    break
                if len(combined) > len(value) + 120:
                    break
        if not candidates:
            raise ValueError("OCR redaction could not locate every detected sensitive value")
        shortest = min(len(candidate) for candidate in candidates)
        for candidate in candidates:
            if len(candidate) == shortest:
                selected.update(candidate)
    return selected


KTP_FIELD_PATTERN = re.compile(
    r"(?i)^\s*(?:NIK|Nama|Tempat\s*/\s*Tgl\s+Lahir|Jenis\s+Kelamin|Alamat|"
    r"RT\s*/\s*RW|Kel\s*/\s*Desa|Kecamatan|Agama|Status\s+Perkawinan|"
    r"Pekerjaan|Kewarganegaraan|Berlaku\s+Hingga)\b"
)


def _ktp_value_regions(
    ocr_lines: list[dict], kept_categories: set[str] | None = None
) -> list[dict] | None:
    """Cover aligned value rows on a recognisable Indonesian KTP layout."""
    text = " ".join(str(block.get("Text", "")) for block in ocr_lines).casefold()
    if "provinsi" not in text or "nik" not in text or "alamat" not in text:
        return None
    labels = [
        block for block in ocr_lines
        if KTP_FIELD_PATTERN.match(str(block.get("Text", "")))
        and block.get("Geometry", {}).get("BoundingBox", {}).get("Left", 1) < 0.24
    ]
    if len(labels) < 7:
        return None
    regions = []
    kept_categories = kept_categories or set()
    labels.sort(key=lambda block: float(block["Geometry"]["BoundingBox"]["Top"]))
    for index, block in enumerate(labels):
        field = str(block.get("Text", "")).casefold().strip()
        if (
            (field.startswith("nama") and "name" in kept_categories)
            or (field.startswith("tempat/tgl lahir") and "date_of_birth" in kept_categories)
            or (field.startswith(("alamat", "rt/rw", "kel/desa", "kecamatan"))
                and "address" in kept_categories)
        ):
            continue
        box = block["Geometry"]["BoundingBox"]
        top = float(box["Top"])
        bottom = top + float(box["Height"])
        # The OCR boxes on a KTP can be taller than the space between rows.
        # Bound each opaque strip at the midpoint to its neighbours so the
        # strips never merge into an unreadable black panel.
        if index:
            previous = labels[index - 1]["Geometry"]["BoundingBox"]
            previous_bottom = float(previous["Top"]) + float(previous["Height"])
            top = max(top - 0.003, (previous_bottom + top) / 2)
        else:
            top = max(0.0, top - 0.003)
        if index + 1 < len(labels):
            next_top = float(labels[index + 1]["Geometry"]["BoundingBox"]["Top"])
            bottom = min(bottom + 0.003, (bottom + next_top) / 2)
        else:
            bottom = min(1.0, bottom + 0.003)
        if bottom <= top:
            raise ValueError("KTP OCR rows overlap too much to redact precisely")
        regions.append({
            "Page": block.get("Page", 1),
            "Geometry": {"BoundingBox": {
                "Left": 0.23, "Top": top, "Width": 0.46, "Height": bottom - top,
            }},
            "ExactRegion": True,
        })
    # Dates printed beside/below the portrait are outside the value column.
    for block in ocr_lines:
        box = block.get("Geometry", {}).get("BoundingBox", {})
        if box.get("Left", 0) > 0.7 and _identity_date_line(str(block.get("Text", "")), True):
            regions.append(block)
    return regions


def _json_redact(value, pattern_matches: dict):
    """Redact parsed JSON values, including escaped and numeric identifiers."""
    if isinstance(value, dict):
        return {key: _json_redact(item, pattern_matches) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_redact(item, pattern_matches) for item in value]
    if isinstance(value, str):
        return redact_sensitive_data(value, pattern_matches)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        candidate = str(value)
        for data_type, matches in _redactable_matches(pattern_matches).items():
            for match in matches:
                if re.sub(r"\D", "", str(match)) == re.sub(r"\D", "", candidate):
                    return MASKS.get(data_type, "[REDACTED]")
    return value


def _redact_ocr_lines(
    document, pattern_matches: dict, ocr_lines: list[dict],
    kept_categories: set[str] | None = None,
) -> int:
    selected = _ocr_blocks_to_redact(pattern_matches, ocr_lines, kept_categories)
    applied = 0
    for block in selected:
        page_number = max(1, int(block.get("Page", 1))) - 1
        if page_number >= document.page_count:
            raise ValueError("OCR line refers to a page outside the document")
        geometry = block.get("Geometry", {})
        page = document[page_number]
        rect = pymupdf.Rect(
            *_expanded_box(
                geometry.get("BoundingBox", {}),
                page.rect.width,
                page.rect.height,
                geometry.get("Polygon"),
            )
        )
        page.add_redact_annot(rect, fill=(0, 0, 0), cross_out=False)
        applied += 1
    return applied


def _ocr_blocks_to_redact(
    pattern_matches: dict, ocr_lines: list[dict], kept_categories: set[str] | None = None
) -> list[dict]:
    ktp_regions = _ktp_value_regions(ocr_lines, kept_categories)
    if ktp_regions is not None:
        return ktp_regions
    value_line_indexes = _ocr_value_lines(pattern_matches, ocr_lines)
    selected = []
    portrait = _mykad_portrait_region(ocr_lines, pattern_matches)
    if portrait is not None:
        selected.append(portrait)
        secondary_portrait = _mykad_secondary_portrait_region(ocr_lines, pattern_matches)
        if secondary_portrait is not None:
            selected.append(secondary_portrait)
    redact_following_address_lines = 0
    redact_following_field_line = False
    identity_document = _identity_document(ocr_lines)
    for index, block in enumerate(ocr_lines):
        text = str(block.get("Text", ""))
        is_address_label = text.strip().casefold().startswith(("address", "alamat"))
        identity_address = _identity_address_line(text, identity_document)
        identity_field = _identity_sensitive_field(text, identity_document)
        identity_date = _identity_date_line(text, identity_document)
        uncertain_sensitive = bool(block.get("CoverUncertain")) and bool(
            re.search(r"\b\d{6,}\b", text)
            or identity_date
            or identity_field
        ) and not re.search(r"(?i)shutterstock|image\s*id|stock\s*photo", text)
        should_redact = (
            index in value_line_indexes
            or uncertain_sensitive
            or is_address_label
            or identity_address
            or identity_field
            or identity_date
            or _passport_mrz_line(text, identity_document)
            or redact_following_address_lines > 0
            or redact_following_field_line
        )
        redact_following_field_line = identity_field and text.rstrip().endswith(":")
        if is_address_label:
            redact_following_address_lines = 2
        elif redact_following_address_lines:
            redact_following_address_lines -= 1
        if should_redact:
            if block.get("CoverUncertain") and block.get("CoverWordBoxes"):
                # A low-confidence LINE can span a watermark or most of an ID.
                # Cover its individual WORD boxes instead of that huge union.
                selected.extend(
                    {"Geometry": geometry, "Page": block.get("Page", 1), "CoverUncertain": True}
                    for geometry in block["CoverWordBoxes"]
                )
            else:
                selected.append(block)
    return selected


def _redact_image(
    file_bytes: bytes, extension: str, pattern_matches: dict, ocr_lines: list[dict] | None,
    kept_categories: set[str] | None = None,
) -> tuple[bytes, int]:
    if not ocr_lines:
        raise ValueError("Image redaction requires OCR geometry")
    selected = _ocr_blocks_to_redact(pattern_matches, ocr_lines, kept_categories)
    expected_hits = sum(len(matches) for matches in _redactable_matches(pattern_matches).values())
    if expected_hits and not selected:
        raise ValueError("Image redaction could not locate detected sensitive content")
    with Image.open(io.BytesIO(file_bytes)) as source:
        source.verify()
    with Image.open(io.BytesIO(file_bytes)) as source:
        image = ImageOps.exif_transpose(source).convert("RGB" if extension in {".jpg", ".jpeg"} else "RGBA")
        draw = ImageDraw.Draw(image)
        width, height = image.size
        for block in selected:
            geometry = block.get("Geometry", {})
            box = geometry.get("BoundingBox", {})
            if block.get("CoverUncertain") and float(box.get("Width", 0)) * float(box.get("Height", 0)) > 0.1:
                raise ValueError("OCR region is too broad to protect precisely")
            if block.get("ExactRegion"):
                left = float(box["Left"]) * width
                top = float(box["Top"]) * height
                right = (float(box["Left"]) + float(box["Width"])) * width
                bottom = (float(box["Top"]) + float(box["Height"])) * height
            else:
                left, top, right, bottom = _expanded_box(
                    box, width, height, geometry.get("Polygon")
                )
            left, top, right, bottom = (
                math.floor(left), math.floor(top), math.ceil(right), math.ceil(bottom)
            )
            draw.rectangle((left, top, right, bottom), fill="black")
        output = io.BytesIO()
        if extension in {".jpg", ".jpeg"}:
            image.save(output, format="JPEG", quality=92, optimize=True)
        else:
            image.save(output, format="PNG", optimize=True)
        return output.getvalue(), len(selected)


def _redact_pdf(
    file_bytes: bytes, pattern_matches: dict, ocr_lines: list[dict] | None = None,
    kept_categories: set[str] | None = None,
) -> tuple[bytes, int]:
    document = pymupdf.open(stream=file_bytes, filetype="pdf")
    try:
        if document.needs_pass:
            raise ValueError("Encrypted PDFs cannot be redacted")
        # Embedded files are not part of the visible document layout and can
        # carry an unredacted copy of the source.  Drop them from the protected
        # output instead of returning the source unchanged or leaving a hidden
        # privacy leak behind.  This also handles benign PDF Content
        # Credentials attachments produced by document editors.
        for embedded_name in list(document.embfile_names()):
            document.embfile_del(embedded_name)

        expected_hits = sum(len(matches) for matches in _redactable_matches(pattern_matches).values())
        applied_hits = (
            _redact_ocr_lines(document, pattern_matches, ocr_lines, kept_categories)
            if ocr_lines else 0
        )
        if not ocr_lines:
            for data_type, matches in _redactable_matches(pattern_matches).items():
                mask = MASKS.get(data_type, "[REDACTED]")
                for match in sorted(set(matches), key=len, reverse=True):
                    match_hits = 0
                    for page in document:
                        rectangles = page.search_for(match)
                        match_hits += len(rectangles)
                        for rectangle in rectangles:
                            page.add_redact_annot(
                                rectangle,
                                text=mask,
                                fontname="Helv",
                                fontsize=7,
                                fill=(0, 0, 0),
                                text_color=(1, 1, 1),
                                cross_out=False,
                            )
                    applied_hits += match_hits

        if ocr_lines and expected_hits and applied_hits == 0:
            raise ValueError("OCR PDF redaction could not locate detected sensitive content")
        if not ocr_lines and expected_hits and applied_hits < expected_hits:
            raise ValueError(
                "PDF redaction could not locate every detected sensitive value in the page layout"
            )

        for page in document:
            # Redact image pixels too. images=0 only adds a visual cover while
            # leaving a scanned document's embedded source image recoverable.
            page.apply_redactions(images=2, graphics=1, text=0)

        # A visible blackout is insufficient if the source still identifies a
        # person in the PDF information dictionary or XMP packet.
        document.set_metadata({})
        if document.xref_xml_metadata():
            document.del_xml_metadata()

        if ocr_lines:
            # Rebuild OCR PDFs from the already-redacted rendered pages. Merely
            # applying PDF image redactions can leave the original image object
            # recoverable in the file even when it is no longer visibly used.
            sanitised = pymupdf.open()
            try:
                for page in document:
                    pixmap = page.get_pixmap(dpi=200, alpha=False, annots=False)
                    clean_page = sanitised.new_page(width=page.rect.width, height=page.rect.height)
                    clean_page.insert_image(clean_page.rect, stream=pixmap.tobytes("png"))
                output = sanitised.tobytes(garbage=4, deflate=True, clean=True)
            finally:
                sanitised.close()
        else:
            output = document.tobytes(garbage=4, deflate=True, clean=True)
    finally:
        document.close()

    verification = pymupdf.open(stream=output, filetype="pdf")
    try:
        remaining_text = "\n".join(page.get_text() for page in verification)
        if ocr_lines:
            source = pymupdf.open(stream=file_bytes, filetype="pdf")
            try:
                source_image_digests = {
                    hashlib.sha256(source.extract_image(xref)["image"]).hexdigest()
                    for page in source
                    for xref, *_ in page.get_images(full=True)
                }
            finally:
                source.close()
            output_image_digests = {
                hashlib.sha256(verification.extract_image(xref)["image"]).hexdigest()
                for page in verification
                for xref, *_ in page.get_images(full=True)
            }
            if source_image_digests & output_image_digests:
                raise ValueError("Protected PDF still contains an original scanned image")
    finally:
        verification.close()
    leaked = [
        match
        for matches in _redactable_matches(pattern_matches).values()
        for match in matches
        if match in remaining_text
    ]
    if leaked:
        raise ValueError("PDF redaction verification found sensitive text in the protected output")
    return output, applied_hits


def redact_document(
    file_bytes: bytes,
    filename: str,
    extracted_text: str,
    pattern_matches: dict,
    ocr_lines: list[dict] | None = None,
    kept_categories: set[str] | None = None,
) -> tuple[bytes, str, dict]:
    """Return a protected document in the same supported format as the source."""
    extension = Path(filename).suffix.lower()
    if extension not in CONTENT_TYPES:
        raise ValueError(f"Unsupported redaction format: {extension or 'unknown'}")

    if extension == ".pdf":
        output, hits = _redact_pdf(
            file_bytes, pattern_matches, ocr_lines=ocr_lines,
            kept_categories=kept_categories,
        )
    elif extension in {".jpg", ".jpeg", ".png"}:
        output, hits = _redact_image(
            file_bytes, extension, pattern_matches, ocr_lines, kept_categories
        )
    else:
        source = file_bytes.decode("utf-8-sig", errors="strict")
        if extension == ".json":
            try:
                parsed = json.loads(source)
            except json.JSONDecodeError as error:
                raise ValueError("JSON output could not be parsed before redaction") from error
            redacted = _json_redact(parsed, pattern_matches)
            output = json.dumps(redacted, ensure_ascii=False, indent=2).encode("utf-8")
            # Count actual changed leaves, then verify every detected value is
            # absent from the parsed protected document.
            protected_text = json.dumps(redacted, ensure_ascii=False)
            leaked = [
                str(match)
                for matches in _redactable_matches(pattern_matches).values()
                for match in matches
                if str(match) in protected_text
            ]
            if leaked:
                raise ValueError("JSON redaction verification found sensitive values")
            hits = sum(
                1
                for data_type, matches in _redactable_matches(pattern_matches).items()
                for match in matches
                if str(match) not in protected_text
            )
        else:
            redacted = redact_sensitive_data(source, pattern_matches)
            output = redacted.encode("utf-8")
            hits = sum(len(matches) for matches in _redactable_matches(pattern_matches).values())
            if any(
                str(match) in redacted
                for matches in _redactable_matches(pattern_matches).values()
                for match in matches
            ):
                raise ValueError("Text redaction verification found sensitive values")

    return (
        output,
        CONTENT_TYPES[extension],
        {
            "format_preserved": True,
            "protected_extension": extension,
            "redaction_hits": hits,
            "source_text_characters": len(extracted_text),
            "ocr_used": bool(ocr_lines),
        },
    )
