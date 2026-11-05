import csv
import io
import json
import time

import pymupdf

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_EXTRACTED_CHARACTERS = 1_000_000
MIN_OCR_LINE_CONFIDENCE = 80.0
TEXT_EXTENSIONS = {"txt", "md", "log", "html", "htm", "xml", "yaml", "yml", "ini", "cfg"}


def extract_text_from_textract(textract_client, bucket: str, key: str) -> tuple[str, list[dict]]:
    """Extract a single-page scanned PDF and retain line geometry for safe redaction."""
    response = textract_client.detect_document_text(
        Document={"S3Object": {"Bucket": bucket, "Name": key}}
    )
    lines = [block for block in response.get("Blocks", []) if block.get("BlockType") == "LINE"]
    low_confidence = [
        block for block in lines if float(block.get("Confidence", 100.0)) < MIN_OCR_LINE_CONFIDENCE
    ]
    if low_confidence:
        raise ValueError(
            f"{key} requires human review because OCR confidence is below "
            f"{MIN_OCR_LINE_CONFIDENCE:.0f}%"
        )
    text = "\n".join(str(block.get("Text", "")) for block in lines)
    return _validate_extracted_text(text, key), lines


def extract_text_from_textract_bytes(
    textract_client, file_bytes: bytes, label: str = "document", *,
    cover_uncertain_lines: bool = False,
) -> tuple[str, list[dict]]:
    """Read an in-memory image without creating an S3 object."""
    response = textract_client.detect_document_text(Document={"Bytes": file_bytes})
    lines = [block for block in response.get("Blocks", []) if block.get("BlockType") == "LINE"]
    low_confidence = [
        block for block in lines
        if float(block.get("Confidence", 100.0)) < MIN_OCR_LINE_CONFIDENCE
    ]
    if low_confidence and not cover_uncertain_lines:
        raise ValueError("OCR confidence is too low; no protected file was issued")
    if cover_uncertain_lines:
        words_by_id = {
            block.get("Id"): block
            for block in response.get("Blocks", [])
            if block.get("BlockType") == "WORD"
        }
        for block in low_confidence:
            # The direct image path covers these pixels even if OCR guessed
            # their text incorrectly. A score alone must not expose the line.
            block["CoverUncertain"] = True
            word_ids = [
                word_id
                for relation in block.get("Relationships", [])
                if relation.get("Type") == "CHILD"
                for word_id in relation.get("Ids", [])
            ]
            word_boxes = [
                words_by_id[word_id]["Geometry"]
                for word_id in word_ids
                if word_id in words_by_id and "Geometry" in words_by_id[word_id]
                and (
                    words_by_id[word_id]["Geometry"].get("BoundingBox", {}).get("Width", 0)
                    * words_by_id[word_id]["Geometry"].get("BoundingBox", {}).get("Height", 0)
                ) <= 0.1
            ]
            if not word_boxes:
                # Some Textract LINE blocks omit CHILD relationships. Use
                # contained WORD geometry before falling back to a potentially
                # enormous line box (for example over a document watermark).
                line_box = block.get("Geometry", {}).get("BoundingBox", {})
                left, top = line_box.get("Left", 0), line_box.get("Top", 0)
                right = left + line_box.get("Width", 0)
                bottom = top + line_box.get("Height", 0)
                for word in words_by_id.values():
                    geometry = word.get("Geometry", {})
                    box = geometry.get("BoundingBox", {})
                    centre_x = box.get("Left", 0) + box.get("Width", 0) / 2
                    centre_y = box.get("Top", 0) + box.get("Height", 0) / 2
                    if left <= centre_x <= right and top <= centre_y <= bottom:
                        if box.get("Width", 0) * box.get("Height", 0) <= 0.1:
                            word_boxes.append(geometry)
            block["CoverWordBoxes"] = word_boxes
    text = "\n".join(str(block.get("Text", "")) for block in lines)
    return _validate_extracted_text(text, label), lines


def extract_text_from_textract_async(
    textract_client,
    bucket: str,
    key: str,
    *,
    timeout_seconds: int = 180,
    poll_seconds: float = 1.0,
) -> tuple[str, list[dict]]:
    """Extract every page of a scanned PDF and fail closed on timeout or partial jobs."""
    started = textract_client.start_document_text_detection(
        DocumentLocation={"S3Object": {"Bucket": bucket, "Name": key}}
    )
    job_id = started.get("JobId")
    if not job_id:
        raise ValueError(f"{key} OCR job did not return an identifier")
    deadline = time.monotonic() + timeout_seconds
    blocks = []
    next_token = None
    while time.monotonic() < deadline:
        request = {"JobId": job_id}
        if next_token:
            request["NextToken"] = next_token
        response = textract_client.get_document_text_detection(**request)
        status = response.get("JobStatus")
        if status in {"FAILED", "PARTIAL_SUCCESS"}:
            raise ValueError(f"{key} requires human review because multi-page OCR was incomplete")
        if status == "SUCCEEDED":
            blocks.extend(response.get("Blocks", []))
            next_token = response.get("NextToken")
            if not next_token:
                break
            continue
        time.sleep(poll_seconds)
    else:
        raise ValueError(f"{key} requires human review because multi-page OCR timed out")
    lines = [block for block in blocks if block.get("BlockType") == "LINE"]
    low_confidence = [
        block for block in lines if float(block.get("Confidence", 100.0)) < MIN_OCR_LINE_CONFIDENCE
    ]
    if low_confidence:
        raise ValueError(
            f"{key} requires human review because OCR confidence is below "
            f"{MIN_OCR_LINE_CONFIDENCE:.0f}%"
        )
    text = "\n".join(str(block.get("Text", "")) for block in lines)
    return _validate_extracted_text(text, key), lines


def _decode_utf8(file_content_bytes: bytes, filename: str) -> str:
    try:
        text = file_content_bytes.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{filename} is not valid UTF-8 text") from error
    if "\x00" in text:
        raise ValueError(f"{filename} contains binary null bytes")
    return text


def _validate_extracted_text(text: str, filename: str) -> str:
    if not text.strip():
        raise ValueError(f"{filename} contains no extractable text")
    if len(text) > MAX_EXTRACTED_CHARACTERS:
        raise ValueError(f"{filename} exceeds the extracted-text safety limit")
    return text


def _recoverable_structured_text(text: str) -> bool:
    """Allow security scanning only when malformed data still has label and value content."""
    import re

    return bool(
        re.search(
            r"(?m)[\"']?[A-Za-z_][\w .-]{1,70}[\"']?\s*[:=,]\s*[\"']?[A-Za-z0-9+]"
            r"[^\r\n]{2,}",
            text,
        )
    )


def extract_text_from_file(file_content_bytes: bytes, filename: str) -> str:
    """
    Intelligently extracts text from different file formats (TXT, CSV, JSON, PDF).
    """
    ext = filename.lower().split(".")[-1] if "." in filename else ""

    if not file_content_bytes:
        raise ValueError(f"{filename} is empty")
    if len(file_content_bytes) > MAX_INPUT_BYTES:
        raise ValueError(f"{filename} exceeds the 5 MB processing limit")

    try:
        if ext == "json":
            decoded = _decode_utf8(file_content_bytes, filename)
            try:
                data = json.loads(decoded)
            except json.JSONDecodeError as error:
                # Malformed structure must not turn into a zero-result scan.
                # The field grammar can still inspect the original UTF-8 text.
                if not _recoverable_structured_text(decoded):
                    raise ValueError(f"Unable to parse {filename}: {error}") from error
                text = decoded
            else:
                text = json.dumps(data, indent=2, ensure_ascii=False)
        elif ext == "csv":
            decoded = _decode_utf8(file_content_bytes, filename)
            try:
                records = list(csv.reader(io.StringIO(decoded), strict=True))
            except csv.Error:
                text = decoded
            else:
                if not records:
                    text = ""
                else:
                    headers = records[0]
                    structured_rows = [" ".join(headers)]
                    for row in records[1:]:
                        structured_rows.append(
                            "\n".join(
                                f"{headers[index]}: {value}"
                                for index, value in enumerate(row)
                                if index < len(headers)
                            )
                        )
                    text = "\n".join(structured_rows)
        elif ext == "pdf":
            pdf_reader = pymupdf.open(stream=file_content_bytes, filetype="pdf")
            if pdf_reader.needs_pass:
                raise ValueError(f"{filename} is encrypted and cannot be inspected")
            try:
                # Any page containing an image may contain pixels that text
                # extraction cannot see.  Do not classify a mixed page from
                # its visible text alone; route the whole document through
                # OCR so the protected copy can redact image geometry.
                image_pages = [
                    page.number + 1
                    for page in pdf_reader
                    if page.get_images(full=True)
                ]
                if image_pages:
                    raise ValueError(
                        f"{filename} contains image pages that require asynchronous "
                        "multi-page OCR and human review"
                    )
                text = "\n".join(page_text for page in pdf_reader if (page_text := page.get_text()))
            finally:
                pdf_reader.close()
        elif ext in TEXT_EXTENSIONS:
            text = _decode_utf8(file_content_bytes, filename)
        else:
            raise ValueError(f"Unsupported document type: .{ext or 'unknown'}")
    except (csv.Error, json.JSONDecodeError, OSError, RuntimeError, TypeError) as error:
        raise ValueError(f"Unable to parse {filename}: {error}") from error

    return _validate_extracted_text(text, filename)
