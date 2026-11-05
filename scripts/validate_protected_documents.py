"""Create and verify format-preserving protected PDFs without printing PII."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pymupdf
from PIL import Image, ImageDraw

from src.classifiers.pattern_matcher import discover_sensitive_data
from src.utils.format_redactor import VISIBLE_REVIEW_TYPES, redact_document


def _extract(pdf_bytes: bytes) -> tuple[str, int, list[tuple[float, float]]]:
    document = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        return (
            "\n".join(page.get_text() for page in document),
            document.page_count,
            [(round(page.rect.width, 2), round(page.rect.height, 2)) for page in document],
        )
    finally:
        document.close()


def _contact_sheet(pdf_bytes: bytes, destination: Path) -> None:
    document = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    thumbnails = []
    try:
        for page in document:
            pixmap = page.get_pixmap(matrix=pymupdf.Matrix(0.55, 0.55), alpha=False)
            image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
            image.thumbnail((300, 410))
            thumbnails.append(image.copy())
    finally:
        document.close()
    columns = 4
    cell_width, cell_height = 320, 450
    rows = max(1, (len(thumbnails) + columns - 1) // columns)
    sheet = Image.new("RGB", (columns * cell_width, rows * cell_height), "#20242a")
    draw = ImageDraw.Draw(sheet)
    for index, image in enumerate(thumbnails):
        x = (index % columns) * cell_width + (cell_width - image.width) // 2
        y = (index // columns) * cell_height + 24
        sheet.paste(image, (x, y))
        draw.text((x, 5 + (index // columns) * cell_height), f"Page {index + 1}", fill="white")
    destination.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(destination, format="PNG", optimize=True)


def protect(source: Path, destination: Path, render_directory: Path) -> dict:
    source_bytes = source.read_bytes()
    source_text, source_pages, source_dimensions = _extract(source_bytes)
    discovery = discover_sensitive_data(source_text)
    patterns = discovery.redaction_map()
    protected, content_type, evidence = redact_document(
        source_bytes, source.name, source_text, patterns
    )
    protected_text, protected_pages, protected_dimensions = _extract(protected)
    redactable_values = {
        value
        for data_type, values in patterns.items()
        if data_type not in VISIBLE_REVIEW_TYPES
        for value in values
    }
    leaked = [value for value in redactable_values if value and value in protected_text]
    if leaked:
        raise RuntimeError("Protected PDF validation found residual sensitive values")
    if source_pages != protected_pages or source_dimensions != protected_dimensions:
        raise RuntimeError("Protected PDF changed page count or page dimensions")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(protected)
    sheet = render_directory / f"{destination.stem}-all-pages.png"
    _contact_sheet(protected, sheet)
    return {
        "source": source.name,
        "output": destination.name,
        "content_type": content_type,
        "pages": protected_pages,
        "dimensions_preserved": True,
        "redaction_hits": evidence["redaction_hits"],
        "detected_by_type": {key: len(values) for key, values in patterns.items() if values},
        "rich_findings": discovery.summary.total_findings,
        "document_risk": discovery.summary.risk,
        "residual_sensitive_values": 0,
        "contact_sheet": str(sheet),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("output/pdf"))
    parser.add_argument("--render-dir", type=Path, default=Path("output/pdf/rendered"))
    args = parser.parse_args()
    results = []
    for source in args.sources:
        destination = args.output_dir / f"{source.stem}-protected.pdf"
        results.append(protect(source, destination, args.render_dir))
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
