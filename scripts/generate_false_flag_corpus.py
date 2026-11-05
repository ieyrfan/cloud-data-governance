"""Generate synthetic multi-format regression documents for false-flag review."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BENIGN_TEMPLATES = [
    "{person} reviewed the {department} report for the {month} meeting. Ward {number} was closed.",
    "Reference {number} appears on page {number}. The report date was {date}.",
    "The {organisation} project used {product} during the {department} review.",
    "The workshop was held near {street}. Participants met in Room {number}.",
    "The test server {ip} returned coordinates {gps} during the demonstration.",
    "This academic paper evaluates OCR accuracy, cloud governance and processing latency.",
    "The {department} team approved the May delivery schedule for the sample project.",
    "Example values are documented for testing and do not identify a real person.",
]

SENSITIVE_TEMPLATES = [
    "Name: Synthetic Person {index}\nPhone: 012-345{suffix}\nEmail: person{index}@example.test",
    "NRIC: 900101-14-{suffix}\nDate of Birth: 01/01/1990\nPatient ID: PT-{index:04d}",
    "Address: No. {number}, Jalan Damai, 43000 Kajang, Selangor",
    "Bank Account Number: 123456789012\nCredit Card: 4111 1111 1111 1111",
    "Mobile Number: +60 12 345 {suffix}\nEmail: contact{index}@example.test",
    "Employee ID: EMP-{index:04d}\nStudent ID: STU-{index:04d}",
]

EXTENSIONS = ("txt", "md", "csv", "json", "html", "xml", "yaml", "log")


def build_case(index: int, benign: bool, extension: str) -> tuple[str, dict]:
    values = {
        "person": ("Jordan", "Apple", "May", "Tan" )[index % 4],
        "department": ("Finance", "Student Affairs", "Research", "Operations")[index % 4],
        "month": ("May", "June", "October", "November")[index % 4],
        "number": 10 + index % 80,
        "date": f"2026-{index % 12 + 1:02d}-14",
        "organisation": ("Jordan Project", "Apple Malaysia", "Cloud Governance Lab")[index % 3],
        "product": ("Amazon Web Services", "DataSentinel", "Project Atlas")[index % 3],
        "street": ("Jalan Damai", "Research Avenue", "Campus Road")[index % 3],
        "ip": f"192.168.{index % 20}.{index % 200 + 1}",
        "gps": f"3.{1390 + index % 20:04d}, 101.{6869 + index % 20:04d}",
        "index": index,
        "suffix": f"{index % 10000000:07d}",
    }
    template = (BENIGN_TEMPLATES if benign else SENSITIVE_TEMPLATES)[
        index % (len(BENIGN_TEMPLATES) if benign else len(SENSITIVE_TEMPLATES))
    ]
    text = template.format(**values)
    if extension == "json":
        text = json.dumps({"title": "Synthetic test document", "content": text})
    elif extension == "csv":
        text = f"section,content\nreport,{text.replace(chr(10), ' | ')}\n"
    elif extension == "html":
        text = f"<html><body><p>{text.replace(chr(10), '<br>')}</p></body></html>"
    elif extension == "xml":
        text = f"<document><content>{text.replace('&', '&amp;').replace('<', '&lt;')}</content></document>"
    elif extension == "yaml":
        text = "document: synthetic\ncontent: " + json.dumps(text)
    elif extension == "log":
        text = f"2026-01-01T10:00:00Z INFO {text.replace(chr(10), ' | ')}"
    elif extension == "md":
        text = f"# Synthetic report\n\n{text}"
    expected = {"id": f"{'benign' if benign else 'sensitive'}-{index:04d}", "benign": benign}
    return text, expected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    if args.count < 100 or args.count > 1000:
        raise SystemExit("count must be between 100 and 1000")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for index in range(args.count):
        benign = index < args.count * 0.6
        extension = EXTENSIONS[index % len(EXTENSIONS)]
        text, metadata = build_case(index, benign, extension)
        path = args.output / f"{metadata['id']}.{extension}"
        path.write_text(text, encoding="utf-8")
        manifest.append({**metadata, "file": path.name, "extension": extension})
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"Generated {len(manifest)} synthetic documents in {args.output}")


if __name__ == "__main__":
    main()
