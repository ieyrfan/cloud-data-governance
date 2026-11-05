"""Evaluate the detector against an annotated, synthetic-only benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.pii_engine import PIIEngine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    records = json.loads(args.dataset.read_text(encoding="utf-8"))
    true_positive = false_positive = false_negative = true_negative = 0
    failures = []
    for record in records:
        expected = set(record["expected"])
        detected = {
            finding.entity_type
            for finding in PIIEngine().scan(record["text"]).findings
            if finding.validation_status != "INVALID" and finding.confidence >= 0.4
        }
        true_positive += len(expected & detected)
        false_positive += len(detected - expected)
        false_negative += len(expected - detected)
        if not expected and not detected:
            true_negative += 1
        if expected != detected:
            failures.append({"id": record["id"], "missing": sorted(expected - detected), "extra": sorted(detected - expected)})
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    f1 = 2 * precision * recall / max(0.000001, precision + recall)
    negative_records = sum(1 for record in records if not record["expected"])
    false_positive_rate = (negative_records - true_negative) / max(1, negative_records)
    print(json.dumps({
        "dataset": "synthetic-only",
        "records": len(records),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative_records": true_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
