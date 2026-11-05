"""Generate a synthetic, value-minimised before/after detector evaluation report."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.pii_engine import PIIEngine  # noqa: E402
from src.pii_engine.mutations import generate_mutations  # noqa: E402


@dataclass(frozen=True)
class Case:
    case_id: str
    expected: str | None
    text: str
    region: str
    format_family: str


CASES = (
    Case("passport_plain", "PASSPORT_NUMBER", "passport_number: ZX928173", "unknown", "plain"),
    Case("passport_alias", "PASSPORT_NUMBER", "Travel Doc Ref = KJ-88-192", "unknown", "plain"),
    Case("passport_xml", "PASSPORT_NUMBER", "<passportNumber>AA0192837</passportNumber>", "EU-like", "xml"),
    Case("passport_json", "PASSPORT_NUMBER", '{"identity":{"passport":{"number":"N771829"}}}', "US-like", "json"),
    Case("national_my", "GENERIC_NATIONAL_ID", "national_id: MY-784-199-AB", "Malaysia-like", "plain"),
    Case("national_sg", "GENERIC_NATIONAL_ID", "citizenNumber = SG-00199281X", "Singapore-like", "plain"),
    Case("national_id", "GENERIC_NATIONAL_ID", "civil_id: ID-91822", "Indonesia-like", "yaml"),
    Case("national_in", "GENERIC_NATIONAL_ID", "personalNumber: IN-827192", "India-like", "plain"),
    Case("national_cn", "GENERIC_NATIONAL_ID", "identity_number: CN-991827", "China-like", "plain"),
    Case("national_jp", "GENERIC_NATIONAL_ID", "resident_id: JP-182771", "Japan-like", "plain"),
    Case("national_kr", "GENERIC_NATIONAL_ID", "civil_id: KR-551829", "Korea-like", "plain"),
    Case("national_uk", "GENERIC_NATIONAL_ID", "national_identifier: UK-91827", "UK-like", "plain"),
    Case("national_ca", "GENERIC_NATIONAL_ID", "personal_number: CA-88219", "Canada-like", "plain"),
    Case("national_au", "GENERIC_NATIONAL_ID", "citizen_ref: AU-77182", "Australia-like", "plain"),
    Case("national_me", "GENERIC_NATIONAL_ID", "civil_id: QA-551829", "Middle-East-like", "plain"),
    Case("employee_numeric", "EMPLOYEE_ID", "employeeNumber: 1293", "unknown", "plain"),
    Case("employee_log", "EMPLOYEE_ID", "INFO personnel.ref|MY-KL-1293", "Malaysia-like", "log"),
    Case("employee_html", "EMPLOYEE_ID", '<input name="worker_id" value="WK/2026/91">', "unknown", "html"),
    Case("student_csv", "STUDENT_ID", "Name,Student Number\nSynthetic Student,STU-88291", "unknown", "csv"),
    Case("patient_yaml", "PATIENT_ID", "medical_record_number: HOSP-00123", "unknown", "yaml"),
    Case("customer_log", "CUSTOMER_ID", "INFO clientReference=CLI-88219", "unknown", "log"),
    Case("phone_uk", "PHONE_NUMBER", "Phone: +44 20 7946 0958", "UK-like", "plain"),
    Case("phone_jp", "PHONE_NUMBER", "mobile = +81-90-1234-5678", "Japan-like", "plain"),
    Case("phone_id", "PHONE_NUMBER", "telefon: +62 812 3456 7890", "Indonesia-like", "plain"),
    Case("address_uk", "POSTAL_ADDRESS", "Address: 221B Baker Street, London NW1 6XE, United Kingdom", "UK-like", "plain"),
    Case("address_us", "POSTAL_ADDRESS", "residential_address:\n1600 Amphitheatre Parkway\nMountain View, CA 94043\nUnited States", "US-like", "multiline"),
    Case("name_cn", "PERSON_NAME", "legal_name: 李 小龍", "China-like", "unicode"),
    Case("name_single", "PERSON_NAME", "preferredName: Madonna", "unknown", "plain"),
    Case("name_eu", "PERSON_NAME", "full_name: José María O\u2019Neill", "EU-like", "unicode"),
    Case("licence", "DRIVING_LICENCE", "driving_licence_no: DL-UK-99182", "UK-like", "plain"),
    Case("visa", "VISA_NUMBER", "visa_number: VSA-88291", "unknown", "plain"),
    Case("tax", "TAX_ID", "tax_identifier: TX-99281", "unknown", "plain"),
    Case("database", "EMPLOYEE_ID", "employees.employee_id: EMP-77219", "unknown", "database"),
    Case("table", "PASSPORT_NUMBER", "Passport Number|Employee Number\nZX928173|EMP-1001", "unknown", "table"),
    Case("ocr", "PASSPORT_NUMBER", "Passport\nNumber:\nZ X 9 2 8 1 7 3", "unknown", "ocr-like"),
    Case("unicode_field", "GENERIC_NATIONAL_ID", "national\uff3fid\uff1a784-199-AB", "unknown", "unicode"),
    Case("negative_build", None, "build_number: 1293", "none", "plain"),
    Case("negative_invoice", None, "invoice_number: ABC-1293", "none", "plain"),
    Case("negative_request", None, "request_id: 123e4567-e89b-12d3-a456-426614174000", "none", "log"),
    Case("negative_project", None, "name of project: DataSentinel", "none", "plain"),
    Case("negative_counts", None, "employee count: 1293\nstudent count: 3000\npatient queue: 12", "none", "plain"),
)

# Captured immediately before this change from the same checkout.  Only these
# case IDs were in the original 26-case baseline; absent cases are reported as
# not measured rather than invented.
BASELINE_MEASURED = {
    "passport_plain": True,
    "passport_alias": False,
    "passport_xml": False,
    "passport_json": False,
    "national_my": False,
    "national_sg": False,
    "national_id": False,
    "employee_numeric": True,
    "employee_log": False,
    "employee_html": False,
    "student_csv": True,
    "patient_yaml": False,
    "customer_log": False,
    "phone_uk": False,
    "phone_jp": False,
    "phone_id": False,
    "address_uk": True,
    "address_us": False,
    "name_cn": False,
    "name_single": False,
    "name_eu": False,
    "licence": False,
    "visa": False,
    "tax": False,
    "negative_build": False,
    "negative_invoice": False,
    "negative_request": False,
    "negative_project": False,
    "negative_counts": False,
}


def _score(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def evaluate() -> dict:
    engine = PIIEngine()
    start = time.perf_counter()
    outcomes = {}
    false_positive_types: Counter[str] = Counter()
    for case in CASES:
        detected_types = {finding.entity_type for finding in engine.scan(case.text).findings}
        outcomes[case.case_id] = case.expected in detected_types if case.expected else not detected_types
        if case.expected is None:
            false_positive_types.update(detected_types)
    elapsed = time.perf_counter() - start

    entity_rows = {}
    for entity_type in sorted({case.expected for case in CASES if case.expected}):
        entity_cases = [case for case in CASES if case.expected == entity_type]
        after_tp = sum(outcomes[case.case_id] for case in entity_cases)
        after = _score(after_tp, false_positive_types[entity_type], len(entity_cases) - after_tp)
        measured = [case for case in entity_cases if case.case_id in BASELINE_MEASURED]
        before_tp = sum(BASELINE_MEASURED[case.case_id] for case in measured)
        before = _score(before_tp, 0, len(measured) - before_tp) if measured else None
        entity_rows[entity_type] = {"before": before, "after": after, "baseline_cases": len(measured), "current_cases": len(entity_cases)}

    def grouped(attribute: str) -> dict[str, dict[str, int | float]]:
        groups = defaultdict(list)
        for case in CASES:
            if case.expected:
                groups[getattr(case, attribute)].append(case)
        return {
            name: {
                "cases": len(cases),
                "detected": sum(outcomes[case.case_id] for case in cases),
                "recall": round(sum(outcomes[case.case_id] for case in cases) / len(cases), 4),
            }
            for name, cases in sorted(groups.items())
        }

    mutation_total = 0
    mutation_detected = 0
    for entity_type, labels, values in (
        ("PASSPORT_NUMBER", ("passport number", "travel doc ref"), ("ZX928173",)),
        ("EMPLOYEE_ID", ("employee id", "staff number"), ("MY-KL-1293",)),
        ("GENERIC_NATIONAL_ID", ("national id", "citizen number"), ("784-199-AB",)),
        ("PHONE_NUMBER", ("phone number", "mobile number"), ("+44 20 7946 0958",)),
    ):
        for case in generate_mutations(entity_type, labels, values, limit=300):
            mutation_total += 1
            mutation_detected += entity_type in {finding.entity_type for finding in engine.scan(case.text).findings}

    measured_positive = [case for case in CASES if case.expected and case.case_id in BASELINE_MEASURED]
    baseline_tp = sum(BASELINE_MEASURED[case.case_id] for case in measured_positive)
    current_positive = [case for case in CASES if case.expected]
    current_tp = sum(outcomes[case.case_id] for case in current_positive)
    negative_cases = [case for case in CASES if case.expected is None]
    false_positive_cases = sum(not outcomes[case.case_id] for case in negative_cases)
    return {
        "dataset": "synthetic-only",
        "baseline": {
            "measured_positive_cases": len(measured_positive),
            "true_positive_cases": baseline_tp,
            "recall": round(baseline_tp / len(measured_positive), 4),
            "false_positive_cases": 0,
            "note": "Captured before implementation; unmeasured rows are null.",
        },
        "current": {
            "positive_cases": len(current_positive),
            "true_positive_cases": current_tp,
            "recall": round(current_tp / len(current_positive), 4),
            "negative_cases": len(negative_cases),
            "false_positive_cases": false_positive_cases,
            "elapsed_ms": round(elapsed * 1000, 3),
        },
        "per_entity": entity_rows,
        "per_region": grouped("region"),
        "per_format": grouped("format_family"),
        "mutation": {
            "cases": mutation_total,
            "detected": mutation_detected,
            "recall": round(mutation_detected / mutation_total, 4),
        },
        "remaining_limitations": [
            "Unlabelled unknown identifiers remain ambiguous and are intentionally not promoted.",
            "Severely corrupted OCR can still require human review.",
            "Country-specific checksum validation is not available for every jurisdiction.",
            "Metrics use synthetic data and are not a production accuracy claim.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "output" / "pii-global-evaluation.json")
    args = parser.parse_args()
    report = evaluate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
