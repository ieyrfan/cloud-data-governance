"""Global, structure-aware and mutation regression coverage using synthetic data only."""

from src.pii_engine import PIIEngine
from src.pii_engine.field_semantics import classify_field
from src.pii_engine.mutations import generate_mutations


def _types(text: str) -> set[str]:
    return {finding.entity_type for finding in PIIEngine().scan(text).findings}


def test_field_semantics_cover_unknown_country_and_person_identifier_families():
    expectations = {
        "travelDocRef": "PASSPORT_NUMBER",
        "citizen_number": "GENERIC_NATIONAL_ID",
        "personnel.ref": "EMPLOYEE_ID",
        "medicalRecordNumber": "PATIENT_ID",
        "client_reference": "CUSTOMER_ID",
        "driving-licence-no": "DRIVING_LICENCE",
        "workPermitId": "RESIDENCE_PERMIT",
        "tax_identifier": "TAX_ID",
    }
    for label, expected in expectations.items():
        semantic = classify_field(label)
        assert semantic is not None
        assert semantic.entity_type == expected


def test_generic_identifiers_do_not_require_country_specific_value_regexes():
    samples = {
        "PASSPORT_NUMBER": "Travel Doc Ref = KJ-88-192",
        "GENERIC_NATIONAL_ID": "citizenNumber = 00199281X",
        "EMPLOYEE_ID": "personnel.ref|MY-KL-1293",
        "STUDENT_ID": "student_id: B032410773",
        "PATIENT_ID": "medical_record_number=HOSP-00123",
        "CUSTOMER_ID": "clientReference: CLI-88219",
        "DRIVING_LICENCE": "driving_licence_no: DL-UK-99182",
        "VISA_NUMBER": "visa_number: VSA-88291",
        "TAX_ID": "tax_identifier: TX-99281",
    }
    for expected, text in samples.items():
        assert expected in _types(text)


def test_structured_inputs_use_schema_relationships():
    samples = (
        ("PASSPORT_NUMBER", '<passportNumber>AA0192837</passportNumber>'),
        ("EMPLOYEE_ID", '<input name="worker_id" value="WK/2026/91">'),
        ("GENERIC_NATIONAL_ID", '{"person":{"identity":{"nationalId":"784-199-AB"}}}'),
        ("PASSPORT_NUMBER", '{"identity":{"passport":{"number":"N771829"}}}'),
        ("STUDENT_ID", "Name,Student Number\nSynthetic Student,STU-88291"),
        ("PATIENT_ID", "patient:\n  medical_record_number: HOSP-00123"),
        ("CUSTOMER_ID", "INFO clientReference=CLI-88219"),
    )
    for expected, text in samples:
        assert expected in _types(text)


def test_global_phones_international_addresses_and_culturally_varied_names():
    samples = {
        "PHONE_NUMBER": (
            "Phone: +44 20 7946 0958\nMobile: +81-90-1234-5678\nTelefon: +62 812 3456 7890"
        ),
        "POSTAL_ADDRESS": (
            "residential_address:\n1600 Amphitheatre Parkway\n"
            "Mountain View, CA 94043\nUnited States"
        ),
        "PERSON_NAME": "legal_name: 李 小龍\npreferredName: Madonna\nfull_name: José María O\u2019Neill",
    }
    for expected, text in samples.items():
        assert expected in _types(text)


def test_negative_context_prevents_identifier_and_name_false_positives():
    negatives = (
        "build_number: 1293",
        "invoice_number: ABC-1293",
        "request_id: 123e4567-e89b-12d3-a456-426614174000",
        "report date: 2026-10-27",
        "employee count: 1293",
        "name of project: DataSentinel",
        "phone model: Pixel 9",
        "student count: 3000",
        "patient queue: 12",
        "customer total: 50",
    )
    for text in negatives:
        assert PIIEngine().scan(text).findings == ()


def test_generated_mutation_sample_has_high_recall_without_pattern_dump():
    specifications = (
        ("PASSPORT_NUMBER", ("passport number", "travel doc ref"), ("ZX928173",)),
        ("EMPLOYEE_ID", ("employee id", "staff number"), ("MY-KL-1293",)),
        ("GENERIC_NATIONAL_ID", ("national id", "citizen number"), ("784-199-AB",)),
        ("PHONE_NUMBER", ("phone number", "mobile number"), ("+44 20 7946 0958",)),
    )
    total = 0
    detected = 0
    engine = PIIEngine()
    for entity_type, labels, values in specifications:
        cases = tuple(generate_mutations(entity_type, labels, values, limit=300))
        total += len(cases)
        detected += sum(
            entity_type in {finding.entity_type for finding in engine.scan(case.text).findings}
            for case in cases
        )
    assert total == 1200
    assert detected / total >= 0.98


def test_new_findings_remain_value_minimised_and_reach_redaction_adapter():
    raw = "citizen_number: 00199281X"
    result = PIIEngine().scan(raw)
    public = result.public_dict()

    assert "00199281X" not in str(public)
    assert result.redaction_map()["government_id"] == ["00199281X"]
    assert "00199281X" not in str(result.safe_debug_report())
    assert result.safe_debug_report()["values_disclosed"] is False
