"""Synthetic and adversarial coverage for the layered PII engine."""

from src.classifiers.pattern_matcher import discover_sensitive_data
from src.pii_engine import PIIEngine
from src.pii_engine.normalizer import normalize_with_offsets


def _types(result):
    return [finding.entity_type for finding in result.findings]


def test_normalization_preserves_original_offsets_through_unicode_noise():
    text = "NRIC\uff1a900101\u200b\u2010\u0031\u0034\u2010\u0035\u0035\u0035\u0035"
    normalized = normalize_with_offsets(text)

    assert "NRIC:900101-14-5555" == normalized.text
    start = normalized.text.index("900101")
    original_start, original_end = normalized.original_span(start, len(normalized.text))
    assert text[original_start:original_end] == "900101\u200b\u2010\u0031\u0034\u2010\u0035\u0035\u0035\u0035"


def test_adversarial_multiline_nric_is_detected_and_calendar_validated():
    text = "No. Kad\nPengenalan : 900101\n-\n14\n-\n5555"
    result = PIIEngine().scan(text)
    finding = next(item for item in result.findings if item.entity_type == "MALAYSIA_NRIC")

    assert finding.validation_status == "VALID"
    assert finding.confidence >= 0.88
    assert "date_validation" in finding.methods
    assert text[finding.start:finding.end].replace("\n", "").replace("-", "") == "900101145555"


def test_invalid_nric_remains_explainable_but_is_not_sent_for_redaction():
    result = PIIEngine().scan("NRIC: 990231-14-5555")
    finding = next(item for item in result.findings if item.entity_type == "MALAYSIA_NRIC")

    assert finding.validation_status == "INVALID"
    assert result.redaction_map().get("my_ic", []) == []


def test_structured_field_names_support_snake_camel_kebab_and_malay():
    text = (
        '"employee_number": "EMP-10291"\n'
        'staffId=STF/92381\n'
        'No Pekerja 10232\n'
        'student-id: STU-88291'
    )
    result = PIIEngine().scan(text)
    findings = {(item.entity_type, item.raw_value) for item in result.findings}

    assert ("EMPLOYEE_ID", "EMP-10291") in findings
    assert ("EMPLOYEE_ID", "STF/92381") in findings
    assert ("EMPLOYEE_ID", "10232") in findings
    assert ("STUDENT_ID", "STU-88291") in findings


def test_passport_is_generic_when_country_cannot_be_proven():
    result = PIIEngine().scan("No. Pasport: A12345678")
    finding = next(item for item in result.findings if item.entity_type == "PASSPORT_NUMBER")

    assert finding.entity_subtype == "GENERIC_PASSPORT_IDENTIFIER"
    assert finding.country is None
    assert finding.validation_status == "PLAUSIBLE"


def test_phone_variants_and_punctuation_wrapped_email_are_detected():
    text = "Mobile: (012) 345 6789; Email: <synthetic.person@example.com>,"
    result = PIIEngine().scan(text)

    assert "PHONE_NUMBER" in _types(result)
    assert "EMAIL_ADDRESS" in _types(result)


def test_dob_requires_birth_context_and_rejects_invalid_calendar_date():
    result = PIIEngine().scan(
        "created_at=2026-10-27\nTarikh Lahir: 31/02/2000\nDate of Birth: 2001-03-17"
    )
    dates = [item for item in result.findings if item.entity_type == "DATE_OF_BIRTH"]

    assert {item.raw_value for item in dates} == {"31/02/2000", "2001-03-17"}
    assert {item.raw_value for item in dates if item.validation_status == "INVALID"} == {"31/02/2000"}
    assert "2026-10-27" not in {item.raw_value for item in dates}


def test_name_and_address_require_context_and_multiple_address_signals():
    text = "Nama: Synthetic Person\nAlamat: No. 10, Jalan Example 3\n41200 Klang, Selangor"
    result = PIIEngine().scan(text)

    assert "PERSON_NAME" in _types(result)
    assert "POSTAL_ADDRESS" in _types(result)


def test_card_uses_luhn_and_random_long_number_is_suppressed():
    valid = PIIEngine().scan("Card Number: 4111 1111 1111 1111")
    invalid = PIIEngine().scan("build counter 4111 1111 1111 1112")

    assert "PAYMENT_CARD" in _types(valid)
    assert "PAYMENT_CARD" not in _types(invalid)


def test_uuid_requires_person_or_account_context():
    identifier = "123e4567-e89b-12d3-a456-426614174000"

    assert "USER_IDENTIFIER" not in _types(PIIEngine().scan(f"request_id={identifier}"))
    assert "USER_IDENTIFIER" in _types(PIIEngine().scan(f"user_id={identifier}"))


def test_secrets_are_masked_and_public_payload_never_contains_raw_value():
    text = "password=synthetic-secret-123\nAuthorization: Bearer abcdefghijklmnop123456"
    result = PIIEngine().scan(text)
    payload = result.public_dict()

    assert len([item for item in result.findings if item.entity_type == "SECRET"]) == 2
    assert "synthetic-secret-123" not in str(payload)
    assert "abcdefghijklmnop123456" not in str(payload)
    assert payload["values_disclosed"] is False


def test_cross_signal_correlation_raises_confidence_and_document_risk():
    text = (
        "Nama: Synthetic Person\n"
        "NRIC: 900101-14-5555\n"
        "Mobile: 012-3456789\n"
        "Email: synthetic.person@example.com\n"
        "Alamat: No. 10, Jalan Example 3\n41200 Klang, Selangor"
    )
    result = discover_sensitive_data(text)

    assert result.summary.total_findings >= 5
    assert result.summary.record_clusters >= 1
    assert result.summary.risk in {"HIGH", "CRITICAL"}
    assert any("cross_signal" in item.methods for item in result.findings)


def test_overlap_resolution_prefers_specific_nric_over_generic_identifier():
    result = discover_sensitive_data("NRIC: 900101-14-5555")
    matching = [item for item in result.findings if item.raw_value == "900101-14-5555"]

    assert len(matching) == 1
    assert matching[0].entity_type == "MALAYSIA_NRIC"


def test_public_finding_contains_explanation_location_and_mask_only():
    text = "Employee ID: EMP-10231"
    payload = PIIEngine().scan(text).public_dict()
    finding = payload["findings"][0]

    assert finding["line"] == 1
    assert finding["column"] > 1
    assert finding["confidence"] >= 0.9
    assert finding["explanation"]
    assert "EMP-10231" not in str(payload)
