import os
import sys

# Add src to Python path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.classifiers.pattern_matcher import (
    find_sensitive_patterns,
    is_luhn_valid,
    redact_sensitive_data,
)


def test_luhn_valid_credit_card():
    # Valid test CC number according to Luhn algorithm
    assert is_luhn_valid("49927398716")
    # Invalid
    assert not is_luhn_valid("49927398717")


def test_find_sensitive_patterns_my_ic():
    text = "User provided the IC number 900101-14-5555 for registration."
    results = find_sensitive_patterns(text)
    assert "900101-14-5555" in results["my_ic"]


def test_invalid_calendar_date_is_not_accepted_as_nric():
    results = find_sensitive_patterns("Impossible NRIC 990231-14-5555")
    assert results["my_ic"] == []


def test_find_sensitive_patterns_my_phone():
    text = "Call me at 012-3456789, 011-12345678, or +60 12-7654321."
    results = find_sensitive_patterns(text)
    assert "012-3456789" in results["my_phone"]
    assert "011-12345678" in results["my_phone"]
    assert "+60 12-7654321" in results["my_phone"]


def test_find_sensitive_patterns_email():
    text = "Contact support@example.com or owner@example.technology for more info."
    results = find_sensitive_patterns(text)
    assert "support@example.com" in results["email"]
    assert "owner@example.technology" in results["email"]


def test_find_sensitive_patterns_no_match():
    text = "This is a clean document with no sensitive data."
    results = find_sensitive_patterns(text)
    assert len(results["my_ic"]) == 0
    assert len(results["my_phone"]) == 0
    assert len(results["email"]) == 0
    assert len(results["credit_card"]) == 0


def test_unlabelled_person_like_prose_is_not_promoted_to_automatic_redaction():
    results = find_sensitive_patterns(
        "Jordan reviewed the Apple finance report for the May 2026 meeting."
    )

    assert results["name"] == []


def test_labelled_person_name_remains_eligible_for_automatic_redaction():
    results = find_sensitive_patterns("Name: Jordan Example")

    assert results["name"] == ["Jordan Example"]


def test_unlabelled_ip_and_coordinates_are_not_promoted_to_redaction():
    results = find_sensitive_patterns(
        "The test server 192.168.1.10 reported coordinates 3.1390, 101.6869."
    )

    assert results["ip_address"] == []
    assert results["gps_coordinates"] == []


def test_unlabelled_phone_is_detected_but_not_promoted_to_automatic_redaction():
    results = find_sensitive_patterns("The report mentions 012-3456789 as a test value.")

    assert results["my_phone"] == []


def test_labelled_phone_remains_eligible_for_automatic_redaction():
    results = find_sensitive_patterns("Contact phone: 012-3456789")

    assert results["my_phone"] == ["012-3456789"]


def test_formatted_credit_card_is_redacted():
    text = "Test card 4111 1111 1111 1111 must not remain visible."
    results = find_sensitive_patterns(text)
    assert results["credit_card"] == ["4111 1111 1111 1111"]
    assert (
        redact_sensitive_data(text, results) == "Test card [REDACTED - CC] must not remain visible."
    )


def test_labelled_malaysian_government_and_bank_identifiers_are_detected():
    text = "EPF NO: 12345678901\nBANK ACCOUNT NO: 1234 5678 9012"
    results = find_sensitive_patterns(text)
    assert results["government_id"] == ["12345678901"]
    assert results["financial_account"] == ["1234 5678 9012"]


def test_multiline_malay_and_english_birth_dates_are_detected():
    text = (
        "Tarikh Lahir\n14/02/1998\n"
        "Date of Birth\n1999-03-15\n"
        "D.O.B.: 16 February 2000\n"
        "Birth Date: March 17, 2001"
    )

    results = find_sensitive_patterns(text)

    assert results["date_of_birth"] == [
        "14/02/1998",
        "1999-03-15",
        "16 February 2000",
        "March 17, 2001",
    ]


def test_invalid_or_unlabelled_dates_are_not_treated_as_birth_dates():
    text = "Report date: 14/02/1998\nTarikh Lahir\n31/02/2000"

    assert find_sensitive_patterns(text)["date_of_birth"] == []


def test_numbered_field_labels_are_not_false_positive_addresses():
    text = "No. Telefon: 012-3456789\nNo. Pekerja: EMP-202601\nNo. 12, Jalan Damai"

    results = find_sensitive_patterns(text)

    assert results["address"] == ["No. 12, Jalan Damai"]
    assert results["my_phone"] == ["012-3456789"]


def test_multiline_labelled_synthetic_ids_and_phone_placeholders_are_protected():
    text = (
        "Synthetic IC / NRIC\nIC-SYN-000001\n"
        "Mobile Number\n+60 1X-0000-0001\n"
        "Employee ID\nEMP-SYN-1001\n"
        "Emergency Contact Number\n+60 1X-9999-0001"
    )

    results = find_sensitive_patterns(text)

    assert results["government_id"] == ["IC-SYN-000001", "EMP-SYN-1001"]
    assert results["my_phone"] == ["+60 1X-0000-0001", "+60 1X-9999-0001"]


def test_empty_label_does_not_consume_the_next_field_label_as_a_value():
    text = "Employee ID\nDate of Birth\n2000-07-23"

    results = find_sensitive_patterns(text)

    assert results["government_id"] == []
    assert results["date_of_birth"] == ["2000-07-23"]
