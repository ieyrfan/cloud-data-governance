from src.classifiers.pattern_matcher import find_sensitive_patterns, redact_sensitive_data
from src.governance.policy_engine import simulate_policy


def test_identity_document_is_restricted_when_ocr_value_pattern_is_missed():
    decision = simulate_policy(
        "malaysia-general",
        [],
        extraction_complete=True,
        document_type="IDENTITY",
    )

    assert decision["decision"] == "RESTRICTED"
    assert decision["policy_id"] == "DS-DOCUMENT-002"
    assert decision["human_review_required"] is True
    assert decision["protected_copy_required"] is True


def test_sensitive_document_categories_never_default_to_public():
    for document_type in ("PAYSLIP", "ACADEMIC_RESULT", "RESUME", "FORM"):
        decision = simulate_policy(
            "malaysia-general",
            [],
            extraction_complete=True,
            document_type=document_type,
        )
        assert decision["decision"] == "CONFIDENTIAL"
        assert decision["policy_id"] == "DS-DOCUMENT-003"


def test_malay_multiline_address_is_detected_until_next_section():
    text = """NAMA: Synthetic Student
ALAMAT:
Blok B-12-3, Pangsapuri Harmoni
Peti Surat 88
43000 Kajang, Selangor
FAKULTI: Teknologi Maklumat
"""

    findings = find_sensitive_patterns(text)

    assert "Blok B-12-3, Pangsapuri Harmoni" in findings["address"]
    assert "Peti Surat 88" in findings["address"]
    assert "43000 Kajang, Selangor" in findings["address"]
    assert all("Teknologi Maklumat" not in value for value in findings["address"])
    protected = redact_sensitive_data(text, findings)
    assert "Pangsapuri Harmoni" not in protected
    assert "Peti Surat 88" not in protected
    assert "43000 Kajang" not in protected
    assert "Synthetic Student" in protected


def test_labelled_rural_address_and_po_box_are_detected():
    text = """Address: No. 7, Kampung Sungai Dua
P.O. Box 123
06700 Pendang, Kedah
Phone: 012-3456789
"""

    findings = find_sensitive_patterns(text)

    assert "No. 7, Kampung Sungai Dua" in findings["address"]
    assert "P.O. Box 123" in findings["address"]
    assert "06700 Pendang, Kedah" in findings["address"]
    assert all("012-3456789" not in value for value in findings["address"])
