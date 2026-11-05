import pytest

from src.classifiers.document_type_classifier import classify_document_type


@pytest.mark.parametrize(
    ("filename", "text", "expected"),
    [
        ("passport-demo.jpg", "PASSPORT NATIONALITY DATE OF BIRTH ISSUING AUTHORITY", "PASSPORT"),
        ("mykad-scan.jpg", "KAD PENGENALAN MALAYSIA WARGANEGARA", "IDENTITY"),
        ("candidate-resume.pdf", "Work Experience Technical Skills", "RESUME"),
        ("monthly-payslip.pdf", "Basic Salary Gross Pay Net Pay EPF SOCSO", "PAYSLIP"),
        ("MRK_0037.pdf", "EXAMINATION RESULT SLIP COURSE CODE CGPA", "ACADEMIC_RESULT"),
        ("vendor-invoice.pdf", "Invoice No. Bill To Amount Due Subtotal", "INVOICE"),
        ("employment-contract.pdf", "This agreement contains terms and conditions", "CONTRACT"),
        ("award-certificate.pdf", "This is to certify has successfully completed", "CERTIFICATE"),
        ("application-form.pdf", "Borang Permohonan Applicant Signature", "FORM"),
        ("security-report.pdf", "Executive Summary Methodology Findings and Recommendations", "REPORT"),
        ("notes.txt", "ordinary uncategorised notes", "OTHER"),
    ],
)
def test_document_type_rules(filename, text, expected):
    result = classify_document_type(text, filename)
    assert result["key"] == expected
    assert result["label"]
    assert 0 <= result["confidence"] <= 1
    assert result["signals"]


def test_document_type_metadata_does_not_copy_source_values():
    secret = "900101-14-1234"
    result = classify_document_type(f"KAD PENGENALAN MALAYSIA {secret}", "identity.png")
    assert result["key"] == "IDENTITY"
    assert secret not in str(result)
