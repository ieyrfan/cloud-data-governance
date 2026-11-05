"""Versioned, value-free policy evaluation for previews and integrations."""

from dataclasses import dataclass

POLICY_VERSION = "2026.10-r1"


@dataclass(frozen=True)
class PolicyProfile:
    key: str
    label: str
    description: str
    restricted_signals: frozenset[str]
    confidential_signals: frozenset[str]
    original_access_minutes: int = 15


PROFILES = {
    "malaysia-general": PolicyProfile(
        key="malaysia-general",
        label="Malaysia general protection",
        description="Fail-closed protection for Malaysian identity, contact and financial data.",
        restricted_signals=frozenset(
            {
                "MY_IC",
                "MALAYSIAN_NRIC",
                "CREDIT_CARD",
                "PAYMENT_CARD",
                "FINANCIAL_ACCOUNT",
                "GOVERNMENT_ID",
                "PASSPORT_NUMBER",
                "AWS_ACCESS_KEY",
                "SECRET",
                "PRIVATE_KEY",
                "PATIENT_ID",
            }
        ),
        confidential_signals=frozenset(
            {
                "ADDRESS",
                "DATE_OF_BIRTH",
                "EMAIL",
                "EMAIL_ADDRESS",
                "MY_PHONE",
                "MALAYSIAN_PHONE",
                "MATRIC_NUMBER",
                "PHONE_NUMBER",
                "POSTAL_ADDRESS",
                "GPS_COORDINATES",
                "EMPLOYEE_ID",
                "STUDENT_ID",
                "CUSTOMER_ID",
                "USER_IDENTIFIER",
            }
        ),
    ),
    "external-review": PolicyProfile(
        key="external-review",
        label="External reviewer protection",
        description="Treat every detected personal signal as restricted before external review.",
        restricted_signals=frozenset(
            {
                "MY_IC",
                "MALAYSIAN_NRIC",
                "CREDIT_CARD",
                "PAYMENT_CARD",
                "FINANCIAL_ACCOUNT",
                "GOVERNMENT_ID",
                "ADDRESS",
                "DATE_OF_BIRTH",
                "EMAIL",
                "EMAIL_ADDRESS",
                "MY_PHONE",
                "MALAYSIAN_PHONE",
                "MATRIC_NUMBER",
                "NAME",
                "PASSPORT_NUMBER",
                "AWS_ACCESS_KEY",
                "SECRET",
                "PRIVATE_KEY",
                "PATIENT_ID",
                "PHONE_NUMBER",
                "POSTAL_ADDRESS",
                "GPS_COORDINATES",
                "EMPLOYEE_ID",
                "STUDENT_ID",
                "CUSTOMER_ID",
                "USER_IDENTIFIER",
            }
        ),
        confidential_signals=frozenset(),
        original_access_minutes=10,
    ),
}

PROFILE_ALIASES = {"malaysia-academic-record": "malaysia-general"}


def public_profiles() -> list[dict]:
    return [
        {
            "key": p.key,
            "label": p.label,
            "description": p.description,
            "policy_version": POLICY_VERSION,
            "original_access_minutes": p.original_access_minutes,
            "restricted_signal_types": sorted(p.restricted_signals),
            "confidential_signal_types": sorted(p.confidential_signals),
            "values_disclosed": False,
        }
        for p in PROFILES.values()
    ]


DOCUMENT_TYPE_BASELINES = {
    "IDENTITY": "RESTRICTED",
    "PAYSLIP": "CONFIDENTIAL",
    "ACADEMIC_RESULT": "CONFIDENTIAL",
    "RESUME": "CONFIDENTIAL",
    "FORM": "CONFIDENTIAL",
}


def simulate_policy(
    profile_key: str,
    signal_types: list[str],
    extraction_complete: bool,
    document_type: str = "OTHER",
) -> dict:
    profile = PROFILES.get(profile_key)
    if profile is None and profile_key in PROFILE_ALIASES:
        profile = PROFILES[PROFILE_ALIASES[profile_key]]
    if not profile:
        raise KeyError(profile_key)
    signals = {str(signal).strip().upper() for signal in signal_types if str(signal).strip()}
    document_type = str(document_type or "OTHER").strip().upper()
    document_baseline = DOCUMENT_TYPE_BASELINES.get(document_type)
    if not extraction_complete:
        decision, policy_id = "UNKNOWN", "DS-FAIL-CLOSED-001"
        reason = "Extraction was not complete, so the document must remain protected for review."
    elif signals & profile.restricted_signals:
        decision, policy_id = "RESTRICTED", "DS-MY-PII-004"
        reason = "At least one restricted signal type matched the selected protection profile."
    elif document_baseline == "RESTRICTED":
        decision, policy_id = "RESTRICTED", "DS-DOCUMENT-002"
        reason = "The recognized document category requires restricted handling even when OCR patterns are incomplete."
    elif signals & profile.confidential_signals or signals:
        decision, policy_id = "CONFIDENTIAL", "DS-DATA-003"
        reason = "Personal or organisation-sensitive signals require protected review."
    elif document_baseline == "CONFIDENTIAL":
        decision, policy_id = "CONFIDENTIAL", "DS-DOCUMENT-003"
        reason = "The recognized document category requires protected review even when no supported value pattern is detected."
    else:
        decision, policy_id = "PUBLIC", "DS-DATA-001"
        reason = "No supported sensitive signal type was supplied to the simulation."
    return {
        "profile": profile_key,
        "policy_id": policy_id,
        "policy_version": POLICY_VERSION,
        "decision": decision,
        "reason": reason,
        "detected_signal_types": sorted(signals),
        "document_type": document_type,
        "human_review_required": decision in {"RESTRICTED", "CONFIDENTIAL", "UNKNOWN"},
        "protected_copy_required": decision != "PUBLIC",
        "original_access_minutes": profile.original_access_minutes,
        "values_disclosed": False,
    }
