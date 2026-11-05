"""Safe, content-free selective redaction policy handling."""

from __future__ import annotations

from collections.abc import Mapping

# These are detector keys already emitted by the existing regex/OCR/PII stack.
SUPPORTED_REDACTION_CATEGORIES = frozenset(
    {
        "name",
        "my_ic",
        "government_id",
        "passport_number",
        "my_phone",
        "address",
        "email",
        "financial_account",
        "credit_card",
        "date_of_birth",
        "matric_number",
        "employee_id",
        "patient_id",
        "customer_id",
        "user_identifier",
        "ip_address",
        "mac_address",
        "gps_coordinates",
        "secret",
        "private_key",
        "aws_access_key",
    }
)

# Credentials and payment/identity secrets may never be retained by a customer
# supplied KEEP policy.  This is an additional safety boundary, not a detector.
NON_KEEPABLE_CATEGORIES = frozenset(
    {"my_ic", "government_id", "passport_number", "credit_card", "secret", "private_key", "aws_access_key"}
)


class RedactionPolicyError(ValueError):
    """Raised when a customer policy is invalid or unsafe."""


def normalize_policy(policy: Mapping[str, str] | None, *, confirmed: bool = False) -> dict[str, str]:
    supplied = dict(policy or {})
    unknown = sorted(set(supplied) - SUPPORTED_REDACTION_CATEGORIES)
    if unknown:
        raise RedactionPolicyError("The redaction policy contains an unsupported category.")
    result = {category: "REDACT" for category in SUPPORTED_REDACTION_CATEGORIES}
    for category, action in supplied.items():
        value = str(action).upper().strip()
        if value not in {"REDACT", "KEEP"}:
            raise RedactionPolicyError("Redaction actions must be REDACT or KEEP.")
        if value == "KEEP" and category in NON_KEEPABLE_CATEGORIES:
            raise RedactionPolicyError("This sensitive category cannot be configured as KEEP.")
        result[category] = value
    if any(value == "KEEP" for value in result.values()) and not confirmed:
        raise RedactionPolicyError("KEEP categories require explicit confirmation.")
    return result


def apply_policy(pattern_matches: Mapping[str, list[str]], policy: Mapping[str, str]) -> tuple[dict[str, list[str]], list[str]]:
    """Return matches to redact and detected categories retained by policy."""
    selected: dict[str, list[str]] = {}
    kept: list[str] = []
    for category, matches in pattern_matches.items():
        if not matches:
            continue
        action = str(policy.get(category, "REDACT")).upper()
        if action == "KEEP":
            kept.append(category)
            continue
        # The legacy redactor intentionally keeps `name` visible in reviewer
        # copies. A private adapter key lets the existing engine redact names
        # when the customer explicitly selected REDACT without changing the
        # detector or its historical default behaviour.
        output_category = "person_name" if category == "name" else category
        selected[output_category] = list(matches)
    return selected, sorted(set(kept))


def public_policy_metadata(policy: Mapping[str, str], *, confirmed: bool) -> dict:
    return {
        "redact_categories": sorted(category for category, action in policy.items() if action == "REDACT"),
        "keep_categories": sorted(category for category, action in policy.items() if action == "KEEP"),
        "policy_version": "DS-REDACTION-POLICY-1",
        "confirmed": bool(confirmed),
    }


def policy_from_metadata(metadata: object) -> tuple[dict[str, str], dict]:
    """Verify that the uploaded object carries only an intact, supported policy."""
    if not isinstance(metadata, dict) or set(metadata) != {
        "redact_categories", "keep_categories", "policy_version", "confirmed"
    }:
        raise RedactionPolicyError("Invalid redaction policy metadata.")
    if metadata["policy_version"] != "DS-REDACTION-POLICY-1" or not isinstance(metadata["confirmed"], bool):
        raise RedactionPolicyError("Unsupported redaction policy version or confirmation.")
    redact, keep = metadata["redact_categories"], metadata["keep_categories"]
    if not isinstance(redact, list) or not isinstance(keep, list):
        raise RedactionPolicyError("Invalid redaction policy categories.")
    if any(not isinstance(category, str) for category in [*redact, *keep]):
        raise RedactionPolicyError("Invalid redaction policy categories.")
    if len(set([*redact, *keep])) != len(redact) + len(keep):
        raise RedactionPolicyError("Duplicate redaction policy category.")
    policy = normalize_policy({category: "KEEP" for category in keep}, confirmed=metadata["confirmed"])
    expected = public_policy_metadata(policy, confirmed=metadata["confirmed"])
    if metadata != expected:
        raise RedactionPolicyError("Incomplete or inconsistent redaction policy metadata.")
    return policy, expected
