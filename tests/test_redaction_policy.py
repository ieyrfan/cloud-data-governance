import pytest

from src.governance.redaction_policy import (
    RedactionPolicyError,
    apply_policy,
    normalize_policy,
    policy_from_metadata,
    public_policy_metadata,
)


def test_safe_default_redacts_every_supported_category():
    policy = normalize_policy(None)
    selected, kept = apply_policy(
        {"name": ["Synthetic Name"], "my_phone": ["0123456789"]}, policy
    )
    assert kept == []
    assert "person_name" in selected
    assert "my_phone" in selected


def test_keep_requires_confirmation_and_does_not_store_values():
    policy = normalize_policy({"my_phone": "KEEP"}, confirmed=True)
    selected, kept = apply_policy(
        {"name": ["Synthetic Name"], "my_phone": ["0123456789"]}, policy
    )
    assert "0123456789" not in selected.get("my_phone", [])
    assert kept == ["my_phone"]

    with pytest.raises(RedactionPolicyError):
        normalize_policy({"my_phone": "KEEP"}, confirmed=False)


def test_high_risk_categories_cannot_be_kept_or_unknown_categories_accepted():
    with pytest.raises(RedactionPolicyError):
        normalize_policy({"my_ic": "KEEP"}, confirmed=True)
    with pytest.raises(RedactionPolicyError):
        normalize_policy({"unsupported": "KEEP"}, confirmed=True)


def test_uploaded_policy_metadata_must_match_all_categories_and_confirmation():
    policy = normalize_policy({"my_phone": "KEEP"}, confirmed=True)
    metadata = public_policy_metadata(policy, confirmed=True)
    assert policy_from_metadata(metadata)[0] == policy
    with pytest.raises(RedactionPolicyError):
        policy_from_metadata({**metadata, "confirmed": False})
    with pytest.raises(RedactionPolicyError):
        policy_from_metadata({**metadata, "redact_categories": []})
    with pytest.raises(RedactionPolicyError):
        policy_from_metadata({**metadata, "keep_categories": ["my_phone", "email", "email"]})
