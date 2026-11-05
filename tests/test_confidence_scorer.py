import os
import sys

# Add src to Python path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.classifiers.confidence_scorer import (
    calculate_confidence_score,
    determine_sensitivity_level,
)


def test_calculate_confidence_score():
    # High confidence (patterns + context keywords)
    patterns = {"my_ic": ["900101-14-5555"]}
    comprehend = []

    score = calculate_confidence_score(
        pattern_matches=patterns, comprehend_matches=comprehend, context_keywords_found=True
    )
    assert score == 0.7  # 0.4 (pattern) + 0.3 (context)


def test_determine_sensitivity_level():
    patterns = {"my_ic": ["900101-14-5555"]}
    assert determine_sensitivity_level(patterns, []) == "RESTRICTED"

    patterns = {"email": ["test@test.com"]}
    assert determine_sensitivity_level(patterns, []) == "CONFIDENTIAL"

    assert determine_sensitivity_level({}, []) == "PUBLIC"


def test_compact_malaysian_nric_is_restricted():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    patterns = find_sensitive_patterns("NRIC : 900101145555")

    assert patterns["my_ic"] == ["900101145555"]
    assert determine_sensitivity_level(patterns, []) == "RESTRICTED"


def test_spaced_or_dotted_malaysian_nric_cannot_bypass_detection():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    for value in ("900101 14 5555", "900101.14.5555"):
        patterns = find_sensitive_patterns(f"Identity: {value}")
        assert patterns["my_ic"] == [value]
        assert determine_sensitivity_level(patterns, []) == "RESTRICTED"


def test_unlabelled_malaysian_address_lines_are_confidential():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    text = "No. 8, Lorong Permata 7/3, Bandar Permata Lunas\n09600 Lunas, Kedah, Malaysia"
    patterns = find_sensitive_patterns(text)

    assert patterns["address"] == [
        "No. 8, Lorong Permata 7/3, Bandar Permata Lunas",
        "09600 Lunas, Kedah, Malaysia",
    ]
    assert determine_sensitivity_level(patterns, []) == "CONFIDENTIAL"


def test_city_state_address_without_postcode_is_detected_inside_contact_line():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    patterns = find_sensitive_patterns(
        "Bandar Botanic, Klang, Selangor | +6012-3456789 | user@example.com"
    )

    assert "Bandar Botanic, Klang, Selangor" in patterns["address"]
    assert determine_sensitivity_level(patterns, []) == "CONFIDENTIAL"


def test_common_non_address_numbers_do_not_trigger_address_detection():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    patterns = find_sensitive_patterns("Course BITS2555 received 83 marks in semester 2.")

    assert patterns["address"] == []


def test_labelled_passport_and_date_of_birth_are_detected():
    from src.classifiers.pattern_matcher import find_sensitive_patterns

    patterns = find_sensitive_patterns("Passport No: A12345678\nDate of Birth: 04-05-2002")

    assert patterns["government_id"] == ["A12345678"]
    assert patterns["date_of_birth"] == ["04-05-2002"]
    assert determine_sensitivity_level(patterns, []) == "RESTRICTED"
