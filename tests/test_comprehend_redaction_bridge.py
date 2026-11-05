from src.classifiers.confidence_scorer import determine_sensitivity_level
from src.handlers.s3_classifier import _merge_comprehend_patterns


def test_high_confidence_comprehend_entities_become_redactable_patterns():
    text = "Student Muhammad Faris lives at 10 Jalan Merdeka."
    name_start = text.index("Muhammad")
    address_start = text.index("10 Jalan")
    entities = [
        {"Type": "NAME", "Score": 0.99, "BeginOffset": name_start, "EndOffset": name_start + 14},
        {"Type": "ADDRESS", "Score": 0.98, "BeginOffset": address_start, "EndOffset": len(text) - 1},
    ]

    patterns = _merge_comprehend_patterns(text, {}, entities)

    assert patterns == {
        "name": ["Muhammad Faris"],
        "address": ["10 Jalan Merdeka"],
    }
    assert determine_sensitivity_level(patterns, entities) == "CONFIDENTIAL"


def test_low_confidence_or_invalid_offsets_are_not_trusted():
    patterns = _merge_comprehend_patterns(
        "ordinary text",
        {},
        [
            {"Type": "NAME", "Score": 0.4, "BeginOffset": 0, "EndOffset": 8},
            {"Type": "ADDRESS", "Score": 0.99, "BeginOffset": -1, "EndOffset": 8},
        ],
    )

    assert patterns == {}
