import json
from pathlib import Path

import pytest

from src.classifiers.pattern_matcher import discover_sensitive_data

CORPUS_PATH = Path(__file__).parent / "fixtures" / "false_positive_corpus.json"


def _category_map(text):
    return discover_sensitive_data(text).redaction_map()


@pytest.mark.parametrize(
    "case",
    json.loads(CORPUS_PATH.read_text(encoding="utf-8")),
    ids=lambda case: case["id"],
)
def test_false_positive_corpus(case):
    results = _category_map(case["text"])
    categories = {category for category, values in results.items() if values}

    assert set(case["must_redact"]).issubset(categories)
    assert not categories.intersection(case["must_keep"])
