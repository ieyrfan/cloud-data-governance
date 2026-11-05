import json
from pathlib import Path

import pytest

from src.classifiers.pattern_matcher import discover_sensitive_data

CORPUS_DIR = Path(__file__).parent / "fixtures" / "generated_false_flag_corpus"
MANIFEST = CORPUS_DIR / "manifest.json"


@pytest.mark.parametrize(
    "case",
    json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else [],
    ids=lambda case: case["id"],
)
def test_generated_corpus(case):
    text = (CORPUS_DIR / case["file"]).read_text(encoding="utf-8")
    categories = {
        category
        for category, values in discover_sensitive_data(text).redaction_map().items()
        if values
    }
    if case["benign"]:
        assert not categories.intersection({"name", "my_phone", "address", "ip_address", "gps_coordinates"})
    else:
        assert categories
