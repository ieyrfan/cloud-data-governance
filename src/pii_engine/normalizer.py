from __future__ import annotations

import unicodedata
from array import array
from dataclasses import dataclass

PUNCTUATION_MAP = {
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
    "\uff0f": "/",
    "\uff1a": ":",
    "\uff1d": "=",
    "\uff08": "(",
    "\uff09": ")",
}
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}


@dataclass(frozen=True)
class NormalizedText:
    original: str
    text: str
    offset_map: array

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if not self.offset_map or start >= len(self.offset_map):
            return 0, 0
        safe_end = min(max(end - 1, start), len(self.offset_map) - 1)
        return self.offset_map[start], self.offset_map[safe_end] + 1


def normalize_with_offsets(text: str) -> NormalizedText:
    """Normalize OCR-hostile Unicode while preserving an exact source offset map."""
    normalized: list[str] = []
    offsets = array("I")
    for index, character in enumerate(str(text or "")):
        if character in ZERO_WIDTH:
            continue
        replacement = PUNCTUATION_MAP.get(character, character)
        replacement = unicodedata.normalize("NFKC", replacement)
        if replacement.isspace() and replacement not in {"\n", "\r"}:
            replacement = " "
        for output_character in replacement:
            normalized.append(output_character)
            offsets.append(index)
    return NormalizedText(str(text or ""), "".join(normalized), offsets)
