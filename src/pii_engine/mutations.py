"""Deterministic synthetic mutation grammar for detector regression testing."""

from __future__ import annotations

import itertools
import random
import re
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class MutationCase:
    entity_type: str
    text: str
    family: str
    label: str


SEPARATORS = (":", " = ", "-", " / ", " | ", "\uff1a", "\uff1d", "\n", " :\n")


def _xml_wrapper(label: str, value: str) -> str:
    tag = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    return f"<{tag}>{value}</{tag}>"


WRAPPERS = (
    lambda label, value: f"{label}{{separator}}{value}",
    lambda label, value: f'"{label}"{{separator}}"{value}"',
    lambda label, value: f"{label}{{separator}}[{value}]",
    _xml_wrapper,
    lambda label, value: f'<input name="{label}" value="{value}">',
)


def field_name_variants(label: str) -> tuple[str, ...]:
    words = tuple(filter(None, re.split(r"[\s_.\-/]+", label)))
    if not words:
        return ()
    camel = words[0].casefold() + "".join(word[:1].upper() + word[1:].casefold() for word in words[1:])
    pascal = "".join(word[:1].upper() + word[1:].casefold() for word in words)
    values = {
        " ".join(words), "_".join(words), "-".join(words), ".".join(words),
        "/".join(words), camel, pascal, " ".join(words).upper(),
    }
    return tuple(sorted(values))


def generate_mutations(
    entity_type: str,
    labels: tuple[str, ...],
    values: tuple[str, ...],
    *,
    limit: int | None = None,
    seed: int = 20261027,
) -> Iterator[MutationCase]:
    """Lazily generate a reproducible cross-product without storing a pattern dump."""
    variants = tuple(
        (variant, value, separator, wrapper)
        for label in labels
        for variant in field_name_variants(label)
        for value, separator, wrapper in itertools.product(values, SEPARATORS, WRAPPERS)
    )
    if limit is not None and len(variants) > limit:
        variants = tuple(random.Random(seed).sample(variants, limit))
    for label, value, separator, wrapper in variants:
        template = wrapper(label, value)
        # XML and input wrappers do not contain the separator placeholder.
        text = template.replace("{separator}", separator)
        family = "markup" if text.startswith("<") else "multiline" if "\n" in text else "field"
        yield MutationCase(entity_type, text, family, label)


__all__ = ["MutationCase", "field_name_variants", "generate_mutations"]
