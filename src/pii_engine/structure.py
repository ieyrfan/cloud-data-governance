"""Small structural grammar that emits label/value observations with offsets."""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass

from src.pii_engine.field_semantics import classify_field


@dataclass(frozen=True)
class FieldObservation:
    label: str
    value: str
    value_start: int
    value_end: int
    structure: str
    distance: int = 0


WRAPPER_CHARS = " \t\r\n:'\"`[]{}()<>,;"
INLINE_FIELD = re.compile(
    r"(?im)(?:^|[,{;])\s*[\"']?(?P<label>[\w][\w .\-/\[\]]{0,70}?)[\"']?\s*"
    r"(?P<separator>::?|==?|\||=>|,|[-\u2013\u2014/]|\uff1a|\uff1d)\s*"
    r"[\"'`\[({<]*(?P<value>[^\r\n,;}<]{1,160})"
)
XML_FIELD = re.compile(
    r"(?is)<(?P<label>[A-Za-z_][\w:.-]{0,70})\b[^>]*>\s*(?P<value>[^<]{1,160})\s*</(?P=label)>"
)
HTML_PAIR = re.compile(
    r"(?is)<(?:label|th|dt|span)\b[^>]*>\s*(?P<label>[^<]{1,80})\s*</(?:label|th|dt|span)>"
    r"\s*<(?:input\b[^>]*value=[\"'](?P<input>[^\"']+)[\"'][^>]*|(?:td|dd|span)\b[^>]*>(?P<value>[^<]+)</(?:td|dd|span)>)"
)
HTML_INPUT = re.compile(r"(?is)<input\b(?P<attrs>[^>]{1,500})>")
HTML_ATTR = re.compile(r"(?is)\b(?P<name>name|id|aria-label|placeholder|value)\s*=\s*([\"'])(?P<value>.*?)\2")
FIELD_SEPARATOR = re.compile(r"::|==|=>|[:=|,\-/\u2013\u2014\uff1a\uff1d]")


def _trimmed_span(source: str, start: int, end: int) -> tuple[str, int, int]:
    raw = source[start:end]
    left = len(raw) - len(raw.lstrip(WRAPPER_CHARS))
    right = len(raw.rstrip(WRAPPER_CHARS))
    return raw[left:right], start + left, start + right


def _append(
    output: list[FieldObservation], source: str, label: str, start: int, end: int,
    structure: str, distance: int = 0,
) -> None:
    if classify_field(label) is None:
        return
    value, value_start, value_end = _trimmed_span(source, start, end)
    if value and len(value) <= 500:
        output.append(FieldObservation(label.strip(), value, value_start, value_end, structure, distance))


def _line_observations(source: str) -> list[FieldObservation]:
    output: list[FieldObservation] = []
    lines = list(re.finditer(r"[^\r\n]*(?:\r?\n|$)", source))
    for index, line_match in enumerate(lines):
        line = line_match.group().rstrip("\r\n")
        if not line.strip():
            continue
        semantic_splits = []
        for separator in FIELD_SEPARATOR.finditer(line):
            label = line[: separator.start()].strip(WRAPPER_CHARS)
            nested_separator = any(character in label for character in ":=|,\uff1a\uff1d")
            if (
                not nested_separator
                and not any(character.isdigit() for character in label)
                and classify_field(label) is not None
            ):
                semantic_splits.append((len(label), label, separator.end()))
        if semantic_splits:
            _, label, value_offset = max(semantic_splits)
            if line[value_offset:].strip(WRAPPER_CHARS):
                start = line_match.start() + value_offset
                _append(output, source, label, start, line_match.start() + len(line), "key_value")
                continue

        inline = INLINE_FIELD.search(line)
        if inline and classify_field(inline.group("label")):
            start = line_match.start() + inline.start("value")
            end = line_match.start() + inline.end("value")
            _append(output, source, inline.group("label"), start, end, "key_value")
            continue

        label_candidates = []
        for width in range(1, 4):
            parts = [item.group().strip(WRAPPER_CHARS) for item in lines[index : index + width]]
            if len(parts) != width or any(not part or any(character.isdigit() for character in part) for part in parts):
                break
            combined = " ".join(parts)
            if classify_field(combined) is not None:
                label_candidates.append((width, combined))
        if not label_candidates:
            continue
        width, label = max(label_candidates)
        for distance, next_match in enumerate(lines[index + width : index + width + 3], start=1):
            candidate = next_match.group().strip()
            if not candidate:
                continue
            if classify_field(candidate) is not None:
                break
            _append(output, source, label, next_match.start(), next_match.start() + len(next_match.group().rstrip("\r\n")), "multiline", distance)
            break
    return output


def _markup_observations(source: str) -> list[FieldObservation]:
    output: list[FieldObservation] = []
    for match in XML_FIELD.finditer(source):
        _append(output, source, match.group("label"), match.start("value"), match.end("value"), "xml")
    for match in HTML_PAIR.finditer(source):
        group = "input" if match.group("input") is not None else "value"
        _append(output, source, match.group("label"), match.start(group), match.end(group), "html_relation")
    for match in HTML_INPUT.finditer(source):
        attributes = {item.group("name").casefold(): item for item in HTML_ATTR.finditer(match.group("attrs"))}
        value = attributes.get("value")
        label = next((attributes.get(name) for name in ("aria-label", "name", "placeholder", "id") if attributes.get(name)), None)
        if not value or not label:
            continue
        base = match.start("attrs")
        _append(output, source, label.group("value"), base + value.start("value"), base + value.end("value"), "html_attribute")
    return output


def _csv_observations(source: str) -> list[FieldObservation]:
    output: list[FieldObservation] = []
    lines = source.splitlines()
    if len(lines) < 2:
        return output
    for delimiter in (",", ";", "\t", "|"):
        try:
            rows = list(csv.reader(io.StringIO(source), delimiter=delimiter, strict=True))
        except csv.Error:
            continue
        if len(rows) < 2 or len(rows[0]) < 2:
            continue
        headers = rows[0]
        if not any(classify_field(header) for header in headers):
            continue
        cursor = len(lines[0])
        for row in rows[1:]:
            for index, value in enumerate(row):
                if index >= len(headers) or not value or classify_field(headers[index]) is None:
                    continue
                found = source.find(value, cursor)
                if found >= 0:
                    _append(output, source, headers[index], found, found + len(value), "csv")
            cursor += sum(len(value) for value in row) + len(row)
        break
    return output


def _json_observations(source: str) -> list[FieldObservation]:
    """Walk nested JSON and use the semantic path as field evidence."""
    try:
        payload = json.loads(source)
    except (json.JSONDecodeError, TypeError):
        return []
    output: list[FieldObservation] = []
    cursor = 0

    def visit(value, path: tuple[str, ...]) -> None:
        nonlocal cursor
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, (*path, str(key)))
            return
        if isinstance(value, list):
            for child in value:
                visit(child, path)
            return
        if value is None or isinstance(value, bool):
            return
        rendered = str(value)
        labels = [path[-1] if path else "", " ".join(path[-2:]), " ".join(path)]
        label = next((item for item in labels if classify_field(item)), "")
        if not label:
            return
        found = source.find(rendered, cursor)
        if found < 0:
            found = source.find(rendered)
        if found >= 0:
            _append(output, source, label, found, found + len(rendered), "json")
            cursor = found + len(rendered)

    visit(payload, ())
    return output


def discover_field_observations(source: str) -> list[FieldObservation]:
    """Parse once, deduplicate by source span and preserve exact redaction offsets."""
    observations = [
        *_line_observations(source),
        *_markup_observations(source),
        *_csv_observations(source),
        *_json_observations(source),
    ]
    unique: dict[tuple[int, int, str], FieldObservation] = {}
    for observation in observations:
        semantic = classify_field(observation.label)
        if semantic:
            unique.setdefault((observation.value_start, observation.value_end, semantic.entity_type), observation)
    return sorted(unique.values(), key=lambda item: (item.value_start, item.value_end))


__all__ = ["FieldObservation", "discover_field_observations"]
