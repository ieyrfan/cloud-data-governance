from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import replace

from src.pii_engine.field_semantics import classify_field
from src.pii_engine.models import DetectionResult, Finding, ScanSummary
from src.pii_engine.normalizer import normalize_with_offsets
from src.pii_engine.rules import CATEGORY, CONTEXT_LABELS, SEVERITY
from src.pii_engine.structure import discover_field_observations

NRIC = re.compile(r"(?<!\d)(\d{6})[\s./-]*(\d{2})[\s./-]*(\d{4})(?!\d)")
EMAIL = re.compile(
    r"(?<![\w.+-])([A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63})(?![\w.-])",
    re.I,
)
PHONE = re.compile(
    r"(?<!\d)(?:\+?60[\s.-]*1\d|\(?01\d\)?)(?:[\s.-]*\d){7,8}(?!\d)"
)
GLOBAL_PHONE = re.compile(r"(?<![\w+])\+(?:\d[\s().-]*){7,15}(?!\d)")
LABELLED_GLOBAL_PHONE = re.compile(
    r"\+?[\d(](?:[\d\s().-]{5,}\d)(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?",
    re.I,
)
CARD = re.compile(r"(?<!\d)(?:\d[\s-]?){13,19}(?!\d)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{1,4}(?![\w:])", re.I)
MAC = re.compile(r"(?<![A-F0-9])(?:[A-F0-9]{2}[:-]){5}[A-F0-9]{2}(?![A-F0-9])", re.I)
GPS = re.compile(r"(?<!\d)([-+]?\d{1,2}\.\d{4,})\s*[,/]\s*([-+]?\d{1,3}\.\d{4,})(?!\d)")
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+([^\s,;]{12,})")
SECRET_KV = re.compile(
    r"(?im)\b(password|passwd|pwd|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token)"
    r"\s*[:=]\s*([^\s,;]{6,})"
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
DATE = re.compile(
    r"\b(?:\d{4}[./-]\d{1,2}[./-]\d{1,2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b"
)
GENERIC_ID_VALUE = re.compile(r"[A-Z0-9](?:[A-Z0-9 ./-]{2,38}[A-Z0-9])?", re.I)
PERSON_VALUE = re.compile(r"[A-Z][A-Z.'/-]+(?:\s+(?:BIN|BINTI|A/L|A/P|[A-Z][A-Z.'/-]+)){1,7}", re.I)
ADDRESS_HINT = re.compile(
    r"(?i)\b(?:no\.?\s*\d+|unit\s*[A-Z0-9-]+|jalan|jln\.?|lorong|persiaran|"
    r"lebuh|taman|kampung|kg\.?|bandar|seksyen|apartment|pangsapuri|condominium)\b"
)
POSTCODE_STATE = re.compile(
    r"(?i)\b\d{5}\b[^\n]{0,80}\b(?:johor|kedah|kelantan|melaka|negeri sembilan|"
    r"pahang|perak|perlis|pulau pinang|penang|sabah|sarawak|selangor|terengganu|"
    r"kuala lumpur|putrajaya|labuan)\b"
)

LEGACY_ENTITY_TYPES = {
    "my_ic": "MALAYSIA_NRIC",
    "my_phone": "PHONE_NUMBER",
    "email": "EMAIL_ADDRESS",
    "credit_card": "PAYMENT_CARD",
    "name": "PERSON_NAME",
    "address": "POSTAL_ADDRESS",
    "matric_number": "STUDENT_ID",
    "government_id": "GOVERNMENT_ID",
    "financial_account": "FINANCIAL_ACCOUNT",
    "date_of_birth": "DATE_OF_BIRTH",
}


def _line_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous_break = text.rfind("\n", 0, offset)
    return line, offset - previous_break


def _mask(entity_type: str, value: str) -> str:
    if entity_type == "EMAIL_ADDRESS" and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    alphanumeric = [index for index, character in enumerate(value) if character.isalnum()]
    visible_tail = 4 if entity_type in {"PAYMENT_CARD", "PASSPORT_NUMBER"} else 3
    keep = set(alphanumeric[-visible_tail:])
    if entity_type == "MALAYSIA_NRIC":
        keep = set(alphanumeric[:6])
    return "".join(character if index in keep or not character.isalnum() else "*" for index, character in enumerate(value))


def _luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _nric_plausible(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12:
        return False
    year, month, day = int(digits[:2]), int(digits[2:4]), int(digits[4:6])
    return any(_valid_date(century + year, month, day) for century in (1900, 2000))


def _valid_date(year: int, month: int, day: int) -> bool:
    from datetime import date

    try:
        date(year, month, day)
        return True
    except ValueError:
        return False


def _date_plausible(value: str) -> bool:
    parts = [int(part) for part in re.split(r"[./-]", value)]
    if len(parts) != 3:
        return False
    if len(str(parts[0])) == 4:
        year, month, day = parts
    else:
        day, month, year = parts
    if year < 100:
        year += 2000 if year < 30 else 1900
    return 1900 <= year <= 2100 and _valid_date(year, month, day)


def _nearby_label(text: str, start: int, entity_type: str, radius: int = 80) -> str:
    window = text[max(0, start - radius) : start].casefold()
    compact_window = re.sub(r"[\W_]+", "", window)
    labels = sorted(CONTEXT_LABELS.get(entity_type, ()), key=len, reverse=True)
    for label in labels:
        compact_label = re.sub(r"[\W_]+", "", label.casefold())
        if re.search(rf"(?:^|[^a-z0-9]){re.escape(label)}(?:[^a-z0-9]|$)", window) or (
            len(compact_label) >= 4 and compact_label in compact_window
        ):
            return label
    return ""


def _field_pattern(labels: tuple[str, ...]) -> re.Pattern:
    def flexible(label: str) -> str:
        tokens = re.split(r"[\s_-]+", label)
        return r"[\s_-]*".join(re.escape(token) for token in tokens)

    label_source = "|".join(flexible(label) for label in sorted(labels, key=len, reverse=True))
    return re.compile(
        rf"(?im)^[ \t]*[\"']?(?P<label>{label_source})[\"']?[ \t]*"
        rf"(?:no\.?|number)?[ \t]*[:=]?[ \t]*"
        rf"(?:(?P<value>[^\r\n]{{1,80}})|(?:\r?\n)[ \t]*(?P<next>[^\r\n]{{1,80}}))"
    )


def _identifier_candidate(value: str, *, letters_only_allowed: bool = False) -> bool:
    """Conservative generic identifier shape used only with strong field semantics."""
    candidate = value.strip(" \t\r\n:'\"`[]{}()<>,;")
    if not 2 <= len(candidate) <= 64 or "@" in candidate or "://" in candidate:
        return False
    if re.search(r"[^\w ./+-]", candidate, re.UNICODE):
        return False
    alphanumeric = [character for character in candidate if character.isalnum()]
    if len(alphanumeric) < 3:
        return False
    if not any(character.isdigit() for character in candidate):
        return letters_only_allowed and len(alphanumeric) >= 5
    return True


def _global_phone_plausible(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15 and len(set(digits)) > 1


def _person_name_plausible(value: str) -> bool:
    candidate = value.strip(" \t\r\n:'\"`[]{}()<>,;")
    if not 1 <= len(candidate.split()) <= 10 or not 2 <= len(candidate) <= 120:
        return False
    if any(character.isdigit() for character in candidate):
        return False
    letters = sum(character.isalpha() for character in candidate)
    if letters < 2 or letters / max(1, len(candidate.replace(" ", ""))) < 0.65:
        return False
    return all(
        character.isalpha() or character.isspace() or character in "-'./\u2019"
        for character in candidate
    )


INTERNATIONAL_ADDRESS_HINT = re.compile(
    r"(?i)\b(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|lane|ln\.?|"
    r"drive|dr\.?|parkway|highway|way|court|suite|apartment|building|block|unit|"
    r"jalan|jln\.?|lorong|persiaran|taman|kampung|kg\.?|bandar|郵便|住所|calle|rue|straße)\b"
)


def _address_plausible(value: str) -> bool:
    candidate = value.strip()
    if not 6 <= len(candidate) <= 500 or not any(character.isalpha() for character in candidate):
        return False
    components = len([part for part in re.split(r"[,\n]", candidate) if part.strip()])
    postal = bool(re.search(r"\b[A-Z0-9][A-Z0-9 -]{2,9}\b", candidate, re.I))
    return bool(INTERNATIONAL_ADDRESS_HINT.search(candidate)) or (
        any(character.isdigit() for character in candidate) and (components >= 2 or postal)
    )


class PIIEngine:
    """Layered local detector with optional seed findings from legacy/NLP detectors."""

    def scan(self, text: str, *, seed_matches: dict[str, list[str]] | None = None) -> DetectionResult:
        source = str(text or "")
        normalized = normalize_with_offsets(source)
        findings: list[Finding] = []
        findings.extend(self._seed_findings(source, seed_matches or {}))
        findings.extend(self._deterministic_findings(normalized.text, normalized.original_span, source))
        findings.extend(self._structured_findings(source))
        findings.extend(self._contextual_findings(source))
        findings = self._resolve_overlaps(findings)
        findings = self._apply_cross_signal(findings)
        return DetectionResult(tuple(findings), self._summarize(source, findings))

    def _finding(
        self,
        source: str,
        entity_type: str,
        value: str,
        start: int,
        end: int,
        *,
        confidence: float,
        methods: tuple[str, ...],
        validation: str,
        rule_id: str,
        context: str = "",
        subtype: str | None = None,
        country: str | None = None,
        explanation: tuple[str, ...] = (),
    ) -> Finding:
        line, column = _line_column(source, start)
        return Finding(
            entity_type=entity_type,
            entity_subtype=subtype or entity_type,
            category=CATEGORY.get(entity_type, "IDENTIFIER"),
            severity=SEVERITY.get(entity_type, "MEDIUM"),
            confidence=max(0.0, min(1.0, confidence)),
            raw_value=value,
            normalized_value=re.sub(r"[\s./()-]", "", value).casefold(),
            start=start,
            end=end,
            line=line,
            column=column,
            context=context,
            methods=methods,
            validation_status=validation,
            rule_id=rule_id,
            country=country,
            explanation=explanation,
            masked_value=_mask(entity_type, value),
        )

    def _seed_findings(self, source: str, seeds: dict[str, list[str]]) -> list[Finding]:
        findings = []
        occupied: set[tuple[str, int, int]] = set()
        for legacy_type, values in seeds.items():
            entity_type = LEGACY_ENTITY_TYPES.get(legacy_type, legacy_type.upper())
            for value in values:
                for match in re.finditer(re.escape(str(value)), source, re.I):
                    key = (entity_type, match.start(), match.end())
                    if key in occupied:
                        continue
                    occupied.add(key)
                    context = _nearby_label(source, match.start(), entity_type)
                    confidence = 0.94 if context else 0.82
                    findings.append(
                        self._finding(
                            source, entity_type, match.group(), match.start(), match.end(),
                            confidence=confidence,
                            methods=("legacy_pattern", "context") if context else ("legacy_pattern",),
                            validation="PLAUSIBLE",
                            rule_id=f"DS-SEED-{legacy_type.upper()}",
                            context=context,
                            country="MY" if entity_type in {"MALAYSIA_NRIC", "PHONE_NUMBER", "POSTAL_ADDRESS"} else None,
                            explanation=("Existing validated detector identified this value.",),
                        )
                    )
        return findings

    def _deterministic_findings(self, text: str, span_mapper, source: str) -> list[Finding]:
        findings = []
        specifications = (
            (EMAIL, "EMAIL_ADDRESS", 0.96, "VALID", "DS-CONTACT-EMAIL", ("pattern", "normalization")),
            (PHONE, "PHONE_NUMBER", 0.82, "PLAUSIBLE", "DS-CONTACT-PHONE-MY", ("pattern", "normalization", "country_format")),
            (MAC, "MAC_ADDRESS", 0.88, "VALID", "DS-NETWORK-MAC", ("pattern",)),
            (AWS_KEY, "AWS_ACCESS_KEY", 0.99, "PLAUSIBLE", "DS-SECRET-AWS-KEY", ("pattern", "credential_prefix")),
            (JWT, "SECRET", 0.99, "PLAUSIBLE", "DS-SECRET-JWT", ("pattern", "token_structure")),
            (PRIVATE_KEY, "PRIVATE_KEY", 1.0, "VALID", "DS-SECRET-PRIVATE-KEY", ("pattern", "block_marker")),
        )
        for pattern, entity_type, confidence, validation, rule_id, methods in specifications:
            for match in pattern.finditer(text):
                start, end = span_mapper(match.start(), match.end())
                value = source[start:end]
                findings.append(self._finding(source, entity_type, value, start, end, confidence=confidence, methods=methods, validation=validation, rule_id=rule_id, explanation=("Structure matches a validated detector rule.",)))

        for match in NRIC.finditer(text):
            start, end = span_mapper(match.start(), match.end())
            value = source[start:end]
            plausible = _nric_plausible(value)
            context = _nearby_label(source, start, "MALAYSIA_NRIC", 120)
            if not plausible and not context:
                continue
            score = 0.70 + (0.18 if plausible else -0.30) + (0.09 if context else 0)
            methods = ["normalization", "flexible_pattern"]
            if plausible:
                methods.append("date_validation")
            if context:
                methods.append("context")
            findings.append(self._finding(source, "MALAYSIA_NRIC", value, start, end, confidence=score, methods=tuple(methods), validation="VALID" if plausible else "INVALID", rule_id="DS-ID-MY-NRIC", context=context, subtype="MALAYSIA_NRIC", country="MY", explanation=("Twelve-digit Malaysian identity structure was detected.", "Embedded date is plausible." if plausible else "Embedded calendar date is invalid; candidate is not promoted to PII.")))

        for match in CARD.finditer(text):
            value = match.group().strip()
            if not _luhn(value):
                continue
            local_start = match.start() + len(match.group()) - len(match.group().lstrip())
            start, end = span_mapper(local_start, local_start + len(value))
            findings.append(self._finding(source, "PAYMENT_CARD", source[start:end], start, end, confidence=0.99, methods=("pattern", "normalization", "luhn_validation"), validation="VALID", rule_id="DS-FIN-CARD", explanation=("Card-length candidate passed Luhn validation.",)))

        for match in GLOBAL_PHONE.finditer(text):
            start, end = span_mapper(match.start(), match.end())
            value = source[start:end].rstrip()
            end = start + len(value)
            if not _global_phone_plausible(value):
                continue
            findings.append(self._finding(
                source, "PHONE_NUMBER", value, start, end,
                confidence=0.90,
                methods=("global_e164_shape", "normalization"),
                validation="PLAUSIBLE",
                rule_id="DS-CONTACT-PHONE-GLOBAL",
                subtype="INTERNATIONAL_PHONE",
                explanation=("Internationally prefixed phone candidate has a plausible digit length.",),
            ))

        for pattern, version in ((IPV4, 4), (IPV6, 6)):
            for match in pattern.finditer(text):
                try:
                    address = ipaddress.ip_address(match.group())
                except ValueError:
                    continue
                context = _nearby_label(source, match.start(), "IP_ADDRESS", 100)
                if not context and (address.is_private or address.is_loopback or address.is_link_local):
                    continue
                start, end = span_mapper(match.start(), match.end())
                findings.append(self._finding(source, "IP_ADDRESS", source[start:end], start, end, confidence=0.58 if not context else 0.78, methods=("pattern", "ip_validation") + (("context",) if context else ()), validation="VALID", rule_id=f"DS-NETWORK-IPV{version}", context=context, subtype=f"IPV{version}"))

        for match in GPS.finditer(text):
            latitude, longitude = float(match.group(1)), float(match.group(2))
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                continue
            start, end = span_mapper(match.start(), match.end())
            context = _nearby_label(source, start, "GPS_COORDINATES", 100)
            findings.append(self._finding(source, "GPS_COORDINATES", source[start:end], start, end, confidence=0.75 if not context else 0.92, methods=("pattern", "coordinate_validation") + (("context",) if context else ()), validation="VALID", rule_id="DS-LOCATION-GPS", context=context))

        for match in BEARER.finditer(text):
            start, end = span_mapper(match.start(1), match.end(1))
            findings.append(self._finding(source, "SECRET", source[start:end], start, end, confidence=0.99, methods=("context", "token_structure"), validation="PLAUSIBLE", rule_id="DS-SECRET-BEARER", context="authorization bearer"))
        for match in SECRET_KV.finditer(text):
            start, end = span_mapper(match.start(2), match.end(2))
            findings.append(self._finding(source, "SECRET", source[start:end], start, end, confidence=0.98, methods=("field_name", "context"), validation="PLAUSIBLE", rule_id="DS-SECRET-KEY-VALUE", context=match.group(1).casefold()))
        return findings

    def _structured_findings(self, source: str) -> list[Finding]:
        """Classify schema-aware values without relying on country-specific formats."""
        findings: list[Finding] = []
        identifier_types = {
            "GENERIC_NATIONAL_ID", "PASSPORT_NUMBER", "EMPLOYEE_ID", "STUDENT_ID",
            "PATIENT_ID", "CUSTOMER_ID", "DRIVING_LICENCE", "VISA_NUMBER",
            "RESIDENCE_PERMIT", "TAX_ID", "FINANCIAL_ACCOUNT", "USER_IDENTIFIER",
        }
        for observation in discover_field_observations(source):
            semantic = classify_field(observation.label)
            if semantic is None:
                continue
            entity_type = semantic.entity_type
            value = observation.value
            start, end = observation.value_start, observation.value_end
            validation = "PLAUSIBLE"
            subtype = entity_type
            country = None
            explanation = [
                f"Structured {observation.structure} field maps to {entity_type}.",
                "The field meaning is evidence even when the identifier format is unknown.",
            ]

            if entity_type in identifier_types:
                letters_only = entity_type == "PASSPORT_NUMBER"
                if not _identifier_candidate(value, letters_only_allowed=letters_only):
                    continue
                if entity_type == "PASSPORT_NUMBER":
                    subtype = "GENERIC_PASSPORT_IDENTIFIER"
                elif entity_type == "GENERIC_NATIONAL_ID":
                    subtype = "GENERIC_NATIONAL_ID"
            elif entity_type == "PHONE_NUMBER":
                phone_match = LABELLED_GLOBAL_PHONE.search(value)
                if not phone_match or not _global_phone_plausible(phone_match.group()):
                    continue
                start += phone_match.start()
                end = start + len(phone_match.group().rstrip())
                value = source[start:end]
                subtype = "INTERNATIONAL_PHONE"
            elif entity_type == "EMAIL_ADDRESS":
                email_match = EMAIL.search(value)
                if not email_match:
                    continue
                start += email_match.start()
                end = start + len(email_match.group())
                value = source[start:end]
                validation = "VALID"
            elif entity_type == "PERSON_NAME":
                if not _person_name_plausible(value):
                    continue
            elif entity_type == "POSTAL_ADDRESS":
                # A labelled multiline address may continue for several lines.
                line_end = end
                for _ in range(3):
                    if line_end >= len(source):
                        break
                    separator = re.match(r"\r?\n", source[line_end:])
                    if not separator:
                        break
                    next_start = line_end + len(separator.group())
                    next_end = source.find("\n", next_start)
                    if next_end < 0:
                        next_end = len(source)
                    next_line = source[next_start:next_end].strip()
                    if not next_line or classify_field(next_line):
                        break
                    line_end = next_end
                candidate = source[start:line_end].strip()
                if not _address_plausible(candidate):
                    continue
                value = candidate
                end = start + len(candidate)
                subtype = "INTERNATIONAL_POSTAL_ADDRESS"
            elif entity_type == "DATE_OF_BIRTH":
                date_match = DATE.search(value)
                if not date_match:
                    continue
                start += date_match.start()
                end = start + len(date_match.group())
                value = source[start:end]
                if not _date_plausible(value):
                    validation = "INVALID"
            else:
                continue

            distance_penalty = min(0.12, observation.distance * 0.04)
            confidence = semantic.confidence - distance_penalty
            findings.append(self._finding(
                source,
                entity_type,
                value,
                start,
                end,
                confidence=confidence,
                methods=("field_semantics", "structure", "shape_analysis"),
                validation=validation,
                rule_id=semantic.rule_id,
                context=semantic.normalized_label,
                subtype=subtype,
                country=country,
                explanation=tuple(explanation),
            ))
        return findings

    def _contextual_findings(self, source: str) -> list[Finding]:
        findings = []
        field_types = ("EMPLOYEE_ID", "STUDENT_ID", "PASSPORT_NUMBER", "FINANCIAL_ACCOUNT", "PATIENT_ID", "CUSTOMER_ID", "USER_IDENTIFIER")
        for entity_type in field_types:
            pattern = _field_pattern(CONTEXT_LABELS[entity_type])
            for match in pattern.finditer(source):
                value = (match.group("value") or "").strip(" :='\"")
                group_name = "value"
                if not value or not GENERIC_ID_VALUE.fullmatch(value) or not any(character.isdigit() for character in value):
                    value = (match.group("next") or "").strip(" :='\"")
                    group_name = "next"
                if not value or not GENERIC_ID_VALUE.fullmatch(value) or not any(character.isdigit() for character in value):
                    continue
                start = match.start(group_name) + len(match.group(group_name)) - len(match.group(group_name).lstrip(" :='\""))
                end = start + len(value)
                subtype = "GENERIC_PASSPORT_IDENTIFIER" if entity_type == "PASSPORT_NUMBER" else entity_type
                findings.append(self._finding(source, entity_type, value, start, end, confidence=0.91, methods=("field_name", "context", "shape_analysis"), validation="PLAUSIBLE", rule_id=f"DS-CONTEXT-{entity_type}", context=match.group("label").casefold(), subtype=subtype, explanation=("Value appears beside a recognized bilingual field label.", "Alphanumeric shape is consistent with the labelled identifier.")))

        name_pattern = _field_pattern(CONTEXT_LABELS["PERSON_NAME"])
        for match in name_pattern.finditer(source):
            value = (match.group("value") or "").strip(" :='\"")
            group_name = "value"
            if not PERSON_VALUE.fullmatch(value):
                value = (match.group("next") or "").strip(" :='\"")
                group_name = "next"
            if not PERSON_VALUE.fullmatch(value):
                continue
            start = match.start(group_name) + len(match.group(group_name)) - len(match.group(group_name).lstrip(" :='\""))
            findings.append(self._finding(source, "PERSON_NAME", value, start, start + len(value), confidence=0.90, methods=("field_name", "context", "name_shape"), validation="PLAUSIBLE", rule_id="DS-IDENTITY-NAME-CONTEXT", context=match.group("label").casefold(), explanation=("Person-like phrase appears beside a name field.",)))

        dob_pattern = _field_pattern(CONTEXT_LABELS["DATE_OF_BIRTH"])
        for match in dob_pattern.finditer(source):
            combined = f"{match.group('value') or ''}\n{match.group('next') or ''}"
            date_match = DATE.search(combined)
            if not date_match:
                continue
            value = date_match.group()
            search_start = match.start()
            start = source.find(value, search_start, match.end())
            if start < 0:
                continue
            plausible = _date_plausible(value)
            findings.append(self._finding(source, "DATE_OF_BIRTH", value, start, start + len(value), confidence=0.96 if plausible else 0.28, methods=("field_name", "context", "date_validation"), validation="PLAUSIBLE" if plausible else "INVALID", rule_id="DS-PERSONAL-DOB", context=match.group("label").casefold(), explanation=("Date appears beside a birth-date label, not a generic timestamp.",) if plausible else ("Birth-date label was present, but the calendar date is invalid.",)))

        address_pattern = _field_pattern(CONTEXT_LABELS["POSTAL_ADDRESS"])
        for match in address_pattern.finditer(source):
            lines = [(match.group("value") or "").strip(), (match.group("next") or "").strip()]
            value = "\n".join(line for line in lines if line)
            if len(value) < 6 or not (ADDRESS_HINT.search(value) or POSTCODE_STATE.search(value)):
                continue
            start = source.find(lines[0], match.start(), match.end())
            findings.append(self._finding(source, "POSTAL_ADDRESS", value, start, start + len(value), confidence=0.94, methods=("field_name", "context", "address_signals"), validation="PLAUSIBLE", rule_id="DS-LOCATION-ADDRESS", context=match.group("label").casefold(), country="MY", explanation=("Multiple address components appear beside an address label.",)))

        for match in UUID.finditer(source):
            context = _nearby_label(source, match.start(), "USER_IDENTIFIER", 80)
            if not context:
                continue
            findings.append(self._finding(source, "USER_IDENTIFIER", match.group(), match.start(), match.end(), confidence=0.78, methods=("pattern", "context"), validation="PLAUSIBLE", rule_id="DS-DIGITAL-CONTEXT-UUID", context=context, explanation=("UUID is linked to a user/account field; unlabelled UUIDs are suppressed.",)))
        return findings

    @staticmethod
    def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
        specificity = {"MALAYSIA_NRIC": 10, "PAYMENT_CARD": 9, "PASSPORT_NUMBER": 8, "PHONE_NUMBER": 7, "GOVERNMENT_ID": 3}
        ordered = sorted(findings, key=lambda item: (-item.confidence, -specificity.get(item.entity_type, 5), item.start, -(item.end - item.start)))
        selected: list[Finding] = []
        for finding in ordered:
            duplicate = any(finding.start == item.start and finding.end == item.end and finding.entity_type == item.entity_type for item in selected)
            conflicting = any(finding.start < item.end and finding.end > item.start for item in selected)
            if not duplicate and not conflicting:
                selected.append(finding)
        return sorted(selected, key=lambda item: (item.start, item.end))

    @staticmethod
    def _apply_cross_signal(findings: list[Finding]) -> list[Finding]:
        enriched = []
        for finding, neighbours in zip(findings, PIIEngine._neighbour_categories(findings), strict=True):
            if len(neighbours) >= 3 and finding.confidence < 0.98:
                methods = tuple(dict.fromkeys((*finding.methods, "cross_signal")))
                explanation = (*finding.explanation, "Nearby independent PII categories increase record-level confidence.")
                enriched.append(replace(finding, confidence=min(0.98, finding.confidence + 0.04), methods=methods, explanation=explanation))
            else:
                enriched.append(finding)
        return enriched

    @staticmethod
    def _neighbour_categories(findings: list[Finding]) -> list[set[str]]:
        """Return categories within 500 characters of each finding in linear time."""
        if not findings:
            return []
        ordered = sorted(enumerate(findings), key=lambda pair: pair[1].start)
        result: list[set[str]] = [set() for _ in findings]
        left = 0
        right = 0
        categories: Counter[str] = Counter()
        for original_index, finding in ordered:
            while right < len(ordered) and ordered[right][1].start <= finding.start + 500:
                categories[ordered[right][1].category] += 1
                right += 1
            while left < len(ordered) and ordered[left][1].start < finding.start - 500:
                category = ordered[left][1].category
                categories[category] -= 1
                if categories[category] <= 0:
                    del categories[category]
                left += 1
            result[original_index] = set(categories)
        return result

    @staticmethod
    def _summarize(source: str, findings: list[Finding]) -> ScanSummary:
        severity = Counter(finding.severity.casefold() for finding in findings)
        categories = Counter(finding.category.casefold() for finding in findings)
        weights = {"CRITICAL": 28, "HIGH": 16, "MEDIUM": 8, "LOW": 3}
        raw_score = sum(weights.get(finding.severity, 5) * finding.confidence for finding in findings)
        risk_score = min(100, round(100 * (1 - math.exp(-raw_score / 55))))
        risk = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
        covered = sum(max(0, finding.end - finding.start) for finding in findings)
        clusters = sum(
            1 for neighbours in PIIEngine._neighbour_categories(findings) if len(neighbours) >= 3
        )
        return ScanSummary(len(findings), len({(item.entity_type, item.normalized_value) for item in findings}), risk, risk_score, covered / max(1, len(source)), dict(severity), dict(categories), clusters)

