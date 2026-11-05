"""Data-driven field-name semantics for contextual PII discovery.

The detector deliberately classifies a field before looking at its value.  This
lets a strong schema signal (for example ``personnel.ref``) protect an unknown
identifier without pretending that every alphanumeric token is PII.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class FieldSemantic:
    entity_type: str
    canonical_label: str
    normalized_label: str
    confidence: float
    rule_id: str


IDENTIFIER_WORDS = {
    "id", "identifier", "identification", "number", "no", "num", "nbr", "code",
    "reference", "ref", "serial", "record", "key",
}

# Each entity contains concept groups.  Aliases are generated as combinations
# rather than stored as an unmaintainable enumeration.
ENTITY_CONCEPTS: dict[str, tuple[set[str], set[str] | None]] = {
    "GENERIC_NATIONAL_ID": (
        {
            "national", "citizen", "civil", "resident", "personal", "identity",
            "government", "govt", "citizenship", "pengenalan", "kependudukan",
        },
        IDENTIFIER_WORDS,
    ),
    "PASSPORT_NUMBER": (
        {"passport", "pasport", "travel document", "travel doc", "passeport", "reisepass"},
        IDENTIFIER_WORDS,
    ),
    "EMPLOYEE_ID": (
        {
            "employee", "employment", "emp", "staff", "personnel", "worker",
            "workforce", "payroll", "pekerja", "staf", "kakitangan",
        },
        IDENTIFIER_WORDS,
    ),
    "STUDENT_ID": (
        {
            "student", "matric", "matriculation", "candidate", "learner",
            "pupil", "pelajar", "mahasiswa", "siswa", "university",
        },
        IDENTIFIER_WORDS,
    ),
    "PATIENT_ID": (
        {"patient", "medical record", "medical", "mrn", "hospital", "clinic", "pesakit"},
        IDENTIFIER_WORDS,
    ),
    "CUSTOMER_ID": (
        {
            "customer", "client", "member", "subscriber", "policy", "claim",
            "account holder", "pelanggan", "ahli",
        },
        IDENTIFIER_WORDS,
    ),
    "DRIVING_LICENCE": (
        {"driving licence", "driving license", "driver licence", "driver license", "lesen memandu"},
        IDENTIFIER_WORDS,
    ),
    "VISA_NUMBER": ({"visa"}, IDENTIFIER_WORDS),
    "RESIDENCE_PERMIT": (
        {"residence permit", "resident permit", "work permit", "permit", "pas kerja"},
        IDENTIFIER_WORDS,
    ),
    "TAX_ID": (
        {"tax", "taxpayer", "tin", "income tax", "cukai", "epf", "kwsp", "socso", "perkeso"},
        IDENTIFIER_WORDS,
    ),
    "FINANCIAL_ACCOUNT": (
        {"bank account", "account", "acct", "iban", "swift", "bic", "akaun bank"},
        IDENTIFIER_WORDS,
    ),
    "PHONE_NUMBER": (
        {"phone", "telephone", "tel", "mobile", "cell", "whatsapp", "telefon", "contact"},
        {"number", "no", "num", "contact", "phone", "telephone", "mobile", "tel"},
    ),
    "EMAIL_ADDRESS": (
        {"email", "e mail", "mail", "e mel"},
        {"address", "id", "email", "mail"},
    ),
    "POSTAL_ADDRESS": (
        {
            "address", "residential address", "mailing address", "postal address",
            "home address", "registered address", "alamat", "alamat surat menyurat",
            "domicile", "residence",
        },
        None,
    ),
    "DATE_OF_BIRTH": (
        {"date of birth", "birth date", "dob", "born", "tarikh lahir", "tarikh kelahiran", "tanggal lahir"},
        None,
    ),
    "PERSON_NAME": (
        {
            "name", "full name", "legal name", "preferred name", "given name", "first name",
            "last name", "family name", "surname", "nama", "nama penuh", "nama sah",
        },
        None,
    ),
    "USER_IDENTIFIER": (
        {"user", "username", "login", "device", "session", "cookie"},
        IDENTIFIER_WORDS | {"name", "handle", "uuid"},
    ),
}

NEGATIVE_FIELDS = {
    "build number", "build id", "invoice number", "invoice id", "order number", "order id",
    "request id", "trace id", "correlation id", "version", "port", "employee count",
    "student count", "patient queue", "customer total", "phone model", "project name",
    "company name", "name of company", "product name", "name of product", "project name",
    "name of project", "report date", "invoice date", "created at", "updated at",
}


def normalize_field_name(label: str) -> str:
    """Collapse case, Unicode, camelCase and schema punctuation into semantic tokens."""
    value = unicodedata.normalize("NFKC", str(label or ""))
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    value = value.casefold().replace("e-mail", "email").replace("e_mel", "e mel")
    value = re.sub(r"[.\\/\[\]{}()_-]+", " ", value)
    value = re.sub(r"[^\w#]+", " ", value, flags=re.UNICODE)
    return re.sub(r"\s+", " ", value).strip()


def _contains_phrase(tokens: tuple[str, ...], phrase: str) -> bool:
    phrase_tokens = tuple(phrase.split())
    width = len(phrase_tokens)
    return any(tokens[index : index + width] == phrase_tokens for index in range(len(tokens) - width + 1))


@lru_cache(maxsize=2048)
def classify_field(label: str) -> FieldSemantic | None:
    normalized = normalize_field_name(label)
    if not normalized or normalized in NEGATIVE_FIELDS:
        return None
    tokens = tuple(normalized.split())
    best: tuple[float, str, str] | None = None
    for entity_type, (subjects, qualifiers) in ENTITY_CONCEPTS.items():
        subject_matches = [subject for subject in subjects if _contains_phrase(tokens, subject)]
        if not subject_matches:
            continue
        subject = max(subject_matches, key=len)
        if qualifiers is None:
            score = 0.96 if normalize_field_name(subject) == normalized else 0.93
        else:
            qualifier_match = any(token in qualifiers for token in tokens)
            # Some domain terms already carry identifier meaning (MRN, TIN,
            # passport, matric, username, IBAN) and do not need a redundant ID.
            intrinsic = subject in {
                "passport", "pasport", "passeport", "reisepass", "mrn", "matric",
                "tin", "iban", "swift", "bic", "username", "visa",
            }
            if not qualifier_match and not intrinsic:
                continue
            score = 0.97 if qualifier_match else 0.93
        candidate = (score, entity_type, subject)
        if best is None or candidate > best:
            best = candidate
    if best is None:
        return None
    confidence, entity_type, subject = best
    return FieldSemantic(
        entity_type=entity_type,
        canonical_label=subject,
        normalized_label=normalized,
        confidence=confidence,
        rule_id=f"DS-FIELD-{entity_type}",
    )


__all__ = ["FieldSemantic", "classify_field", "normalize_field_name"]

