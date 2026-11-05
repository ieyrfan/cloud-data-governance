"""Deterministic document-type classification for the governance inventory.

The result intentionally contains only category metadata and generic rule names;
it never copies document content or detected personal values into DynamoDB.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCUMENT_TYPES = {
    "PASSPORT": "Passport / Travel document",
    "IDENTITY": "Identity document",
    "RESUME": "Resume / CV",
    "PAYSLIP": "Payslip / Payroll",
    "ACADEMIC_RESULT": "Academic result",
    "FORM": "Form / Application",
    "INVOICE": "Invoice / Financial",
    "CERTIFICATE": "Certificate",
    "CONTRACT": "Contract / Agreement",
    "REPORT": "Report",
    "OTHER": "Other document",
}


_RULES = {
    "PASSPORT": {
        "filename": (r"\b(passport|pasport|travel[-_ ]?document)\b",),
        "content": (
            r"passport",
            r"pasport",
            r"travel document",
            r"passport no",
            r"passport number",
        ),
    },
    "IDENTITY": {
        "filename": (r"\b(mykad|nric|identity|ic[-_ ]?(copy|photo|scan)?)\b",),
        "content": (
            r"kad pengenalan malaysia",
            r"identity card",
            r"warganegara",
            r"no\.?\s*(kad pengenalan|k\/p|nric)",
        ),
    },
    "PAYSLIP": {
        "filename": (r"\b(pay[-_ ]?slip|payroll|salary)\b",),
        "content": (
            r"pay\s*slip",
            r"salary statement",
            r"\bnet pay\b",
            r"\bgross pay\b",
            r"\bbasic salary\b",
            r"\b(epf|kwsp|socso|perkeso|pcb)\b",
        ),
    },
    "ACADEMIC_RESULT": {
        "filename": (r"\b(result|transcript|grade|exam|mrk)[-_ ]?\d*\b",),
        "content": (
            r"examination result",
            r"academic transcript",
            r"cumulative grade point",
            r"\b(cgpa|gpa|grade point)\b",
            r"course\s+(code|title)",
        ),
    },
    "RESUME": {
        "filename": (r"\b(resume|curriculum[-_ ]?vitae|cv)\b",),
        "content": (
            r"curriculum vitae",
            r"work experience",
            r"professional experience",
            r"employment history",
            r"career objective",
            r"technical skills",
        ),
    },
    "INVOICE": {
        "filename": (r"\b(invoice|receipt|quotation|purchase[-_ ]?order|po)[-_ ]?\d*\b",),
        "content": (
            r"invoice\s*(number|no\.?)",
            r"amount due",
            r"bill to",
            r"tax invoice",
            r"purchase order",
            r"subtotal",
        ),
    },
    "CONTRACT": {
        "filename": (r"\b(contract|agreement|nda|mou)\b",),
        "content": (
            r"terms and conditions",
            r"this agreement",
            r"party of the first part",
            r"non[- ]disclosure agreement",
            r"memorandum of understanding",
        ),
    },
    "CERTIFICATE": {
        "filename": (r"\b(certificate|certification|award)\b",),
        "content": (
            r"certificate of",
            r"this is to certify",
            r"has successfully completed",
            r"certificate number",
        ),
    },
    "FORM": {
        "filename": (r"\b(form|borang|application|registration)\b",),
        "content": (
            r"application form",
            r"registration form",
            r"borang permohonan",
            r"please complete",
            r"applicant signature",
        ),
    },
    "REPORT": {
        "filename": (r"\b(report|assessment|analysis|proposal)\b",),
        "content": (
            r"executive summary",
            r"findings and recommendations",
            r"methodology",
            r"table of contents",
            r"prepared by",
        ),
    },
}


def classify_document_type(text: str, filename: str = "") -> dict:
    """Return the strongest document category with explainable generic signals."""
    content = re.sub(r"\s+", " ", str(text or "").lower())
    name = re.sub(r"[-_.]+", " ", Path(str(filename or "")).name.lower())
    scored = []
    for key, rules in _RULES.items():
        filename_hits = sum(bool(re.search(pattern, name, re.I)) for pattern in rules["filename"])
        content_hits = sum(bool(re.search(pattern, content, re.I)) for pattern in rules["content"])
        score = filename_hits * 3 + content_hits
        if score:
            scored.append((score, filename_hits, content_hits, key))

    if not scored:
        return {
            "key": "OTHER",
            "label": DOCUMENT_TYPES["OTHER"],
            "confidence": 0.35,
            "signals": ["no category-specific rule matched"],
        }

    score, filename_hits, content_hits, key = max(scored)
    confidence = min(0.99, 0.55 + filename_hits * 0.2 + content_hits * 0.08)
    signals = []
    if filename_hits:
        signals.append("filename convention")
    if content_hits:
        signals.append(f"{content_hits} document-structure indicator" + ("s" if content_hits != 1 else ""))
    return {
        "key": key,
        "label": DOCUMENT_TYPES[key],
        "confidence": round(confidence, 2),
        "signals": signals,
    }
