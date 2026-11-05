from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    """Internal finding. The raw value is deliberately excluded from public output."""

    entity_type: str
    entity_subtype: str
    category: str
    severity: str
    confidence: float
    raw_value: str
    normalized_value: str
    start: int
    end: int
    line: int
    column: int
    context: str
    methods: tuple[str, ...]
    validation_status: str
    rule_id: str
    country: str | None = None
    explanation: tuple[str, ...] = ()
    masked_value: str = "[PROTECTED]"

    @property
    def stable_id(self) -> str:
        payload = f"{self.entity_type}:{self.start}:{self.end}:{self.normalized_value}"
        return "pii_" + hashlib.sha256(payload.encode()).hexdigest()[:16]

    def public_dict(self) -> dict:
        return {
            "id": self.stable_id,
            "entity_type": self.entity_type,
            "entity_subtype": self.entity_subtype,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "masked_value": self.masked_value,
            "start": self.start,
            "end": self.end,
            "line": self.line,
            "column": self.column,
            "context": self.context,
            "methods": list(self.methods),
            "validation": {"status": self.validation_status},
            "rule_id": self.rule_id,
            "country": self.country,
            "explanation": list(self.explanation),
        }

    def safe_debug_dict(self) -> dict:
        """Explain a decision without exposing the raw or normalized value."""
        return {
            "finding_id": self.stable_id,
            "candidate": self.masked_value,
            "entity_type": self.entity_type,
            "entity_subtype": self.entity_subtype,
            "candidate_generators": list(self.methods),
            "field_context": self.context,
            "validator": self.validation_status,
            "decision_rule": self.rule_id,
            "confidence": round(self.confidence, 3),
            "location": {"line": self.line, "column": self.column},
            "raw_value_logged": False,
        }


@dataclass(frozen=True)
class ScanSummary:
    total_findings: int
    unique_findings: int
    risk: str
    risk_score: int
    pii_density: float
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    record_clusters: int = 0

    def public_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "pii_density": round(self.pii_density, 4),
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "record_clusters": self.record_clusters,
        }


@dataclass(frozen=True)
class DetectionResult:
    findings: tuple[Finding, ...]
    summary: ScanSummary

    def public_dict(self) -> dict:
        return {
            "findings": [finding.public_dict() for finding in self.findings],
            "summary": self.summary.public_dict(),
            "values_disclosed": False,
        }

    def redaction_map(self) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        # A detection is not automatically a redaction decision.  Names and
        # location-like values are especially prone to false positives in
        # ordinary prose, titles, organisation names and technical reports.
        # Keep those findings available to the review/evidence layer, but only
        # promote them to automatic redaction when the detector has field
        # context.  Strongly validated identifiers and secrets retain their
        # existing behaviour.
        context_required = {
            "PERSON_NAME",
            "PHONE_NUMBER",
            "POSTAL_ADDRESS",
            "IP_ADDRESS",
            "GPS_COORDINATES",
        }
        legacy_types = {
            "MALAYSIA_NRIC": "my_ic",
            "PHONE_NUMBER": "my_phone",
            "EMAIL_ADDRESS": "email",
            "PAYMENT_CARD": "credit_card",
            "PERSON_NAME": "name",
            "POSTAL_ADDRESS": "address",
            "STUDENT_ID": "matric_number",
            "EMPLOYEE_ID": "government_id",
            "PASSPORT_NUMBER": "government_id",
            "GOVERNMENT_ID": "government_id",
            "GENERIC_NATIONAL_ID": "government_id",
            "DRIVING_LICENCE": "government_id",
            "VISA_NUMBER": "government_id",
            "RESIDENCE_PERMIT": "government_id",
            "TAX_ID": "government_id",
            "PATIENT_ID": "government_id",
            "CUSTOMER_ID": "government_id",
            "FINANCIAL_ACCOUNT": "financial_account",
            "DATE_OF_BIRTH": "date_of_birth",
        }
        for finding in self.findings:
            if finding.validation_status == "INVALID":
                continue
            if finding.entity_type in context_required and not finding.context:
                continue
            key = legacy_types.get(finding.entity_type, finding.entity_type.casefold())
            values = mapping.setdefault(key, [])
            if finding.raw_value not in values:
                values.append(finding.raw_value)
        return mapping

    def safe_debug_report(self) -> dict:
        return {
            "findings": [finding.safe_debug_dict() for finding in self.findings],
            "summary": self.summary.public_dict(),
            "values_disclosed": False,
        }
