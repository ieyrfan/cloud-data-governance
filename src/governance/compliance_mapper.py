class ComplianceMappingEngine:
    def __init__(self):
        # Configurable mapping table for findings
        self.mapping_table = {
            "UNENCRYPTED_SENSITIVE_S3": {
                "PDPA": "Security Principle (S.9)",
                "ISO_27001": "A.10.1.1",
                "GDPR": "Art. 32",
            },
            "KMS_KEY_NOT_ROTATED": {
                "PDPA": "Security Principle",
                "ISO_27001": "A.10.1.2",
                "GDPR": "Art. 32",
            },
            "PUBLIC_S3_WITH_SENSITIVE_DATA": {
                "PDPA": "Security Principle",
                "ISO_27001": "A.9.1.2",
                "GDPR": "Art. 25",
            },
            "DATA_PAST_RETENTION": {
                "PDPA": "Data Retention Principle",
                "ISO_27001": "A.18.1.3",
                "GDPR": "Art. 17 (Right to Erasure)",
            },
        }

    def map_finding(self, finding_code: str) -> dict[str, str]:
        """
        Maps a technical finding code to relevant compliance frameworks.
        """
        return self.mapping_table.get(finding_code, {})

    def generate_compliance_report(self, findings: list[dict]) -> dict:
        """
        Aggregates findings and maps them to frameworks for reporting.
        """
        report = {"PDPA_Violations": [], "ISO_27001_Violations": [], "GDPR_Violations": []}

        for finding in findings:
            code = finding.get("code")
            mapped = self.map_finding(code)

            if mapped.get("PDPA"):
                report["PDPA_Violations"].append({"finding": finding, "control": mapped["PDPA"]})
            if mapped.get("ISO_27001"):
                report["ISO_27001_Violations"].append(
                    {"finding": finding, "control": mapped["ISO_27001"]}
                )
            if mapped.get("GDPR"):
                report["GDPR_Violations"].append({"finding": finding, "control": mapped["GDPR"]})

        return report
