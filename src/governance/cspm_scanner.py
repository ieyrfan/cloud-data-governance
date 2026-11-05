import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class CSPMScanner:
    """Evaluates concrete S3 controls used by this project."""

    def __init__(self, region_name=None, s3_client=None):
        region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        self.s3 = s3_client or boto3.client(
            "s3", region_name=region_name, endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT")
        )

    def _bucket_checks(self, bucket_name):
        checks = []

        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name).get("Status")
            checks.append(
                {
                    "control": "Versioning enabled",
                    "status": "PASS" if versioning == "Enabled" else "FAIL",
                    "detail": versioning or "Not enabled",
                }
            )
        except (BotoCoreError, ClientError) as error:
            checks.append(
                {"control": "Versioning enabled", "status": "ERROR", "detail": str(error)}
            )

        try:
            config = self.s3.get_public_access_block(Bucket=bucket_name)[
                "PublicAccessBlockConfiguration"
            ]
            blocked = all(
                config.get(key)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
            checks.append(
                {
                    "control": "Public access blocked",
                    "status": "PASS" if blocked else "FAIL",
                    "detail": "All four safeguards enabled"
                    if blocked
                    else "One or more safeguards disabled",
                }
            )
        except (BotoCoreError, ClientError, KeyError, TypeError) as error:
            checks.append(
                {"control": "Public access blocked", "status": "ERROR", "detail": str(error)}
            )

        try:
            rules = self.s3.get_bucket_encryption(Bucket=bucket_name)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
            algorithms = [
                rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                for rule in rules
            ]
            encrypted = any(
                algorithm in {"AES256", "aws:kms", "aws:kms:dsse"} for algorithm in algorithms
            )
            checks.append(
                {
                    "control": "Default encryption enabled",
                    "status": "PASS" if encrypted else "FAIL",
                    "detail": ", ".join(filter(None, algorithms)) or "No supported encryption rule",
                }
            )
        except (BotoCoreError, ClientError, KeyError, TypeError) as error:
            checks.append(
                {"control": "Default encryption enabled", "status": "ERROR", "detail": str(error)}
            )

        return checks

    def scan_buckets(self, bucket_names):
        buckets = [
            {"bucket": bucket_name, "checks": self._bucket_checks(bucket_name)}
            for bucket_name in bucket_names
        ]
        all_checks = [check for bucket in buckets for check in bucket["checks"]]
        pass_count = sum(check["status"] == "PASS" for check in all_checks)
        return {
            "status": "PASS"
            if all_checks and pass_count == len(all_checks)
            else "ATTENTION_REQUIRED",
            "checks_passed": pass_count,
            "checks_total": len(all_checks),
            "buckets": buckets,
        }

    def scan_s3_posture(self):
        """Backward-compatible account-wide scan returning readable findings."""
        try:
            names = [bucket["Name"] for bucket in self.s3.list_buckets().get("Buckets", [])]
        except (BotoCoreError, ClientError) as error:
            return [f"S3 inventory failed: {error}"]

        report = self.scan_buckets(names)
        findings = []
        for bucket in report["buckets"]:
            for check in bucket["checks"]:
                if check["status"] != "PASS":
                    findings.append(f"{bucket['bucket']}: {check['control']} ({check['status']})")
        return findings
