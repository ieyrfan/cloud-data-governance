from src.governance.cspm_scanner import CSPMScanner
from src.governance.data_retention import DataRetentionManager
from src.governance.risk_scorer import RiskScoringEngine


class SecureS3:
    def get_bucket_versioning(self, **kwargs):
        return {"Status": "Enabled"}

    def get_public_access_block(self, **kwargs):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_encryption(self, **kwargs):
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }


class TaggingS3:
    def __init__(self):
        self.tag_set = None

    def get_object_tagging(self, **kwargs):
        return {"TagSet": [{"Key": "Existing", "Value": "preserved"}]}

    def put_object_tagging(self, **kwargs):
        self.tag_set = kwargs["Tagging"]["TagSet"]


def test_cspm_reports_all_required_bucket_controls():
    report = CSPMScanner(s3_client=SecureS3()).scan_buckets(["raw", "clean"])
    assert report["status"] == "PASS"
    assert report["checks_passed"] == report["checks_total"] == 6


def test_retention_merges_evidence_tags():
    fake = TaggingS3()
    manager = DataRetentionManager.__new__(DataRetentionManager)
    manager.s3 = fake
    assert manager.apply_retention_tags(
        "raw", "sample.txt", "RESTRICTED", {"Sensitivity": "RESTRICTED", "DataOwner": "Lab"}
    )
    tags = {item["Key"]: item["Value"] for item in fake.tag_set}
    assert tags["Existing"] == "preserved"
    assert tags["RetentionDays"] == str(7 * 365)
    assert tags["Sensitivity"] == "RESTRICTED"


def test_risk_score_prioritises_sensitive_data_and_caps_exposure():
    engine = RiskScoringEngine()
    assert engine.categorize_risk(engine.calculate_risk_score("RESTRICTED", 1, 1)) == "CRITICAL"
    assert engine.categorize_risk(engine.calculate_risk_score("CONFIDENTIAL", 1, 1)) == "HIGH"
    assert engine.calculate_risk_score("RESTRICTED", 10, 10) == 100
