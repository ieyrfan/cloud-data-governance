import os
from datetime import UTC, datetime, timedelta

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class DataRetentionManager:
    def __init__(self, region_name=None):
        region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT")
        self.s3 = boto3.client("s3", region_name=region_name, endpoint_url=endpoint_url)

    def apply_retention_tags(
        self,
        bucket_name: str,
        object_key: str,
        sensitivity: str,
        additional_tags=None,
    ):
        """
        Applies retention tags based on sensitivity.
        e.g., RESTRICTED (7 years), CONFIDENTIAL (5 years), INTERNAL (3 years)
        For testing purposes, we'll use days instead of years.
        """
        retention_days = {
            "RESTRICTED": 7 * 365,
            "CONFIDENTIAL": 5 * 365,
            "INTERNAL": 3 * 365,
            "PUBLIC": 365,
        }

        days = retention_days.get(sensitivity, 365)
        expiry_date = (datetime.now(UTC) + timedelta(days=days)).isoformat()

        try:
            current = self.s3.get_object_tagging(Bucket=bucket_name, Key=object_key)
            merged_tags = {tag["Key"]: tag["Value"] for tag in current.get("TagSet", [])}
            merged_tags.update(
                {"RetentionDays": str(days), "ExpiryDate": expiry_date, "Status": "ACTIVE"}
            )
            merged_tags.update(additional_tags or {})
            if len(merged_tags) > 10:
                raise ValueError("S3 supports at most 10 object tags")
            self.s3.put_object_tagging(
                Bucket=bucket_name,
                Key=object_key,
                Tagging={
                    "TagSet": [{"Key": key, "Value": value} for key, value in merged_tags.items()]
                },
            )
            return True
        except (BotoCoreError, ClientError, ValueError) as e:
            print(f"Error tagging {object_key}: {e}")
            return False

    def process_expired_data(self, bucket_name: str, object_key: str):
        """
        Implements the Soft Delete -> Hard Delete workflow for expired data.
        """
        try:
            # Check current tags
            response = self.s3.get_object_tagging(Bucket=bucket_name, Key=object_key)
            tags = {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

            if str(tags.get("LegalHold", "")).casefold() == "true":
                print(f"Retention deletion blocked by legal hold for {object_key}")
                return

            status = tags.get("Status")

            if status == "ACTIVE":
                # Check if expired
                expiry_str = tags.get("ExpiryDate")
                if expiry_str:
                    expiry_date = datetime.fromisoformat(expiry_str)
                    if datetime.now(UTC) > expiry_date:
                        self._soft_delete(bucket_name, object_key)

            elif status == "SOFT_DELETED":
                # Check if legal hold expired (30 days after soft delete)
                hold_expiry_str = tags.get("LegalHoldExpiry")
                if hold_expiry_str:
                    hold_expiry_date = datetime.fromisoformat(hold_expiry_str)
                    if datetime.now(UTC) > hold_expiry_date:
                        self._hard_delete(bucket_name, object_key)

        except (BotoCoreError, ClientError, TypeError, ValueError) as e:
            print(f"Error processing retention for {object_key}: {e}")

    def _soft_delete(self, bucket_name: str, object_key: str):
        """
        Moves object to Glacier (simulated via storage class) and applies 30-day legal hold.
        """
        print(f"Applying SOFT DELETE to {bucket_name}/{object_key}")

        # In a real AWS environment, we'd copy the object with StorageClass='GLACIER'
        # For simplicity, we just update the tags to reflect the soft delete state.
        legal_hold_expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat()

        self.s3.put_object_tagging(
            Bucket=bucket_name,
            Key=object_key,
            Tagging={
                "TagSet": [
                    {"Key": "Status", "Value": "SOFT_DELETED"},
                    {"Key": "StorageClass", "Value": "GLACIER"},
                    {"Key": "LegalHoldExpiry", "Value": legal_hold_expiry},
                ]
            },
        )

    def _hard_delete(self, bucket_name: str, object_key: str):
        """
        Permanently purges the data.
        """
        print(f"Applying HARD DELETE to {bucket_name}/{object_key}")
        self.s3.delete_object(Bucket=bucket_name, Key=object_key)

        # Log this action for Right-to-Erasure compliance reporting
        print(f"AUDIT: Permanently deleted {bucket_name}/{object_key} for PDPA compliance.")
