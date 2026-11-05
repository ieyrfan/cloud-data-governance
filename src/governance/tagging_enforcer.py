import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class TaggingEnforcer:
    """
    Data Governance Tagging Enforcer.
    In large enterprises, resources without owners (tags) are a huge security and cost risk.
    This enforcer crawls the cloud and quarantines untagged objects.
    """

    def __init__(self, region_name="us-east-1"):
        self.s3 = boto3.client(
            "s3", region_name=region_name, endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT")
        )
        self.required_tags = ["DataOwner", "Sensitivity", "CostCenter"]

    def enforce_object_tags(self, bucket_name: str, object_key: str):
        """
        Validates if an S3 object has the mandatory enterprise governance tags.
        If it lacks tags, it moves it to an isolated 'Quarantine' state.
        """
        print(f"🏷️ [TAG ENFORCER] Validating governance tags for {object_key}")
        try:
            response = self.s3.get_object_tagging(Bucket=bucket_name, Key=object_key)
            existing_tags = {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

            missing_tags = [tag for tag in self.required_tags if tag not in existing_tags]

            if missing_tags:
                print(
                    f"⚠️ [TAG ENFORCER] Missing mandatory tags {missing_tags} on {object_key}. Applying Quarantine policy."
                )

                # Auto-remediation: Append a 'Quarantine' tag to block access until fixed
                new_tags = [{"Key": k, "Value": v} for k, v in existing_tags.items()]
                new_tags.append({"Key": "GovernanceStatus", "Value": "QUARANTINED_MISSING_TAGS"})

                self.s3.put_object_tagging(
                    Bucket=bucket_name, Key=object_key, Tagging={"TagSet": new_tags}
                )
                return False

            print(
                f"✅ [TAG ENFORCER] Object {object_key} is fully compliant with Tagging Governance."
            )
            return True

        except (BotoCoreError, ClientError) as e:
            print(f"Failed to enforce tags: {e}")
            return False
