import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AutoRemediator:
    """
    Active Defense Module: Automatically revokes access or quarantines IAM identities
    when severe anomalies or data exfiltration attempts are detected.
    """

    def __init__(self, region_name="us-east-1"):
        self.iam = boto3.client(
            "iam", region_name=region_name, endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT")
        )

    def quarantine_user(self, user_arn: str, reason: str):
        """
        Instantly attaches an explicit DenyAll policy to a compromised user.
        """
        try:
            username = user_arn.split("/")[-1]
            # AWS Managed Policy for Deny All
            policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"

            self.iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)
            print(
                f"🚨 [ACTIVE DEFENSE] Successfully quarantined user '{username}'. Reason: {reason}"
            )
            return True

        except (BotoCoreError, ClientError) as e:
            print(f"Failed to quarantine user {user_arn}: {e}")
            return False

    def disable_compromised_access_keys(self, username: str):
        """
        Deactivates active access keys if the AI detects anomalous usage patterns.
        """
        try:
            keys = self.iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                self.iam.update_access_key(
                    UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive"
                )
                print(
                    f"🚨 [ACTIVE DEFENSE] Deactivated Access Key {key['AccessKeyId']} for user {username}"
                )
        except (BotoCoreError, ClientError) as e:
            print(f"Error deactivating keys: {e}")
