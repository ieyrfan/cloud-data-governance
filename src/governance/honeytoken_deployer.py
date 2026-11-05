import json
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class HoneytokenDeployer:
    """
    Advanced Cloud Security Concept: Cyber Deception.
    Deploys fake 'highly sensitive' files into the environment.
    If anyone (even insiders) accesses these files, it immediately triggers a critical alert.
    """

    def __init__(self, region_name="us-east-1"):
        self.s3 = boto3.client(
            "s3", region_name=region_name, endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT")
        )

    def deploy_canary_file(self, bucket_name: str):
        """
        Creates a juicy-looking file filled with fake credentials and PII.
        """
        canary_key = "admin/master-database-credentials.json"

        # Fake juicy data (Honeytoken)
        honey_data = {
            "db_host": "production-master-db.internal",
            "db_user": "superadmin",
            "db_password": "FakePassword123!@#",
            "aws_access_key_id": "SYNTHETIC-CANARY-ID-NOT-A-CREDENTIAL",
            "aws_secret_access_key": "SYNTHETIC-CANARY-SECRET-NOT-A-CREDENTIAL",
        }

        try:
            self.s3.put_object(
                Bucket=bucket_name,
                Key=canary_key,
                Body=json.dumps(honey_data, indent=4).encode("utf-8"),
                ServerSideEncryption="AES256",
                ContentType="application/json",
                Tagging="IsCanary=TRUE&DataOwner=SecurityTeam&Sensitivity=Restricted&CostCenter=Academic",
            )
            print(
                f"🍯 [CYBER DECEPTION] Honeytoken successfully planted at s3://{bucket_name}/{canary_key}"
            )

            # In a real environment, you would configure CloudTrail to send an SNS Alert
            # ANY TIME an API call is made to this specific S3 Object Key.

            return True
        except (BotoCoreError, ClientError) as e:
            print(f"Failed to deploy honeytoken: {e}")
            return False
