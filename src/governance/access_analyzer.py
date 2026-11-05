import os
from datetime import datetime, time

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AccessGovernanceAnalyzer:
    def __init__(self, region_name="us-east-1"):
        endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT")
        self.cloudtrail = boto3.client(
            "cloudtrail", region_name=region_name, endpoint_url=endpoint_url
        )

    def analyze_anomalous_access(self, cloudtrail_events: list[dict]) -> list[dict]:
        """
        Detects anomalous access patterns in CloudTrail data events (e.g. S3 GetObject).
        """
        anomalies = []

        for event in cloudtrail_events:
            event_name = event.get("EventName")
            event_time_str = event.get("EventTime")
            user_arn = event.get("UserIdentity", {}).get("Arn", "Unknown")

            # We are primarily interested in data access
            if event_name not in ["GetObject", "ExecuteStatement"]:
                continue

            try:
                # Basic off-hours detection (3 AM to 5 AM)
                if event_time_str:
                    event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                    if time(3, 0) <= event_time.time() <= time(5, 0):
                        anomalies.append(
                            {
                                "type": "OFF_HOURS_ACCESS",
                                "user": user_arn,
                                "event": event_name,
                                "time": str(event_time.time()),
                                "severity": "HIGH",
                            }
                        )
            except (TypeError, ValueError) as e:
                print(f"Error parsing time {event_time_str}: {e}")

            # Note: A real implementation would track volume per user over time
            # and flag deviations (e.g., mass downloads).

        return anomalies

    def build_access_matrix(
        self, cloudtrail_events: list[dict], classified_resources: list[dict]
    ) -> dict:
        """
        Builds the Access-vs-Classification Matrix.
        Cross-references who accessed what resource vs its sensitivity level.
        """
        # Map resource URIs to their sensitivity level
        resource_sensitivity = {
            res["resource_id"]: res["sensitivity_level"] for res in classified_resources
        }

        matrix = {}

        for event in cloudtrail_events:
            user_arn = event.get("UserIdentity", {}).get("Arn", "Unknown")
            resources = event.get("Resources", [])

            for resource in resources:
                res_arn = resource.get("ARN")
                if not res_arn:
                    continue

                # Simplify ARN to S3 URI for matching
                if ":s3:::" in res_arn:
                    s3_uri = res_arn.replace("arn:aws:s3:::", "s3://")

                    sensitivity = resource_sensitivity.get(s3_uri, "UNKNOWN")

                    if user_arn not in matrix:
                        matrix[user_arn] = {
                            "RESTRICTED": 0,
                            "CONFIDENTIAL": 0,
                            "INTERNAL": 0,
                            "PUBLIC": 0,
                            "UNKNOWN": 0,
                        }

                    matrix[user_arn][sensitivity] += 1

        return matrix

    def check_data_residency(self, s3_client, bucket_name: str, allowed_regions: list[str]) -> bool:
        """
        Ensures sensitive data buckets are physically located in allowed regions.
        """
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get("LocationConstraint")

            # 'None' location constraint means us-east-1
            if not region:
                region = "us-east-1"

            return region in allowed_regions
        except (BotoCoreError, ClientError) as e:
            print(f"Error checking bucket location for {bucket_name}: {e}")
            return False
