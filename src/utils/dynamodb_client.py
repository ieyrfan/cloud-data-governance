import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _dynamodb_safe(value):
    """Recursively convert Python floats before boto3 serialises nested evidence."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: _dynamodb_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dynamodb_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_dynamodb_safe(item) for item in value]
    return value


class DynamoDBClient:
    def __init__(self, table_name: str, region_name=None):
        self.table_name = table_name
        region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")

        endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT")
        if endpoint_url:
            self.dynamodb = boto3.resource(
                "dynamodb", region_name=region_name, endpoint_url=endpoint_url
            )
        else:
            self.dynamodb = boto3.resource("dynamodb", region_name=region_name)

        self.table = self.dynamodb.Table(self.table_name)

    def save_classification_result(
        self,
        s3_uri: str,
        sensitivity: str,
        confidence: float,
        findings: dict,
        risk_score: int = 0,
        risk_level: str = "INFO",
        governance_actions: dict | None = None,
        version_id: str | None = None,
    ):
        """
        Saves the classification result to DynamoDB.
        """
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        version_id = version_id or f"{timestamp}#{uuid.uuid4()}"
        item = {
            "resource_id": s3_uri,
            "version_id": version_id,
            "inventory_scope": "CLASSIFICATION",
            "sensitivity_level": sensitivity,
            "confidence_score": str(
                round(confidence, 2)
            ),  # DynamoDB floats must be string or Decimal
            "findings": _dynamodb_safe(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "governance_actions": _dynamodb_safe(governance_actions or {}),
            "timestamp": timestamp,
        }

        try:
            put_arguments = {"Item": item}
            if version_id.startswith("source#"):
                put_arguments["ConditionExpression"] = (
                    "attribute_not_exists(resource_id) AND attribute_not_exists(version_id)"
                )
            self.table.put_item(**put_arguments)
            return version_id
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return version_id
            print(f"Error saving to DynamoDB: {e}")
            return None
        except BotoCoreError as e:
            print(f"Error saving to DynamoDB: {e}")
            return None

    def update_governance_actions(self, s3_uri: str, version_id: str, governance_actions: dict):
        try:
            self.table.update_item(
                Key={"resource_id": s3_uri, "version_id": version_id},
                UpdateExpression="SET governance_actions = :actions",
                ExpressionAttributeValues={":actions": governance_actions},
            )
            return True
        except (BotoCoreError, ClientError) as e:
            print(f"Error updating governance actions: {e}")
            return False

    def save_processing_failure(self, s3_uri: str, error_code: str, *, version_id: str | None = None):
        """Persist a safe, value-free terminal failure state for job polling/retry."""
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        # Sorts ahead of source revisions in the existing descending query.
        version_id = version_id or f"zzfailure#{timestamp}#{uuid.uuid4()}"
        item = {
            "resource_id": s3_uri,
            "version_id": version_id,
            "inventory_scope": "CLASSIFICATION",
            "sensitivity_level": "UNKNOWN",
            "confidence_score": "0",
            "findings": {
                "processing_status": "FAILED",
                "failure_code": str(error_code)[:120],
                "retryable": True,
            },
            "governance_actions": {},
            "risk_score": 100,
            "risk_level": "HIGH",
            "timestamp": timestamp,
        }
        try:
            self.table.put_item(Item=item)
            return version_id
        except (BotoCoreError, ClientError) as error:
            print(f"Error saving processing failure: {type(error).__name__}")
            return None
