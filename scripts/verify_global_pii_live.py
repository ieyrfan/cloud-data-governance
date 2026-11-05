"""Live synthetic acceptance for the global field/structure PII detector."""

from __future__ import annotations

import argparse
import time
import uuid

import boto3
from boto3.dynamodb.conditions import Key


def _outputs(cloudformation, stack: str) -> dict[str, str]:
    response = cloudformation.describe_stacks(StackName=stack)
    return {
        item["OutputKey"]: item["OutputValue"]
        for item in response["Stacks"][0].get("Outputs", [])
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stack", default="cloud-data-governance")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    session = boto3.session.Session(region_name=args.region)
    outputs = _outputs(session.client("cloudformation"), args.stack)
    raw_bucket = outputs["RawDataBucketName"]
    clean_bucket = outputs["CleanDataBucketName"]
    results_table = session.resource("dynamodb").Table(outputs["ResultsTableName"])
    key = f"acceptance/global-pii-r6-{uuid.uuid4().hex[:12]}.txt"
    values = {
        "passport": "KJ-88-192",
        "national_id": "SG-00199281X",
        "employee_id": "MY-KL-1293",
        "phone": "+44 20 7946 0958",
        "address": "221B Baker Street, London NW1 6XE, United Kingdom",
    }
    content = (
        "Synthetic global PII acceptance record.\n"
        f"Travel Doc Ref: {values['passport']}\n"
        f"Citizen Number: {values['national_id']}\n"
        f"Personnel Ref: {values['employee_id']}\n"
        f"Phone: {values['phone']}\n"
        f"Residential Address: {values['address']}\n"
    ).encode()
    s3 = session.client("s3")
    s3.put_object(
        Bucket=raw_bucket,
        Key=key,
        Body=content,
        ContentType="text/plain",
        Tagging="DataOwner=LearnerLab&Sensitivity=Unknown&CostCenter=Academic",
    )

    resource_id = f"s3://{raw_bucket}/{key}"
    deadline = time.monotonic() + args.timeout
    latest = None
    while time.monotonic() < deadline:
        response = results_table.query(
            KeyConditionExpression=Key("resource_id").eq(resource_id),
            ScanIndexForward=False,
            Limit=1,
        )
        if response.get("Items"):
            latest = response["Items"][0]
            break
        time.sleep(3)
    if latest is None:
        raise RuntimeError("Global PII acceptance timed out before classification evidence appeared")
    if latest.get("sensitivity_level") != "RESTRICTED":
        raise RuntimeError("Global PII acceptance did not fail closed as RESTRICTED")

    findings = latest.get("findings", {})
    intelligence = findings.get("pii_intelligence", {})
    entity_types = {item.get("entity_type") for item in intelligence.get("findings", [])}
    required = {
        "PASSPORT_NUMBER",
        "GENERIC_NATIONAL_ID",
        "EMPLOYEE_ID",
        "PHONE_NUMBER",
        "POSTAL_ADDRESS",
    }
    missing = required - entity_types
    if missing:
        raise RuntimeError(f"Global PII acceptance is missing entity types: {', '.join(sorted(missing))}")
    if findings.get("classifier_version") != "2026.10-r6":
        raise RuntimeError("Live evidence does not report classifier version 2026.10-r6")

    protected = s3.get_object(Bucket=clean_bucket, Key=key)["Body"].read().decode("utf-8")
    residual = [label for label, value in values.items() if value in protected]
    if residual:
        raise RuntimeError(f"Protected copy retained synthetic value categories: {', '.join(residual)}")

    print("PASS: live global synthetic record classified RESTRICTED")
    print(f"PASS: required entity types detected ({len(required)}/{len(required)})")
    print("PASS: protected copy contains no controlled synthetic values")
    print("PASS: live evidence reports classifier version 2026.10-r6")
    print(f"Acceptance object: {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
