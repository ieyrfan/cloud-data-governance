"""Re-run the deployed classifier for every existing raw-bucket object.

This migration is intentionally content-blind: it prints object keys and processing
status, never object bodies, credentials, tokens, or generated download URLs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

import boto3


def stack_outputs(cloudformation: Any, stack_name: str) -> dict[str, str]:
    stacks = cloudformation.describe_stacks(StackName=stack_name)["Stacks"]
    return {
        output["OutputKey"]: output["OutputValue"]
        for output in stacks[0].get("Outputs", [])
    }


def event_for(bucket: str, key: str) -> dict[str, Any]:
    return {
        "version": "0",
        "source": "aws.s3",
        "detail-type": "Object Created",
        "detail": {"bucket": {"name": bucket}, "object": {"key": key}},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create current protected copies for all existing raw objects."
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stack-name", default="cloud-data-governance")
    parser.add_argument(
        "--key",
        default="",
        help="Reprocess one exact object key instead of every raw-bucket object.",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    outputs = stack_outputs(session.client("cloudformation"), args.stack_name)
    bucket = outputs["RawDataBucketName"]
    function_name = outputs["ClassifierFunctionName"]
    s3 = session.client("s3")
    lambda_client = session.client("lambda")

    keys: list[str] = [args.key] if args.key else []
    if not keys:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys.extend(item["Key"] for item in page.get("Contents", []))

    print(f"Found {len(keys)} raw object(s) to reprocess.")
    failures: list[str] = []
    for position, key in enumerate(keys, start=1):
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event_for(bucket, key)).encode("utf-8"),
        )
        payload = json.loads(response["Payload"].read() or b"{}")
        successful = (
            not response.get("FunctionError")
            and payload.get("statusCode") == 200
            and not payload.get("failures")
        )
        status = "OK" if successful else "FAILED"
        reference = hashlib.sha256(key.encode()).hexdigest()[:12]
        print(f"[{position}/{len(keys)}] {status}: object-{reference}")
        if not successful:
            failures.append(key)

    if failures:
        print(f"Migration completed with {len(failures)} failure(s).", file=sys.stderr)
        return 1
    print("Migration completed: every raw object has a current protected copy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
