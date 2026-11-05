"""Backfill sparse DynamoDB index keys introduced by the indexed API paths.

This is intentionally a one-time migration: runtime requests never fall back to
table scans. Re-running it is safe because already-migrated rows are skipped.
"""

import argparse
import os
from datetime import UTC, datetime

import boto3


def _scan_all(table):
    items = []
    response = table.scan()
    items.extend(response.get("Items", []))
    while response.get("LastEvaluatedKey"):
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


def _set_missing(table, key, attribute, value, dry_run=False):
    if dry_run:
        return True
    table.update_item(
        Key=key,
        UpdateExpression="SET #field = :value",
        ConditionExpression="attribute_not_exists(#field)",
        ExpressionAttributeNames={"#field": attribute},
        ExpressionAttributeValues={":value": value},
    )
    return True


def backfill(results_table, audit_table, access_table, dry_run=False):
    counts = {"classifications": 0, "audit_events": 0, "access_records": 0}

    for item in _scan_all(results_table):
        if "inventory_scope" in item:
            continue
        _set_missing(
            results_table,
            {"resource_id": item["resource_id"], "version_id": item["version_id"]},
            "inventory_scope",
            "CLASSIFICATION",
            dry_run,
        )
        counts["classifications"] += 1

    for item in _scan_all(audit_table):
        if item.get("log_id") == "__CHAIN_HEAD__" or "ledger_scope" in item:
            continue
        _set_missing(
            audit_table,
            {"log_id": item["log_id"]},
            "ledger_scope",
            "AUDIT",
            dry_run,
        )
        counts["audit_events"] += 1

    for item in _scan_all(access_table):
        record_type = item.get("record_type")
        if not record_type and item.get("requester") and item.get("status"):
            record_type = "ACCESS_REQUEST"
            _set_missing(
                access_table,
                {"request_id": item["request_id"]},
                "record_type",
                record_type,
                dry_run,
            )
        if record_type not in {"ACCESS_REQUEST", "FILE_ACCESS_EVENT"}:
            continue
        if not item.get("created_at"):
            fallback = item.get("decided_at") or datetime.now(UTC).isoformat()
            _set_missing(
                access_table,
                {"request_id": item["request_id"]},
                "created_at",
                fallback,
                dry_run,
            )
        counts["access_records"] += 1
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--stack", default="cloud-data-governance")
    parser.add_argument("--project", default="cloud-data-governance")
    parser.add_argument("--environment", default="dev")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    session = boto3.session.Session(region_name=args.region)
    dynamodb = session.resource("dynamodb")
    stacks = session.client("cloudformation").describe_stacks(StackName=args.stack)
    outputs = {
        output["OutputKey"]: output["OutputValue"]
        for output in stacks["Stacks"][0].get("Outputs", [])
    }
    required = {"ResultsTableName", "AuditTableName", "AccessRequestsTableName"}
    missing = required - outputs.keys()
    if missing:
        raise RuntimeError(f"Stack outputs are missing: {', '.join(sorted(missing))}")
    counts = backfill(
        dynamodb.Table(outputs["ResultsTableName"]),
        dynamodb.Table(outputs["AuditTableName"]),
        dynamodb.Table(outputs["AccessRequestsTableName"]),
        args.dry_run,
    )
    mode = "would update" if args.dry_run else "updated"
    print(
        f"Index migration {mode}: "
        f"{counts['classifications']} classifications, "
        f"{counts['audit_events']} audit events, "
        f"{counts['access_records']} access records checked."
    )


if __name__ == "__main__":
    main()
