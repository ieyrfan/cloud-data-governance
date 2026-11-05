#!/usr/bin/env python3
"""Operational CLI for the Cloud Data Governance project."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import boto3

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
GENESIS_HASH = "0" * 64


def import_credentials(path=None):
    candidates = [Path(path)] if path else [PROJECT_ROOT / "aws", PROJECT_ROOT / "aws.env"]
    credential_file = next((item for item in candidates if item.is_file()), None)
    if not credential_file:
        return
    allowed = {
        "aws_access_key_id": "AWS_ACCESS_KEY_ID",
        "aws_secret_access_key": "AWS_SECRET_ACCESS_KEY",
        "aws_session_token": "AWS_SESSION_TOKEN",
    }
    for raw_line in credential_file.read_text(encoding="utf-8-sig").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip().lower()
        if key in allowed:
            os.environ[allowed[key]] = value.strip()


def demo_data():
    return json.loads((PROJECT_ROOT / "frontend" / "demo-data.json").read_text(encoding="utf-8"))


def stack_outputs(region, stack_name):
    client = boto3.client("cloudformation", region_name=region)
    stack = client.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def scan_table(table_name, region):
    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    items = []
    response = table.scan()
    items.extend(response.get("Items", []))
    while response.get("LastEvaluatedKey"):
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


def newest(items):
    records = {}
    for item in items:
        resource = item.get("resource_id")
        if resource and (
            resource not in records
            or item.get("version_id", "") > records[resource].get("version_id", "")
        ):
            records[resource] = item
    return sorted(records.values(), key=lambda item: item.get("timestamp", ""), reverse=True)


def print_table(headers, rows):
    widths = [len(header) for header in headers]
    rendered = [[str(value) for value in row] for row in rows]
    for row in rendered:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    pattern = "  ".join(f"{{:<{width}}}" for width in widths)
    print(pattern.format(*headers))
    print(pattern.format(*("-" * width for width in widths)))
    for row in rendered:
        print(pattern.format(*row))


def verify_events(events):
    expected_previous = GENESIS_HASH
    for event in sorted(events, key=lambda item: item.get("timestamp", "")):
        if event.get("previous_hash") != expected_previous:
            return False, f"Broken link at {event.get('log_id', 'unknown')}"
        details = event.get("details", {})
        if isinstance(details, str):
            details = json.loads(details)
        payload = {
            "timestamp": event["timestamp"],
            "action": event["action"],
            "actor": event["actor"],
            "resource": event["resource"],
            "details": details,
            "previous_hash": event["previous_hash"],
        }
        calculated = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        if calculated != event.get("current_hash"):
            return False, f"Hash mismatch at {event.get('log_id', 'unknown')}"
        expected_previous = event["current_hash"]
    return True, f"Verified {len(events)} chained event(s)"


def command_summary(context):
    files = context["files"]
    counts = {tier: 0 for tier in ("RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC")}
    for item in files:
        counts[item.get("sensitivity_level", "PUBLIC")] += 1
    print(f"Files: {len(files)} | Review: {counts['RESTRICTED'] + counts['CONFIDENTIAL']}")
    print(" | ".join(f"{tier}: {count}" for tier, count in counts.items()))


def command_files(context, sensitivity=None):
    files = context["files"]
    if sensitivity:
        files = [item for item in files if item.get("sensitivity_level") == sensitivity]
    print_table(
        ["SENSITIVITY", "RISK", "CONFIDENCE", "RESOURCE"],
        [
            [
                item.get("sensitivity_level"),
                item.get("risk_level", "INFO"),
                item.get("confidence_score"),
                item.get("resource_id"),
            ]
            for item in files
        ],
    )


def command_audit(context, verify):
    events = context["audit"]
    print_table(
        ["TIME", "ACTION", "RESOURCE", "HASH"],
        [
            [
                item.get("timestamp"),
                item.get("action"),
                item.get("resource"),
                item.get("current_hash", "")[:12],
            ]
            for item in events
        ],
    )
    if verify:
        valid, message = verify_events(events)
        print(("PASS" if valid else "FAIL") + f": {message}")
        if not valid:
            raise SystemExit(2)


def command_scan(context, region):
    if context["demo"]:
        report = context["posture"]
    else:
        from src.governance.cspm_scanner import CSPMScanner

        report = CSPMScanner(region_name=region).scan_buckets(context["buckets"])
    rows = []
    for bucket in report["buckets"]:
        rows.extend(
            [
                [bucket["bucket"], check["control"], check["status"], check["detail"]]
                for check in bucket["checks"]
            ]
        )
    print_table(["BUCKET", "CONTROL", "STATUS", "DETAIL"], rows)
    print(f"{report['status']}: {report['checks_passed']}/{report['checks_total']} checks passed")


def command_trap(context, region):
    if context["demo"]:
        print("DEMO: honeytoken deployment was simulated; no AWS resource was changed.")
        return
    from src.governance.honeytoken_deployer import HoneytokenDeployer

    if not HoneytokenDeployer(region_name=region).deploy_canary_file(context["buckets"][0]):
        raise SystemExit(1)


def build_context(args):
    if args.demo:
        data = demo_data()
        return {
            "demo": True,
            "files": data["files"],
            "audit": data["audit"],
            "posture": data["posture"],
            "buckets": [],
        }
    outputs = stack_outputs(args.region, args.stack_name)
    required = ["ResultsTableName", "AuditTableName", "RawDataBucketName", "CleanDataBucketName"]
    missing = [name for name in required if not outputs.get(name)]
    if missing:
        raise RuntimeError("Stack is missing outputs: " + ", ".join(missing))
    return {
        "demo": False,
        "files": newest(scan_table(outputs["ResultsTableName"], args.region)),
        "audit": sorted(
            scan_table(outputs["AuditTableName"], args.region),
            key=lambda item: item.get("timestamp", ""),
            reverse=True,
        ),
        "buckets": [outputs["RawDataBucketName"], outputs["CleanDataBucketName"]],
    }


def parser():
    root = argparse.ArgumentParser(
        prog="cgctl", description="Cloud Data Governance operational CLI"
    )
    root.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    root.add_argument("--stack-name", default=os.environ.get("STACK_NAME", "cloud-data-governance"))
    root.add_argument("--credentials-file")
    root.add_argument(
        "--demo", action="store_true", help="Use bundled synthetic data and make no AWS calls"
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("summary")
    files = commands.add_parser("files")
    files.add_argument(
        "--sensitivity", choices=["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"]
    )
    audit = commands.add_parser("audit")
    audit.add_argument("--verify", action="store_true")
    commands.add_parser("scan")
    commands.add_parser("trap")
    return root


def main():
    args = parser().parse_args()
    import_credentials(args.credentials_file)
    try:
        context = build_context(args)
        if args.command == "summary":
            command_summary(context)
        elif args.command == "files":
            command_files(context, args.sensitivity)
        elif args.command == "audit":
            command_audit(context, args.verify)
        elif args.command == "scan":
            command_scan(context, args.region)
        elif args.command == "trap":
            command_trap(context, args.region)
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
