"""Upload supplied PDFs and verify the live AWS classifier without exposing PII."""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import boto3
import pymupdf
from boto3.dynamodb.conditions import Attr

from src.classifiers.pattern_matcher import discover_sensitive_data
from src.utils.format_redactor import VISIBLE_REVIEW_TYPES


def _outputs(client, stack_name: str) -> dict[str, str]:
    stack = client.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}


def _pdf_evidence(content: bytes) -> tuple[str, int, list[tuple[float, float]]]:
    document = pymupdf.open(stream=content, filetype="pdf")
    try:
        return (
            "\n".join(page.get_text() for page in document),
            document.page_count,
            [(round(page.rect.width, 2), round(page.rect.height, 2)) for page in document],
        )
    finally:
        document.close()


def _login(api_url: str, login_file: Path) -> str:
    credentials = {}
    for line in login_file.read_text(encoding="utf-8").splitlines():
        username, separator, password = line.partition("=")
        if separator:
            credentials[username.strip()] = password.strip()
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/auth/login",
        data=json.dumps({"username": "admin", "password": credentials.get("admin", "")}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        return json.loads(response.read())["session_token"]


def _risk(api_url: str, token: str, resource_id: str) -> dict:
    query = urllib.parse.urlencode({"resource_id": resource_id})
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/files/risk?{query}",
        headers={"X-Dashboard-Token": token},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stack-name", default="cloud-data-governance")
    parser.add_argument("--expected-classifier", default="2026.10-r5")
    parser.add_argument("--output-dir", type=Path, default=Path("tmp/pdfs/r5-live"))
    parser.add_argument("--login-file", type=Path, default=Path(".learner-lab-login"))
    args = parser.parse_args()
    session = boto3.Session(region_name=args.region)
    outputs = _outputs(session.client("cloudformation"), args.stack_name)
    raw_bucket = outputs["RawDataBucketName"]
    clean_bucket = outputs["CleanDataBucketName"]
    table = session.resource("dynamodb").Table(outputs["ResultsTableName"])
    s3 = session.client("s3")
    api_url = outputs["ApiUrl"]
    token = _login(api_url, args.login_file)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for source in args.sources:
        source_bytes = source.read_bytes()
        source_text, source_pages, source_dimensions = _pdf_evidence(source_bytes)
        discovery = discover_sensitive_data(source_text)
        patterns = discovery.redaction_map()
        key = f"acceptance/r5-{uuid.uuid4().hex[:12]}-{source.name}"
        s3.put_object(
            Bucket=raw_bucket,
            Key=key,
            Body=source_bytes,
            ContentType="application/pdf",
            Metadata={"original-filename": source.name},
        )
        protected = b""
        classification = None
        resource_id = f"s3://{raw_bucket}/{key}"
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            try:
                protected = s3.get_object(Bucket=clean_bucket, Key=key)["Body"].read()
            except s3.exceptions.ClientError as error:
                if error.response.get("Error", {}).get("Code") not in {"404", "NoSuchKey"}:
                    raise
            response = table.scan(FilterExpression=Attr("resource_id").eq(resource_id))
            items = response.get("Items", [])
            if items:
                classification = max(items, key=lambda item: str(item.get("timestamp", "")))
            if protected and classification:
                break
            time.sleep(5)
        if not protected or not classification:
            raise RuntimeError("Live classification did not complete within 240 seconds")
        protected_text, pages, dimensions = _pdf_evidence(protected)
        sensitive_values = {
            value
            for data_type, values in patterns.items()
            if data_type not in VISIBLE_REVIEW_TYPES
            for value in values
        }
        if any(value and value in protected_text for value in sensitive_values):
            raise RuntimeError("Live protected PDF contains residual sensitive text")
        if pages != source_pages or dimensions != source_dimensions:
            raise RuntimeError("Live protected PDF changed page geometry")
        findings = classification.get("findings", {})
        if findings.get("classifier_version") != args.expected_classifier:
            raise RuntimeError("Live classification used an unexpected classifier version")
        risk_payload = _risk(api_url, token, resource_id)
        intelligence = risk_payload.get("findings", {}).get("pii_intelligence", {})
        public_payload = json.dumps(intelligence)
        if intelligence.get("values_disclosed") is not False:
            raise RuntimeError("PII intelligence payload did not assert value minimisation")
        if any(value and value in public_payload for value in sensitive_values):
            raise RuntimeError("PII intelligence API exposed a raw sensitive value")
        output = args.output_dir / f"{source.stem}-live-protected.pdf"
        output.write_bytes(protected)
        results.append({
            "source": source.name,
            "pages": pages,
            "dimensions_preserved": True,
            "sensitivity": classification.get("sensitivity_level"),
            "classifier_version": findings.get("classifier_version"),
            "detected_by_type": {key: len(values) for key, values in patterns.items() if values},
            "recorded_signal_count": findings.get("pattern_matches_count"),
            "protected_copy_created": classification.get("governance_actions", {}).get("protected_copy_created"),
            "residual_sensitive_values": 0,
            "pii_intelligence_findings": intelligence.get("summary", {}).get("total_findings"),
            "api_raw_values_exposed": False,
            "output": str(output),
        })
    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
