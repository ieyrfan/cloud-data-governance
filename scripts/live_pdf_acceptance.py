"""Live, secret-safe acceptance test for PDF protection and role boundaries."""

from __future__ import annotations

import argparse
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

import boto3
import pymupdf
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def stack_outputs(client: Any, stack_name: str) -> dict[str, str]:
    stack = client.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}


def make_pdf() -> bytes:
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=A4)
    document.setTitle("Controlled governance acceptance evidence")
    document.drawString(72, 780, "Cloud Data Governance acceptance evidence")
    document.drawString(72, 750, "Employee NRIC: 900101-14-5678")
    document.drawString(72, 720, "Email: acceptance.person@example.com")
    document.drawString(72, 690, "This non-sensitive sentence must remain readable.")
    document.showPage()
    document.save()
    return output.getvalue()


def api_json(
    url: str, token: str, *, expected_status: int = 200
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers={"X-Dashboard-Token": token})
    if urllib.parse.urlsplit(url).scheme != "https":
        raise RuntimeError("Acceptance API URL must use HTTPS")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
            status = response.status
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        status = error.code
        payload = json.loads(error.read() or b"{}")
    if status != expected_status:
        raise RuntimeError(f"Expected HTTP {expected_status}, received {status}")
    return status, payload


def api_login(api_url: str, username: str, password: str) -> str:
    """Exchange a role credential for the same short-lived session used by the UI."""
    request = urllib.request.Request(
        f"{api_url}/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if urllib.parse.urlsplit(api_url).scheme != "https":
        raise RuntimeError("Acceptance API URL must use HTTPS")
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        payload = json.loads(response.read())
    token = payload.get("session_token")
    if not token:
        raise RuntimeError(f"{username} login did not return a session token")
    return token


def read_role_logins(path: str) -> dict[str, str]:
    """Read the ignored deployment login file without logging its contents."""
    credentials: dict[str, str] = {}
    with open(path, encoding="utf-8") as source:
        for line in source:
            username, separator, password = line.strip().partition("=")
            if separator and username and password:
                credentials[username] = password
    return credentials


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stack-name", default="cloud-data-governance")
    parser.add_argument("--login-file", default=".learner-lab-login")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    outputs = stack_outputs(session.client("cloudformation"), args.stack_name)
    raw_bucket = outputs["RawDataBucketName"]
    clean_bucket = outputs["CleanDataBucketName"]
    api_url = outputs["ApiUrl"].rstrip("/")
    role_logins = read_role_logins(args.login_file)
    if not role_logins.get("reviewer") or not role_logins.get("admin"):
        raise RuntimeError("Reviewer and administrator logins are unavailable")
    reviewer_token = api_login(api_url, "reviewer", role_logins["reviewer"])
    admin_token = api_login(api_url, "admin", role_logins["admin"])
    if reviewer_token == admin_token:
        raise RuntimeError("Role sessions must be distinct")
    object_key = f"acceptance/format-preserving-{uuid.uuid4().hex[:12]}.pdf"
    source_pdf = make_pdf()

    s3 = session.client("s3")
    s3.put_object(
        Bucket=raw_bucket,
        Key=object_key,
        Body=source_pdf,
        ContentType="application/pdf",
    )
    protected_pdf = b""
    head: dict[str, Any] = {}
    for _ in range(36):
        try:
            head = s3.head_object(Bucket=clean_bucket, Key=object_key)
            protected_pdf = s3.get_object(Bucket=clean_bucket, Key=object_key)["Body"].read()
            break
        except s3.exceptions.ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {"404", "NoSuchKey"}:
                raise
            time.sleep(5)
    if not protected_pdf:
        raise RuntimeError("Protected PDF was not created within 180 seconds")

    if head.get("ContentType") != "application/pdf" or not protected_pdf.startswith(b"%PDF"):
        raise RuntimeError("Protected output is not served as a PDF")
    source_doc = pymupdf.open(stream=source_pdf, filetype="pdf")
    protected_doc = pymupdf.open(stream=protected_pdf, filetype="pdf")
    if len(source_doc) != len(protected_doc):
        raise RuntimeError("PDF page count changed")
    if source_doc[0].rect != protected_doc[0].rect:
        raise RuntimeError("PDF page dimensions changed")
    protected_text = "\n".join(page.get_text() for page in protected_doc)
    if "900101-14-5678" in protected_text or "acceptance.person@example.com" in protected_text:
        raise RuntimeError("Sensitive text remains extractable from protected PDF")
    if "non-sensitive sentence" not in protected_text:
        raise RuntimeError("Expected non-sensitive PDF content was lost")

    resource_id = f"s3://{raw_bucket}/{object_key}"
    query_base = urllib.parse.urlencode({"resource_id": resource_id})
    _, summary = api_json(f"{api_url}/dashboard/summary", reviewer_token)
    if summary.get("access_role") != "REVIEWER":
        raise RuntimeError("Reviewer token did not resolve to REVIEWER")
    _, protected = api_json(
        f"{api_url}/files/download?{query_base}&variant=protected&disposition=inline",
        reviewer_token,
    )
    if protected.get("variant") != "protected" or protected.get("expires_in_seconds") != 120:
        raise RuntimeError("Reviewer protected-download contract is invalid")
    if urllib.parse.urlsplit(protected["url"]).scheme != "https":
        raise RuntimeError("Signed download URL must use HTTPS")
    with urllib.request.urlopen(protected["url"], timeout=20) as response:  # nosec B310
        if response.read(4) != b"%PDF":
            raise RuntimeError("Reviewer signed URL did not return a PDF")
    api_json(
        f"{api_url}/files/download?{query_base}&variant=original&disposition=inline",
        reviewer_token,
        expected_status=403,
    )
    _, original = api_json(
        f"{api_url}/files/download?{query_base}&variant=original&disposition=inline",
        admin_token,
    )
    if original.get("variant") != "original" or original.get("access_role") != "ADMIN":
        raise RuntimeError("Admin original-download contract is invalid")

    print("PASS: protected output is a valid same-size, same-page-count PDF")
    print("PASS: controlled NRIC and email are no longer extractable")
    print("PASS: reviewer can retrieve protected PDF with a 120-second link")
    print("PASS: reviewer original access is denied with HTTP 403")
    print("PASS: administrator is authorized for the original-file route")
    print(f"Acceptance object: {object_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
