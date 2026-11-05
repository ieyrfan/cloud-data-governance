"""Secret-safe live acceptance test for the DataSentinel Integration API."""

from __future__ import annotations

import argparse
import json
import mimetypes
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


def read_client(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key and value:
            values[key] = value
    required = {"tenant_id", "client_id", "api_key"}
    if not required.issubset(values):
        raise RuntimeError("Integration client file is incomplete. Deploy the stack first.")
    return values


def request_json(
    method: str,
    url: str,
    api_key: str,
    *,
    payload: dict[str, Any] | None = None,
    idempotency_key: str = "",
) -> dict[str, Any]:
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Integration API returned HTTP {error.code}: {detail}") from error


def multipart_body(fields: dict[str, str], filename: str, content: bytes, content_type: str):
    boundary = f"----DataSentinel{uuid.uuid4().hex}"
    chunks = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                str(value).encode(),
                b"\r\n",
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            ).encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            content,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return boundary, b"".join(chunks)


def upload_contract(contract: dict[str, Any], filename: str, content: bytes, content_type: str):
    boundary, body = multipart_body(contract["form_fields"], filename, content, content_type)
    request = urllib.request.Request(
        contract["url"],
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:  # nosec B310
            if response.status not in {200, 201, 204}:
                raise RuntimeError(f"S3 upload returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"S3 upload returned HTTP {error.code}: {detail}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://datasentinel.ifhx.my")
    parser.add_argument("--client-file", default=".datasentinel-integration-client")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://"):
        raise RuntimeError("Integration acceptance requires an HTTPS base URL.")
    client = read_client(Path(args.client_file))
    api_key = client["api_key"]

    identity = request_json("GET", f"{base_url}/api/v1/whoami", api_key)
    if identity.get("tenant_id") != client["tenant_id"]:
        raise RuntimeError("Machine identity returned the wrong tenant.")
    if identity.get("client_id") != client["client_id"]:
        raise RuntimeError("Machine identity returned the wrong client.")

    filename = "integration-acceptance.txt"
    content_type = mimetypes.guess_type(filename)[0] or "text/plain"
    controlled_content = (
        b"DataSentinel external application acceptance evidence.\n"
        b"NRIC: 900101-14-5678\n"
        b"Email: integration.acceptance@example.com\n"
        b"This non-sensitive sentence must remain readable.\n"
    )
    idempotency_key = f"acceptance-{uuid.uuid4().hex}"
    creation_payload = {
        "filename": filename,
        "content_type": content_type,
        "purpose": "automated-integration-acceptance",
        "subject_reference": "SYNTHETIC-ONLY",
        "protection_profile": "malaysia-general",
    }
    created = request_json(
        "POST",
        f"{base_url}/api/v1/documents",
        api_key,
        payload=creation_payload,
        idempotency_key=idempotency_key,
    )
    upload_contract(created["upload"], filename, controlled_content, content_type)

    completed = None
    for _ in range(36):
        status = request_json(
            "GET", f"{base_url}/api/v1/jobs/{created['job_id']}", api_key
        )
        if status.get("status") == "completed":
            completed = status
            break
        time.sleep(5)
    if not completed:
        raise RuntimeError("Integration document did not complete within 180 seconds.")
    if completed.get("classification", {}).get("sensitivity") != "RESTRICTED":
        raise RuntimeError("Controlled PII was not classified as RESTRICTED.")
    signal_types = {signal.get("type") for signal in completed.get("detected_signals", [])}
    if not any("NRIC" in str(signal) for signal in signal_types) or not any(
        "EMAIL" in str(signal) for signal in signal_types
    ):
        raise RuntimeError("The Integration API did not report the expected signal types.")
    if "900101" in json.dumps(completed):
        raise RuntimeError("A detected NRIC value leaked through the Integration API response.")

    protected = request_json(
        "GET",
        f"{base_url}/api/v1/documents/{created['document_id']}/protected-copy",
        api_key,
    )
    with urllib.request.urlopen(protected["url"], timeout=30) as response:  # nosec B310
        protected_content = response.read()
    if b"900101-14-5678" in protected_content or b"integration.acceptance@example.com" in protected_content:
        raise RuntimeError("Sensitive values remain in the protected external-API copy.")
    if b"[REDACTED - NRIC]" not in protected_content:
        raise RuntimeError("Protected copy does not contain the expected NRIC redaction marker.")

    replay = request_json(
        "POST",
        f"{base_url}/api/v1/documents",
        api_key,
        payload=creation_payload,
        idempotency_key=idempotency_key,
    )
    if replay.get("document_id") != created["document_id"] or not replay.get("replayed"):
        raise RuntimeError("Idempotency replay did not return the original document.")

    print("PASS: machine identity resolves to the configured tenant and client")
    print("PASS: idempotent document and asynchronous job resources are stable")
    print("PASS: controlled NRIC and email produce a RESTRICTED decision")
    print("PASS: Integration API discloses signal types without detected values")
    print("PASS: protected copy removes the controlled sensitive values")
    print("PASS: protected-copy issuance returns correlation evidence")
    print(f"Acceptance document: {created['document_id']}")
    print(f"Correlation ID: {protected['correlation_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
