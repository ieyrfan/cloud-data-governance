"""Small external-customer example for the DataSentinel Integration API.

The example uses synthetic PII only. It reads the ignored machine credential file,
never prints the API key, and shows the safe result fields a customer application
would consume.
"""

from __future__ import annotations

import argparse
import mimetypes
import time
import uuid
from pathlib import Path

from verify_integration_api import (
    request_json,
    upload_contract,
)


def read_client(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key and value:
            values[key] = value
    if not {"tenant_id", "client_id", "api_key"}.issubset(values):
        raise RuntimeError("Integration client file is incomplete. Deploy the stack first.")
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic customer integration example.")
    parser.add_argument(
        "--base-url", required=True, help="HTTPS URL of your own DataSentinel deployment"
    )
    parser.add_argument("--client-file", default=".datasentinel-integration-client")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://"):
        raise RuntimeError("Customer example requires an HTTPS base URL.")

    client = read_client(Path(args.client_file))
    api_key = client["api_key"]
    identity = request_json("GET", f"{base_url}/api/v1/whoami", api_key)
    print(f"Customer app identity: {identity['tenant_id']} / {identity['client_id']}")
    print(f"Granted scopes: {', '.join(identity['scopes'])}")

    filename = "synthetic-customer-document.txt"
    content_type = mimetypes.guess_type(filename)[0] or "text/plain"
    content = (
        b"Synthetic customer document for demonstration only.\n"
        b"NRIC: 900101-14-5678\n"
        b"Email: customer.demo@example.com\n"
        b"This sentence should remain readable.\n"
    )
    idempotency_key = f"customer-demo-{uuid.uuid4().hex}"
    created = request_json(
        "POST",
        f"{base_url}/api/v1/documents",
        api_key,
        payload={
            "filename": filename,
            "content_type": content_type,
            "purpose": "customer-demo",
            "subject_reference": "SYNTHETIC-CUSTOMER-001",
            "protection_profile": "malaysia-general",
        },
        idempotency_key=idempotency_key,
    )
    print(f"Job created: {created['job_id']}")
    upload_contract(created["upload"], filename, content, content_type)
    print("Upload complete: processing is asynchronous")

    completed = None
    for _ in range(36):
        status = request_json("GET", f"{base_url}/api/v1/jobs/{created['job_id']}", api_key)
        if status.get("status") == "completed":
            completed = status
            break
        time.sleep(5)
    if not completed:
        raise RuntimeError("Customer job did not complete within 180 seconds.")

    classification = completed.get("classification", {})
    signals = [signal.get("type", "UNKNOWN") for signal in completed.get("detected_signals", [])]
    print(f"Decision: {classification.get('sensitivity')} / {classification.get('risk_level')}")
    print(f"Document type: {classification.get('document_type')}")
    print(f"Signals (types only): {', '.join(signals)}")
    print(f"Protected copy available: {completed.get('protected_copy', {}).get('available')}")

    protected = request_json(
        "GET",
        f"{base_url}/api/v1/documents/{created['document_id']}/protected-copy?disposition=attachment",
        api_key,
    )
    print(f"Protected copy issued: expires in {protected.get('expires_in_seconds', 120)} seconds")
    print(f"Audit correlation: {protected['correlation_id']}")
    print("Customer result: the application receives a protected copy, never detected values.")

    replay = request_json(
        "POST",
        f"{base_url}/api/v1/documents",
        api_key,
        payload={
            "filename": filename,
            "content_type": content_type,
            "purpose": "customer-demo",
            "subject_reference": "SYNTHETIC-CUSTOMER-001",
            "protection_profile": "malaysia-general",
        },
        idempotency_key=idempotency_key,
    )
    print(f"Idempotency replay: {replay.get('replayed')} (same job returned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
