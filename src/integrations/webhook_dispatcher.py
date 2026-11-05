import base64
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import boto3
import urllib3


def validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook destinations must be credential-free HTTPS URLs.")
    hostname = parsed.hostname.casefold().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Webhook destinations cannot target localhost.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError("Webhook destinations cannot target private or reserved addresses.")
    if parsed.port and parsed.port != 443:
        raise ValueError("Webhook destinations must use the standard HTTPS port.")
    return url


def sign_webhook(secret: str, timestamp: int, body: bytes) -> str:
    signed = str(timestamp).encode() + b"." + body
    return hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


def _require_public_destination(destination: str) -> None:
    hostname = urlparse(destination).hostname
    if not hostname:
        raise ValueError("Webhook destination has no hostname.")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as error:
        raise ValueError("Webhook destination could not be resolved.") from error
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("Webhook destination resolved to a private or reserved address.")


def _revalidate_public_destination(destination: str) -> None:
    """Re-check DNS immediately before connect to narrow DNS rebinding exposure."""
    _require_public_destination(destination)


def _decrypt_secret(kms_client, ciphertext: str, tenant_id: str, client_id: str) -> str:
    response = kms_client.decrypt(
        CiphertextBlob=base64.b64decode(ciphertext),
        EncryptionContext={"tenant_id": tenant_id, "client_id": client_id},
    )
    return response["Plaintext"].decode()


def lambda_handler(event, _context):
    table_name = os.environ["ACCESS_REQUESTS_TABLE"]
    table = boto3.resource("dynamodb").Table(table_name)
    kms = boto3.client("kms")
    http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", timeout=urllib3.Timeout(total=8.0))
    delivered = 0
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        tenant_id = message["tenant_id"]
        client_id = message["client_id"]
        config_id = f"INTEGRATION_WEBHOOK#{tenant_id}#{client_id}"
        config = table.get_item(Key={"request_id": config_id}, ConsistentRead=True).get("Item")
        if not config or config.get("status") != "ACTIVE":
            continue
        client_id_key = f"INTEGRATION_CLIENT#{tenant_id}#{client_id}"
        client = table.get_item(
            Key={"request_id": client_id_key}, ConsistentRead=True
        ).get("Item")
        if not client or client.get("status") != "ACTIVE":
            continue
        destination = validate_webhook_url(config["url"])
        _require_public_destination(destination)
        body = json.dumps(message["payload"], separators=(",", ":"), sort_keys=True).encode()
        timestamp = int(time.time())
        secret = _decrypt_secret(kms, config["secret_ciphertext"], tenant_id, client_id)
        signature = sign_webhook(secret, timestamp, body)
        _revalidate_public_destination(destination)
        response = http.request(
            "POST",
            destination,
            body=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DataSentinel-Webhook/1.0",
                "X-DataSentinel-Event": message["payload"]["event"],
                "X-DataSentinel-Event-Id": message["payload"]["event_id"],
                "X-DataSentinel-Timestamp": str(timestamp),
                "X-DataSentinel-Signature": f"v1={signature}",
            },
            redirect=False,
        )
        now = datetime.now(UTC)
        delivered_ok = 200 <= response.status < 300
        table.put_item(
            Item={
                "request_id": (
                    f"WEBHOOK_DELIVERY#{message['payload']['event_id']}#"
                    f"{record.get('messageId') or record.get('eventID') or timestamp}"
                ),
                "record_type": "WEBHOOK_DELIVERY",
                "tenant_id": tenant_id,
                "client_id": client_id,
                "event_id": message["payload"]["event_id"],
                "event_type": message["payload"]["event"],
                "destination_host": urlparse(destination).hostname,
                "status": "DELIVERED" if delivered_ok else "FAILED",
                "http_status": response.status,
                "created_at": now.isoformat(),
                "expires_epoch": int((now + timedelta(days=90)).timestamp()),
            }
        )
        if not delivered_ok:
            raise RuntimeError(f"Webhook destination returned HTTP {response.status}")
        delivered += 1
    return {"delivered": delivered}
