import base64
import hashlib
import hmac
import importlib
import json
import socket

import pytest

from src.handlers.s3_classifier import _webhook_message
from src.integrations import webhook_dispatcher


class FakeKms:
    def encrypt(self, **arguments):
        assert arguments["KeyId"] == "test-webhook-key"
        assert arguments["EncryptionContext"] == {
            "tenant_id": "faculty-demo",
            "client_id": "student-portal",
        }
        return {"CiphertextBlob": b"encrypted:" + arguments["Plaintext"]}

    def decrypt(self, **arguments):
        assert arguments["EncryptionContext"] == {
            "tenant_id": "faculty-demo",
            "client_id": "student-portal",
        }
        return {"Plaintext": arguments["CiphertextBlob"].removeprefix(b"encrypted:")}


def _api_module(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ADMIN_PASSWORD", "webhook-admin-password")
    monkeypatch.setenv("SESSION_SIGNING_SECRET", "webhook-session-secret")
    monkeypatch.setenv("WEBHOOK_KMS_KEY_ID", "test-webhook-key")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._demo_integration_records.clear()
    api_main._kms = FakeKms()
    api_main._create_managed_api_client(
        api_main.ApiClientCreate(
            tenant_id="faculty-demo",
            client_id="student-portal",
            label="Student portal",
            scopes=["documents:create", "documents:read"],
            expires_in_days=30,
        ),
        "admin",
    )
    return api_main


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/events",
        "https://localhost/events",
        "https://127.0.0.1/events",
        "https://10.0.0.2/events",
        "https://user:password@hooks.example.com/events",
        "https://hooks.example.com:8443/events",
    ],
)
def test_webhook_url_rejects_unsafe_destinations(url):
    with pytest.raises(ValueError):
        webhook_dispatcher.validate_webhook_url(url)


def test_webhook_signature_is_deterministic_and_bound_to_timestamp_and_body():
    body = b'{"event":"document.processing.completed"}'
    expected = hmac.new(b"secret", b"1729000000." + body, hashlib.sha256).hexdigest()
    assert webhook_dispatcher.sign_webhook("secret", 1729000000, body) == expected
    assert webhook_dispatcher.sign_webhook("secret", 1729000001, body) != expected


def test_webhook_registration_returns_secret_once_and_never_lists_ciphertext(monkeypatch):
    api_main = _api_module(monkeypatch)
    registered = api_main.register_client_webhook(
        "faculty-demo",
        "student-portal",
        api_main.WebhookRegistration(url="https://hooks.example.com/events"),
        {"username": "admin", "role": "ADMIN"},
    )
    assert registered["signing_secret"].startswith("whsec_")
    assert "secret_ciphertext" not in registered

    fetched = api_main.get_client_webhook(
        "faculty-demo",
        "student-portal",
        {"username": "admin", "role": "ADMIN"},
    )
    assert "signing_secret" not in fetched
    assert "secret_ciphertext" not in fetched
    stored = api_main._demo_integration_records[
        "INTEGRATION_WEBHOOK#faculty-demo#student-portal"
    ]
    assert stored["secret_ciphertext"]

    disabled = api_main.disable_client_webhook(
        "faculty-demo",
        "student-portal",
        {"username": "admin", "role": "ADMIN"},
    )
    assert disabled["status"] == "DISABLED"


def test_dispatcher_signs_safe_payload_and_records_delivery(monkeypatch):
    secret = "whsec_delivery-test"
    config = {
        "status": "ACTIVE",
        "url": "https://hooks.example.com/events",
        "secret_ciphertext": base64.b64encode(b"encrypted:" + secret.encode()).decode(),
    }

    class FakeTable:
        def __init__(self):
            self.writes = []

        def get_item(self, **arguments):
            record_id = arguments["Key"]["request_id"]
            if record_id.startswith("INTEGRATION_WEBHOOK#"):
                return {"Item": config}
            return {"Item": {"status": "ACTIVE"}}

        def put_item(self, **arguments):
            self.writes.append(arguments["Item"])

    class FakeResource:
        def __init__(self, table):
            self.table = table

        def Table(self, _name):
            return self.table

    class FakeResponse:
        status = 204

    class FakeHttp:
        def __init__(self):
            self.request_arguments = None

        def request(self, *_args, **kwargs):
            self.request_arguments = kwargs
            return FakeResponse()

    table = FakeTable()
    http = FakeHttp()
    monkeypatch.setenv("ACCESS_REQUESTS_TABLE", "test-table")
    monkeypatch.setattr(webhook_dispatcher.boto3, "resource", lambda *_a, **_k: FakeResource(table))
    monkeypatch.setattr(webhook_dispatcher.boto3, "client", lambda *_a, **_k: FakeKms())
    monkeypatch.setattr(webhook_dispatcher.urllib3, "PoolManager", lambda **_k: http)
    monkeypatch.setattr(
        webhook_dispatcher.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    payload = {
        "event": "document.processing.completed",
        "event_id": "evt_safe",
        "document_id": "doc_safe",
        "values_disclosed": False,
    }
    result = webhook_dispatcher.lambda_handler(
        {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "tenant_id": "faculty-demo",
                            "client_id": "student-portal",
                            "payload": payload,
                        }
                    )
                }
            ]
        },
        None,
    )
    assert result == {"delivered": 1}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    timestamp = int(http.request_arguments["headers"]["X-DataSentinel-Timestamp"])
    assert http.request_arguments["headers"]["X-DataSentinel-Signature"] == (
        f"v1={webhook_dispatcher.sign_webhook(secret, timestamp, body)}"
    )
    assert http.request_arguments["redirect"] is False
    assert table.writes[0]["status"] == "DELIVERED"
    assert "secret" not in json.dumps(table.writes[0]).lower()


def test_cloudformation_wires_encrypted_webhook_queue_worker_and_alarms():
    from pathlib import Path

    template = (Path(__file__).parents[1] / "cloudformation" / "learner-lab.yml").read_text()
    assert "WebhookSigningKey:" in template
    assert "EnableKeyRotation: true" in template
    assert "WebhookDeadLetterQueue:" in template
    assert "maxReceiveCount: 3" in template
    assert "WebhookDispatcherFunction:" in template
    assert "WebhookEventSourceMapping:" in template
    assert "WEBHOOK_QUEUE_URL: !Ref WebhookQueue" in template
    assert "WEBHOOK_KMS_KEY_ID: !Ref WebhookSigningKey" in template
    assert "WebhookDispatcherErrorsAlarm:" in template
    assert "WebhookDeadLetterAlarm:" in template


def test_classifier_webhook_payload_is_deliberately_pii_free():
    message = _webhook_message(
        tenant_id="faculty-demo",
        client_id="student-portal",
        document_id="doc_123",
        source_fingerprint="abc123",
        sensitivity="RESTRICTED",
        confidence=0.99,
        risk_level="HIGH",
        document_type="IDENTITY_DOCUMENT",
        protected_available=True,
    )
    encoded = json.dumps(message)
    assert message["payload"]["values_disclosed"] is False
    assert "findings" not in encoded
    assert "pattern_matches" not in encoded
    assert "s3://" not in encoded
    assert "resource_id" not in encoded


def test_revoking_client_also_disables_its_webhook(monkeypatch):
    api_main = _api_module(monkeypatch)
    api_main.register_client_webhook(
        "faculty-demo",
        "student-portal",
        api_main.WebhookRegistration(url="https://hooks.example.com/events"),
        {"username": "admin", "role": "ADMIN"},
    )
    api_main.revoke_managed_api_client(
        "faculty-demo",
        "student-portal",
        {"username": "admin", "role": "ADMIN"},
    )
    webhook = api_main._demo_integration_records[
        "INTEGRATION_WEBHOOK#faculty-demo#student-portal"
    ]
    assert webhook["status"] == "DISABLED"
    assert webhook["disabled_reason"] == "API_CLIENT_REVOKED"
