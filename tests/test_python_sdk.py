import json
from unittest.mock import patch

from sdk.python.datasentinel_client import DataSentinelClient


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_sdk_sends_machine_key_idempotency_and_privacy_safe_payload():
    calls = []

    def fake_open(request, timeout):
        calls.append((request, timeout))
        return _Response({"document_id": "doc_123", "job_id": "job_123"})

    client = DataSentinelClient("https://datasentinel.example/", "ds_live_secret")
    with patch("urllib.request.urlopen", fake_open):
        result = client.create_document("evidence.pdf", "application/pdf", "request-123")
    request, timeout = calls[0]
    assert result["document_id"] == "doc_123"
    assert request.full_url == "https://datasentinel.example/api/v1/documents"
    assert request.headers["X-api-key"] == "ds_live_secret"
    assert request.headers["Idempotency-key"] == "request-123"
    assert json.loads(request.data) == {
        "filename": "evidence.pdf",
        "content_type": "application/pdf",
        "purpose": "governed document processing",
        "subject_reference": "",
        "protection_profile": "malaysia-general",
    }
    assert timeout == 20
