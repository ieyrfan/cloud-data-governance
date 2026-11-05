"""Small dependency-free DataSentinel Integration API client."""

import json
import urllib.error
import urllib.request


class DataSentinelError(RuntimeError):
    pass


class DataSentinelClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 20):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None, headers: dict | None = None):
        body = None if payload is None else json.dumps(payload).encode()
        request_headers = {"X-API-Key": self.api_key, "Accept": "application/json", **(headers or {})}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise DataSentinelError(f"DataSentinel returned HTTP {error.code}: {detail}") from error

    def whoami(self):
        return self._request("GET", "/api/v1/whoami")

    def create_document(
        self,
        filename: str,
        content_type: str,
        idempotency_key: str,
        *,
        purpose: str = "governed document processing",
        subject_reference: str = "",
        protection_profile: str = "malaysia-general",
    ):
        return self._request(
            "POST",
            "/api/v1/documents",
            {
                "filename": filename,
                "content_type": content_type,
                "purpose": purpose,
                "subject_reference": subject_reference,
                "protection_profile": protection_profile,
            },
            {"Idempotency-Key": idempotency_key},
        )

    def document(self, document_id: str):
        return self._request("GET", f"/api/v1/documents/{document_id}")

    def job(self, job_id: str):
        return self._request("GET", f"/api/v1/jobs/{job_id}")

    def protected_copy(self, document_id: str):
        return self._request("GET", f"/api/v1/documents/{document_id}/protected-copy")
