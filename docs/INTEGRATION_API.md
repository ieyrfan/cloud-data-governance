# DataSentinel Integration API v1

> **Current deployment notice (2 November 2026):** The asynchronous create/job/status and API-key workflow described below is disabled by `STRICT_TRANSIENT_MODE=true` on the public Learner Lab deployment and returns HTTP 410. The active **public, no-login/no-key** contract is `POST /api/v1/protect`, which accepts one raw file body (maximum 3 MiB), `X-Filename`, and optional redaction-policy headers, then returns protected bytes or an error without a document record. Successful responses also carry content-free receipt headers. See [current mode and retention](CURRENT_MODE_AND_RETENTION.md). Do not give clients the old integration instructions for this deployment.

## Product boundary

DataSentinel is a reusable Data Protection and Governance as a Service platform. External systems submit documents and consume classification, protection and policy decisions. The browser dashboard is a management and human-review console, not the primary product boundary.

Base URL for the current demonstration:

```text
https://datasentinel.ifhx.my/api/v1
```

The AWS Academy deployment includes an administrator-managed tenant/client registry with one-time API keys, independent rotation, revocation, explicit scopes and signed webhook configuration. Tenant/client namespacing is active. Production self-service onboarding, OAuth client credentials, per-tenant quotas, billing and organisation lifecycle automation remain future control-plane work.

## Authentication

Every Integration API request requires:

```http
X-API-Key: <client API key>
```

The deployment script derives a temporary key from the active Learner Lab session and writes it to the ignored `.datasentinel-integration-client` file. Only its SHA-256 hash is stored in the Lambda environment. The credential expires operationally with the Learner Lab deployment and must never be committed, pasted into screenshots, embedded in frontend code or sent as a query parameter.

Current scopes:

| Scope | Permission |
|---|---|
| `documents:create` | Create an asynchronous document and secure-upload contract |
| `documents:read` | Read document and job status for the configured client |
| `protected-copy:read` | Request an audited, 120-second protected-copy URL |

The external Integration API intentionally has no original-document scope. Original access remains a human-governed management-console workflow.

## Machine identity

```http
GET /api/v1/whoami
X-API-Key: <client API key>
```

Example response:

```json
{
  "tenant_id": "ifhx-demo",
  "client_id": "booth-client",
  "scopes": [
    "documents:create",
    "documents:read",
    "protected-copy:read"
  ],
  "authentication": "API_KEY_SHA256"
}
```

## Create a document job

```http
POST /api/v1/documents
X-API-Key: <client API key>
Idempotency-Key: university-case-10042
Content-Type: application/json
```

```json
{
  "filename": "result-slip.pdf",
  "content_type": "application/pdf",
  "purpose": "student-record-verification",
  "subject_reference": "STUDENT-10042",
  "protection_profile": "malaysia-academic-record"
}
```

`Idempotency-Key` is mandatory, scoped to the configured tenant and client, and retained for 24 hours. Repeating the same key returns the same `document_id` and `job_id` rather than creating duplicate processing work.

Example `202 Accepted` response:

```json
{
  "document_id": "doc_...",
  "job_id": "job_...",
  "status": "awaiting_upload",
  "replayed": false,
  "upload": {
    "method": "POST",
    "url": "https://...s3.amazonaws.com/",
    "form_fields": {},
    "expires_in_seconds": 300,
    "max_bytes": 5242880
  },
  "links": {
    "document": "/api/v1/documents/doc_...",
    "job": "/api/v1/jobs/job_..."
  }
}
```

Submit the file as `multipart/form-data` to `upload.url`, preserving every returned field and adding the file as the final form part. The policy rejects empty files, files beyond 5 MiB, mismatched content types and altered tenant/client/document metadata.

## Read job or document status

```http
GET /api/v1/jobs/{job_id}
GET /api/v1/documents/{document_id}
X-API-Key: <client API key>
```

Possible states:

- `awaiting_upload` — no raw object exists yet.
- `processing` — the object exists but classification evidence is not complete.
- `completed` — classification and governance evidence are available.

Completed response excerpt:

```json
{
  "status": "completed",
  "classification": {
    "sensitivity": "RESTRICTED",
    "document_type": "ACADEMIC_RESULT",
    "confidence": 0.97,
    "risk_level": "CRITICAL",
    "review_required": true
  },
  "detected_signals": [
    {
      "type": "MALAYSIAN_NRIC",
      "values_disclosed": false
    }
  ],
  "protected_copy": {
    "available": true
  },
  "policy_decision": {
    "default_access": "PROTECTED_ONLY",
    "original_access": "MANAGEMENT_APPROVAL_REQUIRED",
    "policy_id": "DS-MY-PII-004",
    "policy_version": "2026.10"
  }
}
```

Detected values are never returned in JSON.

## Request a protected copy

```http
GET /api/v1/documents/{document_id}/protected-copy?disposition=inline
X-API-Key: <client API key>
```

The response includes a 120-second S3 URL and `correlation_id`. Issuance is written as an `INTEGRATION_ACCESS_EVENT` carrying tenant, client, document, action and retention evidence. Failure to record the event prevents the link from being returned.

## Isolation and safety guarantees

- Object keys are namespaced under `integrations/{tenant_id}/{client_id}/{document_id}/`.
- Document and job records are addressed with tenant-scoped keys.
- A configured client cannot fetch a document created under another tenant/client key.
- Raw key material is not stored in the stack.
- Upload metadata binds tenant, client and document identity into the signed S3 policy.
- Sensitive values are absent from status responses.
- The Integration API exposes protected copies only.
- Every protected-link issuance receives a correlation record.
- Unsupported and unproven content continues to fail closed through the classifier.

## Error model

| Status | Meaning |
|---|---|
| `400` | Missing or invalid idempotency contract |
| `401` | Missing or invalid API key |
| `403` | Client lacks the required scope |
| `404` | Tenant/client-scoped document or job does not exist |
| `409` | Upload/processing/protected copy is not ready |
| `422` | Unsupported extension, MIME mismatch or invalid request body |
| `500` | Secure upload/link issuance could not be completed |
| `503` | Integration authentication or document status dependency unavailable |

## Production evolution

The Learner Lab release demonstrates the complete integration flow with managed clients, key rotation/revocation and signed webhook delivery. A commercial control plane should replace API keys with OAuth 2.0 client credentials or signed JWTs where appropriate, and add self-service organisation onboarding, per-tenant quotas, usage metering, WAF controls and tenant-specific policy administration.
