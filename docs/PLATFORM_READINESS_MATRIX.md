# DataSentinel platform readiness matrix

This matrix distinguishes controls that are active in the AWS Academy Learner
Lab deployment from integration boundaries and production artifacts. A source
file or template is not described as an active cloud control until live evidence
confirms that it is deployed and operating.

| Capability | Learner Lab status | Evidence and boundary |
| --- | --- | --- |
| Multi-page OCR | **Active** | Amazon Textract extracts images and scanned PDF pages. Incomplete or low-confidence extraction fails closed instead of becoming `PUBLIC`. |
| PII classification and protection | **Active** | Versioned classifier and policy evidence, Malaysian NRIC/address/contact patterns, and same-format protected copies. Matching values are not exposed in API explanations or analytics. |
| Malware quarantine | **Integration-ready** | The classifier consumes the trusted `GuardDutyMalwareScanStatus` S3 tag and fails closed when enforcement is enabled. Learner Lab does not provision the external GuardDuty scanner, so enforcement remains off there. |
| Internal RBAC | **Active** | Signed sessions and distinct administrator, data-owner, reviewer, and auditor workspaces. Original access remains approval-controlled. |
| Federated identity | **Integration-ready** | A strict verified-claims adapter maps a trusted issuer, tenant, subject, username, and exactly one DataSentinel group. JWT signature verification remains the responsibility of the production identity authorizer. |
| Tenant and API-client management | **Active** | Versioned `/api/v1` API, hashed client secrets, tenant namespacing, explicit scopes, idempotency, and short-lived protected-copy issuance. |
| Signed webhooks | **Active** | Deliveries use HMAC signatures, identifiers, timestamps, retry evidence, and redacted payloads. |
| Versioned policy studio | **Active** | The console exposes versioned profiles and policy simulation; classification records preserve the applied policy and classifier versions. |
| Review workflow | **Active** | Review records, priority, assignment evidence, original-access approval, and role-specific control views are available without disclosing matched PII values. |
| Audit ledger | **Active** | SHA-256 hash chaining and full server-side verification are active. HMAC checkpoints are signed and verifiable within the application trust boundary. |
| External audit trust anchor | **Integration-ready; optional implemented boundary** | `src/governance/external_anchor.py` publishes content-free checkpoints to a separately governed Object-Lock/KMS S3 bucket when `AUDIT_ANCHOR_BUCKET` is configured; otherwise `external_anchor_active=false` remains explicit. See `cloudformation/production-integrity-anchor.yml`. |
| Rate control | **Active** | API Gateway applies 10 requests/second with a burst of 20, and detailed route metrics are enabled. |
| AWS WAF | **Production artifact** (with origin lock) | `cloudformation/production-edge.yml` places CloudFront in front of the HTTP API, attaches managed common-rule, known-bad-input, and per-IP rate controls, and forwards an origin secret. Configure the same `EDGE_SHARED_SECRET` in the API runtime to reject direct API Gateway bypass. It is not deployed in Learner Lab. |
| Incident workflow | **Active** | Incidents enforce `OPEN -> TRIAGED -> CONTAINED -> RESOLVED` transitions with audit-friendly evidence. |
| Privacy-safe analytics | **Active** | Aggregates reveal signal types and operational counts, never matched values. |
| Retention and legal hold | **Control record only** | Versioned retention-control records capture the requested hold. Storage-level deletion enforcement and Object Lock remain required before claiming deletion is blocked. |
| Observability | **Active** | CloudWatch logs, detailed API metrics, five alarms, encrypted queues, dead-letter monitoring, health and authenticated readiness endpoints. |
| Disaster recovery | **Artifact and procedure** | `deployment/DISASTER_RECOVERY_RUNBOOK.md` defines backup, restore, evidence validation, RTO/RPO targets, and exercises. Learner Lab remains single-region. |
| Developer experience | **Active** | OpenAPI at `/api/docs`, integration contract, dependency-free Python SDK, correlation IDs, idempotency, and asynchronous job status. |

## Presentation-safe statement

DataSentinel is a working API-first data-protection platform in Learner Lab. Its
classification, protected-copy, governance, client API, signed webhook,
operations, rate-control, and evidence capabilities are active. GuardDuty
malware scanning, federated identity verification, AWS WAF association, an
external audit anchor, object-lock governance, and multi-region recovery are
explicit production integrations or artifacts—not simulated active services.
