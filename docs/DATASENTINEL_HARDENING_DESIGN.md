# DataSentinel hardening design

Status: design and approval gate. No hardening code changes are authorised by this document alone.

## 1. Current state

The supported Learner Lab path is an event-driven AWS deployment:

```text
Customer or dashboard upload
  -> private raw S3 object
  -> EventBridge
  -> classifier Lambda
  -> parser + Textract OCR + existing PII detectors
  -> existing redaction engine
  -> clean S3 protected copy
  -> DynamoDB result/audit/access metadata
  -> short-lived protected-copy URL
```

The browser also has a local-only AES-GCM encryption flow. That flow does not upload the selected file or key. It is separate from the temporary server-processing flow.

Verified current boundaries:

- session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, short-lived and revocable;
- Learner Lab template has `ENFORCE_MALWARE_GATE=false`;
- the production edge/WAF template is separate from the current direct API endpoint;
- protected copies and governance metadata are still retained by the current workflow;
- raw-source cleanup is attempted on success and failure paths;
- human inventory is currently global rather than tenant/resource scoped;
- selective redaction now defaults to REDACT and requires confirmation for KEEP;
- 2FA/MFA is not active and must not be simulated in Learner Lab.

## 2. Target state

```text
Customer tenant
  -> authenticated, scoped job request
  -> isolated quarantine object
  -> malware decision (or explicit demo limitation)
  -> parser/OCR/PII detection (unchanged)
  -> validated customer redaction policy
  -> existing redaction engine
  -> output verification and cleanup verification
  -> one-time customer delivery
  -> encrypted original + key delivery only when explicitly selected
  -> delete every temporary object/version/buffer
  -> content-free status and audit metadata
```

The platform never stores a customer key, recovery key, plaintext original, extracted text or PII value. Customer-side decryption is the only supported original-file recovery path after delivery.

## 3. Trust boundaries

| Boundary | Lower-trust principal | Control |
| --- | --- | --- |
| Browser to API | anonymous/customer browser | session cookie, CSRF, schema and rate limits |
| Tenant to tenant | another tenant/client | tenant + owner + resource ACL on every query |
| Upload to parser | untrusted file | quarantine, malware decision, signature/size/page limits |
| Lambda to S3 | runtime role | prefix-scoped least privilege and version binding |
| Platform to customer original | DataSentinel service | customer-held key, one-time delivery, no server decrypt |
| Application audit to trust anchor | application operator | separate write-only anchor in production |

## 4. File lifecycle and cleanup invariant

Every job has a random job ID, immutable object key, source version ID and cleanup state.

Allowed states:

`PROCESSING -> COMPLETED -> DELIVERED -> CLEANED`

Failure states:

`REVIEW_REQUIRED`, `PROCESSING_FAILED`, `MALWARE_REJECTED`, `CLEANUP_FAILED`.

The job cannot be marked complete until:

- source object/version deletion is verified;
- protected temporary output deletion is verified when zero-retention is selected;
- multipart uploads are aborted;
- queue payloads contain metadata only;
- no key, plaintext, OCR text or PII value was logged;
- cleanup result is recorded without content.

## 5. Encryption and key ownership

| Item | Owner | Server may retain? |
| --- | --- | --- |
| Customer key | customer | No |
| Encrypted original | customer or explicitly selected customer storage | No after delivery in zero-retention mode |
| Redacted output | customer or explicitly selected retention mode | Only when the customer selects governed retention |
| AWS SSE/KMS | platform storage boundary | Encryption at rest only; not customer-controlled decryption |
| Recovery key | none | Never generated |

The browser decrypt flow must handle wrong key, corrupt ciphertext, missing key and integrity failure without sending either file to DataSentinel.

## 6. Role and permission matrix

| Action | Admin | Data owner | Reviewer | Auditor | Customer client |
| --- | ---: | ---: | ---: | ---: | ---: |
| health/status | yes | yes | yes | yes | scoped API only |
| content-free metadata | scoped | scoped | assigned scope | assigned scope | own tenant |
| original server download | no | no | no | no | no |
| protected output | scoped | scoped | scoped | protected-only | own job |
| policy confirmation | no override | delegated owner | no override | no | yes |
| access approval | delegated | delegated | no | no | no |
| customer key | never | never | never | never | customer only |
| audit evidence | scoped | scoped | assigned | read-only assigned | own job metadata |

## 7. Tenant isolation matrix

Every result, audit event, access request, API client, job and S3 key must carry:

`tenant_id`, `owner_id`, `created_by`, `resource_id`, `job_id` and `source_version_id`.

The API must reject requests when tenant or owner scope is missing. Inventory, DynamoDB queries, S3 lookup, access approval and protected-copy issuance must apply the same scope before reading any record.

## 8. AWS service inventory and control status

| Service/control | Learner Lab status | Target status |
| --- | --- | --- |
| S3 private buckets | active | active, version/cleanup verified |
| Lambda | active | isolated processing and bounded execution |
| EventBridge | active | immutable job/version event |
| DynamoDB | active | tenant keys and cursor queries |
| Textract | active where enabled | timeout and confidence gates |
| Comprehend | optional | bounded supplementary detector |
| WAF/CloudFront | not the active Learner Lab boundary | production edge only |
| GuardDuty malware scan | not enforced in current template | mandatory production quarantine gate |
| CloudTrail data events | not fully verified | S3/DDB/KMS/IAM data-event coverage |
| External audit anchor | not active by default | separate production trust boundary |
| MFA/2FA | not active | Cognito/SSO/external IdP migration |

## 9. IAM and KMS requirements

- runtime role reads only the assigned temporary source prefix and writes only the assigned output prefix;
- runtime role cannot read customer key material;
- admin cannot call an original-file route;
- audit writer cannot delete audit evidence;
- customer-side decryption requires no AWS permission;
- all bucket policies deny insecure transport and public access;
- production KMS grants are separated from application administration;
- no wildcard object access without an explicit documented exception.

## 10. Redaction policy

The current selective policy adapter remains the only policy layer. Detection remains regex/OCR/classifier-driven.

- all categories default to `REDACT`;
- KEEP requires explicit confirmation;
- high-risk credentials/identity/payment categories cannot be KEEP;
- unknown category becomes `REVIEW_REQUIRED`;
- policy is immutable after processing starts;
- output with KEEP is never labelled PII-free;
- audit stores category names and policy version, never values.

## 11. Logging and audit matrix

Allowed metadata: job ID, tenant reference, event type, duration, status, policy version, source version ID, correlation ID and cleanup result.

Forbidden: file content, extracted text, OCR blocks, regex matches, PII values, key material, passwords, bearer tokens, complete presigned URLs and full request/response bodies.

Application audit, CloudTrail data events and the production external trust anchor are separate evidence layers. Application hash chaining alone is not an external immutable archive.

## 12. Retention matrix

| Data | Current issue | Target |
| --- | --- | --- |
| raw source | success/failure cleanup attempted | deletion verified for every version |
| protected copy | retained by current workflow | deleted after delivery in zero-retention mode |
| OCR/intermediate | must be bounded to Lambda/job lifetime | no persistence |
| DynamoDB metadata | retained | content-free and tenant-scoped only |
| audit metadata | retained | content-free, independently anchored in production |
| queues/DLQ | must remain content-free | bounded retry and expiry |
| logs | metadata only | retention reviewed and monitored |
| backup/replication | not zero-retention by default | explicitly disabled or excluded for temporary content |

## 13. Threat and abuse cases

- cross-tenant resource IDOR;
- leaked presigned URL;
- parser bomb or malformed PDF;
- missing malware result;
- OCR timeout and partial page processing;
- duplicate event and version mismatch;
- policy KEEP bypass through direct API call;
- cleanup failure after customer disconnect;
- queue/DLQ content leakage;
- admin attempting original access;
- stale protected version retrieval;
- unbounded DynamoDB inventory scan;
- browser download policy blocking delivery.

## 14. API and UI hardening plan

API changes:

- remove/disable original-file routes by server-side feature flag;
- add tenant/owner scope validation to every resource route;
- add CSRF protection for cookie-authenticated state changes;
- add per-tenant/client upload and download quotas;
- add policy lock and cleanup status endpoints;
- add cursor pagination and bounded queries;
- expose content-free delivery and cleanup status only.

UI changes:

- show malware/OCR/redaction/cleanup states separately;
- show current Learner Lab limitations;
- remove all original-file controls;
- show customer key responsibility and loss warning;
- show REDACT/KEEP categories and partial-redaction warning;
- never render keys, tokens, full URLs or PII values.

## 15. Test plan

Authentication: cookie flags, expiry, logout revocation, CSRF, throttling and token non-leakage.

Authorization: cross-tenant read/write, IDOR, reviewer/owner/auditor boundaries, machine scopes and admin original denial.

Lifecycle: success/failure/timeout/retry/duplicate cleanup, object versions, multipart uploads, no plaintext in logs/database.

Redaction: all REDACT, selective KEEP, unknown category, low-confidence OCR, post-output verification and no PII in audit/API.

Encryption: wrong key, corrupt file, missing key, local decrypt and server inability to decrypt without key.

Infrastructure: bucket privacy, TLS-only policy, IAM boundaries, malware/WAF status contract and cleanup alarms.

Performance: bounded pagination, concurrent jobs, OCR timeout, queue backlog, throttling and idempotency.

## 16. Migration plan

1. Add tenant/resource identifiers and authorization helpers.
2. Disable original route server-side and remove original UI.
3. Add cleanup state machine and exact-version verification.
4. Move protected delivery to customer-controlled encryption flow.
5. Make malware gate a required production parameter.
6. Add cursor query indexes and quota controls.
7. Add CloudTrail/external-anchor production contract.
8. Update documentation and presentation claims.
9. Run security regression gate.
10. Deploy to Learner Lab only with unverified production controls visibly marked.

## 17. Files/components to change

- `src/api/main.py`
- `src/handlers/s3_classifier.py`
- `src/governance/redaction_policy.py`
- `src/utils/format_redactor.py` only through the policy adapter boundary
- `src/utils/dynamodb_client.py`
- `cloudformation/learner-lab.yml`
- `cloudformation/production-edge.yml`
- `frontend/index.html`
- `frontend/static/app.js`
- `frontend/customer.html`
- `frontend/static/customer.js`
- `scripts/verify_learner_lab.ps1`
- `tests/` security, lifecycle, tenant, policy and browser contracts
- `README.md`, `deployment/`, `docs/`

Must not change detector behaviour in:

- regex definitions;
- OCR/Textract extraction;
- document parser;
- classifier and confidence scoring;
- existing core redaction rules, except the minimum policy adapter boundary.

## 18. Open risks and approval decisions

- true zero-retention cannot be claimed while the current governed protected-copy workflow is selected;
- WAF, GuardDuty malware scanning, external audit anchoring and MFA remain production requirements, not Learner Lab claims;
- removing original access is a breaking API change and needs a migration decision;
- tenant isolation requires a data migration for existing global records;
- customer-controlled encrypted-original delivery requires an explicit customer download/receipt protocol;
- legal hold conflicts with zero-retention and must be selected per job.

## 19. Acceptance gate

Hardening is complete only when all of these are verified:

- admin cannot access an original through any application route;
- customer key is never persisted;
- customer-side decrypt works and fails safely;
- source and temporary output cleanup is verified;
- tenant/owner scope blocks IDOR and cross-tenant access;
- malware/WAF/MFA/external-anchor status is honest and verified;
- logs and audit contain no content or keys;
- source version is bound to the job and output;
- pagination and quotas are bounded;
- selective redaction remains safe by default;
- documentation matches deployment evidence;
- full security regression suite passes.

Approval is required before implementing the breaking original-access removal and the zero-retention migration.
