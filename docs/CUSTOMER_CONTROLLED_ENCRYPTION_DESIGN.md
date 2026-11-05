# DataSentinel Customer-Controlled Encryption Design

Status: **design approved for implementation planning; code and AWS migration are not included in this document**

Date: 1 November 2026

This document defines the target architecture for DataSentinel after the architecture reset. It preserves the current regex, OCR, parser, classification, confidence-scoring and redaction engines. The change is the security boundary around those engines: temporary processing, customer ownership of encryption material, zero post-processing file retention, customer-side decryption and explicit Customer A to Customer B sharing.

## 1. Executive summary

DataSentinel will receive a plaintext document only for the short period required by the existing processing engine. The existing parser, OCR, PII detector, classifier and redactor will run unchanged. The service will return three outputs directly to Customer A: a redacted file, an encrypted copy of the original, and a customer-controlled key file. After delivery is confirmed, all plaintext, temporary output, intermediate OCR data and server-side encrypted output are removed. DataSentinel retains only minimum content-free workflow and audit metadata.

The encrypted original and key are a pair. DataSentinel never stores the key, never provides a recovery key, and never exposes an administrator decrypt operation. Customer A can give Customer B the encrypted file and key through channels chosen by Customer A. Decryption then happens on the recipient's device, outside DataSentinel.

This is **temporary processing with zero post-processing file retention**. It is not a claim that the service never receives plaintext. OCR and regex processing require readable content during the approved processing window.

## 2. Scope and invariants

### Preserved processing engine

The following are frozen interfaces for this migration:

- regex-based PII detection and existing patterns;
- OCR processing and its current failure behaviour;
- document parser and supported file validation;
- PII classification and confidence scoring;
- document-type classification;
- redaction logic and output format;
- fail-closed behaviour for unsupported, malformed, empty, encrypted, low-confidence or incomplete input.

No target-state change may alter detection rules or redaction semantics. Any detector change requires a separate approved change set with its own benchmark and regression evidence.

### Target privacy invariants

The target system must never persist:

- an original plaintext file after the processing job ends;
- a decrypted file;
- extracted text or OCR intermediate output;
- PII values or document content in a database, log, queue, cache, backup or telemetry stream;
- a customer key, private key, data key or recovery key;
- a permanent redacted file unless Customer A explicitly selects customer-controlled output storage.

The target system may retain content-free metadata: opaque job ID, status, timestamps, processing mode, sensitivity label, confidence summary, document category, cleanup result and generic audit event names.

## 3. Entities and trust boundaries

### Customer A

Customer A owns the original file, encrypted file and key. Customer A decides whether to keep the outputs locally, place them in customer-owned storage, or share them with Customer B.

### Customer B

Customer B receives no automatic access. Customer B can decrypt only when Customer A separately provides both the encrypted file and the matching key. DataSentinel must not decide whether Customer B deserves the key.

### DataSentinel

DataSentinel is a temporary processing service and governance coordinator. It can read plaintext only during an authenticated, consented processing job. It has no ownership of the original, no key custody, no recovery path and no administrator decrypt capability.

### Trust-boundary rule

The data plane and control plane are separate. Admin, reviewer and auditor roles may view status and content-free evidence, but none may read original plaintext, access an encrypted original stored by Customer A, obtain a key or bypass customer-side decryption.

## 4. Current state versus target state

### Current deployed state

The current Learner Lab stack uses API Gateway and FastAPI Lambda for the control plane, a private raw S3 bucket for intake, EventBridge and classifier Lambda for processing, Amazon Textract for image/scanned extraction, DynamoDB for results and audit records, and a private protected S3 bucket for the protected copy. The current workflow can retain protected output and metadata, and its raw source cleanup is not a proof of zero retention for every failure path.

### Target state

```text
Customer A browser or client
    │  TLS + explicit processing consent
    ▼
Temporary intake boundary
    │
    ├── existing parser
    ├── existing OCR
    ├── existing regex/PII engine
    ├── existing classifier
    └── existing redactor
    │
    ├── redacted file ───────────────► Customer A
    ├── encrypted original + key ────► Customer A
    └── content-free result/audit ───► minimal metadata store
    │
    ▼
Verified cleanup of plaintext, buffers and intermediates
```

The target does not use the current protected S3 bucket as automatic permanent storage. A customer-owned storage option is a separate, explicit workflow.

## 5. End-to-end lifecycle

```text
Customer creates file locally
        ↓
Customer signs in and selects Temporary processing
        ↓
Customer grants consent and receives a short-lived job authorization
        ↓
Plaintext travels over TLS to the isolated processing boundary
        ↓
Existing regex + OCR + PII detection + classification + redaction runs
        ↓
Redacted output and encrypted original are produced
        ↓
Customer A receives redacted file, encrypted file and key file
        ↓
Delivery is acknowledged without recording file contents
        ↓
Cleanup runs on success, failure, timeout and cancellation
        ↓
Cleanup evidence is stored without content
        ↓
Customer stores encrypted file and key independently
        ↓
Customer-side decryption reconstructs plaintext only when requested
```

Cleanup is not considered successful merely because a delete API returned 200. The worker must verify that its temporary object, temporary directory and intermediate references are gone, and must fail closed if verification cannot be completed.

## 6. Encryption and key ownership

### Recommended design

Customer-side key generation is the default. The browser or customer client generates a cryptographically random key with Web Crypto API or an equivalent vetted library. The key never leaves the customer device except when Customer A deliberately exports the key file.

The service may encrypt the original during temporary processing using a one-time transfer key supplied by the customer client, but it must not persist that key after output delivery. The preferred implementation is client-side encryption before customer custody is established, followed by a temporary processing consent path only when readable processing is explicitly selected.

Because the existing OCR engine requires plaintext, the first migration should implement two explicit modes:

| Mode | Plaintext reaches DataSentinel | Server OCR/redaction | Server retains file after job |
|---|---:|---:|---:|
| Local-only | No | No | No |
| Consent-based temporary processing | Yes, briefly | Yes | No |

The UI must never label the consent-based mode zero-knowledge. The target claim for that mode is temporary processing with zero post-processing file retention.

### Key file

The key file is a customer export, not a server artifact. It must contain only the encryption parameters required by the approved format and integrity metadata. It must not contain plaintext, customer profile data or a hidden recovery field.

Customer A must be warned that losing either the encrypted file or the key file makes recovery impossible. DataSentinel must not retain a master key or recovery copy.

## 7. Customer-side decryption

The decryption tool runs in the browser or a customer-controlled client. It accepts an encrypted file and a matching key file, checks the authenticated encryption tag and reconstructs the original only in local memory or a user-selected local save destination.

Required outcomes:

- correct key and ciphertext produce the original file locally;
- wrong key produces a generic key-mismatch error;
- damaged ciphertext produces an integrity error;
- damaged key file produces a key-format error;
- no key material is sent to DataSentinel;
- no decrypted bytes are sent to DataSentinel;
- download and browser storage are controlled by the customer.

## 8. Redacted output

The redacted file is generated by the existing redaction engine. It must be delivered to Customer A using a streaming response or a short-lived transfer object. Automatic permanent storage is disabled by default.

The UI must state that redaction is a protection decision, not proof that every sensitive value was found. Low-confidence or incomplete extraction remains fail-closed for review. A redacted output may still contain unrecognised sensitive information and must be labelled accordingly.

## 9. AWS architecture

### API Gateway or equivalent endpoint

- authenticates the customer and creates a short-lived processing job;
- accepts metadata and consent, never a permanent file record;
- does not log request bodies, file content, keys or complete presigned URLs;
- issues a one-time upload/processing authorization;
- exposes status and cleanup evidence only.

### Lambda or processing service

- invokes the unchanged processing engine;
- uses fixed memory, timeout and size limits;
- has a job-scoped identity and no customer-key permission;
- writes temporary data only to an isolated job workspace;
- performs cleanup in `finally` paths and a retryable cleanup worker;
- fails closed when cleanup cannot be verified.

### S3

S3 is not a permanent original-file store. If Textract or a job-size constraint requires a temporary object, it must use a job-scoped prefix or bucket with:

- public access blocked;
- TLS-only bucket policy;
- short lifecycle expiration;
- incomplete multipart cleanup;
- controlled versioning and noncurrent-version cleanup;
- no replication, backup or Object Lock that outlives the approved processing window;
- no key file;
- cleanup verification by object version listing.

Customer-controlled encrypted storage, if later offered, must be a separate bucket/account or a customer-owned bucket and must be labelled as customer custody. It is not part of default temporary processing.

### DynamoDB

Only opaque IDs, status, timestamps, generic sensitivity level, confidence summary, document category, processing mode and cleanup state are permitted. No OCR text, PII value, full sensitive filename, key or content hash that is used as a customer identifier may be stored.

### KMS

Platform SSE is encryption at rest and is not customer-controlled encryption. A KMS platform key must not be described as a customer key. KMS decrypt permissions must not create an administrator original-file path. If envelope encryption is used, the customer-controlled key remains outside DataSentinel custody and the processing role has no long-lived decrypt permission.

### Textract/OCR

Textract remains the existing OCR engine. It receives plaintext only during consent-based temporary processing. Extracted text and Textract responses must be held in memory or an isolated temporary workspace, never logged or persisted after redaction.

### CloudWatch and telemetry

Allowed fields are job ID, event type, status, duration, bounded size, error class and cleanup outcome. Forbidden fields are request bodies, OCR text, PII, keys, passwords, bearer tokens, full presigned URLs and plaintext filenames. Exception handling must replace file paths and provider payloads with generic identifiers.

### IAM

- customer roles control jobs and outputs, not platform keys;
- processing role is scoped to a job prefix and time-bounded operation;
- admin has health/status/audit permissions only;
- no role has a permanent original-file download permission;
- no role can read a customer key;
- control-plane IAM is separate from data-plane temporary access;
- wildcard `s3:GetObject` is prohibited for human roles.

### Secrets Manager and Parameter Store

Only application secrets belong here. Customer key material, encrypted original keys and recovery keys are prohibited.

### Backup and disaster recovery

Temporary plaintext must not enter backup, replication, snapshots or dead-letter queues. DynamoDB metadata backup is allowed only if it contains no content or PII. Retention of each service must be documented and tested rather than inferred from labels.

## 10. Access-control matrix

| Capability | Customer A | Customer B | Admin | Reviewer | Auditor |
|---|---:|---:|---:|---:|---:|
| Start own temporary job | Yes | No, unless invited | Operational only | No | No |
| See own job status | Yes | Only shared status | Yes, content-free | Yes, content-free | Yes, content-free |
| See original plaintext | Local device only | Only after A supplies key | No | No | No |
| Obtain customer key from DataSentinel | No | No | No | No | No |
| Download redacted output | Yes | If A shares it | Content-free evidence only | Review output only | No content by default |
| Store encrypted original in DataSentinel | Only by explicit storage choice | Only if A delegates custody | No key access | No | No |
| Decrypt through DataSentinel server | No | No | No | No | No |
| View audit metadata | Own events | Shared events only | Yes | Yes | Yes read-only |

## 11. Customer A to Customer B sharing

The supported sharing flow is:

1. Customer A downloads or transfers the redacted file if that is sufficient.
2. If Customer B needs the original, Customer A transfers the encrypted file.
3. Customer A separately transfers the key through a channel selected by Customer A.
4. Customer B decrypts locally.
5. DataSentinel records only a content-free sharing event if Customer A chooses to record it.

DataSentinel must not join the encrypted-file transfer and key transfer into an automatic grant. Not sharing the key is the revocation mechanism.

## 12. API boundary

The target API is divided into:

- `POST /auth/login` and `POST /auth/logout`;
- `POST /processing/jobs` to create a consented temporary job;
- `POST /processing/jobs/{job_id}/upload-authorisation` for one-time upload permission;
- `GET /processing/jobs/{job_id}` for content-free status;
- `GET /processing/jobs/{job_id}/redacted-output` for one-time output delivery;
- `GET /processing/jobs/{job_id}/encrypted-output` for one-time encrypted-output delivery;
- `GET /processing/jobs/{job_id}/cleanup` for cleanup evidence;
- `POST /sharing/events` for content-free Customer A sharing metadata;
- `GET /audit/events` for role-filtered audit metadata.

The API must not provide:

- a permanent original-file endpoint;
- an admin original download;
- a server decrypt endpoint;
- a key retrieval endpoint;
- a full extracted-text endpoint;
- a PII-value endpoint;
- an endpoint that accepts a customer key for storage.

## 13. UI flow

The customer UI must explain the ownership model before upload:

```text
1. Choose processing mode
2. Read and accept temporary-processing consent
3. Select file
4. Review what will be returned
5. Process
6. Download redacted file
7. Download encrypted original
8. Download key file once
9. Confirm local custody
10. Show cleanup result
```

The confirmation must warn:

> DataSentinel does not keep your key or a recovery copy. Keep the encrypted file and key file together. If either is lost, the original cannot be recovered.

The decryption screen accepts only local file selection. It must not upload either input and must make that fact visible.

## 14. Threat model and abuse cases

### Threats addressed

- administrator attempts to download original;
- database leak exposes classification metadata but not content;
- S3 bucket policy accidentally exposes a temporary object;
- logs capture OCR output or presigned URLs;
- Customer B receives ciphertext without authorization key;
- failed processing leaves plaintext behind;
- cleanup deletes the current object but leaves noncurrent S3 versions;
- browser sends customer key to the server accidentally;
- a stale job result is shown for a different customer job.

### Required abuse tests

- replay an expired upload authorization;
- alter job ID to another customer;
- use reviewer/auditor credentials to upload;
- request original through every existing endpoint;
- submit a key file to every upload or metadata endpoint;
- inject PII into filename, headers and error paths;
- interrupt processing at every stage and inspect cleanup;
- list S3 versions after success and failure;
- inspect CloudWatch, DLQ and DynamoDB for content;
- decrypt with wrong, truncated and mismatched keys;
- try Customer B access without a key;
- retry the same job and verify idempotency without duplicate output.

## 15. Failure behaviour

| Failure | Required result |
|---|---|
| OCR timeout | Job fails closed; temporary data cleanup is retried and verified |
| Detector exception | No `PUBLIC` result; job is `REVIEW_REQUIRED` or `FAILED` |
| Redaction failure | No output is marked protected; cleanup still runs |
| Delivery failure | Output is not considered delivered; cleanup retry policy is explicit |
| Cleanup verification failure | Job remains failed/blocked; no success claim |
| Wrong decryption key | Local generic mismatch error; no server request |
| Corrupt encrypted file | Local integrity error; no server request |
| Lost key | DataSentinel cannot recover the original |
| Lost encrypted file | DataSentinel cannot recover the original |
| Customer B has ciphertext only | Decryption is impossible until A supplies the key |

## 16. Migration plan

### Phase 0: Freeze and inventory

- freeze existing regex, OCR, parser, classifier, confidence and redaction modules;
- inventory every path that reads, writes, logs, queues, backs up or replicates file bytes;
- identify all original download routes and protected-storage assumptions;
- add negative tests for plaintext in logs, DB, queues and error payloads.

### Phase 1: Introduce job boundary

- replace global resource identifiers with tenant/customer-scoped job IDs;
- add explicit processing consent and processing mode;
- add one-time upload authorization;
- add a job cleanup state machine;
- keep the existing engine behind the new boundary without changing its rules.

### Phase 2: Remove automatic file retention

- stop automatic protected S3 persistence;
- stream redacted output to Customer A or write only to customer-owned storage;
- delete temporary object versions and multipart uploads;
- reject any path that continues after cleanup cannot be verified.

### Phase 3: Add customer-controlled encryption

- implement customer-side key generation/export;
- implement authenticated encryption and integrity checks;
- return encrypted original and key as separate customer downloads;
- ensure the server never receives the key;
- add customer-side decryption page and local-only tests.

### Phase 4: Close privileged paths

- remove original download routes;
- remove admin decrypt permissions;
- remove key retrieval and recovery code;
- restrict admin, reviewer and auditor to content-free metadata;
- review IAM and bucket policies with explicit deny tests.

### Phase 5: Verify and only then deploy

- run source, unit, integration, browser, cleanup, security and AWS tests;
- prove no plaintext remains in all configured stores after success and failure;
- prove wrong keys never reach the network;
- deploy first to an isolated stack;
- run acceptance tests against the isolated stack;
- obtain a separate review approval before replacing the existing Learner Lab stack.

## 17. Retention matrix

| Data | During job | After successful job | After failed job | Allowed owner |
|---|---|---|---|---|
| Original plaintext | Isolated processing only | Deleted and verified | Deleted and verified or job blocked for cleanup | Customer A during approved job |
| OCR intermediate | Temporary only | Deleted | Deleted and verified | Processing worker |
| Redacted file | Temporary until delivery | Customer A or explicit customer storage only | Deleted unless delivery is pending | Customer A |
| Encrypted original | Temporary until delivery | Customer A or explicit customer storage only | Deleted unless delivery is pending | Customer A |
| Key file | Customer device only | Customer device only | Customer device only | Customer A |
| Classification summary | Minimal metadata | Allowed if content-free | Allowed if content-free | DataSentinel control plane |
| Audit event | Content-free metadata | Allowed for retention period | Allowed for incident evidence | DataSentinel control plane |
| Logs | Bounded metadata | Minimum retention | Minimum retention | Operations team |

## 18. Security claim boundary

Allowed after evidence exists:

- temporary processing;
- zero post-processing file retention;
- customer-controlled key;
- customer-side decryption;
- no server-side key storage;
- no admin decrypt route;
- customer-owned encrypted file custody.

Not allowed without separate proof:

- zero knowledge;
- end-to-end encryption;
- impossible for administrators to access data;
- no data ever reaches the server;
- guaranteed permanent deletion;
- unbreakable encryption;
- compliance certification.

## 19. Acceptance criteria

The migration is not accepted until all of these pass:

1. Existing detector, OCR, classifier and redaction regression tests are unchanged and green.
2. A customer key is generated or supplied on the customer side and never appears in network requests to DataSentinel.
3. A correct key decrypts the encrypted output locally.
4. A wrong or damaged key fails locally without server contact.
5. Original, OCR output, redacted temporary output and encrypted temporary output are absent after successful cleanup.
6. The same cleanup evidence is produced after OCR failure, redaction failure, timeout, cancellation and delivery failure.
7. S3 current and noncurrent versions, multipart uploads, queues, logs and backups are checked.
8. No PII value or extracted text appears in DynamoDB, CloudWatch, DLQ, telemetry or error response.
9. Admin, reviewer and auditor cannot retrieve original, encrypted original stored by Customer A or key.
10. Customer B cannot decrypt without the separate key supplied by Customer A.
11. Redacted output is delivered in the original file format and is labelled as protection output, not proof of complete detection.
12. The deployment verifier proves release identity and all cleanup checks against an isolated AWS stack.

## 20. Open decisions before implementation

The design uses these defaults unless the project owner changes them:

| Decision | Default |
|---|---|
| Key generation | Customer-side in browser/client |
| Redacted output storage | No automatic server storage |
| Temporary OCR input | Isolated job object only when required by Textract |
| Metadata retention | Minimum content-free metadata and audit evidence |
| Processing modes | Local-only mode plus consent-based temporary processing |
| Key format | Versioned `.datasentinel-key` file with authenticated-encryption parameters |
| Encrypted original recipient | Customer A only |
| Customer B decryption | Outside DataSentinel on a customer-controlled device |
| Recovery | No recovery key, master key or admin override |

Changing one of these defaults requires updating the threat model, retention matrix and acceptance criteria before code changes.

## 21. Verification artefacts and current baseline

The current implementation baseline is documented in `output/qa-20261031/VERIFICATION.md`. It proves the existing server-side temporary source cleanup for controlled PDF and PNG fixtures, but it does not prove this target architecture. The target acceptance suite must be added before claiming that DataSentinel has migrated to customer-controlled encryption.

The existing health stack remains useful for regression: Python tests, Ruff, JavaScript syntax checks, AWS release verification and controlled OCR/redaction fixtures. Those checks must continue to pass after the target boundary is implemented.
