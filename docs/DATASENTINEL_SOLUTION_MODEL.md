# DataSentinel solution model

> **Current live mode (2 November 2026):** The public customer flow uses synchronous `POST /api/v1/protect` and returns the protected bytes directly. It creates no application-side document inventory or S3 output. The asynchronous S3 flow described below is a legacy/alternate model, not the active public workflow. See [current mode and retention](CURRENT_MODE_AND_RETENTION.md).

DataSentinel is a privacy-first document processing service. It receives a document for a limited processing job, detects sensitive information, creates a same-format redacted result, returns the result to the customer, and removes the uploaded source when `EPHEMERAL_PROCESSING_MODE=true`.

The sender remains the owner of the unredacted document. DataSentinel does not provide an unredaction button or an original-file link in ephemeral mode. If a recipient needs an unredacted field, the recipient asks the sender, and the sender decides how to share the original through their own trusted workflow.

## Service contract

```text
customer application
        │
        │ document + policy
        ▼
DataSentinel processing request
        │ malware / type / size checks
        │ OCR or text extraction
        │ PII and sensitive-data detection
        │ same-format redaction
        │ output verification
        ▼
redacted result + privacy receipt
        │
        └── source and temporary processing material deleted
```

The service returns decision metadata such as policy version, signal types, confidence, output checksum, processing ID and cleanup status. It must not return detected values or place document content in logs, telemetry, audit records or error messages.

The customer-facing entry point is `/customer`. It explains the hand-off in plain language, uses the
same secure upload contract as the management console, and shows a clearly labelled synthetic
passport preview. Passport is a distinct inventory category rather than being silently grouped with
all identity-card uploads.

## Permission boundary

DataSentinel can redact. DataSentinel cannot unredact. Any request for an unredacted value belongs to the sender or document owner. A future customer integration may record a permission request and approval receipt, but the original must remain in the sender's system.

## Ephemeral mode boundary

`EPHEMERAL_PROCESSING_MODE=true` removes the original source after the classifier has created and stored the protected result, disables original-file access in the API and hides original-access actions in the console. The current asynchronous learner-lab implementation still uses a short-lived protected output object so a customer can retrieve the result. A strict memory-only response path for every file type is a separate deployment architecture and must not be claimed until it is implemented and tested.

Passport images in JPG, JPEG and PNG use Textract OCR and geometry-aware pixel redaction when
extraction confidence is sufficient. Low-confidence or unsupported extraction must remain in a
review state; it must never be treated as proof that the image is clean.

## Safe product language

Use: “DataSentinel processes documents without becoming the document repository. In ephemeral mode, uploaded originals are deleted after processing, while the sender remains responsible for the unredacted source.”

Do not use: “DataSentinel can never retain any bytes” unless the synchronous memory-only path, worker scratch cleanup, provider logs and failure cleanup have all been independently verified.
