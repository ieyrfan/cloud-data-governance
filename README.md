# DataSentinel — Data Protection and Governance as a Service

## Current live workflow (2 November 2026)

**Start here for the active deployment:** [Current mode, AWS retention map and booth script](docs/CURRENT_MODE_AND_RETENTION.md). The longer inventory and governance sections below document a disabled legacy/alternate mode, not the public customer experience.

This source snapshot supports **direct redaction** for the Learner Lab deployment. The project URL is `https://datasentinel.ifhx.my/`; this repository publication does not verify its current availability or deployed revision. Its public page and `POST /api/v1/protect` need no user account or API key. The API processes one file in memory and returns same-format protected bytes; the browser starts the download immediately. The free public deployment has an atomic, shared 200-request daily allowance (UTC) and a one-request-per-second route target. Only the day and aggregate count are stored for this allowance; no IP address, document name or document content is stored in that table. The application does not create a customer document record, store the submitted file or protected result in S3, or offer an original-file retrieval path. Legacy inventory, review, retention, and stored-document API routes return HTTP 410 in this mode. Supported input is at most 3 MiB; scanned PDFs are limited to three pages. For images, low-confidence OCR lines are covered, a second OCR pass is attempted when useful, and output is re-read before release. If no sensitive field is reliably detected or redaction cannot be verified, no file is issued.

The [public API guide](https://datasentinel.ifhx.my/api/v1/docs) documents the raw-file request, limits, error responses and privacy boundary. This source is prepared under the [MIT license](LICENSE); the bundled Manrope font retains its separate OFL license in `frontend/static/fonts/OFL-Manrope.txt`. This is a source-only distribution. Credentials, real documents, generated PDFs, recordings, browser profiles and local test artifacts are excluded. See [SECURITY.md](SECURITY.md) for publication and deployment boundaries.

This is **application-side non-persistence**, not a promise of zero handling by AWS: HTTPS ingress, Lambda memory, Textract processing, and operational logs remain subject to their service policies. The older S3/DynamoDB pipeline and management console below remain in the repository for historical and alternate-mode reference, but they are not the current public workflow. Do not use their screenshots or API contracts to explain the live direct mode.

After a successful direct download, the browser shows a temporary processing receipt: document type, suggested sensitivity, detected/redacted/kept categories, OCR use, detected-value output check, processing time and random request reference. The API returns this content-free metadata in response headers; it does not create a document record. The check does not prove that every possible sensitive value was detected. `PUBLIC` and `INTERNAL` are not inferred from missing PII: organisational sharing policy remains the sender's decision.

The approved customer-controlled encryption design in [docs/CUSTOMER_CONTROLLED_ENCRYPTION_DESIGN.md](docs/CUSTOMER_CONTROLLED_ENCRYPTION_DESIGN.md) remains a separate target architecture; direct redaction does not make server-side processing zero-knowledge.

An API-first, event-driven AWS platform that allows external applications to submit documents for sensitive-data classification, format-preserving protection, policy-controlled retrieval, and auditable governance evidence. The web interface is the management console; the reusable processing and governance API is the core product.

## What is implemented

- EventBridge receives raw S3 object-created events and invokes the classifier Lambda.
- Strict TXT, CSV, JSON, MD, LOG, image, and PDF extraction. Empty, oversized, malformed, encrypted, binary, low-confidence OCR, mixed multi-page scanned, and unsupported inputs fail instead of silently becoming `PUBLIC`.
- Layered PII intelligence with offset-preserving Unicode normalization, flexible formatting, bilingual field context, validators, overlap resolution, cross-signal correlation, confidence, severity, masked evidence and document-level risk.
- Calendar-valid Malaysian NRIC and DOB, local/`+60` phone, standards-oriented email, contextual names and addresses, employment/student/passport/account identifiers, Luhn-valid cards, network/location identifiers, exposed credentials, bearer tokens and private-key detection.
- `PUBLIC`, `CONFIDENTIAL`, and `RESTRICTED` classification with confidence evidence.
- Format-preserving protection into a separate private S3 bucket: PDF remains PDF, CSV remains CSV, and JSON remains valid JSON. OCR-based PDFs are rebuilt from redacted pixels so their original embedded scan objects are not retained.
- Retention, ownership, sensitivity, cost, and status tags on source objects.
- Versioned classification evidence and sensitivity-based review-priority fields in DynamoDB. Exposure and access breadth are not claimed as measured inputs in this release.
- SHA-256 hash-chained audit records with server-side recomputation of the complete retrieved ledger. This is tamper-evident, not an immutable external archive.
- SNS publication for restricted-data events; subscription is optional and not created automatically.
- Live S3 posture checks for encryption, versioning, and all four public-access safeguards.
- FastAPI dashboard/API with username/password sign-in, internal role-gated sessions, two-minute presigned downloads, and size-limited presigned POST uploads.
- Responsive, dependency-free operations console with overview, inventory, audit, posture, and access-request views.
- Authenticated live pipeline readiness checks for raw/protected S3, EventBridge, the classifier Lambda, DynamoDB evidence stores, and an empty classification dead-letter queue.
- CloudWatch alarms for API errors, classifier errors, and classification failures entering the dead-letter queue, all wired to the restricted-data SNS topic.
- Browser uploads now show intake and classification stages, wait for the protected copy, and only report completion after the classification record is available.
- Four presentation roles with signed browser sessions: administrator, data owner, reviewer, and read-only auditor.
- Just-in-time original-file approvals with protected-copy default access and a 15-minute approval window.
- A dedicated evidence record whenever a protected or original download link is issued, including the actor, copy type, access basis, expiry, and request correlation ID. A link is not returned if that evidence cannot be recorded.
- Evidence-backed classification explanations with a policy ID, policy version, detected signal types, and a rationale that never discloses matched values.
- Downloadable per-resource evidence packs containing the classification decision, access history, approval history, and a manifest. Document bytes are deliberately excluded.
- An explicit control-coverage view that separates active Learner Lab controls from production integrations that are not deployed.
- Live-account CLI plus a read-only synthetic demo mode.
- Learner Lab CloudFormation, deploy, verification, and cleanup scripts.
- A versioned `/api/v1` Integration API with SHA-256-verified machine credentials, tenant/client namespacing, explicit scopes, idempotent document submission, asynchronous job status, protected-copy retrieval, and correlation evidence.

The dashboard's `Evidence coverage` percentage is calculated from required governance-action evidence recorded on the latest version of each resource: private source, protected same-format copy, format-preservation evidence, retention tags, audit record, and—where applicable—successful redaction. It is an evidence-completeness measure, not compliance certification or a security maturity score.

Comprehend, Bedrock, an active GuardDuty scanner, Cognito, WAF, an external audit anchor, and automatic user-policy remediation are not deployed because AWS Academy Learner Lab restricts those services or IAM operations. Textract OCR is active for images and scanned PDFs, including asynchronous multi-page extraction. Incomplete or low-confidence extraction fails closed for human review. A GuardDuty object-tag gate is implemented and becomes fail-closed when `ENFORCE_MALWARE_GATE=true`; the Learner Lab keeps it disabled because it does not provision the scanner that supplies the trusted tag.

## Who we are

DataSentinel is a student-led IFHX cloud-governance project. It demonstrates how an organisation can discover sensitive data, preserve the uploaded file format while creating a protected copy, control access to originals, and retain evidence that explains what the system did.

The sign-in experience introduces this operating model before an operator enters the console. It also labels production integrations honestly: OCR is active, while the external malware scanner, federated identity, WAF association and an external audit trust anchor remain production integrations rather than simulated active controls.

## Architecture

```text
External applications / Browser console / CLI
     |                    short-lived presigned POST (1 byte to 5 MB)
     +--> API Gateway --> FastAPI Lambda --------------------+
                              |                              |
                              v                              v
                         DynamoDB evidence              private raw S3
                              ^                              |
                              |                        Object Created
                              |                              v
                         classifier Lambda <----------- EventBridge
                           |      |      |
                           |      |      +--> SNS restricted-data alert
                           |      +--------> chained audit DynamoDB
                           +---------------> same-format protected S3 + source tags
```

The deployment is budget-conscious: serverless/request-based services, on-demand DynamoDB with point-in-time recovery, seven-day logs, version cleanup, an encrypted EventBridge dead-letter queue, and no continuously running compute.

## Integration API

Deployment creates a temporary external-application credential in the ignored `.datasentinel-integration-client` file. The raw key is never stored in CloudFormation or Lambda; only its SHA-256 hash is deployed. External clients send the key through `X-API-Key` and must also supply an `Idempotency-Key` when creating a document job.

```http
POST /api/v1/documents
X-API-Key: <temporary-client-key>
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

The API returns a short-lived S3 POST contract plus stable `document_id` and `job_id` identifiers. Clients then use `GET /api/v1/jobs/{job_id}` or `GET /api/v1/documents/{document_id}`. Completed results disclose signal types, confidence, sensitivity and policy decisions, but never detected PII values. `GET /api/v1/documents/{document_id}/protected-copy` issues an audited 120-second URL; the external API deliberately exposes no original-file route.

Interactive OpenAPI documentation is available at `/api/docs`. See [docs/INTEGRATION_API.md](docs/INTEGRATION_API.md) for the complete client contract and security boundary.

See [docs/PII_INTELLIGENCE_ENGINE.md](docs/PII_INTELLIGENCE_ENGINE.md) for the detector layers, privacy boundary, masked result schema, synthetic evaluation, performance benchmark and known limitations.

For an evidence-based distinction between active Learner Lab controls,
integration-ready boundaries, and production-only artifacts, see the
[platform readiness matrix](docs/PLATFORM_READINESS_MATRIX.md). The optional
[production edge template](cloudformation/production-edge.yml) places CloudFront
in front of the HTTP API and attaches AWS managed WAF rules plus per-IP rate
control to the distribution. AWS WAF cannot attach directly to an API Gateway
HTTP API; the production edge therefore avoids an invalid direct association.
It is not part of the constrained Learner Lab stack.

## Local demo

Use Python 3.11 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts\run_demo.py
```

Open `http://127.0.0.1:8000`. Use `demo-access-token` for reviewer access or `demo-admin-token` for the admin view. Demo mode uses synthetic bundled data, disables uploads and file retrieval, and makes no AWS calls.

CLI examples:

```powershell
.\.venv\Scripts\python.exe scripts\cgctl.py --demo summary
.\.venv\Scripts\python.exe scripts\cgctl.py --demo files --sensitivity RESTRICTED
.\.venv\Scripts\python.exe scripts\cgctl.py --demo audit --verify
.\.venv\Scripts\python.exe scripts\cgctl.py --demo scan
```

## AWS Academy Learner Lab

Start a fresh Learner Lab session and place its three temporary credential fields in environment variables, the standard AWS CLI profile, or an ignored local file named `aws` or `aws.env`:

```text
aws_access_key_id=...
aws_secret_access_key=...
aws_session_token=...
```

Never commit that file. The deployment derives two distinct internal 32-character session tokens and a temporary administrator password from the current session token unless explicit values are supplied. Values are stored only in ignored local deployment files and are never committed. Direct use of the internal tokens is disabled in the live stack; users sign in with named role credentials.

Deploy and verify from Windows PowerShell:

```powershell
.\scripts\deploy_learner_lab.ps1 -Region us-east-1
.\scripts\verify_learner_lab.ps1 -Region us-east-1
.\scripts\verify_release.ps1 -Region us-east-1
```

Or from AWS CloudShell / Git Bash:

```bash
chmod +x scripts/*_learner_lab.sh
./scripts/deploy_learner_lab.sh
./scripts/verify_learner_lab.sh
```

The core verifier uploads controlled synthetic PII, waits for a `RESTRICTED` result, reads the protected object, confirms audit evidence, checks that the deployed release identity matches the local manifest, and calls both the health and authenticated summary endpoints. The release verifier then adds a format-preserving PDF test, reviewer/original-access boundary checks, and the external Integration API acceptance path. The stack output `DashboardUrl` opens the console.

The Overview processing map performs authenticated live dependency checks. `Operational` means the named AWS resource answered its readiness check at that moment; it is not a substitute for alarms, load testing, or production monitoring. During an upload, keep the dialog open until DataSentinel confirms that classification finished and the protected copy is ready. If processing exceeds 60 seconds, the upload remains accepted and the console tells the operator to refresh rather than falsely reporting failure.

To attach an existing Route 53 hosted zone and an issued ACM certificate, pass all three custom-domain parameters. The configuration is idempotent: it creates or repairs the API Gateway root mapping, upserts the Route 53 alias, and performs a strict HTTPS health check without relying on the workstation DNS cache.

```powershell
.\scripts\deploy_learner_lab.ps1 `
  -Region us-east-1 `
  -CustomDomainName datasentinel.ifhx.my `
  -HostedZoneId YOUR_HOSTED_ZONE_ID `
  -CertificateArn arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERTIFICATE_ID
```

The same repair can be run independently after a stack recreation:

```powershell
.\scripts\configure_custom_domain.ps1 `
  -Region us-east-1 `
  -StackName cloud-data-governance `
  -DomainName datasentinel.ifhx.my `
  -HostedZoneId YOUR_HOSTED_ZONE_ID `
  -CertificateArn arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERTIFICATE_ID
```

Open the `DashboardUrl` stack output and sign in with the temporary Learner Lab administrator account. The current username and generated password are stored in the ignored `.learner-lab-login` file created by the deployment script:

```text
Username: admin
Password: <generated for the current Learner Lab session>
```

Override the generated credential with `ADMIN_USERNAME` and an `ADMIN_PASSWORD` of at least 12 characters when required. The ignored token files are internal automation artifacts and must not be copied into the browser.

Live CLI examples after deployment:

```powershell
.\.venv\Scripts\python.exe scripts\cgctl.py summary
.\.venv\Scripts\python.exe scripts\cgctl.py audit --verify
.\.venv\Scripts\python.exe scripts\cgctl.py scan
```

Remove lab resources when finished:

```powershell
.\scripts\cleanup_learner_lab.ps1
```

See [deployment/LEARNER_LAB.md](deployment/LEARNER_LAB.md) for exact evidence and limitations.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src scripts tests
.\.venv\Scripts\bandit.exe -q -r src scripts -x tests -ll
.\.venv\Scripts\pip-audit.exe -r deployment\lambda-requirements.txt
.\.venv\Scripts\cfn-lint.exe cloudformation\learner-lab.yml
node --check frontend\static\app.js
terraform fmt -check -recursive terraform
terraform -chdir=terraform\environments\dev validate
.\.venv\Scripts\python.exe scripts\generate_release_manifest.py --release datasentinel-booth-2026.10
```

The CI workflow repeats pytest with coverage, Ruff, Bandit, pip-audit, CloudFormation linting, JavaScript syntax validation, Terraform formatting, and a blocking infrastructure security scan. Every third-party action is pinned to an immutable commit SHA. Browser QA evidence and the latest health score are stored under `.gstack/qa-reports/`.

The release-manifest command creates a secret-safe inventory and SHA-256 identity for the exact source tree used for a booth build. It excludes credentials, generated tokens, caches, virtual environments, Terraform state, and Git internals. When Git metadata is unavailable, the source-tree hash remains the release identity and the manifest records that limitation explicitly.

For a presentation-ready walkthrough, roles, recovery notes, and the exact seven-minute sequence, see [`deployment/AWS_DAY_KL_DEMO.md`](deployment/AWS_DAY_KL_DEMO.md).

## Legacy Terraform

`terraform/environments/dev` remains a LocalStack-oriented development path. It is not the supported Learner Lab deployment because it creates IAM roles and KMS keys. `terraform/environments/prod` deliberately contains no deployable placeholder: production infrastructure needs organization-specific IAM, backup, logging, residency, and naming decisions.

## Honest security boundary

The username/password session model is suitable for a timed academic demo, not workforce identity. Reviewers can retrieve only clean-bucket protected copies; privileged roles can additionally request raw originals, and an approved access request can temporarily grant original access. In production, replace demo credentials with an identity provider, named users, MFA, and scoped authorization. Holders of the broad Learner Lab `LabRole` can still access AWS resources directly outside this application.

Every application-issued download link now creates dedicated retrieval evidence with a correlation ID. These records provide accountability, but they are not currently part of the classification hash chain. Production should send them to an append-only audit destination and correlate them with API, identity, and object-access logs.

## Production hardening roadmap

The Learner Lab release deliberately shows these items as future integrations instead of claiming controls that are not deployed:

1. **OCR coverage** — image-bearing PDFs are routed through asynchronous Textract OCR so mixed pages cannot be classified from visible text alone; incomplete or low-confidence OCR still fails closed for human review.
2. **Malware quarantine** — isolate uploads and use GuardDuty Malware Protection for S3 or a scanning workflow before classification and release.
3. **External audit trust anchor** — periodically sign or checkpoint the audit head into a separately controlled account or immutable archive.

The current API also provides application-signed audit checkpoints, incident state transitions, classification-review records, per-resource retention/legal-hold records, a strict federated-claim adapter and a dependency-free Python SDK. See `deployment/PRODUCTION_CONTROL_BOUNDARIES.md`, `deployment/DISASTER_RECOVERY_RUNBOOK.md`, and `sdk/python/README.md`. Application-signed checkpoints are useful evidence but are not described as an independent external trust anchor.
4. **Bounded API pagination** — inventory, audit, and access paths now use timestamp-sorted GSIs instead of runtime table scans, and access records expire through TTL. A future high-volume release should expose cursor pagination so responses never need to retrieve the complete matching partition.
5. **Broader integration coverage** — deepen classifier, failure-recovery, authorization, and optional-governance test paths beyond the current API and redaction coverage.
6. **Single supported cloud deployment path** — use the Learner Lab CloudFormation stack for this environment; the Terraform folders remain LocalStack/development artifacts and are not a production deployment path.
