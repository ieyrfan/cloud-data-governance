# AWS Academy Learner Lab Deployment Guide

> **Current public deployment (1 November 2026):** `STRICT_TRANSIENT_MODE=true` and `PUBLIC_FREE_API_ENABLED=true`. The root page and `/customer` serve a no-login protect-and-download form. `POST /api/v1/protect` returns protected bytes without application-side S3 or DynamoDB document writes; an aggregate-only DynamoDB counter caps free requests at 200 per UTC day. Stored-document and login routes return HTTP 410. The S3/EventBridge/DynamoDB architecture below describes retained legacy stack resources and alternate workflow, not the current customer path. API, classifier, and webhook CloudWatch log-group retention is one day. Do not present the legacy workflow or seven-day log statement below as live behavior.

## Scope

This deployment runs the demonstrable core of the project within the supplied AWS Academy restrictions. It uses only serverless, request-based services and the pre-created `LabRole`. It does not create IAM users, groups, roles, customer-managed KMS keys, EC2 instances, NAT gateways, databases, or continuously running compute.

The deployment targets `us-east-1` by default. `us-west-2` is also accepted because the Learner Lab permits both regions.

## Deployed architecture

1. A user uploads an object to the private raw S3 bucket.
2. S3 publishes an object-created event to EventBridge.
3. EventBridge invokes the classifier Lambda with reserved concurrency set to one.
4. The Lambda extracts text from TXT, CSV, JSON, or text-based PDF files.
5. Regex and Luhn validation detect Malaysian NRIC, mobile numbers, email addresses, and credit cards.
6. Amazon Comprehend is disabled because it is not listed as an available Learner Lab service.
7. The classifier saves a time-sortable version in DynamoDB.
8. A same-format protected copy is written to the clean bucket. Sensitive text is removed; public files are copied after review.
9. Retention metadata is merged into the source object's S3 tags.
10. A hash-chained audit record is written to the audit table.
11. A FastAPI Lambda serves the management console and a versioned Integration API with tenant/client identity, hashed machine credentials, explicit scopes, idempotent asynchronous jobs, and short-lived size-limited presigned POST uploads.
12. Restricted classifications publish a best-effort notification to an encrypted-in-transit SNS endpoint. No email/SMS subscription is created automatically.

Both S3 buckets use SSE-S3 encryption, versioning, complete public-access blocking, bucket-owner-enforced ownership, explicit insecure-transport denial, incomplete-upload cleanup after seven days, and noncurrent-version cleanup after 30 days. Raw-bucket browser CORS is restricted to the deployed API origin. CloudWatch log groups retain logs for seven days. DynamoDB uses on-demand capacity with point-in-time recovery. Failed EventBridge deliveries are retained for four days in an encrypted dead-letter queue.

## Why SSE-S3 is used

The repository's original Terraform creates customer-managed KMS keys, but does not connect them to the buckets. The Learner Lab template uses SSE-S3 (`AES256`) because it is encrypted at rest, avoids KMS request cost, and avoids creating key policies that may conflict with restricted IAM permissions. KMS-specific controls remain prototypes for a less restricted AWS account.

## Deployment from AWS CloudShell

Start the Learner Lab and open CloudShell in `us-east-1`. Upload or clone this repository, then run:

```bash
chmod +x scripts/*_learner_lab.sh
./scripts/deploy_learner_lab.sh
```

Optional variables:

```bash
AWS_REGION=us-west-2 STACK_NAME=cdg-demo ENVIRONMENT=test ./scripts/deploy_learner_lab.sh
```

The script performs these operations:

- verifies the active account and `LabRole`;
- builds a dependency-complete Lambda ZIP;
- creates a private encrypted artifact bucket;
- uploads the ZIP using a content-derived key;
- deploys `cloudformation/learner-lab.yml`; and
- prints every stack output.

## Deployment from Windows PowerShell

The scripts accept credentials from the standard AWS environment/profile or from an ignored local `aws`/`aws.env` file containing the three lowercase Learner Lab fields. The file must never be committed. Then run:

```powershell
.\scripts\deploy_learner_lab.ps1 -Region us-east-1
```

The AWS Academy session credentials include a session token. The scripts derive distinct internal reviewer and admin session secrets plus a temporary console password unless explicit values are set. Direct internal-token login is disabled in the deployed API. Credentials are written only to ignored local files for verification and role sign-in. Refresh all three AWS credential values and redeploy whenever a new lab session starts.

## End-to-end verification

Run:

```bash
./scripts/verify_learner_lab.sh
```

or:

```powershell
.\scripts\verify_learner_lab.ps1
```

The verifier uploads a controlled synthetic file, waits for asynchronous processing, requires a `RESTRICTED` result, checks the protected copy, confirms that audit records exist, and calls the public health and authenticated dashboard endpoints. This is stronger evidence than showing only a successful CloudFormation stack or HTTP 200 response.

For additional CLI evidence:

```bash
RAW_BUCKET=$(aws cloudformation describe-stacks --stack-name cloud-data-governance --query "Stacks[0].Outputs[?OutputKey=='RawDataBucketName'].OutputValue" --output text)
RESULTS_TABLE=$(aws cloudformation describe-stacks --stack-name cloud-data-governance --query "Stacks[0].Outputs[?OutputKey=='ResultsTableName'].OutputValue" --output text)
AUDIT_TABLE=$(aws cloudformation describe-stacks --stack-name cloud-data-governance --query "Stacks[0].Outputs[?OutputKey=='AuditTableName'].OutputValue" --output text)

aws s3api get-public-access-block --bucket "$RAW_BUCKET"
aws s3api get-bucket-encryption --bucket "$RAW_BUCKET"
aws s3api get-bucket-versioning --bucket "$RAW_BUCKET"
aws dynamodb scan --table-name "$RESULTS_TABLE" --max-items 10
aws dynamodb scan --table-name "$AUDIT_TABLE" --max-items 10
aws logs tail /aws/lambda/cloud-data-governance-classifier-dev --since 10m
```

## Dashboard and API authorization

The stack output `DashboardUrl` opens the deployed console. Sign in with the administrator username and password; the browser exchanges them for a short-lived, revocable `HttpOnly`, `Secure`, `SameSite=Strict` session cookie. State-changing browser requests use a double-submit CSRF token. The Lock button revokes the session immediately. `GET /health` and `/config` expose only service/configuration status. Evidence, audit, posture, inventory and upload routes remain authenticated. The hardened Learner Lab deployment exposes protected clean-bucket copies only; server-side original-file access and original access requests are disabled. Protected download URLs expire after two minutes.

Use the console sign-in form:

```text
Username: admin
Password: the generated value in `.learner-lab-login`
```

For a different Learner Lab login, set `ADMIN_USERNAME` and an `ADMIN_PASSWORD` of at least 12 characters before deployment. The ignored token files are used only by internal automation; never expose or commit them.

External applications use the `/api/v1` Integration API rather than the browser session. Deployment writes its temporary bootstrap identity to the ignored `.datasentinel-integration-client` file and deploys only the SHA-256 hash of the API key. The current Learner Lab stack configures one demonstration tenant (`ifhx-demo`) and one client (`booth-client`) with `documents:create`, `documents:read`, and `protected-copy:read` scopes. The external API does not expose original-file retrieval.

Use `GET /api/v1/whoami` to validate the machine identity, `POST /api/v1/documents` with an `Idempotency-Key` to create a stable job, upload to the returned five-minute S3 POST contract, poll `GET /api/v1/jobs/{job_id}`, and request the protected output from `GET /api/v1/documents/{document_id}/protected-copy`. See `docs/INTEGRATION_API.md` for the complete contract.

The token design is deliberately small enough for a timed academic lab. It is not a replacement for Cognito, SSO, or per-user authorization in production. Browser uploads use a five-minute presigned S3 POST policy that enforces a 1-byte to 5-MB object size and supports TXT, CSV, JSON, PDF, MD, and LOG filenames.

## Learner Lab limitations

- Comprehend and Bedrock are disabled because they are not in the supplied service list.
- IAM auto-remediation is not deployed. Learner Lab does not allow ordinary IAM user and role administration.
- Honeytoken placement is available through `cgctl trap`, but automatic access detection is not deployed; CloudTrail data-event monitoring would need additional configuration and testing.
- The audit ledger is tamper-evident, not absolutely immutable. It is serialized to reduce hash-chain races, but production would require stronger write isolation and an external integrity anchor.
- Text-based PDF, CSV, JSON, TXT, MD, and LOG outputs retain their source format. PDF redaction removes matching text and writes a valid PDF, but advanced layouts/forms should still receive visual acceptance testing.
- Amazon Textract OCR is active for JPG, JPEG, PNG and supported single-page image-only PDFs. Low-confidence, mixed-layout or unsupported multi-page scanned inputs fail closed for review rather than being classified as safe.
- Malformed UTF-8/JSON/CSV, encrypted or text-empty PDFs, binary payloads, unsupported extensions, and inputs beyond the 5 MB processing limit are rejected rather than recorded as clean `PUBLIC` data.
- The dashboard `Evidence coverage` score measures recorded required actions on the latest resource versions; it is not compliance certification. The displayed priority score is a sensitivity baseline because exposure and access breadth are not measured in this Learner Lab release.
- Runtime inventory, audit, and access-list APIs use timestamp-sorted DynamoDB GSIs. The deployment performs an idempotent one-time scan only to backfill index keys on evidence created before this schema; high-volume production use should add cursor pagination to bound each response.
- SNS has no subscriber until an operator deliberately creates and confirms one.
- Stack data persists when a timed Learner Lab session ends. Run cleanup when the demonstration is complete. MFA/2FA is not active in Learner Lab and requires Cognito, IAM Identity Center or an organisation IdP during production migration.

## Troubleshooting

If deployment fails, inspect the latest stack event:

```bash
aws cloudformation describe-stack-events --stack-name cloud-data-governance --max-items 20
```

If upload succeeds but no DynamoDB result appears:

```bash
aws logs tail /aws/lambda/cloud-data-governance-classifier-dev --since 10m
aws events list-targets-by-rule --rule cloud-data-governance-classify-upload-dev
```

If the Lambda reports `AccessDenied`, verify that the function uses the exact `LabRole` ARN from the current Learner Lab account. Do not attempt to create a replacement IAM role.

## Cleanup and budget protection

Because both data buckets are versioned, they must be emptied including historical versions before CloudFormation can delete them. Use the supplied cleanup command:

```bash
./scripts/cleanup_learner_lab.sh
```

or:

```powershell
.\scripts\cleanup_learner_lab.ps1
```

The cleanup script empties both stack buckets, deletes the CloudFormation stack, waits for completion, and removes the separate deployment-artifact bucket.
