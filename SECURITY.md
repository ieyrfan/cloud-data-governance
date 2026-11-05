# Publication and security boundaries

DataSentinel is a student-led, educational cloud-governance prototype. Publishing
its source does not certify a production deployment, confirm current cloud
configuration, or guarantee complete PII detection or zero retention by every
service involved in processing.

## Source-only distribution

This repository contains application source, static frontend assets, infrastructure
templates, documentation, and tests with illustrative data. The Manrope font is
redistributed with its OFL license.

Keep the following outside version control:

- AWS credentials, environment files, session tokens, login files, API keys,
  private keys, and account-specific Terraform variable files.
- Terraform state and plans, packaged Lambda ZIPs, virtual environments,
  dependency caches, browser profiles, and generated release manifests.
- Real identity documents, uploads, protected downloads, logs, screenshots,
  presentation recordings, reports, and local security-review artifacts.

The checked-in fixture identifiers are deliberately chosen examples, not records
about real people. The AWS-looking key in `tests/fixtures/pii_benchmark.json` is
the documented `EXAMPLE` test value. The private-key marker in the false-positive
fixture has no usable private-key material. Demo credentials are public test
values for local demonstration and must never be used for a deployed service.

The generated false-flag corpus is intentionally excluded. To recreate it with
synthetic data, run
`python scripts/generate_false_flag_corpus.py --output tests/fixtures/generated_false_flag_corpus`
locally before running its optional tests. No real input documents are needed.

## Before deploying

Use your own deployment URL and credentials. Inspect infrastructure plans and
permissions, keep the public request allowance and throttling appropriate to your
environment, and review the documented direct-mode retention boundary. The
legacy Terraform and LocalStack paths are development examples. Deployment and
cleanup scripts change cloud resources only when explicitly invoked; read them
before use. The repository workflow performs checks and contains no enabled
deployment job.

For current processing behavior, start with
[`docs/CURRENT_MODE_AND_RETENTION.md`](docs/CURRENT_MODE_AND_RETENTION.md).
Known test coverage limits are recorded in
[`docs/DIRECT_MODE_QA_MATRIX.md`](docs/DIRECT_MODE_QA_MATRIX.md).

## Reporting a sensitive issue

Do not put credentials, real documents, or exploit details for an active service
in a public issue. Contact the repository owner through an established private
channel, or use GitHub private vulnerability reporting if it is enabled. If a
real credential is ever published, revoke or rotate it; deleting the current
file alone does not remove it from repository history.
