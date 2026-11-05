# DataSentinel production control boundaries

This document separates controls that are active in the AWS Academy deployment
from production integrations whose trust boundary must sit outside the Learner
Lab account. It is an implementation contract, not evidence that those external
services are currently enabled.

## Malware quarantine

The classifier reads the S3 object tag `GuardDutyMalwareScanStatus`. Production
sets `ENFORCE_MALWARE_GATE=true`; classification is then allowed only when the
status is `NO_THREATS_FOUND`. Missing, failed, unsupported, access-denied or
threat-positive results fail closed before OCR or content parsing. GuardDuty
Malware Protection for S3 and its role are not created by the Learner Lab stack.

## Federated identity

`src/governance/identity_adapter.py` accepts claims only after an upstream API
Gateway authorizer has verified signature, issuer, audience and expiry. It
requires subject, username, tenant and exactly one recognised group. The four
groups map to ADMIN, DATA_OWNER, REVIEWER and AUDITOR. The application never
decodes an unsigned browser-supplied JWT. Cognito/OIDC/SAML provisioning remains
outside the Learner Lab stack.

## WAF and rate control

API Gateway stage throttling is active at 10 requests/second with a burst of 20.
Detailed CloudWatch route metrics are enabled so throttling, latency, integration
failures, and server errors can be monitored without treating a successful HTTP
response as proof that the document pipeline completed.
A production account should associate an AWS WAFv2 regional Web ACL with the API
Gateway stage, enable managed common and known-bad-input rule groups, add an IP
rate-based rule, send WAF logs to a separately controlled destination, and tune
limits from observed traffic. WAF is not represented as active here.

## Audit checkpoints

The API can create and verify HMAC-SHA256 checkpoints over the retrieved audit
chain head and event count. `src/governance/external_anchor.py` can now publish
a content-free checkpoint to a separately governed Object-Lock/KMS S3 bucket
when `AUDIT_ANCHOR_BUCKET` is configured. Without that configuration,
`external_anchor_active=false` remains explicit. Deploy
`cloudformation/production-integrity-anchor.yml` in a separate trust boundary
before enabling `REQUIRE_EXTERNAL_AUDIT_ANCHOR=true`.

## Retention enforcement

The application records retention and legal-hold intent, but a record alone does
not stop S3 lifecycle expiration or an operator deletion. Production must bind
hold state to every deletion path and use an independently enforceable storage
control such as S3 Object Lock where required. Until that exists, report the
feature as a control record rather than deletion enforcement.

## Disaster recovery

The Learner Lab is single-region. Production requires versioned cross-region S3
replication for raw/protected evidence, DynamoDB point-in-time recovery or global
tables according to residency requirements, infrastructure packages in a second
region, Route 53 health-based failover, and a recovery exercise. No RPO/RTO may
be claimed until a timed restore exercise succeeds.

## Observability and incident response

The active stack has Lambda error, classifier DLQ and webhook DLQ alarms plus
retained CloudWatch logs. The API adds incident records with constrained
OPEN -> TRIAGED -> CONTAINED -> RESOLVED transitions. Production must connect the
SNS alarm topic to the organisation's paging/SIEM destination and measure MTTA,
MTTC and MTTR without copying detected PII into telemetry.
