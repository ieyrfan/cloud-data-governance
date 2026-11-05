# DataSentinel — AWS Day KL presentation runbook

This runbook presents only controls that the deployed Learner Lab release can demonstrate. It intentionally separates production-ready integration targets from active controls.

## Demo accounts

The deployment generates temporary credentials for the Administrator, Data owner,
Reviewer, and Auditor personas. Read them from `.learner-lab-login` immediately before
the presentation. Never copy passwords into this runbook, slides, screenshots, source
control, or a public chat. The credentials expire with the Learner Lab environment.

| Persona | Demonstrates |
|---|---|
| Administrator | Full console, protected copies and content-free evidence |
| Data owner | Governance ownership and policy decisions |
| Reviewer | Protected-by-default access and review work |
| Auditor | Read-only evidence and decisions |

## Seven-minute API-first live story

1. **Open with the reusable product (30 seconds).** Open `/api/docs` and expand **Integration API**. Explain: “DataSentinel is not another isolated dashboard. Any approved university portal, mobile application, or enterprise workflow can submit a document and consume a safe protection decision through this API.”
2. **Show the developer contract (60 seconds).** Open **Integration API** in the management console. Point to machine authentication, explicit scopes, tenant/client isolation, idempotency, asynchronous jobs, direct private upload, and protected-copy retrieval. Emphasise that the external API never exposes an original-file endpoint.
3. **Prove the end-to-end API path (60 seconds).** Run `python scripts/verify_integration_api.py`. The controlled synthetic document must produce a stable document/job ID, `RESTRICTED`, Malaysian NRIC and email signal types, a protected copy without the values, and a correlation ID for retrieval evidence. Do not expose the API key or detected values.
4. **Show the operating console (60 seconds).** Sign in as Administrator. In **Overview**, narrate private S3 intake → EventBridge → classifier/OCR → protected S3 → DynamoDB evidence. Explain that the console operates the platform; it is not the core product boundary.
5. **Prove format-preserving protection and least privilege (120 seconds).** Open a restricted synthetic PDF in **Data inventory**, inspect the format-preserving protected PDF and show that the hardened server never exposes an original-file link. Explain that unredacted originals remain customer-controlled and are not retrievable through DataSentinel.
6. **Show evidence, not claims (60 seconds).** Open **Audit evidence** and point to recomputed SHA-256 event hashes, chain links, access correlation IDs, and the content-free evidence pack. Then show **Security posture** for private access, encryption, versioning, transport, and failure-path controls.
7. **Close honestly (30 seconds).** State: “This Learner Lab release proves one configured integration client and four governed human roles. Dynamic customer onboarding, federated identity, WAF, malware quarantine, and external audit anchoring are the next production controls—not capabilities we pretend are already deployed.”

## Presenter wording

> DataSentinel is a customer-controlled protection pipeline. Automation detects and protects data; unredacted originals remain with the sender while the console exposes protected copies and content-free evidence.

> The dashboard is the operating console. The product is the versioned protection API, processing engine, policy boundary, and evidence trail that other applications can reuse.

> The risk score is a sensitivity-based review priority, not a universal breach probability or compliance certification.

> Hash chaining detects changes inside the retrieved ledger. A production deployment would anchor checkpoints outside the same trust boundary.

## Before going on stage

- Start or extend the AWS Academy Learner Lab session; its temporary credentials and deployed resources expire with the lab.
- Run the deployment and verification scripts from the repository root.
- Confirm `.datasentinel-integration-client` exists locally and remains outside source control. Never project, paste, or print its API key.
- Run `scripts/verify_release.ps1` and require `DataSentinel release verification passed all three gates` before opening the booth.
- Confirm the stack is `UPDATE_COMPLETE` or `CREATE_COMPLETE`.
- Upload only synthetic data and verify both protected and original PDFs open in the browser.
- Wait for the upload dialog to report the final sensitivity and confirm that the protected copy is ready; do not treat the S3 transfer alone as classification success.
- Complete the reviewer → owner → reviewer workflow once, then use a different file for the live demo so the request begins pending.
- Keep the live URL in one tab and this runbook in another.
- Have the local demo available only as a visual fallback; do not describe it as live AWS evidence.

## Recovery if the live service is cold

API Gateway may need a few seconds while Lambda starts. Use **Refresh** once. If evidence is still unavailable, call `/health`, confirm the Learner Lab session is running, and use the verification script before continuing. Do not improvise a production-readiness claim from a health response alone.
