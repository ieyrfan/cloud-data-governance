# DataSentinel disaster-recovery runbook

## Recovery objectives

RPO and RTO are **not yet certified**. Record candidate objectives only after
data owners approve residency and retention requirements. A successful recovery
exercise must capture start time, selected restore point, restored object and
record counts, integrity results, protected-copy checks and final service time.

## Preconditions

1. Preserve the last known CloudFormation package and dependency lock material.
2. Export stack outputs, configuration names and the current audit checkpoint.
3. Confirm that the destination region is legally permitted for the data.
4. Confirm raw and protected bucket version replication and DynamoDB restore
   capability before declaring the secondary region recoverable.
5. Keep API credentials, session secrets and webhook signing material outside
   source control; rotate them after a regional failover.

## Restore sequence

1. Declare an incident and freeze destructive lifecycle changes.
2. Identify the latest clean recovery point and verify its audit checkpoint.
3. Deploy the reviewed infrastructure package in the recovery region.
4. Restore DynamoDB data, then raw objects, then protected objects.
5. Reconcile every latest classification with a protected-copy object.
6. Re-enable event processing with classifier concurrency set to one until the
   audit sequence and queue backlog are stable.
7. Run health, authenticated API, controlled classification, redaction,
   access-event and webhook canaries.
8. Change DNS only after the complete canary passes.
9. Rotate machine keys and webhook secrets; notify integrated clients.
10. Capture actual RPO/RTO, missing evidence and remediation actions.

## Failback

Failback is a separate change. Stop writes, reconcile both regions, verify the
new audit head, repeat the canary, then change DNS. Never merge divergent audit
chains by editing historical records.
