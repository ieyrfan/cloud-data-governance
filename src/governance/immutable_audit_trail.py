import hashlib
import json
import os
import time
import uuid
from datetime import UTC, datetime

import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError


class ImmutableAuditTrail:
    """
    Cryptographically chained, tamper-evident audit logging.

    The chain detects modification and interior deletion when verified. DynamoDB
    permissions still control whether records can be deleted, so this is not an
    immutable external archive.
    """

    def __init__(self, region_name=None):
        region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT")
        self.dynamodb = boto3.resource(
            "dynamodb", region_name=region_name, endpoint_url=endpoint_url
        )
        # Keep transactions on a dedicated low-level client. The client attached
        # to a DynamoDB resource has the resource serializer registered on it;
        # sending TypeSerializer output through that client double-serializes
        # values (for example N becomes M) and breaks numeric ADD expressions.
        self.transaction_client = boto3.client(
            "dynamodb", region_name=region_name, endpoint_url=endpoint_url
        )
        self.table_name = os.environ.get("AUDIT_TABLE", "data-governance-audit-ledger-dev")

    def _ensure_table_exists(self):
        try:
            self.dynamodb.meta.client.describe_table(TableName=self.table_name)
        except self.dynamodb.meta.client.exceptions.ResourceNotFoundException:
            # Create the table if it doesn't exist (useful for local dev)
            self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[{"AttributeName": "log_id", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "log_id", "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
            )
            time.sleep(2)  # Wait for table creation

    def _get_previous_hash(self) -> str:
        """Retrieves the hash of the most recent log entry to chain the next one."""
        self._ensure_table_exists()
        table = self.dynamodb.Table(self.table_name)
        # The chain head lives in the base table, where reads are strongly
        # consistent.  The GSI remains a recovery/index path only.
        try:
            head = table.get_item(
                Key={"log_id": "__CHAIN_HEAD__"}, ConsistentRead=True
            ).get("Item")
            if head and head.get("current_hash"):
                return str(head["current_hash"])
        except (AttributeError, ClientError):
            pass

        response = table.query(
            IndexName="AuditByTimestamp",
            KeyConditionExpression=Key("ledger_scope").eq("AUDIT"),
            ScanIndexForward=False,
            Limit=1,
        )
        items = response.get("Items", [])

        if not items:
            return (
                "0000000000000000000000000000000000000000000000000000000000000000"  # Genesis Hash
            )

        # Sort by timestamp to find the latest
        items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return items[0].get("current_hash", "")

    @staticmethod
    def _query_all(table):
        items = []
        query = {
            "IndexName": "AuditByTimestamp",
            "KeyConditionExpression": Key("ledger_scope").eq("AUDIT"),
            "ScanIndexForward": True,
        }
        response = table.query(**query)
        items.extend(response.get("Items", []))
        while response.get("LastEvaluatedKey"):
            response = table.query(
                **query, ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))
        return items

    def record_event(
        self, action: str, actor: str, resource: str, details: dict, event_id: str | None = None
    ):
        """
        Records a new event and cryptographically binds it to the previous event.
        """
        self._ensure_table_exists()
        table = self.dynamodb.Table(self.table_name)
        idempotent = event_id is not None
        log_id = event_id or f"audit-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
        if idempotent and table.get_item(Key={"log_id": log_id}, ConsistentRead=True).get("Item"):
            return log_id

        serializer = TypeSerializer()

        def encode(value):
            return {key: serializer.serialize(item) for key, item in value.items()}

        # A conditional transaction makes the chain append atomic. Concurrent
        # writers can legitimately race for the same head, so re-read and retry
        # with the new predecessor instead of failing the governed operation.
        for attempt in range(5):
            timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            previous_hash = self._get_previous_hash()
            payload = {
                "timestamp": timestamp,
                "action": action,
                "actor": actor,
                "resource": resource,
                "details": details,
                "previous_hash": previous_hash,
            }
            current_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode("utf-8")
            ).hexdigest()
            item = {
                "log_id": log_id,
                "ledger_scope": "AUDIT",
                "timestamp": timestamp,
                "action": action,
                "actor": actor,
                "resource": resource,
                "details": json.dumps(details),
                "previous_hash": previous_hash,
                "current_hash": current_hash,
            }
            put = {"TableName": self.table_name, "Item": encode(item)}
            if idempotent:
                put["ConditionExpression"] = "attribute_not_exists(log_id)"
            update = {
                "TableName": self.table_name,
                "Key": encode({"log_id": "__CHAIN_HEAD__"}),
                "UpdateExpression": (
                    "SET ledger_scope = :scope, current_hash = :hash, updated_at = :timestamp "
                    "ADD event_count :one"
                ),
                "ExpressionAttributeValues": encode(
                    {
                        ":scope": "CHAIN_HEAD",
                        ":hash": current_hash,
                        ":timestamp": timestamp,
                        ":one": 1,
                        ":previous": previous_hash,
                    }
                ),
                "ConditionExpression": (
                    "attribute_not_exists(current_hash) OR current_hash = :previous"
                ),
            }
            try:
                self.transaction_client.transact_write_items(
                    TransactItems=[{"Put": put}, {"Update": update}]
                )
                print(
                    f"[TAMPER-EVIDENT AUDIT] Log {log_id} chained. "
                    f"Hash: {current_hash[:8]}..."
                )
                return log_id
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code")
                if code == "UnknownOperationException":
                    table.put_item(Item=item)
                    return log_id
                if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
                    if idempotent and table.get_item(
                        Key={"log_id": log_id}, ConsistentRead=True
                    ).get("Item"):
                        return log_id
                    if attempt < 4:
                        time.sleep(0.02 * (attempt + 1))
                        continue
                raise

        raise RuntimeError("Audit chain could not advance after concurrent update retries")

    def verify_ledger_integrity(self):
        """
        Auditing function: Recalculates hashes from the Genesis block to ensure
        no logs have been secretly modified or deleted.
        """
        table = self.dynamodb.Table(self.table_name)
        items = self._query_all(table)

        expected_previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"

        for idx, item in enumerate(items):
            # Verify chain linkage
            if item["previous_hash"] != expected_previous_hash:
                return (
                    False,
                    f"Broken chain detected at log {item['log_id']}! Previous hash mismatch.",
                )

            # Reconstruct payload and verify current hash
            payload = {
                "timestamp": item["timestamp"],
                "action": item["action"],
                "actor": item["actor"],
                "resource": item["resource"],
                "details": json.loads(item["details"]),
                "previous_hash": item["previous_hash"],
            }

            payload_str = json.dumps(payload, sort_keys=True)
            calculated_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

            if calculated_hash != item["current_hash"]:
                return False, f"Tampering detected at log {item['log_id']}! Hash mismatch."

            expected_previous_hash = item["current_hash"]

        return True, "The complete retrieved audit chain is internally consistent."

    def current_checkpoint(self) -> dict:
        """Return the strongly-consistent chain head without document content."""
        table = self.dynamodb.Table(self.table_name)
        item = table.get_item(Key={"log_id": "__CHAIN_HEAD__"}, ConsistentRead=True).get("Item", {})
        return {
            "head_hash": str(item.get("current_hash", "")),
            "event_count": int(item.get("event_count", 0) or 0),
            "generated_at": str(item.get("updated_at", "")),
        }
