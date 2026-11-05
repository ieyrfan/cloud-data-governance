from botocore.exceptions import ClientError

from src.governance.immutable_audit_trail import ImmutableAuditTrail


class FakeResourceClient:
    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def describe_table(self, **_kwargs):
        return {"Table": {"TableStatus": "ACTIVE"}}


class FakeTable:
    def get_item(self, **_kwargs):
        return {}

    def query(self, **_kwargs):
        return {"Items": []}


class FakeDynamoResource:
    def __init__(self):
        self.meta = type("Meta", (), {"client": FakeResourceClient()})()
        self.table = FakeTable()

    def Table(self, _table_name):
        return self.table


class CapturingTransactionClient:
    def __init__(self):
        self.request = None

    def transact_write_items(self, **kwargs):
        self.request = kwargs


class RacingTransactionClient(CapturingTransactionClient):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def transact_write_items(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise ClientError(
                {"Error": {"Code": "TransactionCanceledException", "Message": "head raced"}},
                "TransactWriteItems",
            )
        super().transact_write_items(**kwargs)


def test_audit_transaction_uses_low_level_number_encoding():
    audit = ImmutableAuditTrail.__new__(ImmutableAuditTrail)
    audit.dynamodb = FakeDynamoResource()
    audit.transaction_client = CapturingTransactionClient()
    audit.table_name = "audit-test"

    audit.record_event(
        action="CLASSIFY_OBJECT",
        actor="classifier",
        resource="synthetic://document",
        details={"sensitivity": "RESTRICTED"},
        event_id="classify-synthetic",
    )

    transaction = audit.transaction_client.request["TransactItems"]
    values = transaction[1]["Update"]["ExpressionAttributeValues"]
    assert values[":one"] == {"N": "1"}
    assert transaction[1]["Update"]["Key"] == {"log_id": {"S": "__CHAIN_HEAD__"}}


def test_audit_transaction_retries_a_concurrent_head_update():
    audit = ImmutableAuditTrail.__new__(ImmutableAuditTrail)
    audit.dynamodb = FakeDynamoResource()
    audit.transaction_client = RacingTransactionClient()
    audit.table_name = "audit-test"

    result = audit.record_event(
        action="CLASSIFY_OBJECT",
        actor="classifier",
        resource="synthetic://concurrent-document",
        details={"sensitivity": "RESTRICTED"},
        event_id="classify-concurrent",
    )

    assert result == "classify-concurrent"
    assert audit.transaction_client.calls == 2
