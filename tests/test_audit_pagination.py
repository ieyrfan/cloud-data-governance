from src.governance.immutable_audit_trail import ImmutableAuditTrail


class PaginatedAuditTable:
    def __init__(self):
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        if "ExclusiveStartKey" not in kwargs:
            return {
                "Items": [{"timestamp": "2026-09-01T00:00:00Z", "current_hash": "old"}],
                "LastEvaluatedKey": {"log_id": "page-one"},
            }
        return {"Items": [{"timestamp": "2026-09-02T00:00:00Z", "current_hash": "new"}]}


def test_audit_query_reads_every_dynamodb_page():
    table = PaginatedAuditTable()

    items = ImmutableAuditTrail._query_all(table)

    assert [item["current_hash"] for item in items] == ["old", "new"]
    assert all(call["IndexName"] == "AuditByTimestamp" for call in table.calls)
    assert table.calls[1]["ExclusiveStartKey"] == {"log_id": "page-one"}
