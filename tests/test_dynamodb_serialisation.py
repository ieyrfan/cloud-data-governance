from decimal import Decimal

from boto3.dynamodb.types import TypeSerializer

from src.utils.dynamodb_client import DynamoDBClient, _dynamodb_safe


def test_nested_classifier_metadata_is_dynamodb_safe():
    evidence = {
        "document_type": {
            "key": "RESUME",
            "confidence": 0.91,
            "signals": ["filename convention", {"weight": 0.4}],
        }
    }

    converted = _dynamodb_safe(evidence)

    assert converted["document_type"]["confidence"] == Decimal("0.91")
    assert converted["document_type"]["signals"][1]["weight"] == Decimal("0.4")
    TypeSerializer().serialize(converted)


def test_source_version_write_is_idempotent():
    class Table:
        def __init__(self):
            self.arguments = None

        def put_item(self, **kwargs):
            self.arguments = kwargs

    client = DynamoDBClient.__new__(DynamoDBClient)
    client.table = Table()
    version_id = "source#2026-10-14T00:00:00+00:00#abc123"

    saved = client.save_classification_result(
        "s3://raw/item.pdf",
        "RESTRICTED",
        0.9,
        {},
        version_id=version_id,
    )

    assert saved == version_id
    assert "attribute_not_exists" in client.table.arguments["ConditionExpression"]
    assert client.table.arguments["Item"]["inventory_scope"] == "CLASSIFICATION"
