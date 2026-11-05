from pathlib import Path

from src.api import main as api_main


class PaginatedTable:
    def __init__(self):
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        if "ExclusiveStartKey" not in kwargs:
            return {"Items": [{"id": "one"}], "LastEvaluatedKey": {"id": "one"}}
        return {"Items": [{"id": "two"}]}


def test_query_helper_preserves_index_contract_across_pages():
    table = PaginatedTable()
    items = api_main._query_all(
        table,
        IndexName="InventoryByTimestamp",
        KeyConditionExpression="condition",
        ScanIndexForward=False,
    )

    assert items == [{"id": "one"}, {"id": "two"}]
    assert table.calls[1]["IndexName"] == "InventoryByTimestamp"
    assert table.calls[1]["ExclusiveStartKey"] == {"id": "one"}


def test_learner_lab_tables_expose_all_runtime_indexes():
    template = (Path(__file__).parents[1] / "cloudformation" / "learner-lab.yml").read_text()

    assert "IndexName: InventoryByTimestamp" in template
    assert "IndexName: AuditByTimestamp" in template
    assert "IndexName: AccessByTypeAndTime" in template


def test_runtime_api_has_no_table_scan_calls():
    source = (Path(__file__).parents[1] / "src" / "api" / "main.py").read_text()

    assert ".scan(" not in source


def test_index_migration_resolves_table_names_from_stack_outputs():
    source = (Path(__file__).parents[1] / "scripts" / "backfill_query_indexes.py").read_text()

    assert 'outputs["ResultsTableName"]' in source
    assert 'outputs["AuditTableName"]' in source
    assert 'outputs["AccessRequestsTableName"]' in source
    assert "-classifications-" not in source
