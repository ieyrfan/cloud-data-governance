import importlib

from fastapi.testclient import TestClient


class FakeS3:
    def __init__(self):
        self.calls = []

    def head_object(self, **kwargs):
        self.calls.append(("head", kwargs))
        return {"ContentType": "application/pdf"}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        self.calls.append((operation, Params, ExpiresIn))
        return f"https://signed.example/{Params['Bucket']}/{Params['Key']}"


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def query(self, **kwargs):
        record_type = None
        expression = kwargs.get("KeyConditionExpression")
        if expression is not None:
            values = getattr(expression, "_values", ())
            record_type = values[-1] if values else None
        items = [
            item
            for item in self.items
            if record_type is None or item.get("record_type") == record_type
        ]
        return {"Items": items}


class FakeDynamoDB:
    def __init__(self):
        self.table = FakeTable()

    def Table(self, _name):
        return self.table


def _client(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "reviewer-token-1234")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "administrator-token-1234")
    monkeypatch.setenv("RAW_BUCKET", "governed-raw")
    monkeypatch.setenv("CLEAN_BUCKET", "governed-clean")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._s3 = FakeS3()
    api_main._dynamodb = FakeDynamoDB()
    monkeypatch.setattr(
        api_main,
        "_latest_file",
        lambda resource_id: {
            "resource_id": resource_id,
            "governance_actions": {
                "protected_copy_created": True,
                "protected_format_preserved": True,
            },
        },
    )
    return api_main, TestClient(api_main.app)


def test_reviewer_receives_only_clean_bucket_link(monkeypatch):
    api_main, client = _client(monkeypatch)
    headers = {"X-Dashboard-Token": "reviewer-token-1234"}
    resource = "s3://governed-raw/uploads/payroll.pdf"

    protected = client.get(
        "/files/download",
        params={"resource_id": resource, "variant": "protected"},
        headers=headers,
    )
    assert protected.status_code == 200
    assert protected.json()["access_role"] == "REVIEWER"
    assert "/governed-clean/uploads/payroll.pdf" in protected.json()["url"]
    assert protected.json()["access_basis"] == "PROTECTED_DEFAULT"
    assert len(protected.json()["correlation_id"]) == 36

    events = client.get("/access-events", headers=headers)
    assert events.status_code == 200
    assert events.json()["count"] == 1
    assert events.json()["items"][0]["variant"] == "PROTECTED"
    assert events.json()["items"][0]["actor"] == "reviewer"

    original = client.get(
        "/files/download",
        params={"resource_id": resource, "variant": "original"},
        headers=headers,
    )
    assert original.status_code == 410
    assert all("governed-raw" not in str(call) for call in api_main._s3.calls)


def test_administrator_cannot_request_original_link(monkeypatch):
    _, client = _client(monkeypatch)
    response = client.get(
        "/files/download",
        params={
            "resource_id": "s3://governed-raw/uploads/payroll.pdf",
            "variant": "original",
        },
        headers={"X-Dashboard-Token": "administrator-token-1234"},
    )
    assert response.status_code == 410


def test_summary_reports_authenticated_role(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DASHBOARD_TOKEN", "reviewer-token-1234")
    monkeypatch.setenv("ADMIN_DASHBOARD_TOKEN", "administrator-token-1234")
    import src.api.main as api_main

    client = TestClient(importlib.reload(api_main).app)
    reviewer = client.get(
        "/dashboard/summary",
        headers={"X-Dashboard-Token": "reviewer-token-1234"},
    )
    admin = client.get(
        "/dashboard/summary",
        headers={"X-Dashboard-Token": "administrator-token-1234"},
    )
    assert reviewer.json()["access_role"] == "REVIEWER"
    assert admin.json()["access_role"] == "ADMIN"
