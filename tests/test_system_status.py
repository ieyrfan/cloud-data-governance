import importlib

from fastapi.testclient import TestClient


class FakeS3:
    def __init__(self, failing_bucket=""):
        self.failing_bucket = failing_bucket

    def head_bucket(self, *, Bucket):
        if Bucket == self.failing_bucket:
            raise RuntimeError("provider detail must not reach the client")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class FakeTable:
    def load(self):
        return None


class FakeDynamoDB:
    def Table(self, _name):
        return FakeTable()


class FakeEvents:
    def describe_rule(self, *, Name):
        assert Name == "classification-rule"
        return {"State": "ENABLED"}


class FakeLambda:
    def get_function_configuration(self, *, FunctionName):
        assert FunctionName == "classifier-function"
        return {"State": "Active", "LastUpdateStatus": "Successful"}


class FakeSQS:
    def get_queue_attributes(self, *, QueueUrl, AttributeNames):
        assert QueueUrl == "classification-dlq"
        assert AttributeNames == ["ApproximateNumberOfMessages"]
        return {"Attributes": {"ApproximateNumberOfMessages": "0"}}


def live_client(monkeypatch, *, failing_bucket=""):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("DASHBOARD_TOKEN", "reviewer-access-token")
    monkeypatch.setenv("RAW_BUCKET", "raw-bucket")
    monkeypatch.setenv("CLEAN_BUCKET", "clean-bucket")
    monkeypatch.setenv("CLASSIFIER_FUNCTION_NAME", "classifier-function")
    monkeypatch.setenv("CLASSIFICATION_RULE_NAME", "classification-rule")
    monkeypatch.setenv("CLASSIFICATION_DLQ_URL", "classification-dlq")
    import src.api.main as api_main

    api_main = importlib.reload(api_main)
    api_main._s3 = FakeS3(failing_bucket=failing_bucket)
    api_main._dynamodb = FakeDynamoDB()
    api_main._events = FakeEvents()
    api_main._lambda = FakeLambda()
    api_main._sqs = FakeSQS()
    return TestClient(api_main.app)


def test_live_system_status_checks_each_pipeline_dependency(monkeypatch):
    client = live_client(monkeypatch)
    response = client.get(
        "/system/status", headers={"X-Dashboard-Token": "reviewer-access-token"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall"] == "OPERATIONAL"
    assert payload["mode"] == "aws"
    assert [check["id"] for check in payload["checks"]] == [
        "raw-storage",
        "event-pipeline",
        "classification",
        "protected-storage",
        "evidence-store",
    ]
    assert {check["status"] for check in payload["checks"]} == {"OPERATIONAL"}


def test_live_system_status_degrades_without_leaking_provider_error(monkeypatch):
    client = live_client(monkeypatch, failing_bucket="clean-bucket")
    response = client.get(
        "/system/status", headers={"X-Dashboard-Token": "reviewer-access-token"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall"] == "DEGRADED"
    protection = next(check for check in payload["checks"] if check["id"] == "protected-storage")
    assert protection["status"] == "DEGRADED"
    assert protection["detail"] == "The dependency did not answer the live readiness check."
    assert "provider detail" not in response.text
