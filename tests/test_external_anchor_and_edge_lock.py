from src.governance.external_anchor import publish_checkpoint


class FakeS3:
    def __init__(self):
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        return {"ETag": "anchor"}


def test_external_anchor_is_explicitly_disabled_without_separate_bucket(monkeypatch):
    monkeypatch.delenv("AUDIT_ANCHOR_BUCKET", raising=False)
    result = publish_checkpoint(head_hash="a" * 64, event_count=3, generated_at="2026-10-28T00:00:00Z")
    assert result["active"] is False
    assert result["reason"] == "AUDIT_ANCHOR_BUCKET_NOT_CONFIGURED"
    assert "head_hash" in result["checkpoint"]


def test_external_anchor_contains_only_content_free_checkpoint(monkeypatch):
    fake = FakeS3()
    monkeypatch.setenv("AUDIT_ANCHOR_BUCKET", "separate-anchor")
    monkeypatch.setenv("RELEASE_ID", "release-test")
    result = publish_checkpoint(
        head_hash="b" * 64,
        event_count=4,
        generated_at="2026-10-28T00:00:00Z",
        s3_client=fake,
    )
    assert result["active"] is True
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["Bucket"] == "separate-anchor"
    assert call["Metadata"]["content-free"] == "true"
    assert b"release-test" in call["Body"]
    assert b"document" not in call["Body"]

