from src.handlers.s3_classifier import _extract_s3_objects


def test_extracts_direct_s3_notification():
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "raw-bucket"}, "object": {"key": "folder/My+File.txt"}}}
        ]
    }
    assert _extract_s3_objects(event) == [("raw-bucket", "folder/My File.txt", None)]


def test_extracts_eventbridge_s3_event():
    event = {
        "source": "aws.s3",
        "detail-type": "Object Created",
        "detail": {"bucket": {"name": "raw-bucket"}, "object": {"key": "folder%2Fsample.txt"}},
    }
    assert _extract_s3_objects(event) == [("raw-bucket", "folder/sample.txt", None)]


def test_eventbridge_key_preserves_literal_plus():
    event = {
        "source": "aws.s3",
        "detail": {"bucket": {"name": "raw-bucket"}, "object": {"key": "evidence/A+B.txt"}},
    }
    assert _extract_s3_objects(event) == [("raw-bucket", "evidence/A+B.txt", None)]
