# DataSentinel Python SDK

The SDK uses only the Python standard library. It wraps the versioned
Integration API without storing the API key or detected personal values.

```python
from sdk.python.datasentinel_client import DataSentinelClient

client = DataSentinelClient("https://datasentinel.ifhx.my", "ds_live_...")
identity = client.whoami()
submission = client.create_document(
    "evidence.pdf",
    "application/pdf",
    "my-stable-request-id",
    purpose="protected academic review",
)
```

Upload the file using the returned short-lived S3 POST contract, then poll
`client.job(job_id)`. Use `client.protected_copy(document_id)` only when the
client owns the `protected-copy:read` scope. Never log the API key, upload
fields, protected URL, subject reference or original document content.
