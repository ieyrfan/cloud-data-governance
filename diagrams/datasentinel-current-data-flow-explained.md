# DataSentinel: current data flow

## Main customer request

1. **Select:** the customer chooses a file and redaction policy in the browser. The original stays on the customer's device.
2. **Upload:** the browser sends the file bytes and request metadata over HTTPS to API Gateway.
3. **Process:** API Gateway invokes Lambda. Lambda temporarily holds the input and intermediate results in memory while the existing engine extracts content, detects PII, applies redaction and validates the output.
4. **Optional OCR:** for supported scans/images, Lambda sends the needed bytes to Textract. Textract returns OCR text and geometry to Lambda. Normal text extraction does not require this branch.
5. **Release gate:** a supported input with successful checks proceeds. Unsupported input, processing uncertainty or failed validation returns an error without a protected file.
6. **Return:** Lambda returns the protected file and a content-free receipt through API Gateway. The browser downloads it. The customer decides whether to share it with another party.

## Separate metadata and operations flows

- **DynamoDB quota:** stores an aggregate UTC-day count and expiry metadata only. It is not a customer-document record; TTL deletion is not instantaneous.
- **CloudWatch:** receives Lambda operational logs, metrics and alarms. **SNS** is the alarm notification destination; a human receives it only if the subscription is set up and confirmed.
- The file path does not write document bytes to application S3 or create document rows in DynamoDB. AWS services still handle file bytes transiently. “No application file storage” is accurate; “nothing is retained anywhere” is not established.

## What this flow does not do

- It does not automatically send the result to a third-party requester. The customer downloads and chooses whether to share.
- It does not decrypt or restore an original using a customer key. That is a separate design requiring the encrypted file and key to be held by the customer and decryption to occur on their device.
- It does not guarantee every PII value is found. Human review remains important, especially for poor scans or ambiguous content.

## One-minute explanation

“The customer uploads a file and chooses a redaction policy. API Gateway passes it to Lambda, where our current detection and redaction engine processes it in memory. Scanned files use Textract for OCR when needed. We release a protected download only after output checks pass. If checks fail, we stop and return an error. The application does not store document files, but a separate quota counter and operational logs remain, and AWS services handle the data temporarily.”
