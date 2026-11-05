# DataSentinel: current mode, retention and presentation truth

**Verified against source and the Learner Lab account on 2 November 2026.** The current customer entry is [datasentinel.ifhx.my](https://datasentinel.ifhx.my/). Configuration and account state can change after this check.

## One-minute explanation / Penerangan satu minit

**BM:** Pelanggan menghantar satu fail kepada `POST /api/v1/protect`. API mengesan kategori sensitif yang disokong, menutup nilai yang dipilih, memeriksa hasil bagi nilai yang dikesan, dan memulangkan fail terlindung terus dalam respons. Pelayar memulakan muat turun dan memaparkan resit sementara tanpa nilai peribadi. DataSentinel tidak mencipta rekod dokumen pelanggan atau objek S3 bagi laluan ini. Fail asal kekal di pihak pengirim. Ini bukan jaminan bahawa AWS tidak pernah menerima fail, bahawa semua PII pasti dikesan, atau bahawa semua salinan di semua lapisan mempunyai retention sifar.

**EN:** The customer sends one file to `POST /api/v1/protect`. The API detects supported sensitive categories, redacts the selected values, checks the output for detected values, and returns the protected file directly. The browser starts the download and shows a temporary receipt without personal values. This path does not create a customer document record or S3 object. The sender retains the original. It does not mean AWS never receives the bytes, every possible PII value is found, or every layer has zero retention.

## Active flow versus legacy flow

| | Active public direct mode | Legacy/alternate governed-storage mode |
|---|---|---|
| Entry | Public `POST /api/v1/protect`; no login or API key | Presigned upload and asynchronous document/job routes |
| Processing | API Gateway → API Lambda → parser/Textract → detector → redactor → output check | Private raw S3 → EventBridge → classifier Lambda → protected S3 |
| Customer file storage by this application | No raw or protected S3 object created | S3 objects and DynamoDB records exist when mode is enabled |
| Result | Protected bytes in the same HTTP response; browser download | Later retrieval of stored protected copy |
| Status on this deployment | **Active** (`STRICT_TRANSIENT_MODE=true`) | **Disabled** for customer routes with HTTP 410; infrastructure remains provisioned |

Do not demo the old console or asynchronous API as the live public workflow. The API sends a suggested document type/classification and content-free category counts; the suggestion is not permission to share.

## Data and retention map

| Place | What it handles or stores in direct mode | Checked retention / boundary |
|---|---|---|
| Customer browser/device | Original selected file, protected download, temporary page receipt and blob URL | Controlled by the customer's browser/device. This application does not remotely erase a downloaded file. |
| API Gateway HTTP API | Request and response bytes during transit; request metadata | Live `$default` stage has detailed metrics and no configured access-log destination. AWS service handling and account-level logging are separate boundaries. |
| API Lambda | File bytes, extracted text, detected values and protected bytes in process memory | Live timeout **30 seconds**, memory **512 MiB**, reserved concurrency **2**. The direct handler does not write the document to S3/DynamoDB. Lambda operational logs have **1-day CloudWatch retention**. This is a log setting, not a guarantee about all AWS internal processing. |
| Amazon Textract | Image or scanned-PDF bytes submitted synchronously for OCR; text/geometry returned to Lambda | The direct path sends document bytes, not an S3 object. AWS's service data-handling terms apply; this project does not set or prove an account-wide Textract zero-retention policy. See [AWS Textract data protection](https://docs.aws.amazon.com/textract/latest/dg/data-protection.html). |
| DynamoDB public-usage table | UTC day, aggregate request count and expiration timestamp; no IP, file name, file text or document ID | Live TTL is enabled on `expires_epoch`. Code sets expiry two days after the following UTC midnight. TTL deletion is asynchronous and may occur days after expiry; it is not immediate deletion. See [AWS DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html). |
| Raw/clean S3 buckets | Provisioned for disabled legacy mode; direct handler does not upload to them | Read-only check found **0 object versions and 0 delete markers** in both buckets on 2 November 2026. This is a point-in-time observation, not proof about every past or future request. |
| CloudWatch/metrics/CloudTrail | Operational events and metrics may exist independently of application document records | Three Lambda log groups had **1-day retention**. Seven alarms were verified after deployment, including API throttle and near-timeout alarms. CloudTrail data-event coverage and provider-side retention were **not established** by this check. Avoid claiming that all AWS-level access is audited. |

No full filename, OCR text, detected value or document bytes are intentionally placed in the new processing receipt. The response still needs a `Content-Disposition` filename so the protected download is named. The receipt's random correlation ID is not a customer or document identifier and is not a persistent document record.

## Operational limits proven in this deployment

- Input and output: maximum **3 MiB** each. Images: maximum **25 million pixels**. Scanned PDF: maximum **three pages**. API Gateway and Lambda may reject or time out before the browser's two-minute wait.
- Live protect route: **1 request/second**, burst **2**. API Lambda: **2** reserved concurrent executions. This protects a student demonstration; it is not a load-tested service-level objective.
- Public daily quota: **200 requests per UTC day**. A failed quota-counter write fails closed with a service error; an exhausted quota returns HTTP 429 with `Retry-After`.
- CloudWatch alarms cover API Lambda errors, throttles and near-timeout duration, plus legacy classifier/webhook/DLQ failures. Alarm delivery still depends on an SNS subscription. A dedicated Textract spend alarm or AWS Budget was **not verified active**. Do not claim cost alerting for Textract specifically.
- WAF/CloudFront, active malware scanning and identity federation are **not proved active** on this Learner Lab public path. Production templates and designs are not deployment evidence.
- Output metadata has a bounded treatment: generated JPEGs omit source EXIF; PDFs clear the standard information dictionary and XMP packet, and PDFs with embedded attachments are blocked. Tests cover those paths. This is **not** a claim that every possible PDF container feature or file-format metadata field has been exhaustively sanitised.

## Processing receipt: exact meaning

After a successful download the page shows document type, suggested classification, detected/redacted/kept categories, covered areas, OCR use, a check result, elapsed server processing time and a random request reference. The same content-free fields are available as HTTP response headers. “Passed checks for detected values” means the redaction path's available checks completed; it **does not** certify that undetected PII is absent. A KEEP choice is labelled as customer-selected retention of visible information, never as a PII-free result. The page receipt disappears on reload and is not written to the document inventory.

## Presentation script

1. Use a synthetic file. Show the categories before upload and say which can never be kept visible.
2. Upload once. Explain that uncertainty or verification failure returns an error **without a protected file**.
3. Show the downloaded file and temporary receipt. Point out the OCR flag and categories without opening a real person's document.
4. Show `/config`, the source path and current AWS settings as evidence for the direct mode. Say “application-side non-persistence,” not “zero storage everywhere.”
5. State the limits: imperfect detection, no production WAF/malware proof, and no real-world p95/p99 load evidence.

The [quality and failure matrix](DIRECT_MODE_QA_MATRIX.md) separates checks by format and condition. It deliberately reports no global accuracy percentage.

**Release verification on 2 November 2026:** 252 Python tests, seven frontend workflow tests and Ruff lint passed. The deployed `/config` reported `direct_redaction` and the expected release ID. Two live synthetic text requests returned HTTP 200 and the expected REDACT/KEEP receipt fields; a synthetic text PDF returned HTTP 200 with the detected value and source title absent; a no-PII request returned HTTP 422 with no attachment. Seven alarms were present. Both legacy customer-document buckets still had zero object versions and delete markers after these requests. The Chrome extension used for interactive browser QA lacked local-file access, so an end-to-end browser upload of this release was not completed; the browser workflow is covered by frontend automation and direct live API calls instead.

## English booth answer to “Do you store our documents?”

“In the current public flow, the application does not create a document record or write your submitted or protected file into its S3 buckets. It processes the bytes through API Gateway, Lambda and, when needed, Textract, then returns the protected file directly. A daily aggregate request counter and operational logs remain. Your browser and device keep the downloaded file. We do not claim zero retention across every AWS service.”
