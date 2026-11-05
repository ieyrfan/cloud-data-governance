# DataSentinel: current AWS architecture

**Status shown:** active public direct-redaction route, based on the source and Learner Lab verification documented on 2 November 2026. Recheck the live stack before presenting if it has changed since then.

## Walkthrough

1. **Customer device:** the customer selects one file and redaction policy. The original remains with the customer.
2. **Amazon API Gateway HTTP API:** receives the HTTPS request and invokes the API Lambda. The current route is rate-limited to 1 request/second with a burst of 2.
3. **AWS Lambda:** runs the FastAPI direct route. File bytes are processed in memory by the existing extraction, PII/regex detection, redaction and output-validation path. This diagram does not imply a change to that engine.
4. **Amazon Textract:** optional OCR branch for supported scanned/image inputs. Lambda sends the needed scan bytes and receives OCR text and geometry.
5. **Direct response:** after successful checks, protected file bytes and a content-free receipt return through API Gateway to the customer browser. The application does not write the customer document to S3 or create a document record in DynamoDB.
6. **Amazon DynamoDB:** separate quota metadata only: UTC day, aggregate count and expiry. TTL expiration is asynchronous.
7. **Amazon CloudWatch and SNS:** CloudWatch collects Lambda operational logs/metrics and alarms. The alarm topic can notify a person only when a subscription is configured and confirmed. Lambda log retention is documented as one day; this does not prove zero retention in every AWS service.
8. **Deployment and permissions:** CloudFormation provisions resources. The Lambda uses the Learner Lab IAM role for AWS service access. Verify the actual role policy before claiming least privilege.

## Legacy resources

The lower dashed lane shows the older stored-document workflow still present in stack/code: private raw S3 → EventBridge → classifier Lambda → protected S3 and governance DynamoDB, with an SQS dead-letter route for failures. Public stored-document endpoints are disabled in the verified direct-mode configuration and return HTTP 410. This lane is not part of the active public customer request.

## Presentation wording

“The customer sends a file over HTTPS. API Gateway invokes Lambda, which processes the file in memory and calls Textract only when OCR is needed. Once output checks pass, the protected file is returned directly to the browser. The application does not store document files in S3 or document records in DynamoDB. A quota counter and operational logs remain, and AWS services handle the bytes temporarily.”

Call this **application-side non-persistence**. Do not call it zero retention across AWS, zero knowledge, or perfect detection. This current path does not provide a customer-side decryption/recovery feature.
