import base64
import hashlib
import json
import os
import urllib.parse
from datetime import UTC, datetime

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.classifiers.comprehend_client import ComprehendClient
from src.classifiers.confidence_scorer import (
    calculate_confidence_score,
    determine_sensitivity_level,
)
from src.classifiers.document_type_classifier import classify_document_type
from src.classifiers.pattern_matcher import discover_sensitive_data
from src.governance.policy_engine import PROFILE_ALIASES, PROFILES, simulate_policy
from src.governance.redaction_policy import (
    RedactionPolicyError,
    apply_policy,
    normalize_policy,
    policy_from_metadata,
    public_policy_metadata,
)
from src.integrations.malware_gate import evaluate_scan_status
from src.utils.dynamodb_client import DynamoDBClient

# Lazily initialized on the first real invocation. This preserves warm-Lambda
# connection reuse while allowing event parsing and unit tests without AWS credentials.
s3 = None
textract = None
comprehend_client = None
dynamodb_client = None
sqs = None

CLASSIFIER_ID = "DS-CLASSIFIER-MY-PII"
CLASSIFIER_VERSION = "2026.10-r7"
POLICY_ID = "DS-DATA-001"
POLICY_VERSION = "2026.10-r1"

# Context keywords that indicate sensitive data
CONTEXT_KEYWORDS = [
    "nric",
    "salary",
    "medical",
    "confidential",
    "password",
    "credit",
    "card",
    "ic number",
]

COMPREHEND_PATTERN_TYPES = {
    "NAME": "name",
    "ADDRESS": "address",
    "EMAIL": "email",
    "PHONE": "my_phone",
    "SSN": "government_id",
    "PASSPORT_NUMBER": "government_id",
    "DRIVER_ID": "government_id",
    "BANK_ACCOUNT_NUMBER": "financial_account",
    "BANK_ROUTING": "financial_account",
    "CREDIT_DEBIT_NUMBER": "credit_card",
    "CREDIT_CARD_NUMBER": "credit_card",
}


def _webhook_message(
    *,
    tenant_id: str,
    client_id: str,
    document_id: str,
    source_fingerprint: str,
    sensitivity: str,
    confidence: float,
    risk_level: str,
    document_type: str,
    protected_available: bool,
) -> dict:
    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "payload": {
            "event": "document.processing.completed",
            "event_id": f"evt_{source_fingerprint}",
            "occurred_at": datetime.now(UTC).isoformat(),
            "document_id": document_id,
            "classification": {
                "sensitivity": sensitivity,
                "confidence": confidence,
                "risk_level": risk_level,
                "document_type": document_type,
            },
            "protected_copy": {"available": protected_available},
            "values_disclosed": False,
        },
    }


def _merge_comprehend_patterns(text: str, patterns: dict, entities: list[dict]) -> dict:
    """Turn high-confidence NLP offsets into redactable values without logging the values."""
    for entity in entities:
        data_type = COMPREHEND_PATTERN_TYPES.get(str(entity.get("Type", "")).upper())
        if not data_type or float(entity.get("Score", 0)) < 0.8:
            continue
        begin = int(entity.get("BeginOffset", -1))
        end = int(entity.get("EndOffset", -1))
        if begin < 0 or end <= begin or end > len(text):
            continue
        value = text[begin:end].strip()
        if value and value not in patterns.setdefault(data_type, []):
            patterns[data_type].append(value)
    return patterns


def _initialize_clients():
    global s3, textract, comprehend_client, dynamodb_client, sqs
    if s3 is None:
        s3 = boto3.client("s3", endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"))
    if textract is None and os.environ.get("ENABLE_TEXTRACT", "false").lower() == "true":
        textract = boto3.client("textract", endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"))
    if comprehend_client is None:
        comprehend_enabled = os.environ.get("ENABLE_COMPREHEND", "false").lower() == "true"
        comprehend_client = ComprehendClient(enabled=comprehend_enabled)
    if dynamodb_client is None:
        dynamodb_client = DynamoDBClient(
            table_name=os.environ.get("DYNAMODB_TABLE", "DataGovernanceResults")
        )
    if sqs is None and os.environ.get("WEBHOOK_QUEUE_URL"):
        sqs = boto3.client("sqs", endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT"))


def _extract_s3_objects(event):
    """Supports direct S3 notifications and EventBridge S3 Object Created events."""
    objects = []
    for record in event.get("Records", []):
        if "s3" in record:
            objects.append(
                (
                    record["s3"]["bucket"]["name"],
                    urllib.parse.unquote_plus(record["s3"]["object"]["key"]),
                    record["s3"]["object"].get("versionId"),
                )
            )

    detail = event.get("detail", {})
    if event.get("source") == "aws.s3" and detail.get("bucket") and detail.get("object"):
        objects.append(
            (
                detail["bucket"]["name"],
                urllib.parse.unquote(detail["object"]["key"]),
                detail["object"].get("version-id") or detail["object"].get("versionId"),
            )
        )
    return objects


def lambda_handler(event, context):
    """
    Triggered by S3 object creation.
    Downloads the file, classifies it, and stores the result in DynamoDB.
    """
    print(f"Received classification event with {len(_extract_s3_objects(event))} object(s)")

    # Handle S3 Event (usually wrapped in EventBridge or direct S3 trigger)
    # This assumes standard S3 event structure
    objects = _extract_s3_objects(event)
    if objects:
        _initialize_clients()
    processed = 0
    failures = []

    for bucket_name, object_key, event_version_id in objects:
        s3_uri = f"s3://{bucket_name}/{object_key}"
        object_reference = hashlib.sha256(s3_uri.encode()).hexdigest()[:16]
        print(f"Processing governed object reference: {object_reference}")

        try:
            # 1. Fetch Data
            get_args = {"Bucket": bucket_name, "Key": object_key}
            if event_version_id:
                get_args["VersionId"] = event_version_id
            response = s3.get_object(**get_args)
            file_bytes = response["Body"].read()
            object_metadata = response.get("Metadata", {})
            object_tags = {}
            try:
                tag_response = s3.get_object_tagging(Bucket=bucket_name, Key=object_key)
                object_tags = {
                    item["Key"]: item["Value"] for item in tag_response.get("TagSet", [])
                }
            except (BotoCoreError, ClientError, AttributeError):
                # An enabled malware gate must never treat missing scan evidence as clean.
                object_tags = {}
            malware_gate = evaluate_scan_status(
                object_tags,
                enforced=os.environ.get("ENFORCE_MALWARE_GATE", "false").lower() == "true",
            )
            if not malware_gate["allowed"]:
                raise RuntimeError(
                    "Object is quarantined until malware scanning records NO_THREATS_FOUND"
                )
            display_filename = object_metadata.get(
                "original-filename", os.path.basename(object_key)
            )
            policy_metadata = {}
            try:
                policy_token = object_metadata.get("redaction-policy", "")
                if policy_token:
                    decoded = json.loads(base64.urlsafe_b64decode(policy_token + "=" * (-len(policy_token) % 4)))
                    policy, policy_metadata = policy_from_metadata(decoded)
                else:
                    policy = normalize_policy(None, confirmed=False)
                    policy_metadata = public_policy_metadata(policy, confirmed=False)
            except (ValueError, TypeError, KeyError, json.JSONDecodeError, RedactionPolicyError) as error:
                raise RuntimeError("Invalid redaction policy metadata") from error
            requested_profile = str(object_metadata.get("protection-profile", "malaysia-general")).strip()
            policy_profile = (
                requested_profile
                if requested_profile in PROFILES or requested_profile in PROFILE_ALIASES
                else "malaysia-general"
            )
            source_identity = str(response.get("VersionId") or response.get("ETag") or "")
            if not source_identity:
                source_identity = hashlib.sha256(file_bytes).hexdigest()
            source_fingerprint = hashlib.sha256(
                f"{bucket_name}:{object_key}:{source_identity}".encode()
            ).hexdigest()
            last_modified = response.get("LastModified")
            source_timestamp = (
                last_modified.astimezone().isoformat()
                if hasattr(last_modified, "astimezone")
                else "unknown"
            )
            source_version_id = f"source#{source_timestamp}#{source_fingerprint}"

            # Use intelligent document parser
            from src.utils.document_parser import (
                MAX_INPUT_BYTES,
                extract_text_from_file,
                extract_text_from_textract,
                extract_text_from_textract_async,
            )

            ocr_lines = None
            extension = os.path.splitext(object_key.lower())[1]
            is_image = extension in {".jpg", ".jpeg", ".png"}
            parser_filename = f"document{extension}" if extension else "document"
            if len(file_bytes) > MAX_INPUT_BYTES:
                raise ValueError("Document exceeds the 5 MB processing limit")
            if is_image:
                if textract is None:
                    raise RuntimeError("OCR is required for image classification")
                file_content, ocr_lines = extract_text_from_textract(
                    textract, bucket_name, object_key
                )
            else:
                try:
                    file_content = extract_text_from_file(file_bytes, parser_filename)
                except ValueError as parse_error:
                    is_pdf = extension == ".pdf"
                    needs_async_ocr = "asynchronous multi-page OCR" in str(parse_error)
                    no_text = "contains no extractable text" in str(parse_error)
                    if not (is_pdf and (no_text or needs_async_ocr) and textract is not None):
                        raise
                    if needs_async_ocr:
                        file_content, ocr_lines = extract_text_from_textract_async(
                            textract, bucket_name, object_key
                        )
                    else:
                        file_content, ocr_lines = extract_text_from_textract(
                            textract, bucket_name, object_key
                        )

            if not file_content.strip():
                # Treat an empty extraction as a processing failure rather than
                # silently returning.  The per-object failure path below then
                # applies ephemeral cleanup so an unreadable upload cannot sit
                # indefinitely in the raw bucket.
                raise RuntimeError("No extractable text found")

            # 2. Layered local discovery: normalization, patterns, context,
            # validation, overlap resolution, correlation, confidence and risk.
            discovery = discover_sensitive_data(file_content)
            pattern_matches = discovery.redaction_map()

            # 3. Layer 2: Context Keyword Detection
            file_content_lower = file_content.lower()
            context_keywords_found = any(
                keyword in file_content_lower for keyword in CONTEXT_KEYWORDS
            )

            # 4. Layer 3: NLP with Comprehend
            comprehend_matches = comprehend_client.detect_pii(file_content)
            pattern_matches = _merge_comprehend_patterns(
                file_content, pattern_matches, comprehend_matches
            )
            redaction_matches, kept_categories = apply_policy(pattern_matches, policy)

            # 5. Confidence Scoring & Sensitivity
            legacy_confidence = calculate_confidence_score(
                pattern_matches, comprehend_matches, context_keywords_found
            )
            confidence = max(
                legacy_confidence,
                max((finding.confidence for finding in discovery.findings), default=0.0),
            )
            sensitivity = determine_sensitivity_level(pattern_matches, comprehend_matches)
            public_signals = {
                "my_ic": "MALAYSIAN_NRIC",
                "my_phone": "MALAYSIAN_PHONE",
                "email": "EMAIL_ADDRESS",
                "credit_card": "PAYMENT_CARD",
                "government_id": "GOVERNMENT_ID",
                "financial_account": "FINANCIAL_ACCOUNT",
                "matric_number": "MATRIC_NUMBER",
                "date_of_birth": "DATE_OF_BIRTH",
                "name": "NAME",
                "address": "ADDRESS",
                "aws_access_key": "AWS_ACCESS_KEY",
                "secret": "SECRET",
                "private_key": "PRIVATE_KEY",
                "ip_address": "IP_ADDRESS",
                "mac_address": "MAC_ADDRESS",
                "gps_coordinates": "GPS_COORDINATES",
                "patient_id": "PATIENT_ID",
                "customer_id": "CUSTOMER_ID",
                "user_identifier": "USER_IDENTIFIER",
            }
            selected_signals = [
                public_signals.get(data_type, data_type.upper())
                for data_type, matches in pattern_matches.items()
                if matches
            ]
            document_type = classify_document_type(file_content, display_filename)
            policy_decision = simulate_policy(
                policy_profile,
                selected_signals,
                True,
                document_type=document_type["key"],
            )
            sensitivity = policy_decision["decision"]

            # Prepare findings payload
            findings = {
                "pattern_matches_count": sum(len(m) for m in pattern_matches.values()),
                "pattern_types_detected": [
                    data_type for data_type, matches in pattern_matches.items() if matches
                ],
                "pattern_counts": {
                    data_type: len(matches) for data_type, matches in pattern_matches.items()
                },
                "pii_intelligence": discovery.public_dict(),
                "context_keywords_detected": context_keywords_found,
                "comprehend_entities_count": len(comprehend_matches),
                "document_type": document_type,
                "display_filename": display_filename,
                "source_fingerprint": source_fingerprint,
                "source_version_id": source_identity,
                "classifier_id": CLASSIFIER_ID,
                "classifier_version": CLASSIFIER_VERSION,
                "policy_id": POLICY_ID,
                "policy_version": POLICY_VERSION,
                "protection_profile": requested_profile,
                "applied_policy_profile": policy_profile,
                "policy_decision": policy_decision["decision"],
                "malware_scan_status": malware_gate["status"],
                "malware_gate_mode": malware_gate["mode"],
                "redaction_policy": {
                    **policy_metadata,
                    "keep_categories": kept_categories,
                    "status": "APPLIED",
                },
                "redaction_status": (
                    "COMPLETED_WITH_SELECTED_CATEGORIES_KEPT"
                    if kept_categories
                    else "COMPLETED_FULL_REDACTION"
                ),
            }

            from src.governance.risk_scorer import RiskScoringEngine

            risk_engine = RiskScoringEngine()
            # Both governed buckets are private. Access breadth begins at one
            # until CloudTrail-based access analysis supplies a measured value.
            risk_score = risk_engine.calculate_risk_score(
                sensitivity, exposure_level=1, access_breadth=1
            )
            risk_level = risk_engine.categorize_risk(risk_score)
            governance_actions = {
                "source_private_by_design": True,
                "redacted_copy_created": False,
                "retention_tags_applied": False,
                "audit_event_created": False,
                "source_deleted_after_processing": False,
            }

            print(f"Result for {object_reference}: {sensitivity} (Confidence: {confidence})")

            # 6. Create the user-facing protected copy in the same file format.
            # Reviewers never receive raw-bucket URLs, even when no PII was detected.
            clean_bucket = os.environ.get("CLEAN_BUCKET", f"{bucket_name}-clean")
            try:
                from src.utils.format_redactor import redact_document

                protected_bytes, protected_content_type, protection_metadata = redact_document(
                    file_bytes,
                    object_key,
                    file_content,
                    redaction_matches,
                    ocr_lines=ocr_lines,
                )
                protection_status = "REDACTED" if sensitivity != "PUBLIC" else "REVIEWED_CLEAN"
                protected_response = s3.put_object(
                    Bucket=clean_bucket,
                    Key=object_key,
                    Body=protected_bytes,
                    ContentType=protected_content_type,
                    ContentDisposition="inline",
                    Metadata={
                        "governance-status": protection_status.lower(),
                        "source-format-preserved": "true",
                        "redaction-hits": str(protection_metadata["redaction_hits"]),
                    },
                    Tagging=f"Status={protection_status}&FormatPreserved=true",
                )
                governance_actions["protected_copy_created"] = True
                governance_actions["protected_format_preserved"] = True
                if sensitivity != "PUBLIC":
                    governance_actions["redacted_copy_created"] = True
                findings["protected_output"] = protection_metadata
                findings["protected_version_id"] = str(protected_response.get("VersionId") or "")
                print(f"Protected version created for object reference {object_reference}")
            except Exception as e:
                raise RuntimeError(f"Failed to save required protected version: {e}") from e

            if os.environ.get("ENABLE_RETENTION", "false").lower() == "true":
                from src.governance.data_retention import DataRetentionManager

                retention_ok = DataRetentionManager().apply_retention_tags(
                    bucket_name,
                    object_key,
                    sensitivity,
                    additional_tags={
                        "DataOwner": os.environ.get("DEFAULT_DATA_OWNER", "LearnerLab"),
                        "Sensitivity": sensitivity,
                        "CostCenter": os.environ.get("DEFAULT_COST_CENTER", "Academic"),
                        "GovernanceStatus": "CLASSIFIED",
                    },
                )
                if not retention_ok:
                    raise RuntimeError(
                        "Required retention and governance tags could not be applied"
                    )
                governance_actions["retention_tags_applied"] = True

            if os.environ.get("EPHEMERAL_PROCESSING_MODE", "false").lower() == "true":
                try:
                    delete_args = {"Bucket": bucket_name, "Key": object_key}
                    if event_version_id:
                        delete_args["VersionId"] = event_version_id
                    s3.delete_object(**delete_args)
                    governance_actions["source_deleted_after_processing"] = True
                except (BotoCoreError, ClientError) as error:
                    raise RuntimeError(
                        "Ephemeral mode could not remove the uploaded source"
                    ) from error

            # 7. Store Results
            version_id = dynamodb_client.save_classification_result(
                s3_uri,
                sensitivity,
                confidence,
                findings,
                risk_score=risk_score,
                risk_level=risk_level,
                governance_actions=governance_actions,
                version_id=source_version_id,
            )
            if not version_id:
                raise RuntimeError("Classification result could not be saved to DynamoDB")

            if os.environ.get("AUDIT_TABLE"):
                try:
                    from src.governance.immutable_audit_trail import ImmutableAuditTrail

                    ImmutableAuditTrail().record_event(
                        action="CLASSIFY_OBJECT",
                        actor="data-classifier-lambda",
                        resource=s3_uri,
                        details={
                            "version_id": version_id,
                            "sensitivity": sensitivity,
                            "confidence": confidence,
                        },
                        event_id=f"classify-{source_fingerprint}",
                    )
                    audit_trail = ImmutableAuditTrail()
                    checkpoint = audit_trail.current_checkpoint()
                    from src.governance.external_anchor import publish_checkpoint

                    anchor_result = publish_checkpoint(**checkpoint)
                    if os.environ.get("REQUIRE_EXTERNAL_AUDIT_ANCHOR", "false").lower() == "true" \
                            and not anchor_result.get("active"):
                        raise RuntimeError("External audit anchor is required but not configured")
                    findings["audit_anchor"] = {
                        "active": bool(anchor_result.get("active")),
                        "checkpoint_sha256": anchor_result.get("sha256", ""),
                    }
                    governance_actions["audit_event_created"] = True
                    if not dynamodb_client.update_governance_actions(
                        s3_uri, version_id, governance_actions
                    ):
                        raise RuntimeError("Classification action evidence could not be updated")
                except Exception as audit_error:
                    raise RuntimeError(
                        f"Required audit logging failed: {audit_error}"
                    ) from audit_error

            if sensitivity == "RESTRICTED":
                try:
                    from src.governance.alerting import SecurityAlerter

                    SecurityAlerter().send_critical_alert(
                        title="Restricted data detected",
                        message=f"Classification confidence {confidence:.0%}; review is required.",
                        resource=s3_uri,
                    )
                except Exception as alert_error:  # noqa: BLE001 - alerts must not fail classification
                    print(f"Security notification failed for {object_reference}: {alert_error}")

            webhook_queue_url = os.environ.get("WEBHOOK_QUEUE_URL", "")
            tenant_id = object_metadata.get("tenant-id", "")
            client_id = object_metadata.get("client-id", "")
            document_id = object_metadata.get("document-id", "")
            if webhook_queue_url and tenant_id and client_id and document_id:
                sqs.send_message(
                    QueueUrl=webhook_queue_url,
                    MessageBody=json.dumps(
                        _webhook_message(
                            tenant_id=tenant_id,
                            client_id=client_id,
                            document_id=document_id,
                            source_fingerprint=source_fingerprint,
                            sensitivity=sensitivity,
                            confidence=confidence,
                            risk_level=risk_level,
                            document_type=findings["document_type"],
                            protected_available=bool(
                                governance_actions.get("protected_copy_created")
                            ),
                        ),
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )

            processed += 1

        except Exception as e:  # noqa: BLE001 - per-object boundary records every failure
            print(f"Error processing object reference {object_reference}: {type(e).__name__}")
            if os.environ.get("EPHEMERAL_PROCESSING_MODE", "false").lower() == "true" and s3 is not None:
                try:
                    delete_args = {"Bucket": bucket_name, "Key": object_key}
                    if event_version_id:
                        delete_args["VersionId"] = event_version_id
                    s3.delete_object(**delete_args)
                    print(f"Ephemeral source cleanup completed for object reference {object_reference}")
                except (BotoCoreError, ClientError) as cleanup_error:
                    # Keep the original failure as the processing result, but
                    # make cleanup failure visible for operational remediation.
                    print(
                        f"Ephemeral source cleanup failed for {object_reference}: "
                        f"{type(cleanup_error).__name__}"
                    )
            if dynamodb_client is not None:
                try:
                    dynamodb_client.save_processing_failure(
                        s3_uri,
                        type(e).__name__,
                    )
                except Exception:  # noqa: BLE001 - failure reporting cannot mask batch status
                    print(f"Failure state could not be persisted for {object_reference}")
            failures.append(
                {
                    "resource_reference": object_reference,
                    "error_code": type(e).__name__,
                }
            )
            continue

    if failures:
        raise RuntimeError(json.dumps({"processed": processed, "failures": failures}))

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"processed": processed, "message": "Classification completed successfully."}
        ),
    }
