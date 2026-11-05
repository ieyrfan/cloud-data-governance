#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${STACK_NAME:-cloud-data-governance}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CREDENTIALS_FILE="${AWS_CREDENTIALS_FILE:-}"
if [[ -z "$CREDENTIALS_FILE" && -f "${PROJECT_DIR}/aws" ]]; then CREDENTIALS_FILE="${PROJECT_DIR}/aws"; fi
if [[ -z "$CREDENTIALS_FILE" && -f "${PROJECT_DIR}/aws.env" ]]; then CREDENTIALS_FILE="${PROJECT_DIR}/aws.env"; fi
if [[ -n "$CREDENTIALS_FILE" ]]; then
  while IFS='=' read -r key value; do
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]\r]*$//')"
    case "$key" in
      aws_access_key_id) export AWS_ACCESS_KEY_ID="$value" ;;
      aws_secret_access_key) export AWS_SECRET_ACCESS_KEY="$value" ;;
      aws_session_token) export AWS_SESSION_TOKEN="$value" ;;
    esac
  done < "$CREDENTIALS_FILE"
fi
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
  if [[ -f "${PROJECT_DIR}/.learner-lab-login" ]]; then
    ADMIN_PASSWORD="$(awk -F= '$1 == "admin" {sub(/^admin=/, ""); print; exit}' "${PROJECT_DIR}/.learner-lab-login")"
  fi
fi
if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "Administrator password is unavailable. Deploy first or set ADMIN_PASSWORD." >&2
  exit 1
fi

output() {
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

RAW_BUCKET="$(output RawDataBucketName)"
CLEAN_BUCKET="$(output CleanDataBucketName)"
RESULTS_TABLE="$(output ResultsTableName)"
AUDIT_TABLE="$(output AuditTableName)"
API_URL="$(output ApiUrl)"
RELEASE_ID="$(output ReleaseId)"
LOCAL_RELEASE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["source_tree_sha256"])' "${PROJECT_DIR}/release-manifest.json")"
if [[ "$RELEASE_ID" != "$LOCAL_RELEASE_ID" ]]; then
  echo "Verification failed: deployed release does not match the local release manifest." >&2
  exit 1
fi
TEST_KEY="evidence/learner-lab-sensitive-sample.txt"
TEST_FILE="$(mktemp)"
trap 'rm -f "$TEST_FILE"' EXIT

printf '%s\n' \
  'Classification evidence sample for the academic Learner Lab.' \
  'NRIC: 900101-14-5555' \
  'Email: learner@example.com' > "$TEST_FILE"

echo "Uploading controlled synthetic test data..."
aws s3api put-object --region "$REGION" --bucket "$RAW_BUCKET" --key "$TEST_KEY" \
  --body "$TEST_FILE" --content-type text/plain \
  --tagging 'DataOwner=LearnerLab&Sensitivity=Unknown&CostCenter=Academic' >/dev/null

RESOURCE_ID="s3://${RAW_BUCKET}/${TEST_KEY}"
echo "Waiting up to 60 seconds for asynchronous classification..."
FOUND=""
for _ in {1..12}; do
  FOUND="$(aws dynamodb query --region "$REGION" --table-name "$RESULTS_TABLE" \
    --key-condition-expression 'resource_id = :resource' \
    --expression-attribute-values "{\":resource\":{\"S\":\"${RESOURCE_ID}\"}}" \
    --no-scan-index-forward --query 'sort_by(Items,&timestamp.S)[-1].sensitivity_level.S' \
    --output text 2>/dev/null || true)"
  [[ "$FOUND" == "RESTRICTED" ]] && break
  sleep 5
done

if [[ "$FOUND" != "RESTRICTED" ]]; then
  echo "Verification failed: expected RESTRICTED but received '${FOUND:-no result}'." >&2
  echo "Inspect: aws logs tail /aws/lambda/$(output ClassifierFunctionName) --since 10m --region $REGION" >&2
  exit 1
fi

echo "Classification result: RESTRICTED"
echo "Redacted copy:"
aws s3 cp "s3://${CLEAN_BUCKET}/${TEST_KEY}" - --region "$REGION"

AUDIT_COUNT="0"
for _ in {1..6}; do
  AUDIT_COUNT="$(aws dynamodb scan --region "$REGION" --table-name "$AUDIT_TABLE" \
    --select COUNT --query Count --output text)"
  [[ "$AUDIT_COUNT" -gt 0 ]] && break
  sleep 2
done
if [[ "$AUDIT_COUNT" -lt 1 ]]; then
  echo "Verification failed: no audit record was created." >&2
  exit 1
fi
echo "Audit records present: ${AUDIT_COUNT}"

curl_api_with_retry() {
  curl --retry 5 --retry-delay 1 --retry-max-time 30 --retry-all-errors \
    --fail --silent --show-error "$@"
}

echo "Public health endpoint:"
HEALTH_RESPONSE="$(curl_api_with_retry "${API_URL}/health")"
HEALTH_RELEASE_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("release_id", ""))' <<< "$HEALTH_RESPONSE")"
if [[ "$HEALTH_RELEASE_ID" != "$RELEASE_ID" ]]; then
  echo "Verification failed: health endpoint release identity does not match the stack output." >&2
  exit 1
fi
printf '%s' "$HEALTH_RESPONSE"
echo
echo "Administrator sign-in and authenticated dashboard API:"
LOGIN_PAYLOAD="$(ADMIN_USERNAME="$ADMIN_USERNAME" ADMIN_PASSWORD="$ADMIN_PASSWORD" python3 -c 'import json,os; print(json.dumps({"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]}))')"
LOGIN_RESPONSE="$(curl_api_with_retry -X POST -H 'Content-Type: application/json' \
  --data "$LOGIN_PAYLOAD" \
  "${API_URL}/auth/login")"
SESSION_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])' <<< "$LOGIN_RESPONSE")"
curl_api_with_retry -H "X-Dashboard-Token: ${SESSION_TOKEN}" "${API_URL}/dashboard/summary"
echo

echo "Core Learner Lab verification passed."
echo "Raw bucket:     ${RAW_BUCKET}"
echo "Clean bucket:   ${CLEAN_BUCKET}"
echo "Results table:  ${RESULTS_TABLE}"
echo "API URL:        ${API_URL}"
