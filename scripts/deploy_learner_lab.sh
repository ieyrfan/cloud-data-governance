#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${STACK_NAME:-cloud-data-governance}"
PROJECT_NAME="${PROJECT_NAME:-cloud-data-governance}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
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

if [[ "$REGION" != "us-east-1" && "$REGION" != "us-west-2" ]]; then
  echo "Learner Lab permits this deployment only in us-east-1 or us-west-2." >&2
  exit 1
fi

if [[ -z "${DASHBOARD_TOKEN:-}" && -n "${AWS_SESSION_TOKEN:-}" ]]; then
  DASHBOARD_TOKEN="$(python3 -c 'import hashlib,os; print(hashlib.sha256(("reviewer:" + os.environ["AWS_SESSION_TOKEN"]).encode()).hexdigest()[:32])')"
fi
if [[ -z "${ADMIN_DASHBOARD_TOKEN:-}" && -n "${AWS_SESSION_TOKEN:-}" ]]; then
  ADMIN_DASHBOARD_TOKEN="$(python3 -c 'import hashlib,os; print(hashlib.sha256(("administrator:" + os.environ["AWS_SESSION_TOKEN"]).encode()).hexdigest()[:32])')"
fi
DASHBOARD_TOKEN="${DASHBOARD_TOKEN:-}"
ADMIN_DASHBOARD_TOKEN="${ADMIN_DASHBOARD_TOKEN:-}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
  ADMIN_PASSWORD="$(printf '%s' "console-admin-password:${AWS_SESSION_TOKEN}" | sha256sum | cut -c1-24)"
fi
INTEGRATION_API_KEY="$(printf '%s' "integration-api-key:${AWS_SESSION_TOKEN}" | sha256sum | cut -c1-32)"
INTEGRATION_API_KEY_HASH="$(printf '%s' "$INTEGRATION_API_KEY" | sha256sum | cut -c1-64)"
if [[ ${#DASHBOARD_TOKEN} -lt 16 ]]; then
  echo "Set DASHBOARD_TOKEN to at least 16 characters before deployment." >&2
  exit 1
fi
if [[ ${#ADMIN_DASHBOARD_TOKEN} -lt 16 ]]; then
  echo "Set ADMIN_DASHBOARD_TOKEN to at least 16 characters before deployment." >&2
  exit 1
fi
if [[ "$DASHBOARD_TOKEN" == "$ADMIN_DASHBOARD_TOKEN" ]]; then
  echo "Reviewer and administrator tokens must be different." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
LAB_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/LabRole"
python3 "${PROJECT_DIR}/scripts/generate_release_manifest.py" \
  --release datasentinel-booth-2026.10 >/dev/null
RELEASE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["source_tree_sha256"])' "${PROJECT_DIR}/release-manifest.json")"
if [[ ! "$RELEASE_ID" =~ ^[a-f0-9]{64}$ ]]; then
  echo "Release identity is invalid." >&2
  exit 1
fi
ARTIFACT_BUCKET="${PROJECT_NAME}-artifacts-${ACCOUNT_ID}-${REGION}"
BUILD_DIR="$(mktemp -d)"
PACKAGE_DIR="${BUILD_DIR}/package"
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "Checking access to the pre-created LabRole..."
aws iam get-role --role-name LabRole --region "$REGION" >/dev/null

echo "Building Lambda package..."
mkdir -p "$PACKAGE_DIR"
python3 -m pip install --quiet --disable-pip-version-check \
  --platform manylinux_2_28_x86_64 \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --only-binary=:all: \
  -r "${PROJECT_DIR}/deployment/lambda-requirements.txt" \
  -t "$PACKAGE_DIR"
cp -R "${PROJECT_DIR}/src" "$PACKAGE_DIR/src"
cp -R "${PROJECT_DIR}/frontend" "$PACKAGE_DIR/frontend"
(
  cd "$PACKAGE_DIR"
  python3 -m zipfile -c "${BUILD_DIR}/cloud-data-governance.zip" .
)
CODE_HASH="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:16])' "${BUILD_DIR}/cloud-data-governance.zip")"
CODE_KEY="lambda/cloud-data-governance-${CODE_HASH}.zip"

echo "Preparing encrypted deployment artifact bucket..."
if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" >/dev/null 2>&1; then
  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" >/dev/null
  else
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=${REGION}" >/dev/null
  fi
fi
aws s3api put-public-access-block --bucket "$ARTIFACT_BUCKET" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
aws s3api put-bucket-encryption --bucket "$ARTIFACT_BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3 cp "${BUILD_DIR}/cloud-data-governance.zip" \
  "s3://${ARTIFACT_BUCKET}/${CODE_KEY}" --region "$REGION" --only-show-errors

echo "Deploying CloudFormation stack ${STACK_NAME} in ${REGION}..."
aws cloudformation deploy \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "${PROJECT_DIR}/cloudformation/learner-lab.yml" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "ProjectName=${PROJECT_NAME}" \
    "Environment=${ENVIRONMENT}" \
    "LabRoleArn=${LAB_ROLE_ARN}" \
    "LambdaCodeBucket=${ARTIFACT_BUCKET}" \
    "LambdaCodeKey=${CODE_KEY}" \
    "ReleaseId=${RELEASE_ID}" \
    "DashboardToken=${DASHBOARD_TOKEN}" \
    "AdminDashboardToken=${ADMIN_DASHBOARD_TOKEN}" \
    "AdminUsername=${ADMIN_USERNAME}" \
    "AdminPassword=${ADMIN_PASSWORD}" \
    "IntegrationApiKeyHash=${INTEGRATION_API_KEY_HASH}" \
    "IntegrationTenantId=ifhx-demo" \
    "IntegrationClientId=booth-client"

echo "Backfilling sparse query indexes for existing evidence..."
python3 "${PROJECT_DIR}/scripts/backfill_query_indexes.py" \
  --region "$REGION" --stack "$STACK_NAME" --project "$PROJECT_NAME" --environment "$ENVIRONMENT"

echo "Verifying webhook queue consumption..."
WEBHOOK_FUNCTION_NAME="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='WebhookDispatcherFunctionName'].OutputValue | [0]" --output text)"
read -r MAPPING_UUID MAPPING_STATE < <(aws lambda list-event-source-mappings --region "$REGION" \
  --function-name "$WEBHOOK_FUNCTION_NAME" --query 'EventSourceMappings[0].[UUID,State]' --output text)
if [[ -z "${MAPPING_UUID:-}" || "$MAPPING_UUID" == "None" ]]; then
  echo "Webhook event source mapping was not created." >&2
  exit 1
fi
if [[ "$MAPPING_STATE" != "Enabled" && "$MAPPING_STATE" != "Enabling" ]]; then
  aws lambda update-event-source-mapping --region "$REGION" --uuid "$MAPPING_UUID" --enabled >/dev/null
fi
for _ in {1..12}; do
  MAPPING_STATE="$(aws lambda get-event-source-mapping --region "$REGION" --uuid "$MAPPING_UUID" \
    --query State --output text)"
  [[ "$MAPPING_STATE" == "Enabled" ]] && break
  sleep 5
done
if [[ "$MAPPING_STATE" != "Enabled" ]]; then
  echo "Webhook event source mapping is not healthy: $MAPPING_STATE" >&2
  exit 1
fi

OWNER_PASSWORD="$(printf '%s' "owner:${ADMIN_DASHBOARD_TOKEN}" | sha256sum | cut -c1-24)"
REVIEWER_PASSWORD="$(printf '%s' "reviewer:${ADMIN_DASHBOARD_TOKEN}" | sha256sum | cut -c1-24)"
AUDITOR_PASSWORD="$(printf '%s' "auditor:${ADMIN_DASHBOARD_TOKEN}" | sha256sum | cut -c1-24)"
umask 077
write_atomic() {
  local destination="$1"
  local temporary="${destination}.$$.tmp"
  cat > "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$destination"
}
printf '%s\n' "$DASHBOARD_TOKEN" | write_atomic "${PROJECT_DIR}/.learner-lab-token"
printf '%s\n' "$ADMIN_DASHBOARD_TOKEN" | write_atomic "${PROJECT_DIR}/.learner-lab-admin-token"
printf 'admin=%s\nowner=%s\nreviewer=%s\nauditor=%s\n' \
  "$ADMIN_PASSWORD" "$OWNER_PASSWORD" "$REVIEWER_PASSWORD" "$AUDITOR_PASSWORD" \
  | write_atomic "${PROJECT_DIR}/.learner-lab-login"
printf 'tenant_id=ifhx-demo\nclient_id=booth-client\napi_key=%s\n' "$INTEGRATION_API_KEY" \
  | write_atomic "${PROJECT_DIR}/.datasentinel-integration-client"

echo "Deployment complete. Stack outputs:"
aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output table

echo
echo "Next: run scripts/verify_learner_lab.sh"
echo "Console sign-in and Integration API credentials are ready in ignored local files."
