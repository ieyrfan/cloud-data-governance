#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${STACK_NAME:-cloud-data-governance}"
PROJECT_NAME="${PROJECT_NAME:-cloud-data-governance}"
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
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ARTIFACT_BUCKET="${PROJECT_NAME}-artifacts-${ACCOUNT_ID}-${REGION}"

output() {
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

for bucket in "$(output RawDataBucketName)" "$(output CleanDataBucketName)"; do
  echo "Emptying versioned bucket ${bucket} before stack deletion..."
  aws s3 rm "s3://${bucket}" --recursive --region "$REGION" --only-show-errors || true
  versions="$(aws s3api list-object-versions --bucket "$bucket" --region "$REGION" \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json)"
  if [[ "$versions" != '{\n    "Objects": null\n}' && "$versions" != *'"Objects": null'* ]]; then
    aws s3api delete-objects --bucket "$bucket" --region "$REGION" --delete "$versions" >/dev/null || true
  fi
  markers="$(aws s3api list-object-versions --bucket "$bucket" --region "$REGION" \
    --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json)"
  if [[ "$markers" != *'"Objects": null'* ]]; then
    aws s3api delete-objects --bucket "$bucket" --region "$REGION" --delete "$markers" >/dev/null || true
  fi
done

echo "Deleting stack ${STACK_NAME}..."
aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK_NAME"
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK_NAME"

echo "Deleting deployment artifacts..."
aws s3 rm "s3://${ARTIFACT_BUCKET}" --recursive --region "$REGION" --only-show-errors || true
aws s3api delete-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" 2>/dev/null || true
echo "Cleanup complete."
