#!/usr/bin/env bash
# Deploy to LocalStack
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../terraform/environments/dev"
tflocal init
tflocal apply
