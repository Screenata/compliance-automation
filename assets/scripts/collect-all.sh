#!/usr/bin/env bash
# .compliance/scripts/collect-all.sh
# Runs all evidence collection scripts in this directory
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SECRETS_FILE="$REPO_ROOT/.compliance/secrets.env"

# Load secrets from .compliance/secrets.env if it exists (for local testing)
if [ -f "$SECRETS_FILE" ]; then
  echo "Loading secrets from .compliance/secrets.env"
  set -a
  # shellcheck source=/dev/null
  source "$SECRETS_FILE"
  set +a
fi

echo "SOC 2 Evidence Collection — $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "================================================"

failed=0
for script in "${SCRIPT_DIR}"/*.sh; do
  [ "$(basename "$script")" = "collect-all.sh" ] && continue
  tool=$(basename "$script" .sh)
  echo ""
  echo "--- Collecting: ${tool} ---"
  if bash "$script"; then
    echo "OK: ${tool}"
  else
    echo "FAILED: ${tool} (continuing...)"
    failed=$((failed + 1))
  fi
done

echo ""
echo "================================================"
echo "Collection complete. ${failed} failure(s)."
[ "$failed" -eq 0 ] || exit 1
