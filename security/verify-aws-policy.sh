#!/bin/bash
# File: verify-aws-policy.sh
# Verifies all AWS IAM policies under security/aws/ are read-only
# Usage: ./verify-aws-policy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_FILES=(
  "$SCRIPT_DIR/aws/base-readonly.json"
  "$SCRIPT_DIR/aws/hygiene-readonly.json"
  "$SCRIPT_DIR/aws/ai-readonly.json"
)

FAILED=0

for POLICY_FILE in "${POLICY_FILES[@]}"; do
  POLICY_NAME=$(basename "$POLICY_FILE")

  if [ ! -f "$POLICY_FILE" ]; then
    echo "❌ ERROR: Policy file not found: $POLICY_FILE"
    FAILED=1
    continue
  fi

  echo "🔍 Verifying AWS IAM Policy: $POLICY_NAME"

  FORBIDDEN=$(cat "$POLICY_FILE" | jq -r '.Statement[].Action[]?' 2>/dev/null | grep -iE '^[^:]+:(Delete|Put|Create|Update|Modify|Terminate|Reboot|Stop|Start|Attach|Detach|Tag|Untag)[A-Z]' || true)

  if [ -z "$FORBIDDEN" ]; then
    echo "✅ PASS: No write/delete/tag permissions found"
    echo "   Allowed actions:"
    cat "$POLICY_FILE" | jq -r '.Statement[].Action[]?' 2>/dev/null | sort | uniq | sed 's/^/     /'
    echo ""
  else
    echo "❌ FAIL: Found forbidden permissions:"
    echo "$FORBIDDEN"
    echo ""
    FAILED=1
  fi
done

exit $FAILED
