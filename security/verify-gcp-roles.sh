#!/bin/bash
# File: verify-gcp-roles.sh
# Verifies GCP service account has only read-only IAM roles for CleanCloud
# Usage: ./verify-gcp-roles.sh <service-account-email> [project-id]
#
# Examples:
#   ./verify-gcp-roles.sh cleancloud@my-project.iam.gserviceaccount.com my-project
#   ./verify-gcp-roles.sh cleancloud@my-project.iam.gserviceaccount.com  # uses current gcloud project

set -e

SA_EMAIL="${1:-}"
PROJECT_ID="${2:-}"

REQUIRED_ROLES=(
  "roles/compute.viewer"
  "roles/cloudsql.viewer"
  "roles/monitoring.viewer"
  "roles/browser"
)

# Roles that would indicate write access — none of these should be present
FORBIDDEN_ROLES=(
  "roles/owner"
  "roles/editor"
  "roles/compute.admin"
  "roles/compute.instanceAdmin"
  "roles/compute.storageAdmin"
  "roles/cloudsql.admin"
  "roles/cloudsql.editor"
  "roles/monitoring.admin"
  "roles/monitoring.editor"
  "roles/iam.serviceAccountAdmin"
  "roles/resourcemanager.projectIamAdmin"
  "roles/resourcemanager.organizationAdmin"
)

if [ -z "$SA_EMAIL" ]; then
  echo "Usage: ./verify-gcp-roles.sh <service-account-email> [project-id]"
  echo ""
  echo "Example:"
  echo "  ./verify-gcp-roles.sh cleancloud@my-project.iam.gserviceaccount.com my-project"
  exit 1
fi

echo "Verifying GCP Service Account: $SA_EMAIL"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
  echo "ERROR: gcloud CLI not found. Please install: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

# Check if logged in
if ! gcloud auth print-access-token &> /dev/null 2>&1; then
  echo "ERROR: Not authenticated. Run 'gcloud auth login' first."
  exit 1
fi

# Resolve project
if [ -z "$PROJECT_ID" ]; then
  PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
  if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: No project specified and no default project set."
    echo "Pass project as second argument or run: gcloud config set project PROJECT_ID"
    exit 1
  fi
fi

echo "Checking project-level bindings: $PROJECT_ID"
echo ""

# Get all IAM bindings for the SA on this project
MEMBER="serviceAccount:$SA_EMAIL"
BINDINGS=$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --format="value(bindings.role)" \
  --filter="bindings.members=$MEMBER" 2>/dev/null || true)

if [ -z "$BINDINGS" ]; then
  echo "WARNING: No project-level IAM bindings found for $SA_EMAIL"
  echo "         The service account may have org-level bindings instead."
  echo "         To check org-level bindings, run:"
  echo "         gcloud organizations get-iam-policy ORG_ID --flatten='bindings[].members' \\"
  echo "           --format='value(bindings.role)' --filter='bindings.members=serviceAccount:$SA_EMAIL'"
  echo ""
else
  echo "Roles bound at project level:"
  echo "$BINDINGS" | sort | uniq | sed 's/^/  /'
  echo ""

  # Check for forbidden roles
  FOUND_FORBIDDEN=0
  for role in "${FORBIDDEN_ROLES[@]}"; do
    if echo "$BINDINGS" | grep -q "^${role}$"; then
      echo "FAIL: Forbidden role found: $role"
      FOUND_FORBIDDEN=1
    fi
  done

  if [ "$FOUND_FORBIDDEN" -eq 0 ]; then
    echo "PASS: No write/admin roles found"
    echo ""
  else
    echo ""
    exit 1
  fi
fi

# Verify required roles are present (either project or org level may have them)
echo "Required roles for CleanCloud:"
ALL_OK=1
for role in "${REQUIRED_ROLES[@]}"; do
  if echo "$BINDINGS" | grep -q "^${role}$"; then
    echo "  PRESENT  $role"
  else
    echo "  MISSING  $role  (may be bound at org level)"
    ALL_OK=0
  fi
done
echo ""

if [ "$ALL_OK" -eq 1 ]; then
  echo "PASS: All required roles are present at project level"
else
  echo "NOTE: Some roles not found at project level."
  echo "      If org-level bindings exist, scanning will still work."
  echo "      To verify org-level bindings, check with your GCP organization admin."
fi
echo ""

exit 0
