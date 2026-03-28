import json
from pathlib import Path

import pytest

ROLES_PATH = Path("security/gcp-readonly-roles.json")

# GCP predefined roles that would grant write/admin access
FORBIDDEN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/compute.admin",
    "roles/compute.instanceAdmin",
    "roles/compute.instanceAdmin.v1",
    "roles/compute.storageAdmin",
    "roles/compute.networkAdmin",
    "roles/cloudsql.admin",
    "roles/cloudsql.editor",
    "roles/monitoring.admin",
    "roles/monitoring.editor",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
}

REQUIRED_ROLES = {
    "roles/compute.viewer",
    "roles/cloudsql.viewer",
    "roles/monitoring.viewer",
    "roles/browser",
}


@pytest.mark.safety
@pytest.mark.gcp
def test_gcp_roles_file_exists():
    """Ensure the published GCP roles file exists and is valid JSON."""
    assert ROLES_PATH.exists(), f"GCP roles file not found: {ROLES_PATH}"
    data = json.loads(ROLES_PATH.read_text())
    assert "roles" in data, "gcp-readonly-roles.json must have a 'roles' key"


@pytest.mark.safety
@pytest.mark.gcp
def test_gcp_roles_are_strictly_read_only():
    """Ensure the published GCP roles file never lists mutating/admin roles."""
    data = json.loads(ROLES_PATH.read_text())

    for entry in data.get("roles", []):
        role = entry.get("role", "")
        assert role not in FORBIDDEN_ROLES, (
            f"Forbidden GCP role detected in security/gcp-readonly-roles.json: {role}"
        )
        # Also reject any role that doesn't end in .viewer, .reader, or .browser
        # (belt-and-suspenders: catches new write roles not yet in FORBIDDEN_ROLES)
        assert role.endswith((".viewer", ".reader", "/browser")), (
            f"Unexpected non-read-only role in security/gcp-readonly-roles.json: {role} "
            f"(expected roles ending in .viewer, .reader, or /browser)"
        )


@pytest.mark.safety
@pytest.mark.gcp
def test_gcp_all_required_roles_present():
    """Ensure all roles needed to run CleanCloud are documented."""
    data = json.loads(ROLES_PATH.read_text())
    documented = {entry["role"] for entry in data.get("roles", [])}

    for role in REQUIRED_ROLES:
        assert role in documented, (
            f"Required GCP role missing from security/gcp-readonly-roles.json: {role}"
        )
