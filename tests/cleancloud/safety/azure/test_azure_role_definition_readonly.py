import json
from pathlib import Path

import pytest

FORBIDDEN_ACTIONS = ("*/delete", "*/write", "*/create", "*/update")

ROLE_PATH = Path("cleancloud/security/azure-readonly-role.json")


@pytest.mark.safety
@pytest.mark.azure
def test_azure_role_is_read_only():
    """
    Ensure the Azure role definition never grants mutating actions.
    Mirrors AWS IAM policy test.
    """
    role = json.loads(ROLE_PATH.read_text())

    for perm in role.get("permissions", []):
        for action in perm.get("actions", []):
            for forbidden in FORBIDDEN_ACTIONS:
                assert forbidden not in action.lower(), f"Forbidden Azure action detected: {action}"
