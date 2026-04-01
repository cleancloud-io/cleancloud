import json
from pathlib import Path

import pytest

FORBIDDEN_ACTIONS = ("*/delete", "*/write", "*/create", "*/update")

ROLE_FILES = [
    Path("security/azure/hygiene-readonly-role.json"),
    Path("security/azure/ai-readonly-role.json"),
]


def _check_role_file(role_path: Path) -> None:
    role = json.loads(role_path.read_text())

    for perm in role.get("Permissions", []):
        for action in perm.get("Actions", []):
            for forbidden in FORBIDDEN_ACTIONS:
                assert (
                    forbidden not in action.lower()
                ), f"Forbidden Azure action detected in {role_path.name}: {action}"


@pytest.mark.safety
@pytest.mark.azure
@pytest.mark.parametrize("role_path", ROLE_FILES, ids=lambda p: p.name)
def test_azure_role_is_read_only(role_path):
    """
    Ensure Azure role definitions never grant mutating actions.
    Covers both hygiene and AI/ML role files.
    """
    _check_role_file(role_path)
