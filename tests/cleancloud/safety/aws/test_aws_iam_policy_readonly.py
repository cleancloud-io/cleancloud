import json
from pathlib import Path

import pytest

from cleancloud.safety.aws.allowlist import FORBIDDEN_AWS_API_PREFIXES

POLICY_FILES = [
    Path("security/aws/base-readonly.json"),
    Path("security/aws/hygiene-readonly.json"),
    Path("security/aws/ai-readonly.json"),
]


@pytest.mark.safety
@pytest.mark.aws
@pytest.mark.parametrize("policy_path", POLICY_FILES, ids=lambda p: p.name)
def test_aws_iam_policy_is_strictly_read_only(policy_path):
    """
    Ensure all published AWS IAM policies never grant mutating permissions.
    """
    policy = json.loads(policy_path.read_text())

    for statement in policy.get("Statement", []):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            for forbidden in FORBIDDEN_AWS_API_PREFIXES:
                assert (
                    forbidden not in action
                ), f"Forbidden IAM action in {policy_path.name}: {action}"
