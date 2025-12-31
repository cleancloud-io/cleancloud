import json
from pathlib import Path

import pytest

from cleancloud.safety.aws.allowlist import FORBIDDEN_AWS_API_PREFIXES

POLICY_PATH = Path("cleancloud/security/aws-readonly-policy.json")


@pytest.mark.safety
@pytest.mark.aws
def test_aws_iam_policy_is_strictly_read_only():
    """
    Ensure the published AWS IAM policy never grants mutating permissions.
    """
    policy = json.loads(POLICY_PATH.read_text())

    for statement in policy.get("Statement", []):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            for forbidden in FORBIDDEN_AWS_API_PREFIXES:
                assert forbidden not in action, f"Forbidden IAM action detected: {action}"
