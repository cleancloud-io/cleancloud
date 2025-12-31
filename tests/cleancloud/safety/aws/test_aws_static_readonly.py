import ast
from pathlib import Path

import pytest

from cleancloud.safety.aws.allowlist import FORBIDDEN_AWS_API_PREFIXES

AWS_PROVIDER_ROOT = Path("cleancloud/providers/aws")


@pytest.mark.safety
@pytest.mark.aws
def test_no_forbidden_aws_api_calls_in_provider():
    """
    Ensure AWS provider code never references mutating SDK calls.
    This is a non-negotiable safety invariant.
    """
    for py_file in AWS_PROVIDER_ROOT.rglob("*.py"):
        tree = ast.parse(py_file.read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                for forbidden in FORBIDDEN_AWS_API_PREFIXES:
                    if node.attr.startswith(forbidden):
                        raise AssertionError(
                            f"Forbidden AWS API call '{node.attr}' " f"found in {py_file}"
                        )
