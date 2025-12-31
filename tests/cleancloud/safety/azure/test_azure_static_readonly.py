import ast
from pathlib import Path

import pytest

from cleancloud.safety.azure.allowlist import FORBIDDEN_AZURE_METHOD_PREFIXES

AZURE_PROVIDER_ROOT = Path("cleancloud/providers/azure")


@pytest.mark.safety
@pytest.mark.azure
def test_no_forbidden_azure_sdk_calls():
    """
    Ensure Azure provider code never references mutating SDK calls.
    """
    for py_file in AZURE_PROVIDER_ROOT.rglob("*.py"):
        tree = ast.parse(py_file.read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                for forbidden in FORBIDDEN_AZURE_METHOD_PREFIXES:
                    if node.attr.lower().startswith(forbidden):
                        raise AssertionError(
                            f"Forbidden Azure SDK call '{node.attr}' found in {py_file}"
                        )
