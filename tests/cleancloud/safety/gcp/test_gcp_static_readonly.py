import ast
from pathlib import Path

import pytest

from cleancloud.safety.gcp.allowlist import FORBIDDEN_GCP_METHOD_PREFIXES

GCP_PROVIDER_ROOT = Path("cleancloud/providers/gcp")

# Python built-ins that happen to share names with GCP SDK forbidden prefixes.
# These are string/list/dict/shutil methods that are safe to call in provider code.
_PYTHON_BUILTIN_EXCEPTIONS = frozenset(
    {"insert", "remove", "update", "add", "reset", "copy", "move"}
)


def _is_forbidden(attr: str) -> bool:
    """
    Return True if `attr` looks like a GCP SDK mutating method.

    Rules:
    - Exact match: e.g. "delete", "start", "stop"
    - Prefix + underscore: e.g. "set_labels", "add_access_config"
    - Excludes: Python built-in methods that collide (list.insert, dict.update, etc.)
    """
    for forbidden in FORBIDDEN_GCP_METHOD_PREFIXES:
        if attr == forbidden:
            if attr in _PYTHON_BUILTIN_EXCEPTIONS:
                continue  # likely a Python built-in, not a GCP SDK call
            return True
        if attr.startswith(f"{forbidden}_"):
            return True
    return False


@pytest.mark.safety
@pytest.mark.gcp
def test_no_forbidden_gcp_method_calls_in_provider():
    """
    Ensure GCP provider code never references mutating SDK method calls.
    This is a non-negotiable safety invariant — CleanCloud is read-only.
    """
    for py_file in GCP_PROVIDER_ROOT.rglob("*.py"):
        tree = ast.parse(py_file.read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if _is_forbidden(node.attr):
                    raise AssertionError(
                        f"Forbidden GCP SDK method '{node.attr}' found in {py_file}"
                    )
