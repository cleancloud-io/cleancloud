import os

import pytest


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path):
    """Run all CLI tests in a temp directory so they never auto-detect the
    project-level cleancloud.yaml. Tests that need a config pass it explicitly."""
    original = os.getcwd()
    os.chdir(tmp_path)
    yield
    os.chdir(original)
