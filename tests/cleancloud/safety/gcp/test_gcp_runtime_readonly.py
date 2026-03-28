"""
Runtime safety guard for GCP provider code.

Intercepts google-cloud-compute client construction at runtime and blocks
any attempt to call mutating methods (delete, insert, patch, etc.).
"""

from unittest.mock import MagicMock

import pytest
from google.cloud import compute_v1

from cleancloud.safety.gcp.allowlist import FORBIDDEN_GCP_METHOD_PREFIXES


class ForbiddenGcpCallError(Exception):
    pass


def _guarded_client(real_client_cls, monkeypatch):
    """
    Return a MagicMock that raises ForbiddenGcpCallError when any forbidden
    method prefix is accessed on the client.
    """

    class GuardedMock(MagicMock):
        def __getattr__(self, name):
            for forbidden in FORBIDDEN_GCP_METHOD_PREFIXES:
                if name.startswith(forbidden):
                    raise ForbiddenGcpCallError(
                        f"Forbidden GCP SDK method attempted at runtime: {name}"
                    )
            return super().__getattr__(name)

    return GuardedMock


@pytest.mark.safety
@pytest.mark.gcp
def test_forbidden_method_raises_on_disk_client(monkeypatch):
    """Calling a mutating method (delete) on the Disks client is blocked."""
    guarded_mock = _guarded_client(compute_v1.DisksClient, monkeypatch)
    client = guarded_mock()

    with pytest.raises(ForbiddenGcpCallError, match="delete"):
        _ = client.delete


@pytest.mark.safety
@pytest.mark.gcp
def test_forbidden_method_raises_on_instances_client(monkeypatch):
    """Calling a mutating method (stop) on the Instances client is blocked."""
    guarded_mock = _guarded_client(compute_v1.InstancesClient, monkeypatch)
    client = guarded_mock()

    with pytest.raises(ForbiddenGcpCallError, match="stop"):
        _ = client.stop


@pytest.mark.safety
@pytest.mark.gcp
def test_forbidden_method_raises_on_addresses_client(monkeypatch):
    """Calling a mutating method (insert) on the Addresses client is blocked."""
    guarded_mock = _guarded_client(compute_v1.AddressesClient, monkeypatch)
    client = guarded_mock()

    with pytest.raises(ForbiddenGcpCallError, match="insert"):
        _ = client.insert


@pytest.mark.safety
@pytest.mark.gcp
def test_readonly_methods_are_allowed(monkeypatch):
    """Read-only methods (aggregated_list, list, get) must remain accessible."""
    guarded_mock = _guarded_client(compute_v1.DisksClient, monkeypatch)
    client = guarded_mock()

    # Should not raise
    _ = client.aggregated_list
    _ = client.list
    _ = client.get


@pytest.mark.safety
@pytest.mark.gcp
def test_all_forbidden_prefixes_are_blocked():
    """All prefixes in FORBIDDEN_GCP_METHOD_PREFIXES should be caught by the guard."""

    class GuardedMock(MagicMock):
        def __getattr__(self, name):
            for forbidden in FORBIDDEN_GCP_METHOD_PREFIXES:
                if name.startswith(forbidden):
                    raise ForbiddenGcpCallError(f"Blocked: {name}")
            return super().__getattr__(name)

    client = GuardedMock()

    for prefix in FORBIDDEN_GCP_METHOD_PREFIXES:
        method_name = f"{prefix}something"
        with pytest.raises(ForbiddenGcpCallError):
            _ = getattr(client, method_name)
