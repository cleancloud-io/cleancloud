# tests/cleancloud/providers/azure/test_azure_unattached_managed_disks.py
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cleancloud.providers.azure.rules.unattached_managed_disks import find_unattached_managed_disks


@pytest.fixture
def mock_compute_client(monkeypatch):
    class Disk:
        def __init__(self, disk_id, name, managed_by, created_days_ago, location):
            self.id = disk_id
            self.name = name
            self.managed_by = managed_by
            self.time_created = datetime.now(timezone.utc) - timedelta(days=created_days_ago)
            self.location = location
            self.sku = MagicMock(name="Standard_LRS")
            self.tags = None
            self.disk_size_gb = 128

    mock_client = MagicMock()
    mock_client.disks.list.return_value = [
        Disk("disk-1", "disk-1", None, 20, "eastus"),  # should be flagged
        Disk("disk-2", "disk-2", "vm-1", 20, "eastus"),  # should NOT be flagged
        Disk("disk-3", "disk-3", None, 2, "eastus"),  # too new, NOT flagged
    ]
    monkeypatch.setattr(
        "cleancloud.providers.azure.rules.unattached_managed_disks.ComputeManagementClient",
        lambda credential, subscription_id: mock_client,
    )
    return mock_client


def test_find_unattached_managed_disks(mock_compute_client):
    findings = find_unattached_managed_disks(subscription_id="sub-1", credential=MagicMock())
    resource_ids = [f.resource_id for f in findings]

    assert "disk-1" in resource_ids
    assert "disk-2" not in resource_ids
    assert "disk-3" not in resource_ids
