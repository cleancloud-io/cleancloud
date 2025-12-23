from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.untagged_resources import find_untagged_resources


@pytest.fixture
def mock_compute_client(mocker):
    # Mock disks.list()
    disk_old = SimpleNamespace(
        id="disk-1",
        name="disk-old",
        location="eastus",
        managed_by=None,
        time_created=datetime.now(timezone.utc),
        sku=SimpleNamespace(name="Standard_LRS"),
        tags=None,
    )
    disk_attached = SimpleNamespace(
        id="disk-2",
        name="disk-attached",
        location="eastus",
        managed_by="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        time_created=datetime.now(timezone.utc),
        sku=None,
        tags={"env": "prod"},
    )

    disks_client = mocker.MagicMock()
    disks_client.list.return_value = [disk_old, disk_attached]

    client = mocker.MagicMock()
    client.disks = disks_client
    return client


def test_find_untagged_resources(mock_compute_client):
    findings = find_untagged_resources(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_compute_client,
    )
    resource_ids = [f.resource_id for f in findings]
    assert "disk-1" in resource_ids
    assert "disk-2" not in resource_ids
