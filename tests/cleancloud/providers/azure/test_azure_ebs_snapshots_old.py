from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots


def test_find_old_snapshots(monkeypatch):
    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    recent_date = datetime.now(timezone.utc) - timedelta(days=20)

    mock_sku = SimpleNamespace(name="Standard_LRS")

    mock_snapshots = [
        SimpleNamespace(
            id="snap-1",
            name="snap-1",
            location="eastus",
            tags=None,
            time_created=old_date,
            disk_size_gb=10,
            sku=mock_sku,
        ),
        SimpleNamespace(
            id="snap-2",
            name="snap-2",
            location="eastus",
            tags=None,
            time_created=recent_date,
            disk_size_gb=10,
            sku=mock_sku,
        ),
    ]

    class MockSnapshots:
        def list(self):
            return mock_snapshots

    class MockComputeClient:
        def __init__(self, credential, subscription_id):
            self.snapshots = MockSnapshots()

    monkeypatch.setattr(
        "cleancloud.providers.azure.rules.ebs_snapshots_old.ComputeManagementClient",
        MockComputeClient,
    )

    findings = find_old_snapshots(
        subscription_id="sub-1",
        credential=None,
        region_filter="eastus",
    )

    snapshot_ids = [f.resource_id for f in findings]

    assert "snap-1" in snapshot_ids
    assert "snap-2" not in snapshot_ids

    # Verify cost estimate (10 GB * $0.05/GB)
    finding = [f for f in findings if f.resource_id == "snap-1"][0]
    assert finding.estimated_monthly_cost_usd == 0.5
