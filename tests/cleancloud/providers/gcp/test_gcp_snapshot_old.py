"""Unit tests for gcp.compute.snapshot.old rule."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.snapshot_old import find_old_snapshots


def _ts(days_ago: int) -> str:
    """Return a GCP-format RFC3339 creation timestamp for N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_snapshot(
    name,
    status="READY",
    creation_timestamp=None,
    disk_size_gb=100,
    storage_bytes=0,
    source_disk="zones/us-central1-a/disks/my-disk",
    labels=None,
    storage_locations=None,
    source_disk_id="",
    chain_name="",
):
    return SimpleNamespace(
        name=name,
        status=status,
        creation_timestamp=creation_timestamp or _ts(100),
        disk_size_gb=disk_size_gb,
        storage_bytes=storage_bytes,
        source_disk=source_disk,
        labels=labels or {},
        storage_locations=storage_locations or [],
        source_disk_id=source_disk_id,
        chain_name=chain_name,
    )


def _mock_client(snapshots, monkeypatch):
    """Patch compute_v1.SnapshotsClient to return the given snapshot list."""
    mock = MagicMock()
    mock.list.return_value = snapshots
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    return mock


def test_old_snapshot_is_flagged(monkeypatch):
    """A READY snapshot older than 90 days should produce a finding."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.compute.snapshot.old"
    assert f.provider == "gcp"
    assert "old-snap" in f.resource_id
    assert f.region == "global"
    assert f.details["days_old"] >= 100


def test_recent_snapshot_not_flagged(monkeypatch):
    """A snapshot created 30 days ago is below the 90-day threshold."""
    _mock_client([_make_snapshot("new-snap", creation_timestamp=_ts(30))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_non_ready_snapshot_not_flagged(monkeypatch):
    """Snapshots not in READY status are skipped."""
    _mock_client(
        [_make_snapshot("creating-snap", status="CREATING", creation_timestamp=_ts(200))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_source_disk_deleted_high_confidence(monkeypatch):
    """When source_disk is empty, confidence should be HIGH (orphaned snapshot)."""
    _mock_client(
        [_make_snapshot("orphan-snap", source_disk="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.HIGH
    assert findings[0].details["source_disk_deleted"] is True


def test_source_disk_present_medium_confidence(monkeypatch):
    """When source disk still exists, confidence should be MEDIUM."""
    _mock_client(
        [
            _make_snapshot(
                "active-source-snap",
                source_disk="zones/us-central1-a/disks/live-disk",
                creation_timestamp=_ts(100),
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.MEDIUM
    assert findings[0].details["source_disk_deleted"] is False


def test_cost_from_storage_bytes(monkeypatch):
    """When storage_bytes is available, it's used instead of disk_size_gb."""
    # 50 GB of actual storage bytes
    storage_bytes = 50 * (1024**3)
    _mock_client(
        [
            _make_snapshot(
                "compressed-snap",
                disk_size_gb=200,
                storage_bytes=storage_bytes,
                creation_timestamp=_ts(100),
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    expected_cost = round(50 * 0.026, 2)
    assert findings[0].estimated_monthly_cost_usd == expected_cost


def test_cost_fallback_to_disk_size_gb(monkeypatch):
    """When storage_bytes is 0, disk_size_gb is used for cost estimate."""
    _mock_client(
        [
            _make_snapshot(
                "fallback-snap", disk_size_gb=100, storage_bytes=0, creation_timestamp=_ts(100)
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    expected_cost = round(100 * 0.026, 2)
    assert findings[0].estimated_monthly_cost_usd == expected_cost


def test_zero_size_snapshot_no_cost(monkeypatch):
    """A snapshot with zero disk_size_gb and zero storage_bytes has None cost."""
    _mock_client(
        [
            _make_snapshot(
                "empty-snap", disk_size_gb=0, storage_bytes=0, creation_timestamp=_ts(100)
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_custom_days_old_threshold(monkeypatch):
    """days_old parameter controls the age threshold."""
    _mock_client(
        [_make_snapshot("mid-snap", creation_timestamp=_ts(50))],
        monkeypatch,
    )
    # With threshold=30, a 50-day-old snapshot should be flagged
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), days_old=30)
    assert len(findings) == 1

    # With threshold=90 (default), same snapshot should not be flagged
    findings2 = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), days_old=90)
    assert findings2 == []


def test_region_filter_has_no_effect(monkeypatch):
    """Snapshots are global resources — region_filter is ignored."""
    _mock_client(
        [_make_snapshot("global-snap", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    # Even with a region_filter, the snapshot is still returned (region_filter doesn't apply)
    findings = find_old_snapshots(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )
    assert len(findings) == 1


def test_labels_in_details(monkeypatch):
    """Labels on the snapshot appear in finding details."""
    _mock_client(
        [
            _make_snapshot(
                "labeled-snap",
                creation_timestamp=_ts(100),
                labels={"backup-policy": "manual", "team": "data"},
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["labels"] == {"backup-policy": "manual", "team": "data"}


def test_permission_denied_raises_permission_error(monkeypatch):
    """PermissionDenied during list iteration raises PermissionError."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(PermissionDenied("compute.snapshots.list denied")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError, match="compute.snapshots.list"):
        find_old_snapshots(project_id="proj-1", credentials=MagicMock())


def test_forbidden_raises_permission_error(monkeypatch):
    """Forbidden (HTTP 403) raises PermissionError."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(Forbidden("403 Forbidden")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError):
        find_old_snapshots(project_id="proj-1", credentials=MagicMock())


def test_not_found_returns_empty(monkeypatch):
    """NotFound (Compute API not enabled) returns empty list."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(NotFound("Compute Engine API not enabled")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_multiple_snapshots_mixed_age(monkeypatch):
    """Only snapshots exceeding the threshold are flagged."""
    _mock_client(
        [
            _make_snapshot("old-1", creation_timestamp=_ts(120)),
            _make_snapshot("recent-1", creation_timestamp=_ts(10)),
            _make_snapshot("old-2", source_disk="", creation_timestamp=_ts(200)),
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 2
    names = {f.details["snapshot_name"] for f in findings}
    assert names == {"old-1", "old-2"}


# ---------------------------------------------------------------------------
# storage_locations, source_disk_id, chain_name
# ---------------------------------------------------------------------------


def test_storage_locations_in_details(monkeypatch):
    """storage_locations should appear in details to show regional vs multi-regional."""
    _mock_client(
        [_make_snapshot("snap-regional", storage_locations=["us-central1"])],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["storage_locations"] == ["us-central1"]


def test_empty_storage_locations_stored_as_empty_list(monkeypatch):
    """When storage_locations is absent, details should contain an empty list."""
    _mock_client(
        [_make_snapshot("snap-no-loc", storage_locations=[])],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["storage_locations"] == []


def test_source_disk_id_in_details_when_present(monkeypatch):
    """source_disk_id should appear in details when non-empty."""
    _mock_client(
        [_make_snapshot("snap-with-id", source_disk_id="1234567890")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["source_disk_id"] == "1234567890"


def test_source_disk_id_absent_when_empty(monkeypatch):
    """source_disk_id should not appear in details when empty."""
    _mock_client(
        [_make_snapshot("snap-no-id", source_disk_id="")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert "source_disk_id" not in findings[0].details


def test_chain_name_in_details_when_present(monkeypatch):
    """chain_name should appear in details when set."""
    _mock_client(
        [_make_snapshot("snap-chained", chain_name="weekly-backup-chain")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["chain_name"] == "weekly-backup-chain"


def test_chain_name_absent_when_empty(monkeypatch):
    """chain_name should not appear in details when not set."""
    _mock_client(
        [_make_snapshot("snap-no-chain", chain_name="")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert "chain_name" not in findings[0].details


def test_source_disk_url_in_details_when_disk_present(monkeypatch):
    """Full source_disk URL should be stored in details alongside the short name."""
    full_url = "projects/my-proj/zones/us-central1-a/disks/my-disk"
    _mock_client(
        [_make_snapshot("snap-url", source_disk=full_url)],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["source_disk_url"] == full_url
    assert findings[0].details["source_disk"] == "my-disk"  # short name still present


# ---------------------------------------------------------------------------
# Helper: iterator that raises on first __next__ call
# ---------------------------------------------------------------------------


class _RaiseOnIter:
    """Iterable that raises the given exception on the first iteration."""

    def __init__(self, exc):
        self._exc = exc

    def __iter__(self):
        raise self._exc
        yield  # make it a generator
