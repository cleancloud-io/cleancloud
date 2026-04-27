"""Unit tests for gcp.compute.snapshot.old rule."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
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
    storage_bytes_status="",
    source_disk="zones/us-central1-a/disks/my-disk",
    source_disk_id="",
    labels=None,
    storage_locations=None,
    chain_name="",
    snapshot_type="",
    auto_created=False,
    source_snapshot_schedule_policy="",
    source_snapshot_schedule_policy_id="",
):
    return SimpleNamespace(
        name=name,
        status=status,
        creation_timestamp=_ts(100) if creation_timestamp is None else creation_timestamp,
        disk_size_gb=disk_size_gb,
        storage_bytes=storage_bytes,
        storage_bytes_status=storage_bytes_status,
        source_disk=source_disk,
        source_disk_id=source_disk_id,
        labels=labels or {},
        storage_locations=storage_locations or [],
        chain_name=chain_name,
        snapshot_type=snapshot_type,
        auto_created=auto_created,
        source_snapshot_schedule_policy=source_snapshot_schedule_policy,
        source_snapshot_schedule_policy_id=source_snapshot_schedule_policy_id,
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


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


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
    assert f.details["age_days"] >= 100


def test_recent_snapshot_not_flagged(monkeypatch):
    """A snapshot created 30 days ago is below the 90-day threshold."""
    _mock_client([_make_snapshot("new-snap", creation_timestamp=_ts(30))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_non_ready_snapshot_not_flagged(monkeypatch):
    """Snapshots not in READY status are skipped (spec 8.2)."""
    _mock_client(
        [_make_snapshot("creating-snap", status="CREATING", creation_timestamp=_ts(200))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_failed_snapshot_not_flagged(monkeypatch):
    """FAILED snapshots are skipped (spec 8.2)."""
    _mock_client(
        [_make_snapshot("failed-snap", status="FAILED", creation_timestamp=_ts(200))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_absent_name_skipped(monkeypatch):
    """Malformed snapshot with empty name is skipped (spec 8.1)."""
    _mock_client([_make_snapshot("")], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_unparsable_timestamp_skipped(monkeypatch):
    """Snapshot with unparsable creation_timestamp is skipped (spec 8.3)."""
    _mock_client(
        [_make_snapshot("bad-ts-snap", creation_timestamp="not-a-timestamp")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_missing_timestamp_skipped(monkeypatch):
    """Snapshot with empty creation_timestamp is skipped (spec 8.3)."""
    _mock_client(
        [_make_snapshot("no-ts-snap", creation_timestamp="")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# spec 8.5: archive snapshot exclusion
# ---------------------------------------------------------------------------


def test_archive_snapshot_skipped(monkeypatch):
    """Archive snapshots are excluded regardless of age (spec 8.5)."""
    _mock_client(
        [_make_snapshot("archive-snap", snapshot_type="ARCHIVE", creation_timestamp=_ts(200))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_standard_snapshot_type_not_skipped(monkeypatch):
    """STANDARD snapshot type is not excluded (spec 8.5 only excludes ARCHIVE)."""
    _mock_client(
        [_make_snapshot("std-snap", snapshot_type="STANDARD", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# spec 8.6 / 8.7: schedule-created and auto-created exclusions
# ---------------------------------------------------------------------------


def test_auto_created_snapshot_skipped(monkeypatch):
    """auto_created == True snapshots are skipped (spec 8.7)."""
    _mock_client(
        [_make_snapshot("auto-snap", auto_created=True, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_schedule_policy_skipped(monkeypatch):
    """Non-empty sourceSnapshotSchedulePolicy skips the snapshot (spec 8.6)."""
    _mock_client(
        [
            _make_snapshot(
                "sched-snap",
                source_snapshot_schedule_policy="projects/p/regions/us/resourcePolicies/daily",
                creation_timestamp=_ts(100),
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_schedule_policy_id_skipped(monkeypatch):
    """Non-empty sourceSnapshotSchedulePolicyId skips the snapshot (spec 8.6)."""
    _mock_client(
        [
            _make_snapshot(
                "sched-id-snap",
                source_snapshot_schedule_policy_id="1234567890",
                creation_timestamp=_ts(100),
            )
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# spec 9.7 / 9.8: cost model and confidence contracts
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_is_none(monkeypatch):
    """estimated_monthly_cost_usd must always be None (spec 9.7)."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].estimated_monthly_cost_usd is None


def test_estimated_monthly_cost_is_none_with_storage_bytes(monkeypatch):
    """Even when storage_bytes is available, cost is still None (spec 9.7)."""
    storage_bytes = 50 * (1024**3)
    _mock_client(
        [_make_snapshot("big-snap", disk_size_gb=200, storage_bytes=storage_bytes)],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_confidence_is_low(monkeypatch):
    """Confidence must be LOW for all findings (spec 9.8)."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].confidence == ConfidenceLevel.LOW


def test_confidence_is_low_when_source_disk_absent(monkeypatch):
    """Confidence is still LOW even when source_disk is empty — no inference (spec 9.6 / 9.8)."""
    _mock_client(
        [_make_snapshot("orphan-snap", source_disk="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.LOW


def test_risk_is_low(monkeypatch):
    """Risk must be LOW for all findings (spec 9.9)."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# spec 9.6: source_disk must not infer "deleted" state
# ---------------------------------------------------------------------------


def test_no_source_disk_deleted_field_in_details(monkeypatch):
    """details must not contain 'source_disk_deleted' (spec 9.6)."""
    _mock_client(
        [_make_snapshot("orphan-snap", source_disk="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert "source_disk_deleted" not in findings[0].details


# ---------------------------------------------------------------------------
# spec 10.3: required details fields
# ---------------------------------------------------------------------------


def test_age_days_in_details(monkeypatch):
    """age_days should appear in details (spec 10.3)."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["age_days"] >= 100


def test_max_age_days_threshold_in_details(monkeypatch):
    """max_age_days_threshold should appear in details as the configured threshold (spec 10.3)."""
    _mock_client([_make_snapshot("old-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), max_age_days=90)
    assert findings[0].details["max_age_days_threshold"] == 90


def test_storage_bytes_status_in_details(monkeypatch):
    """storage_bytes_status should appear in details (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap", storage_bytes_status="UPDATING", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["storage_bytes_status"] == "UPDATING"


def test_storage_bytes_status_absent_stored_as_none(monkeypatch):
    """When storage_bytes_status is absent/empty, details stores None."""
    _mock_client(
        [_make_snapshot("snap", storage_bytes_status="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["storage_bytes_status"] is None


def test_snapshot_type_in_details(monkeypatch):
    """snapshot_type should appear in details (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap", snapshot_type="STANDARD", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["snapshot_type"] == "STANDARD"


def test_snapshot_type_absent_stored_as_none(monkeypatch):
    """When snapshot_type is absent/empty, details stores None."""
    _mock_client(
        [_make_snapshot("snap", snapshot_type="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["snapshot_type"] is None


def test_auto_created_in_details(monkeypatch):
    """auto_created field should appear in details for eligible snapshots (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap", auto_created=False, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert "auto_created" in findings[0].details


def test_source_disk_in_details_when_present(monkeypatch):
    """source_disk should appear in details when non-empty (spec 10.3)."""
    full_path = "zones/us-central1-a/disks/my-disk"
    _mock_client(
        [_make_snapshot("snap", source_disk=full_path, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["source_disk"] == full_path


def test_source_disk_absent_from_details_when_empty(monkeypatch):
    """source_disk should not appear in details when empty (spec 10.3 / 9.6)."""
    _mock_client(
        [_make_snapshot("snap", source_disk="", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert "source_disk" not in findings[0].details


def test_no_source_disk_url_field(monkeypatch):
    """details must not contain a 'source_disk_url' field — spec uses 'source_disk' only."""
    full_path = "projects/my-proj/zones/us-central1-a/disks/my-disk"
    _mock_client(
        [_make_snapshot("snap", source_disk=full_path, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert "source_disk_url" not in findings[0].details


# ---------------------------------------------------------------------------
# spec 10.2: signals_used must disclose storage context
# ---------------------------------------------------------------------------


def test_storage_bytes_in_signals_as_context_only(monkeypatch):
    """When storage_bytes > 0, signals_used should note it as context only (spec 10.2)."""
    storage_bytes = 20 * (1024**3)
    _mock_client(
        [_make_snapshot("snap", storage_bytes=storage_bytes, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert any("context only" in s for s in findings[0].evidence.signals_used)


def test_status_ready_in_signals(monkeypatch):
    """signals_used must disclose status: READY (spec 10.2)."""
    _mock_client([_make_snapshot("snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert any("READY" in s for s in findings[0].evidence.signals_used)


def test_age_and_threshold_in_signals(monkeypatch):
    """signals_used must disclose age and threshold (spec 10.2)."""
    _mock_client([_make_snapshot("snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), max_age_days=90)
    combined = " ".join(findings[0].evidence.signals_used)
    assert "90" in combined  # threshold
    assert "days" in combined


# ---------------------------------------------------------------------------
# Threshold / region_filter
# ---------------------------------------------------------------------------


def test_custom_days_old_threshold(monkeypatch):
    """max_age_days parameter controls the age threshold."""
    _mock_client(
        [_make_snapshot("mid-snap", creation_timestamp=_ts(50))],
        monkeypatch,
    )
    # With threshold=30, a 50-day-old snapshot should be flagged
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), max_age_days=30)
    assert len(findings) == 1

    # With threshold=90 (default), same snapshot should not be flagged
    findings2 = find_old_snapshots(project_id="proj-1", credentials=MagicMock(), max_age_days=90)
    assert findings2 == []


def test_region_filter_has_no_effect(monkeypatch):
    """Snapshots are global resources — region_filter is ignored (spec 9.1.3)."""
    _mock_client(
        [_make_snapshot("global-snap", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Multiple snapshots
# ---------------------------------------------------------------------------


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


def test_exclusion_rules_reduce_findings(monkeypatch):
    """Archive, auto-created, and schedule-created snapshots do not appear in findings."""
    _mock_client(
        [
            _make_snapshot("eligible-snap", creation_timestamp=_ts(100)),
            _make_snapshot("archive-snap", snapshot_type="ARCHIVE", creation_timestamp=_ts(100)),
            _make_snapshot("auto-snap", auto_created=True, creation_timestamp=_ts(100)),
            _make_snapshot(
                "sched-snap",
                source_snapshot_schedule_policy="projects/p/regions/r/resourcePolicies/pol",
                creation_timestamp=_ts(100),
            ),
        ],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].details["snapshot_name"] == "eligible-snap"


# ---------------------------------------------------------------------------
# Labels, storage_locations, source_disk_id, chain_name
# ---------------------------------------------------------------------------


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


def test_storage_locations_in_details(monkeypatch):
    """storage_locations should appear in details (spec 10.3)."""
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
    """source_disk_id should appear in details when non-empty (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap-with-id", source_disk_id="1234567890")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["source_disk_id"] == "1234567890"


def test_source_disk_id_absent_when_empty(monkeypatch):
    """source_disk_id should not appear in details when empty (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap-no-id", source_disk_id="")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert "source_disk_id" not in findings[0].details


def test_chain_name_in_details_when_present(monkeypatch):
    """chain_name should appear in details when set (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap-chained", chain_name="weekly-backup-chain")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["chain_name"] == "weekly-backup-chain"


def test_chain_name_absent_when_empty(monkeypatch):
    """chain_name should not appear in details when not set (spec 10.3)."""
    _mock_client(
        [_make_snapshot("snap-no-chain", chain_name="")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert "chain_name" not in findings[0].details


def test_chain_name_in_signals_when_present(monkeypatch):
    """chain_name should appear in signals_used (spec 10.2)."""
    _mock_client(
        [_make_snapshot("snap-chained", chain_name="weekly-backup-chain")],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())

    assert any("weekly-backup-chain" in s for s in findings[0].evidence.signals_used)


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------


def test_resource_id_format(monkeypatch):
    """resource_id should follow the canonical project/global/snapshots/{name} path."""
    _mock_client([_make_snapshot("my-snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="my-proj", credentials=MagicMock())
    assert findings[0].resource_id == "projects/my-proj/global/snapshots/my-snap"


def test_resource_type(monkeypatch):
    """resource_type should be 'gcp.compute.snapshot'."""
    _mock_client([_make_snapshot("snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].resource_type == "gcp.compute.snapshot"


def test_region_is_global(monkeypatch):
    """region should always be 'global' for snapshot findings (spec 10.1)."""
    _mock_client([_make_snapshot("snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].region == "global"


# ---------------------------------------------------------------------------
# Failure behavior (spec 9.10)
# ---------------------------------------------------------------------------


def test_permission_denied_raises_permission_error(monkeypatch):
    """PermissionDenied during list iteration raises PermissionError (spec 9.10)."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(PermissionDenied("compute.snapshots.list denied")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError, match="compute.snapshots.list"):
        find_old_snapshots(project_id="proj-1", credentials=MagicMock())


def test_forbidden_raises_permission_error(monkeypatch):
    """Forbidden (HTTP 403) raises PermissionError (spec 9.10)."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(Forbidden("403 Forbidden")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError):
        find_old_snapshots(project_id="proj-1", credentials=MagicMock())


def test_not_found_returns_empty(monkeypatch):
    """NotFound (Compute API not enabled) returns empty list (spec 9.10)."""
    mock = MagicMock()
    mock.list.return_value = iter(_RaiseOnIter(NotFound("Compute Engine API not enabled")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.snapshot_old.compute_v1.SnapshotsClient",
        lambda credentials: mock,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Polish: spec-wording, defensive normalization, input-shape hardening
# ---------------------------------------------------------------------------


def test_chain_signal_exact_phrasing(monkeypatch):
    """Chain signal must use exact spec phrasing (spec 10.2)."""
    _mock_client(
        [_make_snapshot("snap", chain_name="my-chain", creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert any(
        s.startswith("Snapshot is part of a named incremental chain:") and "my-chain" in s
        for s in findings[0].evidence.signals_used
    )


def test_chain_name_camelcase_fallback(monkeypatch):
    """chain_name should fall back to chainName attribute when snake_case is absent."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    del snap.chain_name  # remove snake_case attribute to force fallback
    snap.chainName = "camel-chain"
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["chain_name"] == "camel-chain"
    assert any("camel-chain" in s for s in findings[0].evidence.signals_used)


def test_missing_auto_created_attribute_does_not_skip(monkeypatch):
    """A snapshot object with no auto_created attribute must not be skipped or crash."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    del snap.auto_created  # simulate object without the attribute
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


def test_none_schedule_policy_does_not_skip(monkeypatch):
    """source_snapshot_schedule_policy == None must not trigger skip (not in (None,'') is False)."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    snap.source_snapshot_schedule_policy = None
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Fix 1: zero storage_bytes surfaced in signals (spec 9.7)
# ---------------------------------------------------------------------------


def test_zero_storage_bytes_surfaced_in_signals(monkeypatch):
    """storage_bytes == 0 must still appear as billed-storage context in signals (spec 9.7)."""
    _mock_client(
        [_make_snapshot("snap", storage_bytes=0, creation_timestamp=_ts(100))],
        monkeypatch,
    )
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert any(
        "Billed storage (storageBytes)" in s and "0.0 GB" in s
        for s in findings[0].evidence.signals_used
    )


def test_storage_bytes_context_signal_always_present(monkeypatch):
    """storageBytes context signal is always emitted, regardless of value (spec 9.7)."""
    _mock_client([_make_snapshot("snap", creation_timestamp=_ts(100))], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert any("Billed storage (storageBytes)" in s for s in findings[0].evidence.signals_used)


# ---------------------------------------------------------------------------
# Fix 2: non-negative normalization for numeric context fields (spec 7)
# ---------------------------------------------------------------------------


def test_negative_disk_size_gb_normalized_to_zero(monkeypatch):
    """Negative disk_size_gb values must normalize to 0, not be preserved (spec 7)."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    snap.disk_size_gb = -50
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["disk_size_gb"] == 0


def test_negative_storage_bytes_normalized_to_zero(monkeypatch):
    """Negative storage_bytes values must normalize to 0, not be preserved (spec 7)."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    snap.storage_bytes = -1024
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert findings[0].details["storage_bytes"] == 0


# ---------------------------------------------------------------------------
# Fix 3: malformed context fields fall back gracefully (spec 9.10)
# ---------------------------------------------------------------------------


def test_malformed_labels_falls_back_to_empty_dict(monkeypatch):
    """If snapshot.labels is not dict-convertible, labels falls back to {} (spec 9.10)."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    snap.labels = 42  # int — dict(42) raises TypeError
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].details["labels"] == {}


def test_malformed_storage_locations_falls_back_to_empty_list(monkeypatch):
    """If snapshot.storage_locations is not list-convertible, it falls back to [] (spec 9.10)."""
    snap = _make_snapshot("snap", creation_timestamp=_ts(100))
    snap.storage_locations = 42  # int — list(42) raises TypeError
    _mock_client([snap], monkeypatch)
    findings = find_old_snapshots(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].details["storage_locations"] == []


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
