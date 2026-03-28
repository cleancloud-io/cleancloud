"""Unit tests for gcp.compute.vm.stopped rule."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms


def _ts(days_ago: int) -> str:
    """Return a GCP-format RFC3339 timestamp for N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_disk(size_gb=100, disk_type="PERSISTENT", boot=False):
    return SimpleNamespace(disk_size_gb=size_gb, type_=disk_type, boot=boot)


def _make_instance(
    name,
    status,
    last_stop_timestamp=None,
    disks=None,
    machine_type="n1-standard-2",
    labels=None,
    automatic_restart=True,
    last_start_timestamp="",
):
    return SimpleNamespace(
        name=name,
        status=status,
        last_stop_timestamp=last_stop_timestamp or "",
        last_start_timestamp=last_start_timestamp,
        disks=disks or [],
        machine_type=f"zones/us-central1-a/machineTypes/{machine_type}",
        labels=labels or {},
        scheduling=SimpleNamespace(automatic_restart=automatic_restart),
    )


def _make_scoped_instance_list(instances):
    return SimpleNamespace(instances=instances)


def _mock_client(zone_instance_map, monkeypatch):
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        (zone, _make_scoped_instance_list(instances))
        for zone, instances in zone_instance_map.items()
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.vm_stopped.compute_v1.InstancesClient",
        lambda credentials: mock,
    )
    return mock


def test_terminated_vm_old_enough_is_flagged(monkeypatch):
    """TERMINATED VM stopped 35 days ago should produce a finding."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "old-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(35),
                    disks=[_make_disk(size_gb=100)],
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.compute.vm.stopped"
    assert f.provider == "gcp"
    assert "old-vm" in f.resource_id
    assert f.details["days_stopped"] >= 35


def test_running_vm_not_flagged(monkeypatch):
    """RUNNING instance should not be flagged regardless of age."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("live-vm", status="RUNNING", last_stop_timestamp=_ts(60))
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_recently_stopped_not_flagged(monkeypatch):
    """TERMINATED VM stopped 5 days ago is below the 30-day threshold."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("new-stop", status="TERMINATED", last_stop_timestamp=_ts(5))
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_no_stop_timestamp_flagged_as_medium_confidence(monkeypatch):
    """TERMINATED with no lastStopTimestamp should flag at MEDIUM confidence."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("mystery-vm", status="TERMINATED", last_stop_timestamp="")
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.MEDIUM


def test_cost_calculated_from_attached_disks(monkeypatch):
    """Monthly cost = total PERSISTENT disk GB * $0.04/GB."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "disk-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    disks=[
                        _make_disk(size_gb=200, disk_type="PERSISTENT"),
                        _make_disk(size_gb=100, disk_type="PERSISTENT"),
                        _make_disk(size_gb=50, disk_type="SCRATCH"),  # SCRATCH: excluded
                    ],
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == round(300 * 0.04, 2)
    assert findings[0].details["total_disk_gb"] == 300


def test_scratch_disks_excluded_from_cost(monkeypatch):
    """Only PERSISTENT disks contribute to cost estimate."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "scratch-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    disks=[_make_disk(size_gb=375, disk_type="SCRATCH")],
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    # No PERSISTENT disk → cost is $0 → estimated_monthly_cost_usd is None
    assert findings[0].estimated_monthly_cost_usd is None


def test_region_filter(monkeypatch):
    """Only zones matching the region prefix should be scanned."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("central-vm", status="TERMINATED", last_stop_timestamp=_ts(40))
            ],
            "zones/eu-west1-b": [
                _make_instance("eu-vm", status="TERMINATED", last_stop_timestamp=_ts(40))
            ],
        },
        monkeypatch,
    )
    findings = find_stopped_vms(
        project_id="proj-1", credentials=MagicMock(), region_filter="eu-west1"
    )

    assert len(findings) == 1
    assert "eu-vm" in findings[0].resource_id


def test_custom_days_stopped_threshold(monkeypatch):
    """days_stopped parameter controls the threshold."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("short-stop", status="TERMINATED", last_stop_timestamp=_ts(10))
            ]
        },
        monkeypatch,
    )
    # With threshold=7, a VM stopped 10 days ago should be flagged
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock(), days_stopped=7)
    assert len(findings) == 1

    # With threshold=30 (default), same VM should not be flagged
    findings2 = find_stopped_vms(project_id="proj-1", credentials=MagicMock(), days_stopped=30)
    assert len(findings2) == 0


def test_short_stopped_vm_medium_confidence(monkeypatch):
    """TERMINATED VM stopped 35 days ago (< 90 days) should have MEDIUM confidence."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("short-stop", status="TERMINATED", last_stop_timestamp=_ts(35))
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].confidence == ConfidenceLevel.MEDIUM


def test_long_stopped_vm_high_confidence(monkeypatch):
    """TERMINATED VM stopped 95 days ago (>= 90 days) should have HIGH confidence."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("long-stop", status="TERMINATED", last_stop_timestamp=_ts(95))
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].confidence == ConfidenceLevel.HIGH


def test_boot_disk_count_in_details_and_signal(monkeypatch):
    """Boot disk presence should appear in details and signals."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "abandoned-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    disks=[_make_disk(size_gb=50, boot=True), _make_disk(size_gb=100)],
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["boot_disk_count"] == 1
    assert any("Boot disk" in s for s in findings[0].evidence.signals_used)


def test_no_boot_disk_no_boot_signal(monkeypatch):
    """VMs with no boot disk should not emit a boot disk signal."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "data-only-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    disks=[_make_disk(size_gb=100, boot=False)],
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["boot_disk_count"] == 0
    assert not any("Boot disk" in s for s in findings[0].evidence.signals_used)


def test_unknown_stop_time_summary_does_not_claim_duration(monkeypatch):
    """When stop time is unknown, summary should not imply a specific duration."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance("mystery-vm", status="TERMINATED", last_stop_timestamp="")
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    # Summary should describe state, not claim a specific stopped duration
    assert "duration unknown" in findings[0].summary


def test_automatic_restart_false_in_details(monkeypatch):
    """automatic_restart=False should be recorded in details."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "no-restart-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    automatic_restart=False,
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["automatic_restart"] is False


def test_last_start_timestamp_in_details_when_present(monkeypatch):
    """last_start_timestamp should appear in details when available."""
    ts = "2024-01-01T10:00:00Z"
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "old-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    last_start_timestamp=ts,
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["last_start_timestamp"] == ts


def test_last_start_timestamp_absent_when_empty(monkeypatch):
    """last_start_timestamp should not appear in details when empty."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_instance(
                    "old-vm",
                    status="TERMINATED",
                    last_stop_timestamp=_ts(40),
                    last_start_timestamp="",
                )
            ]
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert "last_start_timestamp" not in findings[0].details


def test_permission_denied_raises_permission_error(monkeypatch):
    """PermissionDenied during aggregated_list should become PermissionError."""
    mock = MagicMock()
    mock.aggregated_list.side_effect = PermissionDenied("compute.instances.list denied")
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.vm_stopped.compute_v1.InstancesClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError, match="compute.instances.list"):
        find_stopped_vms(project_id="proj-1", credentials=MagicMock())


def test_not_found_returns_empty(monkeypatch):
    """NotFound (Compute API not enabled) should return empty list."""
    mock = MagicMock()
    mock.aggregated_list.side_effect = NotFound("Compute API not enabled")
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.vm_stopped.compute_v1.InstancesClient",
        lambda credentials: mock,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []
