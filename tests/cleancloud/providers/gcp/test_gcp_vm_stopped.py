"""Unit tests for gcp.compute.vm.stopped rule."""

import warnings
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _ts(days_ago: int) -> str:
    """Return a GCP-format RFC3339 timestamp for N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_disk(size_gb=100, type_="PERSISTENT", boot=False):
    return SimpleNamespace(disk_size_gb=size_gb, type_=type_, boot=boot)


def _make_metadata_item(key: str, value: str):
    return SimpleNamespace(key=key, value=value)


def _make_instance(
    name="test-vm",
    status="TERMINATED",
    last_stop_timestamp=None,
    last_start_timestamp="",
    disks=None,
    machine_type="n1-standard-2",
    labels=None,
    automatic_restart=True,
    network_interfaces=None,
    guest_accelerators=None,
    metadata_items=None,
):
    """Build a minimal Compute Engine instance object."""
    metadata = None
    if metadata_items is not None:
        metadata = SimpleNamespace(items=metadata_items)

    return SimpleNamespace(
        name=name,
        status=status,
        # Default to 35 days ago — old enough for the 30-day threshold
        last_stop_timestamp=_ts(35) if last_stop_timestamp is None else last_stop_timestamp,
        last_start_timestamp=last_start_timestamp,
        disks=disks or [],
        machine_type=f"zones/us-central1-a/machineTypes/{machine_type}",
        labels=labels or {},
        scheduling=SimpleNamespace(automatic_restart=automatic_restart),
        network_interfaces=network_interfaces or [],
        guest_accelerators=guest_accelerators or [],
        metadata=metadata,
    )


def _make_scoped_list(instances, warning_code=None):
    """Build a zone-scoped instance list, optionally with a partial-coverage warning."""
    ns = SimpleNamespace(instances=instances)
    if warning_code:
        ns.warning = SimpleNamespace(code=warning_code, message="partial coverage")
    else:
        ns.warning = None
    return ns


def _mock_client(zone_instance_map, monkeypatch):
    """Patch InstancesClient.aggregated_list to return the supplied zone/instance map."""
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        (zone, scoped_list) for zone, scoped_list in zone_instance_map.items()
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.vm_stopped.compute_v1.InstancesClient",
        lambda credentials: mock,
    )
    return mock


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_stopped_vm_old_enough_is_flagged(monkeypatch):
    """TERMINATED VM stopped 35 days ago should produce a finding."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("old-vm")])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.compute.vm.stopped"
    assert f.provider == "gcp"
    assert "old-vm" in f.resource_id
    assert f.region == "us-central1"


def test_stopped_status_also_accepted(monkeypatch):
    """status='STOPPED' is also a STOPPED_VM state and must be flagged."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("stopped-vm", status="STOPPED")]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].details["raw_status"] == "STOPPED"


def test_running_vm_not_flagged(monkeypatch):
    """RUNNING instance should not be flagged regardless of age."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("live-vm", status="RUNNING")])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_recently_stopped_not_flagged(monkeypatch):
    """TERMINATED VM stopped 5 days ago is below the 30-day threshold."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("new-stop", last_stop_timestamp=_ts(5))]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_staging_vm_not_flagged(monkeypatch):
    """STAGING instance is a transitional state and must be skipped."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("staging-vm", status="STAGING")]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_suspended_vm_not_flagged(monkeypatch):
    """SUSPENDED instance has different billing semantics and must be skipped."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("suspended-vm", status="SUSPENDED")]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Stop timestamp contract (spec 8.6, 9.5)
# ---------------------------------------------------------------------------


def test_missing_stop_timestamp_skips(monkeypatch):
    """TERMINATED VM with no lastStopTimestamp must be skipped, not emitted."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("mystery-vm", last_stop_timestamp="")]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_unparsable_stop_timestamp_skips(monkeypatch):
    """TERMINATED VM with an unparsable lastStopTimestamp must be skipped."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("bad-ts-vm", last_stop_timestamp="not-a-date")]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Zone scope contract (spec 9.2)
# ---------------------------------------------------------------------------


def test_non_zone_scope_skipped(monkeypatch):
    """Scope keys not in 'zones/ZONE' form must be skipped."""
    _mock_client(
        {
            # 'global/' is not a zone scope
            "global/": _make_scoped_list([_make_instance("global-vm")]),
            "zones/us-central1-a": _make_scoped_list([_make_instance("zone-vm")]),
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert "zone-vm" in findings[0].resource_id


def test_regions_scope_skipped(monkeypatch):
    """'regions/...' scope key must be skipped (not a zone scope)."""
    _mock_client(
        {
            "regions/us-central1": _make_scoped_list([_make_instance("region-vm")]),
            "zones/us-east1-b": _make_scoped_list([_make_instance("zone-vm")]),
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert "zone-vm" in findings[0].resource_id


# ---------------------------------------------------------------------------
# Region derivation and filter (spec 9.2)
# ---------------------------------------------------------------------------


def test_region_derived_from_zone(monkeypatch):
    """Region in the finding is derived from the zone (drop trailing letter)."""
    _mock_client(
        {"zones/europe-west1-b": _make_scoped_list([_make_instance("eu-vm")])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings[0].region == "europe-west1"


def test_region_filter_matches(monkeypatch):
    """Only instances in the matching region are flagged."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list([_make_instance("central-vm")]),
            "zones/eu-west1-b": _make_scoped_list([_make_instance("eu-vm")]),
        },
        monkeypatch,
    )
    findings = find_stopped_vms(
        project_id="proj-1", credentials=MagicMock(), region_filter="eu-west1"
    )
    assert len(findings) == 1
    assert "eu-vm" in findings[0].resource_id


def test_region_filter_no_match_returns_empty(monkeypatch):
    """Region filter that matches no zone returns no findings."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    findings = find_stopped_vms(
        project_id="proj-1", credentials=MagicMock(), region_filter="asia-east1"
    )
    assert findings == []


def test_unknown_region_with_filter_skips(monkeypatch):
    """Non-standard zone produces 'unknown' region; filter cannot evaluate → skip."""
    # Zone 'custom-a' → region 'custom' (no dash → falls through to 'unknown')
    _mock_client(
        {"zones/custom-a": _make_scoped_list([_make_instance("weird-vm")])},
        monkeypatch,
    )
    findings = find_stopped_vms(
        project_id="proj-1", credentials=MagicMock(), region_filter="custom"
    )
    assert findings == []


def test_unknown_region_with_filter_emits_warning(monkeypatch):
    """Unknown region with active filter emits a UserWarning naming the zone and filter."""
    _mock_client(
        {"zones/custom-a": _make_scoped_list([_make_instance("weird-vm")])},
        monkeypatch,
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_stopped_vms(project_id="proj-1", credentials=MagicMock(), region_filter="custom")

    assert any(
        issubclass(w.category, UserWarning)
        and "custom-a" in str(w.message)
        and "region_filter" in str(w.message)
        for w in caught
    )


def test_unknown_region_without_filter_emits(monkeypatch):
    """Non-standard zone with 'unknown' region still emits when no filter is set."""
    _mock_client(
        {"zones/custom-a": _make_scoped_list([_make_instance("weird-vm")])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1
    assert findings[0].region == "unknown"


# ---------------------------------------------------------------------------
# MIG exclusion (spec 9.4)
# ---------------------------------------------------------------------------


def test_mig_member_skipped(monkeypatch):
    """Instance with 'created-by' referencing instanceGroupManagers must be skipped."""
    mig_instance = _make_instance(
        "mig-vm",
        metadata_items=[
            _make_metadata_item(
                "created-by",
                "projects/123/zones/us-central1-a/instanceGroupManagers/my-mig",
            )
        ],
    )
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([mig_instance])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_mig_exclusion_requires_exact_proof(monkeypatch):
    """'created-by' without 'instanceGroupManagers/' must NOT trigger MIG exclusion."""
    non_mig_instance = _make_instance(
        "standalone-vm",
        metadata_items=[_make_metadata_item("created-by", "some-other-resource/my-tool")],
    )
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([non_mig_instance])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


def test_no_metadata_not_excluded(monkeypatch):
    """Instance with no metadata at all must not be excluded by MIG check."""
    instance = _make_instance("no-meta-vm", metadata_items=None)
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([instance])},
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Custom threshold
# ---------------------------------------------------------------------------


def test_custom_max_age_days(monkeypatch):
    """max_age_days parameter controls the stop-age threshold."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", last_stop_timestamp=_ts(10))]
            )
        },
        monkeypatch,
    )
    # With threshold=7, stopped 10 days ago → flagged
    assert len(find_stopped_vms(project_id="p", credentials=MagicMock(), max_age_days=7)) == 1
    # With threshold=30, stopped 10 days ago → not flagged
    assert find_stopped_vms(project_id="p", credentials=MagicMock(), max_age_days=30) == []


# ---------------------------------------------------------------------------
# Confidence (spec 9.7)
# ---------------------------------------------------------------------------


def test_short_stopped_vm_medium_confidence(monkeypatch):
    """VM stopped 35 days ago (< 90 days) should have MEDIUM confidence."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", last_stop_timestamp=_ts(35))]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].confidence
        == ConfidenceLevel.MEDIUM
    )


def test_long_stopped_vm_high_confidence(monkeypatch):
    """VM stopped 95 days ago (>= 90 days) should have HIGH confidence."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", last_stop_timestamp=_ts(95))]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].confidence
        == ConfidenceLevel.HIGH
    )


# ---------------------------------------------------------------------------
# Risk (spec 9.8)
# ---------------------------------------------------------------------------


def test_risk_always_medium(monkeypatch):
    """Risk is always MEDIUM when a finding is emitted."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    assert find_stopped_vms(project_id="p", credentials=MagicMock())[0].risk == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Cost model (spec 9.6)
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_always_none(monkeypatch):
    """estimated_monthly_cost_usd is always None regardless of disk size."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "big-disk-vm",
                        disks=[_make_disk(size_gb=1000)],
                    )
                ]
            )
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="p", credentials=MagicMock())
    assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# Details shape (spec 10.3)
# ---------------------------------------------------------------------------


def test_raw_status_in_details(monkeypatch):
    """raw_status must appear in details with the exact API value."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", status="TERMINATED")])},
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["raw_status"]
        == "TERMINATED"
    )


def test_stop_age_days_in_details(monkeypatch):
    """stop_age_days must appear in details."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", last_stop_timestamp=_ts(40))]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["stop_age_days"] >= 40
    )


def test_max_age_days_threshold_in_details(monkeypatch):
    """max_age_days_threshold must appear in details."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock(), max_age_days=14)[0].details[
            "max_age_days_threshold"
        ]
        == 14
    )


def test_last_stop_timestamp_in_details_is_iso(monkeypatch):
    """last_stop_timestamp in details is an ISO 8601 string."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    ts = find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["last_stop_timestamp"]
    assert isinstance(ts, str) and "T" in ts


def test_mig_membership_false_in_details(monkeypatch):
    """mig_membership is False for non-MIG instances that are emitted."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["mig_membership"]
        is False
    )


def test_persistent_disk_count_in_details(monkeypatch):
    """persistent_disk_count counts only PERSISTENT disks."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "vm",
                        disks=[
                            _make_disk(100, "PERSISTENT"),
                            _make_disk(200, "PERSISTENT"),
                            _make_disk(375, "SCRATCH"),
                        ],
                    )
                ]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details[
            "persistent_disk_count"
        ]
        == 2
    )


def test_persistent_disk_total_gb_in_details(monkeypatch):
    """persistent_disk_total_gb sums only PERSISTENT disk sizes."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "vm",
                        disks=[
                            _make_disk(200, "PERSISTENT"),
                            _make_disk(100, "PERSISTENT"),
                            _make_disk(375, "SCRATCH"),  # excluded
                        ],
                    )
                ]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details[
            "persistent_disk_total_gb"
        ]
        == 300
    )


def test_disk_kinds_present_in_details(monkeypatch):
    """disk_kinds_present lists all distinct attached disk kinds."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "vm",
                        disks=[
                            _make_disk(100, "PERSISTENT"),
                            _make_disk(375, "SCRATCH"),
                        ],
                    )
                ]
            )
        },
        monkeypatch,
    )
    kinds = find_stopped_vms(project_id="p", credentials=MagicMock())[0].details[
        "disk_kinds_present"
    ]
    assert sorted(kinds) == ["PERSISTENT", "SCRATCH"]


def test_boot_disk_count_in_details_and_signal(monkeypatch):
    """Boot disk presence appears in details and signals."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "vm",
                        disks=[_make_disk(50, boot=True), _make_disk(100)],
                    )
                ]
            )
        },
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["boot_disk_count"] == 1
    assert any("Boot disk" in s for s in f.evidence.signals_used)


def test_no_boot_disk_no_boot_signal(monkeypatch):
    """VMs with no boot disk should not emit a boot disk signal."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", disks=[_make_disk(100, boot=False)])]
            )
        },
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["boot_disk_count"] == 0
    assert not any("Boot disk" in s for s in f.evidence.signals_used)


def test_external_nat_ip_present_in_details_and_signal(monkeypatch):
    """external_nat_ip_present=True appears in details and signals."""
    nic = SimpleNamespace(access_configs=[SimpleNamespace(nat_ip="34.1.2.3")])
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", network_interfaces=[nic])]
            )
        },
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["external_nat_ip_present"] is True
    assert any("External NAT IP" in s for s in f.evidence.signals_used)


def test_external_nat_ip_absent_in_details(monkeypatch):
    """external_nat_ip_present=False when no access config has a natIP."""
    nic = SimpleNamespace(access_configs=[SimpleNamespace(nat_ip="")])
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", network_interfaces=[nic])]
            )
        },
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["external_nat_ip_present"] is False
    assert not any("External NAT IP" in s for s in f.evidence.signals_used)


def test_gpu_attached_in_details_and_signal(monkeypatch):
    """gpu_attached=True appears in details and signals when accelerators present."""
    accel = SimpleNamespace(accelerator_count=1, accelerator_type="nvidia-tesla-t4")
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", guest_accelerators=[accel])]
            )
        },
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["gpu_attached"] is True
    assert any("GPU" in s for s in f.evidence.signals_used)


def test_gpu_not_attached_in_details(monkeypatch):
    """gpu_attached=False when no accelerators are present."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", guest_accelerators=[])])},
        monkeypatch,
    )
    f = find_stopped_vms(project_id="p", credentials=MagicMock())[0]
    assert f.details["gpu_attached"] is False
    assert not any("GPU" in s for s in f.evidence.signals_used)


def test_last_start_timestamp_in_details_when_present(monkeypatch):
    """last_start_timestamp appears in details when non-empty."""
    ts = "2024-01-01T10:00:00Z"
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", last_start_timestamp=ts)])},
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["last_start_timestamp"]
        == ts
    )


def test_last_start_timestamp_absent_when_empty(monkeypatch):
    """last_start_timestamp is absent from details when empty."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", last_start_timestamp="")])},
        monkeypatch,
    )
    assert (
        "last_start_timestamp"
        not in find_stopped_vms(project_id="p", credentials=MagicMock())[0].details
    )


def test_automatic_restart_in_details_when_present(monkeypatch):
    """automatic_restart appears in details when the scheduling field is present."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", automatic_restart=False)])},
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["automatic_restart"]
        is False
    )


def test_machine_type_parsed_from_url(monkeypatch):
    """machine_type in details is the final URL segment, not the full resource path."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", machine_type="e2-medium")]
            )
        },
        monkeypatch,
    )
    assert (
        find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["machine_type"]
        == "e2-medium"
    )


def test_labels_in_details(monkeypatch):
    """Instance labels appear in details."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", labels={"env": "staging", "owner": "team-a"})]
            )
        },
        monkeypatch,
    )
    assert find_stopped_vms(project_id="p", credentials=MagicMock())[0].details["labels"] == {
        "env": "staging",
        "owner": "team-a",
    }


# ---------------------------------------------------------------------------
# Evidence shape (spec 10.2)
# ---------------------------------------------------------------------------


def test_evidence_discloses_stopped_state(monkeypatch):
    """signals_used discloses the STOPPED_VM lifecycle state."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_used
    assert any("STOPPED_VM" in s for s in sigs)


def test_evidence_discloses_stop_age_and_threshold(monkeypatch):
    """signals_used discloses stop age in days and the threshold."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", last_stop_timestamp=_ts(40))]
            )
        },
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock(), max_age_days=30)[
        0
    ].evidence.signals_used
    assert any("40" in s for s in sigs)
    assert any("30" in s for s in sigs)


def test_evidence_discloses_disk_count_and_size(monkeypatch):
    """signals_used discloses persistent disk count and total size."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm", disks=[_make_disk(200), _make_disk(100)])]
            )
        },
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_used
    assert any("300" in s for s in sigs)  # total GB
    assert any("2" in s for s in sigs)  # disk count


def test_evidence_no_cost_estimate_in_signals(monkeypatch):
    """signals_used must not include a flat disk cost estimate."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", disks=[_make_disk(500)])])},
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_used
    assert not any("$/month" in s or "per GB" in s or "0.04" in s for s in sigs)


def test_evidence_disk_kinds_in_signals(monkeypatch):
    """signals_used discloses attached disk kinds when present."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [
                    _make_instance(
                        "vm", disks=[_make_disk(100, "PERSISTENT"), _make_disk(375, "SCRATCH")]
                    )
                ]
            )
        },
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_used
    assert any("SCRATCH" in s for s in sigs)


def test_evidence_automatic_restart_in_signals(monkeypatch):
    """signals_used discloses automaticRestart context when scheduling present."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm", automatic_restart=False)])},
        monkeypatch,
    )
    sigs = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_used
    assert any("automaticRestart" in s for s in sigs)


def test_signals_not_checked_includes_blind_spots(monkeypatch):
    """signals_not_checked covers the required blind spots for a normal (known-region) finding."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    snc = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_not_checked
    combined = " ".join(snc)
    assert "missing_last_stop_timestamp" in combined
    assert len(snc) >= 4


def test_region_unparseable_absent_when_region_known(monkeypatch):
    """region_unparseable must NOT appear in signals_not_checked when region is known."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    snc = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_not_checked
    combined = " ".join(snc)
    assert "region_unparseable" not in combined


def test_region_unparseable_in_signals_not_checked_only_when_unknown(monkeypatch):
    """region_unparseable is conditionally added to signals_not_checked only when region is unknown."""
    # Zone 'zones/badzone' → zone name 'badzone' → no dash in parts[0] → region 'unknown'
    _mock_client(
        {"zones/badzone": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    snc = find_stopped_vms(project_id="p", credentials=MagicMock())[0].evidence.signals_not_checked
    combined = " ".join(snc)
    assert "region_unparseable" in combined


def test_extra_path_in_zone_scope_skipped(monkeypatch):
    """zones/ZONE/extra scope key must be rejected — only exact zones/ZONE is valid."""
    _mock_client(
        {
            "zones/us-central1-a/extra": _make_scoped_list([_make_instance("vm")]),
        },
        monkeypatch,
    )
    findings = find_stopped_vms(project_id="p", credentials=MagicMock())
    assert findings == []


def test_malformed_instance_skipped_not_aborted(monkeypatch):
    """A malformed instance record is skipped with a warning; valid siblings still emit."""

    class _BrokenInstance:
        name = "broken-vm"

        @property
        def status(self):
            raise AttributeError("simulated malformed record")

    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_BrokenInstance(), _make_instance("good-vm")])},
        monkeypatch,
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        findings = find_stopped_vms(project_id="p", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["instance_name"] == "good-vm"
    assert any(
        issubclass(w.category, UserWarning) and "malformed instance" in str(w.message)
        for w in caught
    )


# ---------------------------------------------------------------------------
# Rule identity and resource shape
# ---------------------------------------------------------------------------


def test_rule_id_and_provider(monkeypatch):
    """rule_id and provider are correct."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("vm")])},
        monkeypatch,
    )
    f = find_stopped_vms(project_id="proj-1", credentials=MagicMock())[0]
    assert f.rule_id == "gcp.compute.vm.stopped"
    assert f.provider == "gcp"
    assert f.resource_type == "gcp.compute.instance"


def test_resource_id_canonical_path(monkeypatch):
    """resource_id uses the canonical projects/zones/instances path."""
    _mock_client(
        {"zones/us-central1-a": _make_scoped_list([_make_instance("my-vm")])},
        monkeypatch,
    )
    rid = find_stopped_vms(project_id="proj-1", credentials=MagicMock())[0].resource_id
    assert rid == "projects/proj-1/zones/us-central1-a/instances/my-vm"


# ---------------------------------------------------------------------------
# Failure behavior (spec 9.9)
# ---------------------------------------------------------------------------


def test_permission_denied_raises_permission_error(monkeypatch):
    """PermissionDenied during aggregated_list should surface as PermissionError."""
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


def test_partial_coverage_warning_emitted(monkeypatch):
    """Partial-coverage scope warning is surfaced via warnings.warn."""
    _mock_client(
        {
            "zones/us-central1-a": _make_scoped_list(
                [_make_instance("vm")], warning_code="NO_RESULTS_ON_PAGE"
            )
        },
        monkeypatch,
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_stopped_vms(project_id="proj-1", credentials=MagicMock())

    assert any(
        issubclass(w.category, UserWarning) and "partial coverage" in str(w.message).lower()
        for w in caught
    )
