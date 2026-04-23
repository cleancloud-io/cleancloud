"""
Tests for azure.resource.untagged -- spec-aligned.

Covers: must-emit (disk + snapshot), must-skip, id/name guards, region filter,
        provisioning-state contract, tag contract, age contract (SDK/nested/conflict/
        invalid fail-closed), disk confidence contract (attachment context),
        snapshot confidence, finding shape, failure behavior,
        resolver unit tests (_resolve_provisioning_state, _resolve_tags,
        _resolve_time_created, _coerce_datetime, _resolve_disk_attachment_context).
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from cleancloud.providers.azure.rules.untagged_resources import (
    _UNRESOLVABLE,
    _coerce_datetime,
    _resolve_disk_attachment_context,
    _resolve_provisioning_state,
    _resolve_tags,
    _resolve_time_created,
    find_untagged_resources,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_MIN_AGE = 7  # days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ago(days: float) -> datetime:
    """Return a UTC datetime `days` ago (negative = future)."""
    return datetime.now(timezone.utc) - timedelta(days=days)


def _make_disk(
    disk_id="disk-1",
    name="my-disk",
    location="eastus",
    provisioning_state="Succeeded",
    disk_state="Unattached",
    managed_by=None,
    managed_by_extended=None,
    time_created=None,
    tags=None,
    properties=None,
) -> SimpleNamespace:
    """
    Build a fully qualifying disk SimpleNamespace.
    Defaults to time_created=10 days ago, so the disk passes the 7-day
    age check out of the box.
    """
    if time_created is None:
        time_created = _ago(10)
    return SimpleNamespace(
        id=disk_id,
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        disk_state=disk_state,
        managed_by=managed_by,
        managed_by_extended=managed_by_extended,
        time_created=time_created,
        tags=tags,
        properties=properties,
    )


def _make_snap(
    snap_id="snap-1",
    name="my-snap",
    location="eastus",
    provisioning_state="Succeeded",
    time_created=None,
    tags=None,
    properties=None,
) -> SimpleNamespace:
    """
    Build a fully qualifying snapshot SimpleNamespace.
    Defaults to time_created=10 days ago.
    """
    if time_created is None:
        time_created = _ago(10)
    return SimpleNamespace(
        id=snap_id,
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        time_created=time_created,
        tags=tags,
        properties=properties,
    )


def _run(disks=None, snaps=None, region_filter=None):
    client = MagicMock()
    client.disks.list.return_value = disks or []
    client.snapshots.list.return_value = snaps or []
    return find_untagged_resources(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=client,
    )


def _one_disk(disks, region_filter=None):
    results = _run(disks=disks, region_filter=region_filter)
    disk_findings = [f for f in results if f.resource_type == "azure.compute.disk"]
    assert len(disk_findings) == 1
    return disk_findings[0]


def _one_snap(snaps, region_filter=None):
    results = _run(snaps=snaps, region_filter=region_filter)
    snap_findings = [f for f in results if f.resource_type == "azure.compute.snapshot"]
    assert len(snap_findings) == 1
    return snap_findings[0]


# ===========================================================================
# TestMustEmit -- both resource families
# ===========================================================================


class TestMustEmit:
    def test_qualifying_disk_emits(self):
        assert len(_run(disks=[_make_disk()])) == 1

    def test_qualifying_snapshot_emits(self):
        assert len(_run(snaps=[_make_snap()])) == 1

    def test_multiple_qualifying_disks_all_emit(self):
        disks = [_make_disk(disk_id=f"disk-{i}", name=f"d{i}") for i in range(3)]
        assert len(_run(disks=disks)) == 3

    def test_multiple_qualifying_snaps_all_emit(self):
        snaps = [_make_snap(snap_id=f"snap-{i}", name=f"s{i}") for i in range(3)]
        assert len(_run(snaps=snaps)) == 3

    def test_disk_and_snap_both_emit(self):
        results = _run(disks=[_make_disk()], snaps=[_make_snap()])
        assert len(results) == 2
        types = {f.resource_type for f in results}
        assert types == {"azure.compute.disk", "azure.compute.snapshot"}

    def test_disk_tags_none_emits(self):
        # None -> zero direct tags -> emit
        assert len(_run(disks=[_make_disk(tags=None)])) == 1

    def test_disk_tags_empty_dict_emits(self):
        # {} -> zero direct tags -> emit
        assert len(_run(disks=[_make_disk(tags={})])) == 1

    def test_snap_tags_none_emits(self):
        assert len(_run(snaps=[_make_snap(tags=None)])) == 1

    def test_snap_tags_empty_dict_emits(self):
        assert len(_run(snaps=[_make_snap(tags={})])) == 1


# ===========================================================================
# TestMustSkip -- disks
# ===========================================================================


class TestMustSkipDisks:
    def test_tagged_disk_skips(self):
        assert _run(disks=[_make_disk(tags={"env": "prod"})]) == []

    def test_provisioning_state_failed_skips(self):
        assert _run(disks=[_make_disk(provisioning_state="Failed")]) == []

    def test_provisioning_state_creating_skips(self):
        assert _run(disks=[_make_disk(provisioning_state="Creating")]) == []

    def test_provisioning_state_succeeded_with_warnings_skips(self):
        # Spec: only exact "Succeeded" qualifies
        assert _run(disks=[_make_disk(provisioning_state="SucceededWithWarnings")]) == []

    def test_provisioning_state_lowercase_succeeded_skips(self):
        assert _run(disks=[_make_disk(provisioning_state="succeeded")]) == []

    def test_disk_age_6_days_skips(self):
        assert _run(disks=[_make_disk(time_created=_ago(6))]) == []

    def test_disk_age_exactly_7_days_emits(self):
        assert len(_run(disks=[_make_disk(time_created=_ago(7))])) == 1

    def test_disk_time_created_future_skips(self):
        assert _run(disks=[_make_disk(time_created=_ago(-1))]) == []

    def test_disk_time_created_absent_skips(self):
        disk = _make_disk()
        disk.time_created = None
        assert _run(disks=[disk]) == []

    def test_disk_time_created_invalid_string_skips(self):
        disk = _make_disk()
        disk.time_created = "not-a-date"
        assert _run(disks=[disk]) == []

    def test_disk_tags_missing_field_skips(self):
        disk = _make_disk()
        del disk.tags
        assert _run(disks=[disk]) == []

    def test_disk_tags_non_mapping_non_none_skips(self):
        disk = _make_disk(tags="tagged")
        assert _run(disks=[disk]) == []

    def test_disk_tags_list_skips(self):
        disk = _make_disk(tags=["env", "prod"])
        assert _run(disks=[disk]) == []


# ===========================================================================
# TestMustSkip -- snapshots
# ===========================================================================


class TestMustSkipSnaps:
    def test_tagged_snap_skips(self):
        assert _run(snaps=[_make_snap(tags={"team": "infra"})]) == []

    def test_snap_age_6_days_skips(self):
        assert _run(snaps=[_make_snap(time_created=_ago(6))]) == []

    def test_snap_age_exactly_7_days_emits(self):
        assert len(_run(snaps=[_make_snap(time_created=_ago(7))])) == 1

    def test_snap_time_created_future_skips(self):
        assert _run(snaps=[_make_snap(time_created=_ago(-1))]) == []

    def test_snap_time_created_absent_skips(self):
        snap = _make_snap()
        snap.time_created = None
        assert _run(snaps=[snap]) == []

    def test_snap_provisioning_state_not_succeeded_skips(self):
        assert _run(snaps=[_make_snap(provisioning_state="Failed")]) == []

    def test_snap_tags_missing_field_skips(self):
        snap = _make_snap()
        del snap.tags
        assert _run(snaps=[snap]) == []

    def test_snap_tags_non_mapping_skips(self):
        snap = _make_snap(tags=42)
        assert _run(snaps=[snap]) == []


# ===========================================================================
# TestIdNameGuards -- spec 8.2, 8.3
# ===========================================================================


class TestIdNameGuards:
    def test_disk_id_absent_skips(self):
        disk = _make_disk()
        del disk.id
        assert _run(disks=[disk]) == []

    def test_disk_id_none_skips(self):
        assert _run(disks=[_make_disk(disk_id=None)]) == []

    def test_disk_id_empty_skips(self):
        assert _run(disks=[_make_disk(disk_id="")]) == []

    def test_disk_name_absent_skips(self):
        disk = _make_disk()
        del disk.name
        assert _run(disks=[disk]) == []

    def test_disk_name_none_skips(self):
        assert _run(disks=[_make_disk(name=None)]) == []

    def test_disk_name_empty_skips(self):
        assert _run(disks=[_make_disk(name="")]) == []

    def test_snap_id_absent_skips(self):
        snap = _make_snap()
        del snap.id
        assert _run(snaps=[snap]) == []

    def test_snap_name_absent_skips(self):
        snap = _make_snap()
        del snap.name
        assert _run(snaps=[snap]) == []

    def test_snap_id_empty_skips(self):
        assert _run(snaps=[_make_snap(snap_id="")]) == []

    def test_snap_name_empty_skips(self):
        assert _run(snaps=[_make_snap(name="")]) == []


# ===========================================================================
# TestRegionFilter -- spec 8.4
# ===========================================================================


class TestRegionFilter:
    def test_matching_region_emits(self):
        assert len(_run(disks=[_make_disk(location="eastus")], region_filter="eastus")) == 1

    def test_non_matching_region_skips(self):
        assert _run(disks=[_make_disk(location="westus")], region_filter="eastus") == []

    def test_region_filter_is_case_insensitive(self):
        assert len(_run(disks=[_make_disk(location="eastus")], region_filter="EastUS")) == 1

    def test_no_region_filter_emits_all(self):
        disks = [
            _make_disk(disk_id="d1", name="a", location="eastus"),
            _make_disk(disk_id="d2", name="b", location="westus"),
        ]
        assert len(_run(disks=disks)) == 2

    def test_snap_region_filter_respected(self):
        assert _run(snaps=[_make_snap(location="westus")], region_filter="eastus") == []


# ===========================================================================
# TestProvisioningStateContract -- spec 9.2
# ===========================================================================


class TestProvisioningStateContract:
    def test_sdk_succeeded_emits(self):
        assert len(_run(disks=[_make_disk(provisioning_state="Succeeded")])) == 1

    def test_nested_provisioning_state_used_when_sdk_absent(self):
        disk = _make_disk()
        disk.provisioning_state = None
        disk.properties = SimpleNamespace(provisioning_state="Succeeded", provisioningState=None)
        assert len(_run(disks=[disk])) == 1

    def test_nested_camel_case_used(self):
        disk = _make_disk()
        disk.provisioning_state = None
        disk.properties = SimpleNamespace(provisioning_state=None, provisioningState="Succeeded")
        assert len(_run(disks=[disk])) == 1

    def test_sdk_nested_conflict_skips(self):
        disk = _make_disk()
        disk.provisioning_state = "Succeeded"
        disk.properties = SimpleNamespace(provisioning_state="Failed", provisioningState=None)
        assert _run(disks=[disk]) == []

    def test_both_absent_skips(self):
        disk = _make_disk(provisioning_state=None)
        disk.properties = None
        assert _run(disks=[disk]) == []


# ===========================================================================
# TestTagContract -- spec 9.3
# ===========================================================================


class TestTagContract:
    def test_tags_none_zero_count(self):
        assert len(_run(disks=[_make_disk(tags=None)])) == 1

    def test_tags_empty_dict_zero_count(self):
        assert len(_run(disks=[_make_disk(tags={})])) == 1

    def test_tags_non_empty_skips(self):
        assert _run(disks=[_make_disk(tags={"env": "prod"})]) == []

    def test_tags_field_missing_skips(self):
        disk = _make_disk()
        del disk.tags
        assert _run(disks=[disk]) == []

    def test_tags_string_value_skips(self):
        disk = _make_disk(tags="yes-tagged")
        assert _run(disks=[disk]) == []

    def test_tags_int_value_skips(self):
        disk = _make_disk(tags=1)
        assert _run(disks=[disk]) == []

    def test_tags_list_value_skips(self):
        disk = _make_disk(tags=["env", "prod"])
        assert _run(disks=[disk]) == []

    def test_snap_tags_none_zero_count(self):
        assert len(_run(snaps=[_make_snap(tags=None)])) == 1

    def test_snap_tags_non_empty_skips(self):
        assert _run(snaps=[_make_snap(tags={"x": "y"})]) == []

    def test_snap_tags_missing_field_skips(self):
        snap = _make_snap()
        del snap.tags
        assert _run(snaps=[snap]) == []


# ===========================================================================
# TestAgeContract -- spec 9.4
# ===========================================================================


class TestAgeContract:
    def test_sdk_time_created_used(self):
        disk = _make_disk(time_created=_ago(10))
        assert len(_run(disks=[disk])) == 1

    def test_nested_time_created_used_when_sdk_absent(self):
        disk = _make_disk()
        disk.time_created = None
        disk.properties = SimpleNamespace(time_created=_ago(10), timeCreated=None)
        assert len(_run(disks=[disk])) == 1

    def test_nested_camel_time_created_used(self):
        disk = _make_disk()
        disk.time_created = None
        disk.properties = SimpleNamespace(time_created=None, timeCreated=_ago(10))
        assert len(_run(disks=[disk])) == 1

    def test_sdk_present_but_invalid_skips_no_fallback(self):
        # SDK surface present but unparseable -- must skip, not fall back to nested
        disk = _make_disk()
        disk.time_created = "not-a-date"
        disk.properties = SimpleNamespace(time_created=None, timeCreated=_ago(10))
        assert _run(disks=[disk]) == []

    def test_nested_present_but_invalid_skips(self):
        disk = _make_disk()
        disk.time_created = None
        disk.properties = SimpleNamespace(time_created="bad", timeCreated=None)
        assert _run(disks=[disk]) == []

    def test_sdk_nested_conflict_skips(self):
        disk = _make_disk()
        disk.time_created = _ago(10)
        disk.properties = SimpleNamespace(time_created=_ago(50), timeCreated=None)
        assert _run(disks=[disk]) == []

    def test_sdk_nested_agree_within_60s_emits(self):
        base = _ago(10)
        disk = _make_disk()
        disk.time_created = base
        disk.properties = SimpleNamespace(
            time_created=base + timedelta(seconds=30), timeCreated=None
        )
        assert len(_run(disks=[disk])) == 1

    def test_time_created_iso_string_accepted(self):
        disk = _make_disk()
        disk.time_created = _ago(10).isoformat().replace("+00:00", "Z")
        assert len(_run(disks=[disk])) == 1

    def test_time_created_future_skips(self):
        assert _run(disks=[_make_disk(time_created=_ago(-1))]) == []

    def test_both_absent_skips(self):
        disk = _make_disk()
        disk.time_created = None
        disk.properties = None
        assert _run(disks=[disk]) == []

    def test_snap_age_contract(self):
        assert _run(snaps=[_make_snap(time_created=_ago(6))]) == []
        assert len(_run(snaps=[_make_snap(time_created=_ago(8))])) == 1

    def test_snap_sdk_invalid_skips_no_fallback(self):
        snap = _make_snap()
        snap.time_created = "garbage"
        snap.properties = SimpleNamespace(time_created=None, timeCreated=_ago(10))
        assert _run(snaps=[snap]) == []


# ===========================================================================
# TestDiskConfidenceContract -- spec 9.5 / 11.2
# ===========================================================================


class TestDiskConfidenceContract:
    def test_unattached_disk_medium_confidence(self):
        disk = _make_disk(
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=None,
        )
        f = _one_disk([disk])
        assert f.confidence.value == "medium"

    def test_attached_disk_low_confidence(self):
        disk = _make_disk(
            disk_state="Attached",
            managed_by="/subscriptions/s/vms/vm1",
            managed_by_extended=None,
        )
        # managed_by is present but tags are None -> would emit as untagged
        # however managed_by is set, so disk attachment context is "attached"
        f = _one_disk([disk])
        assert f.confidence.value == "low"

    def test_managed_by_extended_nonempty_low_confidence(self):
        disk = _make_disk(
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=["/sub/vms/vm2"],
        )
        f = _one_disk([disk])
        assert f.confidence.value == "low"

    def test_disk_state_not_unattached_low_confidence(self):
        disk = _make_disk(
            disk_state="Reserved",
            managed_by=None,
            managed_by_extended=None,
        )
        f = _one_disk([disk])
        assert f.confidence.value == "low"

    def test_managed_by_extended_unresolvable_low_confidence(self):
        # Field absent from all sources -> unresolved -> LOW
        disk = _make_disk(
            disk_state="Unattached",
            managed_by=None,
        )
        del disk.managed_by_extended
        f = _one_disk([disk])
        assert f.confidence.value == "low"

    def test_managed_by_field_absent_low_confidence(self):
        disk = _make_disk(disk_state="Unattached", managed_by_extended=None)
        del disk.managed_by
        f = _one_disk([disk])
        assert f.confidence.value == "low"

    def test_snapshot_always_low_confidence(self):
        f = _one_snap([_make_snap()])
        assert f.confidence.value == "low"


# ===========================================================================
# TestFindingShape -- spec 11
# ===========================================================================


class TestFindingShape:
    def test_disk_finding_required_fields(self):
        f = _one_disk([_make_disk()])
        assert f.provider == "azure"
        assert f.rule_id == "azure.resource.untagged"
        assert f.resource_type == "azure.compute.disk"
        assert f.resource_id == "disk-1"
        assert f.region == "eastus"
        assert f.risk.value == "low"
        assert f.estimated_monthly_cost_usd is None

    def test_disk_details_required_keys(self):
        f = _one_disk([_make_disk()])
        d = f.details
        assert d["resource_name"] == "my-disk"
        assert d["subscription_id"] == _SUB
        assert d["resource_family"] == "managed_disk"
        assert d["tags_present"] is False
        assert d["current_tag_count"] == 0
        assert isinstance(d["age_days"], float)
        assert d["provisioning_state"] == "Succeeded"
        assert isinstance(d["tags"], dict)

    def test_disk_details_disk_context_keys(self):
        # disk_state, managed_by, managed_by_extended present in details
        f = _one_disk([_make_disk(disk_state="Unattached", managed_by=None)])
        d = f.details
        assert "disk_state" in d
        assert "managed_by" in d
        assert "managed_by_extended" in d

    def test_disk_age_days_rounded(self):
        f = _one_disk([_make_disk(time_created=_ago(10))])
        assert f.details["age_days"] == round(f.details["age_days"], 1)

    def test_disk_estimated_cost_always_none(self):
        f = _one_disk([_make_disk()])
        assert f.estimated_monthly_cost_usd is None

    def test_snap_finding_required_fields(self):
        f = _one_snap([_make_snap()])
        assert f.provider == "azure"
        assert f.rule_id == "azure.resource.untagged"
        assert f.resource_type == "azure.compute.snapshot"
        assert f.resource_id == "snap-1"
        assert f.region == "eastus"
        assert f.risk.value == "low"
        assert f.estimated_monthly_cost_usd is None

    def test_snap_details_required_keys(self):
        f = _one_snap([_make_snap()])
        d = f.details
        assert d["resource_name"] == "my-snap"
        assert d["subscription_id"] == _SUB
        assert d["resource_family"] == "snapshot"
        assert d["tags_present"] is False
        assert d["current_tag_count"] == 0
        assert isinstance(d["age_days"], float)
        assert d["provisioning_state"] == "Succeeded"
        assert isinstance(d["tags"], dict)

    def test_disk_evidence_has_required_signals(self):
        f = _one_disk([_make_disk()])
        used = " ".join(f.evidence.signals_used)
        assert "managed_disk" in used
        assert "Succeeded" in used
        assert "zero current tags" in used
        assert str(_MIN_AGE) in used

    def test_snap_evidence_has_required_signals(self):
        f = _one_snap([_make_snap()])
        used = " ".join(f.evidence.signals_used)
        assert "snapshot" in used
        assert "Succeeded" in used
        assert "zero current tags" in used

    def test_disk_evidence_signals_not_checked(self):
        f = _one_disk([_make_disk()])
        combined = " ".join(f.evidence.signals_not_checked).lower()
        assert "policy" in combined
        assert "tag" in combined

    def test_snap_evidence_time_window(self):
        f = _one_snap([_make_snap()])
        assert f.evidence.time_window is not None
        assert str(_MIN_AGE) in f.evidence.time_window


# ===========================================================================
# TestFailureBehavior -- spec 12
# ===========================================================================


class TestFailureBehavior:
    def test_disks_list_raises_propagates(self):
        client = MagicMock()
        client.disks.list.side_effect = RuntimeError("API error")
        client.snapshots.list.return_value = []
        with pytest.raises(RuntimeError):
            find_untagged_resources(subscription_id=_SUB, credential=None, client=client)

    def test_snapshots_list_raises_propagates(self):
        client = MagicMock()
        client.disks.list.return_value = []
        client.snapshots.list.side_effect = RuntimeError("API error")
        with pytest.raises(RuntimeError):
            find_untagged_resources(subscription_id=_SUB, credential=None, client=client)

    def test_malformed_disk_skipped_other_emits(self):
        # Disk with no id is skipped; the valid disk still emits
        bad = SimpleNamespace(
            id=None,
            name="bad",
            location="eastus",
            provisioning_state="Succeeded",
            time_created=_ago(10),
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=None,
            tags=None,
            properties=None,
        )
        good = _make_disk(disk_id="disk-good", name="good")
        results = _run(disks=[bad, good])
        ids = [f.resource_id for f in results]
        assert "disk-good" in ids
        assert None not in ids

    def test_inject_client_used(self):
        client = MagicMock()
        client.disks.list.return_value = [_make_disk()]
        client.snapshots.list.return_value = []
        results = find_untagged_resources(subscription_id=_SUB, credential=None, client=client)
        client.disks.list.assert_called_once()
        assert len(results) == 1


# ===========================================================================
# TestResolveProvisioningState -- unit tests for the resolver
# ===========================================================================


class TestResolveProvisioningState:
    def _ns(self, sdk=None, props=None):
        return SimpleNamespace(provisioning_state=sdk, properties=props)

    def test_sdk_value_returned(self):
        assert _resolve_provisioning_state(self._ns(sdk="Succeeded")) == "Succeeded"

    def test_nested_snake_case_used(self):
        obj = self._ns(
            sdk=None, props=SimpleNamespace(provisioning_state="Succeeded", provisioningState=None)
        )
        assert _resolve_provisioning_state(obj) == "Succeeded"

    def test_nested_camel_case_used(self):
        obj = self._ns(
            sdk=None, props=SimpleNamespace(provisioning_state=None, provisioningState="Succeeded")
        )
        assert _resolve_provisioning_state(obj) == "Succeeded"

    def test_conflict_returns_none(self):
        obj = self._ns(
            sdk="Succeeded",
            props=SimpleNamespace(provisioning_state="Failed", provisioningState=None),
        )
        assert _resolve_provisioning_state(obj) is None

    def test_both_absent_returns_none(self):
        obj = self._ns(sdk=None, props=None)
        assert _resolve_provisioning_state(obj) is None


# ===========================================================================
# TestResolveTags -- unit tests for the resolver
# ===========================================================================


class TestResolveTags:
    def _ns(self, tags):
        return SimpleNamespace(tags=tags)

    def test_none_returns_empty_dict(self):
        assert _resolve_tags(self._ns(None)) == {}

    def test_empty_dict_returns_empty_dict(self):
        assert _resolve_tags(self._ns({})) == {}

    def test_non_empty_dict_returned(self):
        result = _resolve_tags(self._ns({"env": "prod"}))
        assert result == {"env": "prod"}

    def test_missing_field_returns_unresolvable(self):
        obj = SimpleNamespace()
        assert _resolve_tags(obj) is _UNRESOLVABLE

    def test_string_value_returns_unresolvable(self):
        assert _resolve_tags(self._ns("tagged")) is _UNRESOLVABLE

    def test_int_value_returns_unresolvable(self):
        assert _resolve_tags(self._ns(42)) is _UNRESOLVABLE

    def test_list_value_returns_unresolvable(self):
        assert _resolve_tags(self._ns(["a", "b"])) is _UNRESOLVABLE


# ===========================================================================
# TestResolveTimeCreated -- unit tests for the resolver
# ===========================================================================


class TestResolveTimeCreated:
    def _ns(self, sdk=None, props=None):
        return SimpleNamespace(time_created=sdk, properties=props)

    def test_sdk_datetime_returned(self):
        dt = _ago(10)
        result = _resolve_time_created(self._ns(sdk=dt))
        assert result == dt

    def test_nested_snake_case_used(self):
        dt = _ago(10)
        obj = self._ns(sdk=None, props=SimpleNamespace(time_created=dt, timeCreated=None))
        assert _resolve_time_created(obj) == dt

    def test_nested_camel_used(self):
        dt = _ago(10)
        obj = self._ns(sdk=None, props=SimpleNamespace(time_created=None, timeCreated=dt))
        assert _resolve_time_created(obj) == dt

    def test_sdk_invalid_no_fallback(self):
        # SDK is present-but-invalid; must skip, not use nested
        dt = _ago(10)
        obj = self._ns(sdk="bad", props=SimpleNamespace(time_created=dt, timeCreated=None))
        assert _resolve_time_created(obj) is None

    def test_nested_invalid_skips(self):
        obj = self._ns(sdk=None, props=SimpleNamespace(time_created="bad", timeCreated=None))
        assert _resolve_time_created(obj) is None

    def test_material_conflict_skips(self):
        obj = self._ns(
            sdk=_ago(10),
            props=SimpleNamespace(time_created=_ago(50), timeCreated=None),
        )
        assert _resolve_time_created(obj) is None

    def test_agree_within_60s_returns_sdk(self):
        base = _ago(10)
        obj = self._ns(
            sdk=base,
            props=SimpleNamespace(time_created=base + timedelta(seconds=30), timeCreated=None),
        )
        result = _resolve_time_created(obj)
        assert result == base

    def test_both_absent_returns_none(self):
        assert _resolve_time_created(self._ns(sdk=None, props=None)) is None

    def test_iso_string_accepted(self):
        dt = _ago(10)
        iso = dt.isoformat().replace("+00:00", "Z")
        obj = self._ns(sdk=iso)
        result = _resolve_time_created(obj)
        assert result is not None
        assert abs((result - dt).total_seconds()) < 1


# ===========================================================================
# TestCoerceDatetime -- unit tests
# ===========================================================================


class TestCoerceDatetime:
    def test_none_returns_none(self):
        assert _coerce_datetime(None) is None

    def test_aware_datetime_returned_unchanged(self):
        dt = _ago(5)
        assert _coerce_datetime(dt) == dt

    def test_naive_datetime_gets_utc(self):
        naive = datetime(2024, 1, 15, 12, 0, 0)
        result = _coerce_datetime(naive)
        assert result.tzinfo is not None
        assert result.tzinfo == timezone.utc

    def test_iso_z_suffix_accepted(self):
        result = _coerce_datetime("2024-01-15T12:00:00Z")
        assert result is not None
        assert result.year == 2024

    def test_iso_plus_utc_offset_accepted(self):
        result = _coerce_datetime("2024-01-15T12:00:00+00:00")
        assert result is not None

    def test_invalid_string_returns_none(self):
        assert _coerce_datetime("not-a-date") is None

    def test_unsupported_type_returns_none(self):
        assert _coerce_datetime(12345) is None


# ===========================================================================
# TestResolveDiskAttachmentContext -- unit tests for confidence helper
# ===========================================================================


class TestResolveDiskAttachmentContext:
    def _ns(self, disk_state="Unattached", managed_by=None, managed_by_extended=None, props=None):
        return SimpleNamespace(
            disk_state=disk_state,
            managed_by=managed_by,
            managed_by_extended=managed_by_extended,
            properties=props,
        )

    def test_fully_unattached_returns_unattached(self):
        obj = self._ns(disk_state="Unattached", managed_by=None, managed_by_extended=None)
        assert _resolve_disk_attachment_context(obj) == "unattached"

    def test_managed_by_set_returns_attached(self):
        obj = self._ns(disk_state="Unattached", managed_by="/sub/vms/vm1")
        assert _resolve_disk_attachment_context(obj) == "attached"

    def test_managed_by_extended_nonempty_returns_attached(self):
        obj = self._ns(
            disk_state="Unattached", managed_by=None, managed_by_extended=["/sub/vms/vm2"]
        )
        assert _resolve_disk_attachment_context(obj) == "attached"

    def test_disk_state_reserved_returns_attached(self):
        # "Reserved" is a pre-attachment state; treated as "attached" semantically
        obj = self._ns(disk_state="Reserved", managed_by=None, managed_by_extended=None)
        assert _resolve_disk_attachment_context(obj) == "attached"

    def test_disk_state_active_sas_returns_special_state(self):
        obj = self._ns(disk_state="ActiveSAS", managed_by=None, managed_by_extended=None)
        assert _resolve_disk_attachment_context(obj) == "special_state"

    def test_disk_state_attached_returns_attached(self):
        obj = self._ns(disk_state="Attached", managed_by=None, managed_by_extended=None)
        assert _resolve_disk_attachment_context(obj) == "attached"

    def test_managed_by_field_missing_returns_unresolved(self):
        obj = SimpleNamespace(disk_state="Unattached", managed_by_extended=None, properties=None)
        assert _resolve_disk_attachment_context(obj) == "unresolved"

    def test_managed_by_extended_field_missing_returns_unresolved(self):
        obj = SimpleNamespace(disk_state="Unattached", managed_by=None, properties=None)
        assert _resolve_disk_attachment_context(obj) == "unresolved"

    def test_disk_state_conflict_returns_unresolved(self):
        obj = self._ns(
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=None,
            props=SimpleNamespace(disk_state="Attached", diskState=None),
        )
        assert _resolve_disk_attachment_context(obj) == "unresolved"

    def test_managed_by_extended_uncoercible_returns_unresolved(self):
        obj = SimpleNamespace(
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=42,  # not iterable
            properties=None,
        )
        assert _resolve_disk_attachment_context(obj) == "unresolved"
