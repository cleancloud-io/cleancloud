"""
Tests for azure.compute.disk.unattached -- spec-aligned.

Covers: must-emit, must-skip, id/name guards, region filter,
        provisioning-state contract, disk-state contract,
        attachment contract (managed_by, managed_by_extended),
        shared-disk contract (max_shares), frequent-attach contract,
        age-anchor contract (primary/fallback/ISO strings/no-fallback),
        finding shape, failure behavior, SDK/camelCase fallbacks,
        conflict detection, resolver unit tests.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from cleancloud.providers.azure.rules.unattached_managed_disks import (
    _UNRESOLVABLE,
    _coerce_datetime,
    _resolve_age_anchor,
    _resolve_managed_by,
    _resolve_managed_by_extended,
    _resolve_max_shares,
    _resolve_optimized_for_frequent_attach,
    find_unattached_managed_disks,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"


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
    max_shares=1,
    optimized_for_frequent_attach=False,
    last_ownership_update_time=None,
    time_created=None,
    sku_name="Standard_LRS",
    disk_size_gb=128,
    tags=None,
    properties=None,
) -> SimpleNamespace:
    """
    Build a fully qualifying disk SimpleNamespace.
    Defaults to time_created=10 days ago when no age anchor is supplied,
    so the disk passes the 7-day age check out of the box.
    """
    if last_ownership_update_time is None and time_created is None:
        time_created = _ago(10)
    return SimpleNamespace(
        id=disk_id,
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        disk_state=disk_state,
        managed_by=managed_by,
        managed_by_extended=managed_by_extended,
        max_shares=max_shares,
        optimized_for_frequent_attach=optimized_for_frequent_attach,
        last_ownership_update_time=last_ownership_update_time,
        time_created=time_created,
        sku=SimpleNamespace(name=sku_name) if sku_name else None,
        disk_size_gb=disk_size_gb,
        tags=tags,
        properties=properties,
    )


def _run(disks, region_filter=None):
    client = MagicMock()
    client.disks.list.return_value = disks
    return find_unattached_managed_disks(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=client,
    )


def _one(disks, region_filter=None):
    results = _run(disks, region_filter)
    assert len(results) == 1
    return results[0]


# ===========================================================================
# TestMustEmit -- spec 13.1
# ===========================================================================


class TestMustEmit:
    def test_qualifying_disk_emits(self):
        assert len(_run([_make_disk()])) == 1

    def test_spec_example_lowt_10_days_emits(self):
        # spec 13.1.1: all conditions met, last_ownership_update_time 10 days ago
        disk = _make_disk(
            provisioning_state="Succeeded",
            disk_state="Unattached",
            managed_by=None,
            managed_by_extended=None,
            max_shares=1,
            optimized_for_frequent_attach=False,
            last_ownership_update_time=_ago(10),
        )
        assert len(_run([disk])) == 1

    def test_multiple_qualifying_disks_all_emit(self):
        disks = [_make_disk(disk_id=f"disk-{i}", name=f"d{i}") for i in range(3)]
        assert len(_run(disks)) == 3


# ===========================================================================
# TestMustSkip -- spec 13.2
# ===========================================================================


class TestMustSkip:
    def test_managed_by_present_skips(self):
        assert _run([_make_disk(managed_by="/subscriptions/s/vms/vm1")]) == []

    def test_managed_by_extended_nonempty_skips(self):
        assert _run([_make_disk(managed_by_extended=["/subscriptions/s/vms/vm1"])]) == []

    def test_disk_state_reserved_skips(self):
        assert _run([_make_disk(disk_state="Reserved")]) == []

    def test_disk_state_active_sas_skips(self):
        assert _run([_make_disk(disk_state="ActiveSAS")]) == []

    def test_disk_state_ready_to_upload_skips(self):
        assert _run([_make_disk(disk_state="ReadyToUpload")]) == []

    def test_max_shares_gt_1_skips(self):
        assert _run([_make_disk(max_shares=2)]) == []

    def test_optimized_for_frequent_attach_true_skips(self):
        assert _run([_make_disk(optimized_for_frequent_attach=True)]) == []

    def test_primary_anchor_recent_skips_even_if_time_created_old(self):
        # spec 13.2.8: last_ownership_update_time 2 days ago, time_created 200 days ago
        # -> primary is used, no fallback, skip
        disk = _make_disk(
            last_ownership_update_time=_ago(2),
            time_created=_ago(200),
        )
        assert _run([disk]) == []

    def test_provisioning_state_not_succeeded_skips(self):
        assert _run([_make_disk(provisioning_state="Failed")]) == []


# ===========================================================================
# TestIdNameGuards -- spec 8.1, 8.2
# ===========================================================================


class TestIdNameGuards:
    def test_id_absent_skips(self):
        disk = _make_disk()
        del disk.id
        assert _run([disk]) == []

    def test_id_empty_skips(self):
        assert _run([_make_disk(disk_id="")]) == []

    def test_name_absent_skips(self):
        disk = _make_disk()
        del disk.name
        assert _run([disk]) == []

    def test_name_empty_skips(self):
        assert _run([_make_disk(name="")]) == []


# ===========================================================================
# TestRegionFilter -- spec 8.3
# ===========================================================================


class TestRegionFilter:
    def test_no_filter_emits(self):
        assert len(_run([_make_disk()])) == 1

    def test_matching_filter_emits(self):
        assert len(_run([_make_disk(location="eastus")], region_filter="eastus")) == 1

    def test_filter_is_case_insensitive(self):
        # Both sides are lowercased before comparison
        assert len(_run([_make_disk(location="eastus")], region_filter="EastUS")) == 1

    def test_mismatched_filter_skips(self):
        assert _run([_make_disk(location="eastus")], region_filter="westus") == []


# ===========================================================================
# TestProvisioningStateContract -- spec 9.1
# ===========================================================================


class TestProvisioningStateContract:
    def test_failed_skips(self):
        assert _run([_make_disk(provisioning_state="Failed")]) == []

    def test_none_skips(self):
        assert _run([_make_disk(provisioning_state=None)]) == []

    def test_sdk_nested_conflict_skips(self):
        # SDK "Succeeded", nested camelCase "Failed" -> conflict -> skip
        disk = _make_disk(provisioning_state="Succeeded")
        disk.properties = SimpleNamespace(provisioningState="Failed")
        assert _run([disk]) == []

    def test_nested_snake_fallback_emits(self):
        # SDK None, nested snake "Succeeded" -> use nested -> emit
        disk = _make_disk(provisioning_state=None)
        disk.properties = SimpleNamespace(
            provisioning_state="Succeeded",
            provisioningState=None,
        )
        assert len(_run([disk])) == 1

    def test_nested_camelcase_fallback_emits(self):
        # SDK None, nested camelCase "Succeeded" -> use nested -> emit
        disk = _make_disk(provisioning_state=None)
        disk.properties = SimpleNamespace(provisioningState="Succeeded")
        assert len(_run([disk])) == 1


# ===========================================================================
# TestDiskStateContract -- spec 9.2
# ===========================================================================


class TestDiskStateContract:
    def test_attached_skips(self):
        assert _run([_make_disk(disk_state="Attached")]) == []

    def test_frozen_skips(self):
        assert _run([_make_disk(disk_state="Frozen")]) == []

    def test_none_skips(self):
        assert _run([_make_disk(disk_state=None)]) == []

    def test_sdk_nested_conflict_skips(self):
        # SDK "Unattached", nested "Attached" -> conflict -> skip
        disk = _make_disk(disk_state="Unattached")
        disk.properties = SimpleNamespace(diskState="Attached")
        assert _run([disk]) == []

    def test_nested_camelcase_fallback_emits(self):
        # SDK None, nested camelCase "Unattached" -> use nested -> emit
        disk = _make_disk(disk_state=None)
        disk.properties = SimpleNamespace(diskState="Unattached")
        assert len(_run([disk])) == 1


# ===========================================================================
# TestAttachmentContract -- spec 9.3
# ===========================================================================


class TestAttachmentContract:
    def test_managed_by_confirmed_absent_emits(self):
        # Attribute present on disk with value None -> confirmed absent
        disk = _make_disk(managed_by=None)
        assert len(_run([disk])) == 1

    def test_managed_by_absent_from_all_sources_skips(self):
        # Attribute deleted from disk, no properties -> _UNRESOLVABLE -> skip
        disk = _make_disk()
        del disk.managed_by
        assert _run([disk]) == []

    def test_managed_by_sdk_none_nested_nonempty_conflict_skips(self):
        # SDK None (absent), nested camelCase non-empty (attached) -> conflict -> skip
        disk = _make_disk(managed_by=None)
        disk.properties = SimpleNamespace(managedBy="/subscriptions/s/vms/vm-conflict")
        assert _run([disk]) == []

    def test_managed_by_extended_confirmed_empty_emits(self):
        disk = _make_disk(managed_by_extended=None)  # None -> [] confirmed empty
        assert len(_run([disk])) == 1

    def test_managed_by_extended_absent_from_all_sources_skips(self):
        disk = _make_disk()
        del disk.managed_by_extended
        # properties is None -> neither source found -> _UNRESOLVABLE -> skip
        assert _run([disk]) == []

    def test_managed_by_extended_present_source_uncoercible_skips(self):
        # SDK confirmed empty (None -> []), nested present but non-iterable -> skip
        disk = _make_disk(managed_by_extended=None)
        # Only camelCase on props so snake_case returns _UNRESOLVABLE, then camelCase=42
        disk.properties = SimpleNamespace(managedByExtended=42)
        assert _run([disk]) == []

    def test_managed_by_extended_conflict_empty_vs_nonempty_skips(self):
        # SDK empty ([]), nested non-empty -> conflict -> skip
        disk = _make_disk(managed_by_extended=None)  # sdk: []
        disk.properties = SimpleNamespace(managedByExtended=["/subscriptions/s/vms/vm1"])
        assert _run([disk]) == []

    def test_managed_by_extended_nested_camelcase_empty_emits(self):
        # SDK absent, nested camelCase empty list -> confirmed empty -> emit
        disk = _make_disk()
        del disk.managed_by_extended
        disk.properties = SimpleNamespace(managedByExtended=[])
        assert len(_run([disk])) == 1


# ===========================================================================
# TestSharedDiskContract -- spec 9.4
# ===========================================================================


class TestSharedDiskContract:
    def test_max_shares_1_emits(self):
        assert len(_run([_make_disk(max_shares=1)])) == 1

    def test_max_shares_2_skips(self):
        assert _run([_make_disk(max_shares=2)]) == []

    def test_max_shares_unknown_skips(self):
        # None -> unknown -> must not be treated as 1 -> skip
        assert _run([_make_disk(max_shares=None)]) == []

    def test_max_shares_malformed_string_skips(self):
        # Non-numeric -> coercion fails -> unresolvable -> skip
        assert _run([_make_disk(max_shares="abc")]) == []

    def test_max_shares_conflict_skips(self):
        # SDK 1, nested camelCase 2 -> conflict -> skip
        disk = _make_disk(max_shares=1)
        disk.properties = SimpleNamespace(maxShares=2)
        assert _run([disk]) == []

    def test_max_shares_nested_camelcase_fallback_emits(self):
        # SDK None, nested camelCase 1 -> use nested -> emit
        disk = _make_disk(max_shares=None)
        disk.properties = SimpleNamespace(maxShares=1)
        assert len(_run([disk])) == 1


# ===========================================================================
# TestFrequentAttachContract -- spec 9.5
# ===========================================================================


class TestFrequentAttachContract:
    def test_false_emits(self):
        assert len(_run([_make_disk(optimized_for_frequent_attach=False)])) == 1

    def test_true_skips(self):
        assert _run([_make_disk(optimized_for_frequent_attach=True)]) == []

    def test_unknown_skips(self):
        # None -> unknown -> must not be treated as False -> skip
        assert _run([_make_disk(optimized_for_frequent_attach=None)]) == []

    def test_string_false_skips(self):
        # "false" is not a reliable boolean (bool("false") == True is wrong) -> skip
        assert _run([_make_disk(optimized_for_frequent_attach="false")]) == []

    def test_string_true_skips(self):
        assert _run([_make_disk(optimized_for_frequent_attach="true")]) == []

    def test_conflict_skips(self):
        # SDK False, nested camelCase True -> conflict -> skip
        disk = _make_disk(optimized_for_frequent_attach=False)
        disk.properties = SimpleNamespace(optimizedForFrequentAttach=True)
        assert _run([disk]) == []

    def test_nested_camelcase_false_fallback_emits(self):
        # SDK None, nested camelCase False -> use nested -> emit
        disk = _make_disk(optimized_for_frequent_attach=None)
        disk.properties = SimpleNamespace(optimizedForFrequentAttach=False)
        assert len(_run([disk])) == 1


# ===========================================================================
# TestAgeAnchorContract -- spec 9.6
# ===========================================================================


class TestAgeAnchorContract:
    def test_last_ownership_update_time_used_as_primary(self):
        disk = _make_disk(last_ownership_update_time=_ago(10))
        f = _one([disk])
        assert f.details["age_anchor"] == "last_ownership_update_time"

    def test_time_created_used_as_fallback_when_primary_absent(self):
        disk = _make_disk(time_created=_ago(10))
        # last_ownership_update_time defaults to None in _make_disk when time_created given
        f = _one([disk])
        assert f.details["age_anchor"] == "time_created"

    def test_primary_present_recent_skips_no_fallback_to_time_created(self):
        # spec 13.2.8
        disk = _make_disk(last_ownership_update_time=_ago(2), time_created=_ago(200))
        assert _run([disk]) == []

    def test_primary_present_invalid_skips_no_fallback(self):
        # Primary exists but unparseable -> skip; time_created not consulted
        disk = _make_disk(time_created=_ago(200))
        disk.last_ownership_update_time = "not-a-datetime"
        assert _run([disk]) == []

    def test_primary_future_skips(self):
        disk = _make_disk(last_ownership_update_time=_ago(-1))
        assert _run([disk]) == []

    def test_time_created_future_skips(self):
        disk = _make_disk(last_ownership_update_time=None, time_created=_ago(-1))
        assert _run([disk]) == []

    def test_both_absent_skips(self):
        disk = _make_disk()
        disk.last_ownership_update_time = None
        disk.time_created = None
        assert _run([disk]) == []

    def test_age_exactly_7_days_emits(self):
        disk = _make_disk(last_ownership_update_time=_ago(7))
        assert len(_run([disk])) == 1

    def test_age_6_days_skips(self):
        disk = _make_disk(last_ownership_update_time=_ago(6))
        assert _run([disk]) == []

    def test_iso_string_datetime_parsed_for_time_created(self):
        # Raw ARM REST payload may return ISO strings with "Z" suffix
        iso_str = (_ago(10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        disk = _make_disk(last_ownership_update_time=None, time_created=None)
        disk.time_created = iso_str
        assert len(_run([disk])) == 1

    def test_iso_string_datetime_parsed_for_last_ownership_update_time(self):
        iso_str = (_ago(10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        disk = _make_disk(last_ownership_update_time=None, time_created=None)
        disk.last_ownership_update_time = iso_str
        assert len(_run([disk])) == 1


# ===========================================================================
# TestFindingShape -- spec 11
# ===========================================================================


class TestFindingShape:
    def setup_method(self):
        self.f = _one([_make_disk(disk_id="disk-abc", name="my-disk", tags={"env": "prod"})])

    def test_provider(self):
        assert self.f.provider == "azure"

    def test_rule_id(self):
        assert self.f.rule_id == "azure.compute.disk.unattached"

    def test_resource_type(self):
        assert self.f.resource_type == "azure.compute.disk"

    def test_resource_id(self):
        assert self.f.resource_id == "disk-abc"

    def test_region(self):
        assert self.f.region == "eastus"

    def test_risk_low(self):
        from cleancloud.core.risk import RiskLevel

        assert self.f.risk == RiskLevel.LOW

    def test_confidence_medium(self):
        from cleancloud.core.confidence import ConfidenceLevel

        assert self.f.confidence == ConfidenceLevel.MEDIUM

    def test_estimated_monthly_cost_always_none(self):
        assert self.f.estimated_monthly_cost_usd is None

    def test_signals_used_count(self):
        assert len(self.f.evidence.signals_used) == 8

    def test_required_detail_keys(self):
        d = self.f.details
        for key in (
            "resource_name",
            "subscription_id",
            "disk_state",
            "managed_by",
            "managed_by_extended",
            "max_shares",
            "optimized_for_frequent_attach",
            "age_anchor",
            "age_days",
            "sku",
            "size_gb",
            "tags",
        ):
            assert key in d, f"missing detail key: {key}"

    def test_tags_present_when_disk_has_tags(self):
        assert self.f.details["tags"] == {"env": "prod"}

    def test_tags_empty_dict_when_disk_has_none_tags(self):
        f = _one([_make_disk(tags=None)])
        assert f.details["tags"] == {}

    def test_age_anchor_label_in_details(self):
        assert self.f.details["age_anchor"] in ("last_ownership_update_time", "time_created")

    def test_age_days_is_numeric(self):
        assert isinstance(self.f.details["age_days"], float)


# ===========================================================================
# TestFailureBehavior -- spec 12
# ===========================================================================


class TestFailureBehavior:
    def test_disk_list_raises_propagates(self):
        client = MagicMock()
        client.disks.list.side_effect = RuntimeError("network error")
        with pytest.raises(RuntimeError):
            find_unattached_managed_disks(subscription_id=_SUB, credential=None, client=client)

    def test_malformed_disk_skipped_good_disk_still_emits(self):
        bad = _make_disk(disk_id="")  # fails id guard
        good = _make_disk(disk_id="good", name="good")
        assert len(_run([bad, good])) == 1

    def test_no_findings_when_all_disks_skip(self):
        disks = [
            _make_disk(managed_by="/vm/1"),
            _make_disk(disk_state="Reserved"),
            _make_disk(max_shares=2),
        ]
        assert _run(disks) == []


# ===========================================================================
# TestResolveManagedBy -- unit
# ===========================================================================


class TestResolveManagedBy:
    def test_attribute_none_is_confirmed_absent(self):
        disk = SimpleNamespace(managed_by=None, properties=None)
        assert _resolve_managed_by(disk) is None

    def test_attribute_nonempty_is_confirmed_attached(self):
        disk = SimpleNamespace(managed_by="/subscriptions/s/vms/vm1", properties=None)
        assert _resolve_managed_by(disk) == "/subscriptions/s/vms/vm1"

    def test_attribute_missing_returns_unresolvable(self):
        disk = SimpleNamespace(properties=None)
        assert _resolve_managed_by(disk) is _UNRESOLVABLE

    def test_sdk_none_nested_nonempty_is_conflict(self):
        disk = SimpleNamespace(
            managed_by=None,
            properties=SimpleNamespace(managedBy="/subscriptions/s/vms/vm2"),
        )
        assert _resolve_managed_by(disk) is _UNRESOLVABLE

    def test_both_absent_returns_unresolvable(self):
        disk = SimpleNamespace(properties=SimpleNamespace())
        assert _resolve_managed_by(disk) is _UNRESOLVABLE

    def test_nested_snake_fallback_none_is_absent(self):
        disk = SimpleNamespace(properties=SimpleNamespace(managed_by=None, managedBy=None))
        assert _resolve_managed_by(disk) is None


# ===========================================================================
# TestResolveManagedByExtended -- unit
# ===========================================================================


class TestResolveManagedByExtended:
    def test_none_is_confirmed_empty(self):
        disk = SimpleNamespace(managed_by_extended=None, properties=None)
        assert _resolve_managed_by_extended(disk) == []

    def test_nonempty_list_is_attached(self):
        disk = SimpleNamespace(managed_by_extended=["/vm/1"], properties=None)
        assert _resolve_managed_by_extended(disk) == ["/vm/1"]

    def test_absent_from_all_sources_returns_unresolvable(self):
        disk = SimpleNamespace(properties=None)
        assert _resolve_managed_by_extended(disk) is _UNRESOLVABLE

    def test_present_source_uncoercible_returns_unresolvable(self):
        # SDK confirmed empty, nested present but non-iterable
        disk = SimpleNamespace(
            managed_by_extended=None,
            properties=SimpleNamespace(managedByExtended=42),
        )
        assert _resolve_managed_by_extended(disk) is _UNRESOLVABLE

    def test_conflict_empty_vs_nonempty_returns_unresolvable(self):
        disk = SimpleNamespace(
            managed_by_extended=None,
            properties=SimpleNamespace(managedByExtended=["/vm/1"]),
        )
        assert _resolve_managed_by_extended(disk) is _UNRESOLVABLE

    def test_both_empty_agree_returns_empty_list(self):
        disk = SimpleNamespace(
            managed_by_extended=None,
            properties=SimpleNamespace(managedByExtended=[]),
        )
        assert _resolve_managed_by_extended(disk) == []


# ===========================================================================
# TestResolveMaxShares -- unit
# ===========================================================================


class TestResolveMaxShares:
    def test_1_returns_1(self):
        disk = SimpleNamespace(max_shares=1, properties=None)
        assert _resolve_max_shares(disk) == 1

    def test_2_returns_2(self):
        disk = SimpleNamespace(max_shares=2, properties=None)
        assert _resolve_max_shares(disk) == 2

    def test_none_returns_none(self):
        disk = SimpleNamespace(max_shares=None, properties=None)
        assert _resolve_max_shares(disk) is None

    def test_malformed_string_returns_none(self):
        disk = SimpleNamespace(max_shares="abc", properties=None)
        assert _resolve_max_shares(disk) is None

    def test_conflict_returns_none(self):
        disk = SimpleNamespace(
            max_shares=1,
            properties=SimpleNamespace(max_shares=None, maxShares=2),
        )
        assert _resolve_max_shares(disk) is None

    def test_nested_camelcase_fallback(self):
        disk = SimpleNamespace(
            max_shares=None,
            properties=SimpleNamespace(max_shares=None, maxShares=1),
        )
        assert _resolve_max_shares(disk) == 1


# ===========================================================================
# TestResolveOptimizedForFrequentAttach -- unit
# ===========================================================================


class TestResolveOptimizedForFrequentAttach:
    def test_false_returns_false(self):
        disk = SimpleNamespace(optimized_for_frequent_attach=False, properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is False

    def test_true_returns_true(self):
        disk = SimpleNamespace(optimized_for_frequent_attach=True, properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is True

    def test_none_returns_none(self):
        disk = SimpleNamespace(optimized_for_frequent_attach=None, properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is None

    def test_string_false_returns_none(self):
        disk = SimpleNamespace(optimized_for_frequent_attach="false", properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is None

    def test_string_true_returns_none(self):
        disk = SimpleNamespace(optimized_for_frequent_attach="true", properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is None

    def test_integer_1_returns_none(self):
        # int is not a reliable boolean
        disk = SimpleNamespace(optimized_for_frequent_attach=1, properties=None)
        assert _resolve_optimized_for_frequent_attach(disk) is None

    def test_conflict_returns_none(self):
        disk = SimpleNamespace(
            optimized_for_frequent_attach=False,
            properties=SimpleNamespace(
                optimized_for_frequent_attach=None,
                optimizedForFrequentAttach=True,
            ),
        )
        assert _resolve_optimized_for_frequent_attach(disk) is None

    def test_nested_camelcase_false_fallback(self):
        disk = SimpleNamespace(
            optimized_for_frequent_attach=None,
            properties=SimpleNamespace(
                optimized_for_frequent_attach=None,
                optimizedForFrequentAttach=False,
            ),
        )
        assert _resolve_optimized_for_frequent_attach(disk) is False


# ===========================================================================
# TestCoerceDatetime -- unit
# ===========================================================================


class TestCoerceDatetime:
    def test_none_returns_none(self):
        assert _coerce_datetime(None) is None

    def test_aware_datetime_returned_unchanged(self):
        dt = datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)
        assert _coerce_datetime(dt) == dt

    def test_naive_datetime_gets_utc(self):
        dt = datetime(2024, 1, 15, 10, 0)
        result = _coerce_datetime(dt)
        assert result.tzinfo == timezone.utc

    def test_iso_string_z_suffix(self):
        result = _coerce_datetime("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2024 and result.month == 1 and result.day == 15

    def test_iso_string_plus_offset(self):
        result = _coerce_datetime("2024-01-15T10:30:00+00:00")
        assert result is not None
        assert result.tzinfo is not None

    def test_unparseable_string_returns_none(self):
        assert _coerce_datetime("not-a-date") is None

    def test_integer_returns_none(self):
        assert _coerce_datetime(12345) is None


# ===========================================================================
# TestResolveAgeAnchor -- unit
# ===========================================================================


class TestResolveAgeAnchor:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_last_ownership_update_time_returned_as_primary(self):
        now = self._now()
        lowt = now - timedelta(days=10)
        disk = SimpleNamespace(
            last_ownership_update_time=lowt,
            time_created=now - timedelta(days=200),
            properties=None,
        )
        label, days = _resolve_age_anchor(disk, now)
        assert label == "last_ownership_update_time"
        assert 9.9 < days < 10.1

    def test_time_created_used_when_primary_absent(self):
        now = self._now()
        disk = SimpleNamespace(
            last_ownership_update_time=None,
            time_created=now - timedelta(days=10),
            properties=None,
        )
        label, days = _resolve_age_anchor(disk, now)
        assert label == "time_created"
        assert 9.9 < days < 10.1

    def test_primary_invalid_returns_none_no_fallback(self):
        now = self._now()
        disk = SimpleNamespace(
            last_ownership_update_time="bad-value",
            time_created=now - timedelta(days=200),
            properties=None,
        )
        assert _resolve_age_anchor(disk, now) is None

    def test_primary_future_returns_none(self):
        now = self._now()
        disk = SimpleNamespace(
            last_ownership_update_time=now + timedelta(days=1),
            time_created=now - timedelta(days=200),
            properties=None,
        )
        assert _resolve_age_anchor(disk, now) is None

    def test_both_absent_returns_none(self):
        now = self._now()
        disk = SimpleNamespace(
            last_ownership_update_time=None,
            time_created=None,
            properties=None,
        )
        assert _resolve_age_anchor(disk, now) is None
