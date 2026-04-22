"""Tests for azure.compute.snapshot.old rule."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.disk_snapshots_old import find_old_snapshots

_MAX_DAYS = 90  # default max_age_days
_REVIEW_DAYS = 30  # fixed review_age_days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snap_id(name: str) -> str:
    return (
        f"/subscriptions/sub-123/resourceGroups/rg" f"/providers/Microsoft.Compute/snapshots/{name}"
    )


def _make_snapshot(
    name: str = "snap-1",
    *,
    location: str = "eastus",
    age_days: int = 45,
    provisioning_state: str = "Succeeded",
    disk_size_gb: int = 10,
    sku_name: str = "Standard_LRS",
    incremental: bool = False,
    tags: dict = None,
    completion_percent: float = None,
    source_resource_id: str = None,
) -> SimpleNamespace:
    time_created = datetime.now(timezone.utc) - timedelta(days=age_days)
    sku = SimpleNamespace(name=sku_name) if sku_name is not None else None
    creation_data = SimpleNamespace(
        create_option="Copy",
        source_resource_id=source_resource_id,
    )
    snap = SimpleNamespace(
        id=_snap_id(name),
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        time_created=time_created,
        disk_size_gb=disk_size_gb,
        sku=sku,
        incremental=incremental,
        creation_data=creation_data,
        tags=tags if tags is not None else {},
    )
    if completion_percent is not None:
        snap.completion_percent = completion_percent
    return snap


def _run(mocker, snapshots, *, region_filter=None, max_age_days=_MAX_DAYS):
    client = mocker.MagicMock()
    client.snapshots.list.return_value = snapshots
    return find_old_snapshots(
        subscription_id="sub-123",
        credential=None,
        client=client,
        region_filter=region_filter,
        max_age_days=max_age_days,
    )


# ---------------------------------------------------------------------------
# TestMustEmit — spec 13.1
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_45_day_snapshot_emits(self, mocker):
        """spec 13.1 example 1: age=45, confidence LOW."""
        findings = _run(mocker, [_make_snapshot(age_days=45)])
        assert len(findings) == 1

    def test_120_day_snapshot_emits(self, mocker):
        """spec 13.1 example 2: age=120, confidence MEDIUM."""
        findings = _run(mocker, [_make_snapshot(age_days=120)])
        assert len(findings) == 1

    def test_incremental_snapshot_emits(self, mocker):
        """spec 13.1 example 3: incremental snapshots must not be suppressed."""
        snap = _make_snapshot(age_days=95, incremental=True)
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_exactly_at_review_threshold_emits(self, mocker):
        """age_days == 30 (lower bound inclusive) → emit."""
        findings = _run(mocker, [_make_snapshot(age_days=30)])
        assert len(findings) == 1

    def test_exactly_at_max_age_emits(self, mocker):
        """age_days == max_age_days (90) → emit with MEDIUM confidence."""
        findings = _run(mocker, [_make_snapshot(age_days=90)])
        assert len(findings) == 1

    def test_completion_percent_100_emits(self, mocker):
        """completionPercent == 100 → passes the guard → emit."""
        snap = _make_snapshot(age_days=45, completion_percent=100)
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_completion_percent_absent_emits(self, mocker):
        """completionPercent absent → guard not applied → emit."""
        findings = _run(mocker, [_make_snapshot(age_days=45)])
        assert len(findings) == 1

    def test_multiple_snapshots_mixed_ages(self, mocker):
        old = _make_snapshot("old", age_days=120)
        new = _make_snapshot("new", age_days=5)
        findings = _run(mocker, [old, new])
        assert len(findings) == 1
        assert findings[0].resource_id == _snap_id("old")

    def test_empty_snapshot_list(self, mocker):
        findings = _run(mocker, [])
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip — spec 13.2
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_too_new_skipped(self, mocker):
        """spec 13.2 example 1: age < 30 days → skip."""
        findings = _run(mocker, [_make_snapshot(age_days=10)])
        assert findings == []

    def test_29_days_skipped(self, mocker):
        """age_days == 29 (one below threshold) → skip."""
        findings = _run(mocker, [_make_snapshot(age_days=29)])
        assert findings == []

    def test_provisioning_state_creating_skipped(self, mocker):
        """spec 13.2 example 2: provisioningState != Succeeded → skip."""
        snap = _make_snapshot(age_days=45, provisioning_state="Creating")
        findings = _run(mocker, [snap])
        assert findings == []

    def test_provisioning_state_failed_skipped(self, mocker):
        snap = _make_snapshot(age_days=45, provisioning_state="Failed")
        findings = _run(mocker, [snap])
        assert findings == []

    def test_provisioning_state_none_skipped(self, mocker):
        snap = _make_snapshot(age_days=45, provisioning_state=None)
        findings = _run(mocker, [snap])
        assert findings == []

    def test_time_created_none_skipped(self, mocker):
        """spec 13.2 example 3: timeCreated absent → skip."""
        snap = _make_snapshot(age_days=45)
        snap.time_created = None
        findings = _run(mocker, [snap])
        assert findings == []

    def test_completion_percent_80_skipped(self, mocker):
        """spec 13.2 example 4: completionPercent < 100 → skip."""
        snap = _make_snapshot(age_days=45, completion_percent=80)
        findings = _run(mocker, [snap])
        assert findings == []

    def test_completion_percent_99_skipped(self, mocker):
        """completionPercent=99 (just below 100) → skip."""
        snap = _make_snapshot(age_days=45, completion_percent=99)
        findings = _run(mocker, [snap])
        assert findings == []

    def test_completion_percent_0_skipped(self, mocker):
        snap = _make_snapshot(age_days=45, completion_percent=0)
        findings = _run(mocker, [snap])
        assert findings == []

    def test_region_filter_mismatch_skipped(self, mocker):
        """spec 13.2 example 5: location != region_filter → skip."""
        snap = _make_snapshot(age_days=45, location="westus")
        findings = _run(mocker, [snap], region_filter="eastus")
        assert findings == []

    def test_id_none_skipped(self, mocker):
        """spec 13.2 example 6: id absent → skip."""
        snap = _make_snapshot(age_days=45)
        snap.id = None
        findings = _run(mocker, [snap])
        assert findings == []

    def test_id_empty_skipped(self, mocker):
        snap = _make_snapshot(age_days=45)
        snap.id = ""
        findings = _run(mocker, [snap])
        assert findings == []

    def test_name_absent_skipped(self, mocker):
        """resource_name is required; snapshot without name is skipped conservatively."""
        snap = _make_snapshot(age_days=45)
        snap.name = None
        findings = _run(mocker, [snap])
        assert findings == []

    def test_completion_percent_non_numeric_skipped(self, mocker):
        """Non-numeric completionPercent is malformed → skip conservatively."""
        snap = _make_snapshot(age_days=45, completion_percent=100)
        snap.completion_percent = "not-a-number"
        findings = _run(mocker, [snap])
        assert findings == []


# ---------------------------------------------------------------------------
# TestConfidenceModel — spec 8
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_lower_band_confidence_low(self, mocker):
        """30 <= age < 90 → LOW."""
        from cleancloud.core.confidence import ConfidenceLevel

        findings = _run(mocker, [_make_snapshot(age_days=45)])
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_upper_band_confidence_medium(self, mocker):
        """age >= 90 → MEDIUM."""
        from cleancloud.core.confidence import ConfidenceLevel

        findings = _run(mocker, [_make_snapshot(age_days=120)])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_confidence_never_high(self, mocker):
        """spec 8: HIGH must never be used regardless of age."""
        from cleancloud.core.confidence import ConfidenceLevel

        findings = _run(mocker, [_make_snapshot(age_days=1000)])
        assert findings[0].confidence != ConfidenceLevel.HIGH
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_exactly_at_max_age_is_medium(self, mocker):
        """age_days == max_age_days (90) → MEDIUM (>= max_age_days)."""
        from cleancloud.core.confidence import ConfidenceLevel

        findings = _run(mocker, [_make_snapshot(age_days=90)])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_one_below_max_age_is_low(self, mocker):
        """age_days == max_age_days - 1 (89) → LOW (< max_age_days)."""
        from cleancloud.core.confidence import ConfidenceLevel

        findings = _run(mocker, [_make_snapshot(age_days=89)])
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_custom_max_age_shifts_band(self, mocker):
        """Custom max_age_days=60: age=65 → MEDIUM; age=55 → LOW."""
        from cleancloud.core.confidence import ConfidenceLevel

        f65 = _run(mocker, [_make_snapshot(age_days=65)], max_age_days=60)
        f55 = _run(mocker, [_make_snapshot(age_days=55)], max_age_days=60)
        assert f65[0].confidence == ConfidenceLevel.MEDIUM
        assert f55[0].confidence == ConfidenceLevel.LOW


# ---------------------------------------------------------------------------
# TestRegionFilter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_exact_lowercase_match_emits(self, mocker):
        snap = _make_snapshot(age_days=45, location="eastus")
        findings = _run(mocker, [snap], region_filter="eastus")
        assert len(findings) == 1

    def test_no_match_skips(self, mocker):
        snap = _make_snapshot(age_days=45, location="westus")
        findings = _run(mocker, [snap], region_filter="eastus")
        assert findings == []

    def test_no_filter_includes_all_regions(self, mocker):
        s1 = _make_snapshot("s1", age_days=45, location="eastus")
        s2 = _make_snapshot("s2", age_days=45, location="westeurope")
        findings = _run(mocker, [s1, s2])
        assert len(findings) == 2

    def test_region_stored_as_lowercase(self, mocker):
        snap = _make_snapshot(age_days=45, location="eastus")
        findings = _run(mocker, [snap])
        assert findings[0].region == "eastus"


# ---------------------------------------------------------------------------
# TestFindingShape — spec 12.1
# ---------------------------------------------------------------------------


class TestFindingShape:
    @pytest.fixture
    def finding(self, mocker):
        f = _run(mocker, [_make_snapshot(age_days=45)])
        assert len(f) == 1
        return f[0]

    def test_provider(self, finding):
        assert finding.provider == "azure"

    def test_rule_id(self, finding):
        assert finding.rule_id == "azure.compute.snapshot.old"

    def test_resource_type(self, finding):
        assert finding.resource_type == "azure.compute.snapshot"

    def test_resource_id(self, finding):
        assert finding.resource_id == _snap_id("snap-1")

    def test_risk_low(self, finding):
        from cleancloud.core.risk import RiskLevel

        assert finding.risk == RiskLevel.LOW

    def test_region_is_lowercase(self, finding):
        assert finding.region == "eastus"

    def test_cost_always_none(self, finding):
        """spec 10: estimated_monthly_cost_usd must always be None."""
        assert finding.estimated_monthly_cost_usd is None

    def test_cost_none_regardless_of_disk_size(self, mocker):
        """spec 10 anti-goal: large diskSizeGB must not produce a cost estimate."""
        snap = _make_snapshot(age_days=45, disk_size_gb=1000)
        findings = _run(mocker, [snap])
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestEvidenceContract — spec 12.2
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    @pytest.fixture
    def finding(self, mocker):
        f = _run(mocker, [_make_snapshot(age_days=45)])
        assert len(f) == 1
        return f[0]

    def test_signal_age(self, finding):
        assert any("Snapshot age is 45 days" in s for s in finding.evidence.signals_used)

    def test_signal_provisioning_state(self, finding):
        assert "Snapshot provisioning state is Succeeded" in finding.evidence.signals_used

    def test_completion_percent_signal_when_present(self, mocker):
        """completionPercent was present and used as gate → signal reflects actual value."""
        snap = _make_snapshot(age_days=45, completion_percent=100)
        findings = _run(mocker, [snap])
        assert "Snapshot completionPercent is 100" in findings[0].evidence.signals_used

    def test_completion_percent_signal_above_100(self, mocker):
        """completionPercent > 100 passes the gate and the signal shows the actual value."""
        snap = _make_snapshot(age_days=45, completion_percent=100.5)
        findings = _run(mocker, [snap])
        assert "Snapshot completionPercent is 100.5" in findings[0].evidence.signals_used

    def test_no_completion_signal_when_absent(self, finding):
        """completionPercent absent → no completion signal in evidence."""
        assert not any("completionPercent" in s for s in finding.evidence.signals_used)

    def test_signals_not_checked_restore(self, finding):
        assert "Business or application restore intent" in finding.evidence.signals_not_checked

    def test_signals_not_checked_backup(self, finding):
        assert "Azure Backup or external backup ownership" in finding.evidence.signals_not_checked

    def test_signals_not_checked_dr(self, finding):
        assert "Disaster recovery retention intent" in finding.evidence.signals_not_checked

    def test_signals_not_checked_billing(self, finding):
        assert (
            "Whether deleting the snapshot reduces billed used size"
            in finding.evidence.signals_not_checked
        )


# ---------------------------------------------------------------------------
# TestDetails — spec 12.3
# ---------------------------------------------------------------------------


class TestDetails:
    @pytest.fixture
    def finding(self, mocker):
        snap = _make_snapshot(
            "snap-x",
            age_days=45,
            disk_size_gb=20,
            sku_name="Premium_LRS",
            incremental=True,
            tags={"env": "prod"},
            source_resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/disk1",
        )
        f = _run(mocker, [snap])
        assert len(f) == 1
        return f[0]

    def test_resource_name(self, finding):
        assert finding.details["resource_name"] == "snap-x"

    def test_subscription_id(self, finding):
        assert finding.details["subscription_id"] == "sub-123"

    def test_age_days(self, finding):
        assert finding.details["age_days"] == 45

    def test_time_created_is_iso_string(self, finding):
        val = finding.details["time_created"]
        assert isinstance(val, str)
        assert "T" in val

    def test_disk_size_gb(self, finding):
        assert finding.details["disk_size_gb"] == 20

    def test_sku(self, finding):
        assert finding.details["sku"] == "Premium_LRS"

    def test_sku_none_when_absent(self, mocker):
        snap = _make_snapshot(age_days=45, sku_name=None)
        findings = _run(mocker, [snap])
        assert findings[0].details["sku"] is None

    def test_incremental(self, finding):
        assert finding.details["incremental"] is True

    def test_source_resource_id(self, finding):
        assert "disk1" in finding.details["source_resource_id"]

    def test_source_resource_id_none_when_absent(self, mocker):
        snap = _make_snapshot(age_days=45, source_resource_id=None)
        findings = _run(mocker, [snap])
        assert findings[0].details["source_resource_id"] is None

    def test_tags_populated(self, finding):
        assert finding.details["tags"] == {"env": "prod"}

    def test_tags_normalized_to_empty_dict(self, mocker):
        """spec 12.3: tags must always be present, normalized to {} when None."""
        snap = _make_snapshot(age_days=45)
        snap.tags = None
        findings = _run(mocker, [snap])
        assert findings[0].details["tags"] == {}


# ---------------------------------------------------------------------------
# TestTimeCreated
# ---------------------------------------------------------------------------


class TestTimeCreated:
    def test_aware_datetime_accepted(self, mocker):
        snap = _make_snapshot(age_days=45)
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_naive_datetime_treated_as_utc(self, mocker):
        snap = _make_snapshot(age_days=45)
        snap.time_created = datetime.now() - timedelta(days=45)  # naive
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_iso_string_with_tz_parsed(self, mocker):
        """ISO 8601 string with timezone (Z) is accepted."""
        snap = _make_snapshot(age_days=45)
        snap.time_created = "2020-01-01T00:00:00Z"  # well over 30 days ago
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_naive_iso_string_treated_as_utc(self, mocker):
        """Naive ISO string (no tz offset) must not raise when subtracted from now."""
        snap = _make_snapshot(age_days=45)
        snap.time_created = "2020-01-01T00:00:00"  # no timezone — must not raise TypeError
        findings = _run(mocker, [snap])
        assert len(findings) == 1

    def test_unparseable_string_time_created_skipped(self, mocker):
        """Unparseable string for time_created → skip."""
        snap = _make_snapshot(age_days=45)
        snap.time_created = "not-a-date"
        findings = _run(mocker, [snap])
        assert findings == []

    def test_non_string_non_datetime_time_created_skipped(self, mocker):
        """Non-string, non-datetime time_created → skip."""
        snap = _make_snapshot(age_days=45)
        snap.time_created = 12345  # integer, not parseable
        findings = _run(mocker, [snap])
        assert findings == []


# ---------------------------------------------------------------------------
# TestFailureBehavior — spec 11
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_list_exception_propagates(self, mocker):
        """spec 11: snapshots.list() failure must propagate, not return []."""
        client = mocker.MagicMock()
        client.snapshots.list.side_effect = RuntimeError("API unavailable")
        with pytest.raises(RuntimeError, match="API unavailable"):
            find_old_snapshots(
                subscription_id="sub-123",
                credential=None,
                client=client,
            )
