"""Tests for azure.container_registry.unused rule."""

import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.container_registry_unused import (
    find_unused_container_registries,
)

# Use a 1-day window for most tests: keeps expected_buckets small (~25)
# while still exercising all coverage/retry logic.
_DAYS = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_h() -> datetime:
    """Current UTC time floored to the hour."""
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _registry_id(name: str) -> str:
    return (
        f"/subscriptions/sub-123/resourceGroups/rg-test"
        f"/providers/Microsoft.ContainerRegistry/registries/{name}"
    )


def _make_registry(
    name: str,
    *,
    location: str = "eastus",
    sku_name: str = "Standard",
    provisioning_state: str = "Succeeded",
    tags: dict = None,
    creation_date: datetime = None,
    days_unused: int = _DAYS,
) -> SimpleNamespace:
    if creation_date is None:
        # One hour before window_start — always passes the creation date guard.
        creation_date = (
            datetime.now(timezone.utc) - timedelta(days=days_unused) - timedelta(hours=1)
        )
    sku = SimpleNamespace(name=sku_name) if sku_name is not None else None
    return SimpleNamespace(
        id=_registry_id(name),
        name=name,
        location=location,
        sku=sku,
        provisioning_state=provisioning_state,
        creation_date=creation_date,
        tags=tags if tags is not None else {},
    )


def _make_metric_response(
    total_value: float = 0.0,
    days_unused: int = _DAYS,
    coverage_fraction: float = 0.92,
) -> SimpleNamespace:
    """
    Metric response with enough in-window hourly datapoints to satisfy
    coverage_fraction of expected_buckets for the given days_unused.

    Timestamps are offset 2h+ from now so they stay safely inside
    [window_start, window_end) regardless of sub-hour timing.
    """
    now = _now_h()
    approx_expected = days_unused * 24 + 1  # conservative upper bound
    num_points = math.ceil(approx_expected * coverage_fraction)
    data_points = [
        SimpleNamespace(timestamp=now - timedelta(hours=i + 2), total=total_value)
        for i in range(num_points)
    ]
    return SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data_points)])])


def _make_sparse_response() -> SimpleNamespace:
    """Metric response with only 1 datapoint — coverage well below 80%."""
    now = _now_h()
    data_points = [SimpleNamespace(timestamp=now - timedelta(hours=2), total=0.0)]
    return SimpleNamespace(value=[SimpleNamespace(timeseries=[SimpleNamespace(data=data_points)])])


def _make_clients(mocker, registries, metric_side_effects):
    acr = mocker.MagicMock()
    mon = mocker.MagicMock()
    acr.registries.list.return_value = registries
    mon.metrics.list.side_effect = metric_side_effects
    return acr, mon


def _run(mocker, registries, metric_side_effects, *, days_unused=_DAYS, region_filter=None):
    acr, mon = _make_clients(mocker, registries, metric_side_effects)
    return find_unused_container_registries(
        subscription_id="sub-123",
        credential=None,
        client=acr,
        monitor_client=mon,
        days_unused=days_unused,
        region_filter=region_filter,
    )


# ---------------------------------------------------------------------------
# Autouse: suppress retry sleeps so tests run instantly
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    return mocker.patch("cleancloud.providers.azure.rules.container_registry_unused.time.sleep")


# ---------------------------------------------------------------------------
# TestMustEmit — spec 14.1
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_standard_sku_emits(self, mocker):
        reg = _make_registry("acr1", sku_name="Standard")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_premium_sku_emits(self, mocker):
        reg = _make_registry("acr1", sku_name="Premium")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == 50.0

    def test_basic_sku_emits(self, mocker):
        reg = _make_registry("acr1", sku_name="Basic")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == 5.0

    def test_unknown_sku_emits_with_null_cost(self, mocker):
        """spec 14.1 example 4: unknown SKU → emit, cost None."""
        reg = _make_registry("acr1", sku_name=None)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_both_metrics_zero_emits(self, mocker):
        reg = _make_registry("acr1")
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(0.0), _make_metric_response(0.0)],
        )
        assert len(findings) == 1

    def test_multiple_registries_only_unused_emits(self, mocker):
        unused = _make_registry("unused")
        active = _make_registry("active")
        findings = _run(
            mocker,
            [unused, active],
            [
                _make_metric_response(0.0),  # unused pull → ZERO
                _make_metric_response(0.0),  # unused push → ZERO
                _make_metric_response(50.0),  # active pull → ACTIVE → skip
            ],
        )
        assert len(findings) == 1
        assert "unused" in findings[0].resource_id

    def test_empty_registry_list(self, mocker):
        findings = _run(mocker, [], [])
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip — spec 14.2
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_registry_id_none_skipped(self, mocker):
        reg = _make_registry("acr1")
        reg.id = None
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_registry_id_empty_skipped(self, mocker):
        reg = _make_registry("acr1")
        reg.id = ""
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_provisioning_state_creating_skipped(self, mocker):
        reg = _make_registry("acr1", provisioning_state="Creating")
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_provisioning_state_failed_skipped(self, mocker):
        reg = _make_registry("acr1", provisioning_state="Failed")
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_provisioning_state_none_skipped(self, mocker):
        reg = _make_registry("acr1", provisioning_state=None)
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_creation_date_absent_skipped(self, mocker):
        reg = _make_registry("acr1")
        del reg.creation_date
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_creation_date_after_window_start_skipped(self, mocker):
        """Registry too new — created after window_start → spec 8.5."""
        # days_unused=1 → window_start=now-24h; creation 1 hour ago is inside window
        reg = _make_registry(
            "acr1",
            creation_date=datetime.now(timezone.utc) - timedelta(hours=1),
            days_unused=_DAYS,
        )
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_creation_date_well_before_window_start_emits(self, mocker):
        """Created well before window_start → passes spec 8.5 guard."""
        reg = _make_registry(
            "acr1",
            creation_date=datetime.now(timezone.utc) - timedelta(days=_DAYS) - timedelta(hours=2),
            days_unused=_DAYS,
        )
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_pull_metric_active_skipped(self, mocker):
        reg = _make_registry("acr1")
        findings = _run(mocker, [reg], [_make_metric_response(50.0)])  # pull ACTIVE
        assert findings == []

    def test_push_metric_active_skipped(self, mocker):
        """Zero pulls but active pushes (spec 14.2 example 4) → skip."""
        reg = _make_registry("acr1")
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(0.0), _make_metric_response(10.0)],  # pull ZERO, push ACTIVE
        )
        assert findings == []

    def test_pull_metric_all_attempts_exception_skipped(self, mocker):
        """spec 14.2 example 5: pull metric UNKNOWN after all retries → skip."""
        reg = _make_registry("acr1")
        findings = _run(mocker, [reg], Exception("monitor unavailable"))
        assert findings == []

    def test_push_metric_all_attempts_exception_skipped(self, mocker):
        """spec 14.2 example 6: push metric UNKNOWN after all retries → skip."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                _make_metric_response(0.0),  # pull attempt 1 → ZERO
                Exception("push down"),  # push attempt 1
                Exception("push down"),  # push attempt 2
                Exception("push down"),  # push attempt 3
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert findings == []

    def test_pull_low_coverage_all_attempts_skipped(self, mocker):
        """spec 14.2 example 7: coverage < 0.80 on all pull attempts → UNKNOWN → skip."""
        reg = _make_registry("acr1")
        findings = _run(
            mocker,
            [reg],
            [_make_sparse_response(), _make_sparse_response(), _make_sparse_response()],
        )
        assert findings == []

    def test_push_low_coverage_all_attempts_skipped(self, mocker):
        """Push coverage < 0.80 on all attempts → UNKNOWN → skip."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                _make_metric_response(0.0),  # pull → ZERO
                _make_sparse_response(),
                _make_sparse_response(),
                _make_sparse_response(),
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert findings == []

    def test_region_filter_no_match_skipped(self, mocker):
        reg = _make_registry("acr1", location="westus")
        findings = _run(mocker, [reg], [], region_filter="eastus")
        assert findings == []


# ---------------------------------------------------------------------------
# TestRegionFilter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_exact_match_emits(self, mocker):
        reg = _make_registry("acr1", location="eastus")
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(), _make_metric_response()],
            region_filter="eastus",
        )
        assert len(findings) == 1
        assert findings[0].region == "eastus"

    def test_no_filter_all_regions_included(self, mocker):
        r1 = _make_registry("acr1", location="eastus")
        r2 = _make_registry("acr2", location="westeurope")
        findings = _run(
            mocker,
            [r1, r2],
            [
                _make_metric_response(),
                _make_metric_response(),
                _make_metric_response(),
                _make_metric_response(),
            ],
        )
        assert len(findings) == 2

    def test_hyphens_not_removed_from_location(self, mocker):
        """spec 7: lowercase only — hyphens are preserved. 'east-us' != 'eastus'."""
        reg = _make_registry("acr1", location="east-us")
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(), _make_metric_response()],
            region_filter="eastus",
        )
        assert findings == []

    def test_hyphenated_filter_matches_hyphenated_location(self, mocker):
        reg = _make_registry("acr1", location="east-us")
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(), _make_metric_response()],
            region_filter="east-us",
        )
        assert len(findings) == 1

    def test_region_in_finding_is_lowercase(self, mocker):
        reg = _make_registry("acr1", location="eastus")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert findings[0].region == "eastus"
        assert findings[0].details["location"] == "eastus"


# ---------------------------------------------------------------------------
# TestFindingShape
# ---------------------------------------------------------------------------


class TestFindingShape:
    @pytest.fixture
    def finding(self, mocker):
        reg = _make_registry("acr1", sku_name="Standard", tags={"env": "prod"})
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        return findings[0]

    def test_provider(self, finding):
        assert finding.provider == "azure"

    def test_rule_id(self, finding):
        assert finding.rule_id == "azure.container_registry.unused"

    def test_resource_type(self, finding):
        assert finding.resource_type == "azure.container_registry"

    def test_resource_id_is_original_arm_id(self, finding):
        assert finding.resource_id == _registry_id("acr1")

    def test_risk_low(self, finding):
        from cleancloud.core.risk import RiskLevel

        assert finding.risk == RiskLevel.LOW

    def test_confidence_high(self, finding):
        from cleancloud.core.confidence import ConfidenceLevel

        assert finding.confidence == ConfidenceLevel.HIGH

    def test_details_registry_name(self, finding):
        assert finding.details["registry_name"] == "acr1"

    def test_details_sku(self, finding):
        assert finding.details["sku"] == "Standard"

    def test_details_sku_is_none_when_absent(self, mocker):
        reg = _make_registry("acr1", sku_name=None)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert findings[0].details["sku"] is None

    def test_details_location(self, finding):
        assert finding.details["location"] == "eastus"

    def test_details_created_at_is_iso_string(self, finding):
        val = finding.details["created_at"]
        assert isinstance(val, str)
        assert "T" in val  # ISO 8601 separator

    def test_details_days_unused_threshold(self, mocker):
        reg = _make_registry("acr1", days_unused=7)
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(days_unused=7), _make_metric_response(days_unused=7)],
            days_unused=7,
        )
        assert findings[0].details["days_unused_threshold"] == 7

    def test_details_tags_populated(self, finding):
        assert finding.details["tags"] == {"env": "prod"}

    def test_details_tags_always_present_when_empty(self, mocker):
        """spec 12.3: tags must always be in details, normalized to {} when not set."""
        reg = _make_registry("acr1", tags={})
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert "tags" in findings[0].details
        assert findings[0].details["tags"] == {}


# ---------------------------------------------------------------------------
# TestEvidenceContract — spec 12.2
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    @pytest.fixture
    def finding(self, mocker):
        reg = _make_registry("acr1", sku_name="Standard")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        return findings[0]

    def test_signal_creation_date(self, finding):
        assert any(
            "creation date" in s and "window_start" in s for s in finding.evidence.signals_used
        )

    def test_signal_metrics_zero(self, finding):
        assert any(
            "SuccessfulPullCount" in s and "SuccessfulPushCount" in s and "ZERO" in s
            for s in finding.evidence.signals_used
        )

    def test_signal_sku(self, finding):
        assert any("Registry SKU: Standard" in s for s in finding.evidence.signals_used)

    def test_signal_cost_when_known(self, finding):
        assert any("ACR Standard tier costs" in s for s in finding.evidence.signals_used)

    def test_no_cost_signal_when_sku_unknown(self, mocker):
        reg = _make_registry("acr1", sku_name=None)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert not any("tier costs" in s for s in findings[0].evidence.signals_used)

    def test_signals_not_checked_reactivation(self, finding):
        assert "Planned reactivation or migration intent" in finding.evidence.signals_not_checked

    def test_signals_not_checked_stopped_workloads(self, finding):
        assert (
            "Images referenced by stopped or undeployed workloads"
            in finding.evidence.signals_not_checked
        )

    def test_signals_not_checked_failed_pulls(self, finding):
        assert (
            "Failed pull or login attempts not treated as active use"
            in finding.evidence.signals_not_checked
        )

    def test_signals_not_checked_storage_charges(self, finding):
        assert (
            "Storage charges not included in estimated base monthly cost"
            in finding.evidence.signals_not_checked
        )

    def test_time_window_reflects_days_unused(self, mocker):
        reg = _make_registry("acr1", days_unused=30)
        findings = _run(
            mocker,
            [reg],
            [_make_metric_response(days_unused=30), _make_metric_response(days_unused=30)],
            days_unused=30,
        )
        assert findings[0].evidence.time_window == "30 days"


# ---------------------------------------------------------------------------
# TestCostModel — spec 11
# ---------------------------------------------------------------------------


class TestCostModel:
    def _cost(self, mocker, sku_name):
        reg = _make_registry("acr1", sku_name=sku_name)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1
        return findings[0].estimated_monthly_cost_usd

    def test_basic_cost(self, mocker):
        assert self._cost(mocker, "Basic") == 5.0

    def test_standard_cost(self, mocker):
        assert self._cost(mocker, "Standard") == 20.0

    def test_premium_cost(self, mocker):
        assert self._cost(mocker, "Premium") == 50.0

    def test_none_when_sku_absent(self, mocker):
        assert self._cost(mocker, None) is None

    def test_none_when_sku_unrecognized(self, mocker):
        assert self._cost(mocker, "ClassicV2") is None

    def test_cost_lookup_case_insensitive(self, mocker):
        """spec 7: cost table is lowercase; 'STANDARD' → $20."""
        assert self._cost(mocker, "STANDARD") == 20.0

    def test_cost_lookup_mixed_case(self, mocker):
        assert self._cost(mocker, "Premium") == 50.0


# ---------------------------------------------------------------------------
# TestMetricEvaluation — spec 9.2
# ---------------------------------------------------------------------------


class TestMetricEvaluation:
    def test_all_three_pull_attempts_exhausted_on_exception(self, mocker):
        """All 3 pull attempts raise → UNKNOWN → skip. Pull is attempted 3 times."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(mocker, [reg], Exception("unavailable"))
        find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert mon.metrics.list.call_count == 3  # only pull attempts; push never reached

    def test_retry_sleep_delays(self, mocker, no_sleep):
        """Exponential backoff: sleep(1.0) then sleep(2.0) between attempts."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(mocker, [reg], Exception("unavailable"))
        find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        delays = [c.args[0] for c in no_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    def test_succeeds_on_second_attempt_emits(self, mocker):
        """First pull attempt raises; second returns ZERO → registry emits."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                Exception("transient"),  # pull attempt 1 → retry
                _make_metric_response(0.0),  # pull attempt 2 → ZERO
                _make_metric_response(0.0),  # push attempt 1 → ZERO
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert len(findings) == 1

    def test_low_coverage_retried_then_succeeds(self, mocker):
        """Low coverage on attempt 1 → retry; good coverage on attempt 2 → emit."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                _make_sparse_response(),  # pull attempt 1 → coverage < 0.80 → retry
                _make_metric_response(0.0),  # pull attempt 2 → ZERO
                _make_metric_response(0.0),  # push attempt 1 → ZERO
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert len(findings) == 1

    def test_all_attempts_low_coverage_skipped(self, mocker):
        """Low coverage on all 3 pull attempts → UNKNOWN → skip."""
        reg = _make_registry("acr1")
        findings = _run(
            mocker,
            [reg],
            [_make_sparse_response(), _make_sparse_response(), _make_sparse_response()],
        )
        assert findings == []

    def test_unusable_response_shape_retried(self, mocker):
        """response.value is None → unusable shape → retry; next attempt good → emit."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                SimpleNamespace(value=None),  # pull attempt 1 → unusable → retry
                _make_metric_response(0.0),  # pull attempt 2 → ZERO
                _make_metric_response(0.0),  # push → ZERO
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert len(findings) == 1

    def test_no_value_attribute_retried(self, mocker):
        """Response without .value attribute → unusable shape → retry."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(
            mocker,
            [reg],
            [
                SimpleNamespace(),  # pull attempt 1: no .value attr → retry
                _make_metric_response(0.0),  # pull attempt 2 → ZERO
                _make_metric_response(0.0),  # push → ZERO
            ],
        )
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert len(findings) == 1

    def test_datapoints_outside_window_excluded(self, mocker):
        """Datapoints outside [window_start, window_end) are excluded from coverage and totals."""
        reg = _make_registry("acr1")
        # 50 zero-valued points, all 2 years before window_start → observed_buckets=0 → UNKNOWN
        now = datetime.now(timezone.utc)
        out_of_window = [
            SimpleNamespace(timestamp=now - timedelta(days=730 + i), total=0.0) for i in range(50)
        ]
        bad_response = SimpleNamespace(
            value=[SimpleNamespace(timeseries=[SimpleNamespace(data=out_of_window)])]
        )
        acr, mon = _make_clients(mocker, [reg], [bad_response, bad_response, bad_response])
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert findings == []

    def test_dimension_slices_summed_per_bucket(self, mocker):
        """Totals from multiple timeseries at the same timestamp are summed per bucket."""
        reg = _make_registry("acr1")
        acr = mocker.MagicMock()
        mon = mocker.MagicMock()
        acr.registries.list.return_value = [reg]
        now = _now_h()

        # Slice 1: 23 in-window points; shared_ts has total=1.0, rest are 0.0
        shared_ts = now - timedelta(hours=2)
        slice1_data = [SimpleNamespace(timestamp=shared_ts, total=1.0)]
        slice1_data += [
            SimpleNamespace(timestamp=now - timedelta(hours=i + 3), total=0.0) for i in range(22)
        ]
        # Slice 2: only shared_ts with total=2.0 → merges into same bucket
        slice2_data = [SimpleNamespace(timestamp=shared_ts, total=2.0)]

        # After summing: bucket at shared_ts = 1.0+2.0 = 3.0 > 0 → ACTIVE
        pull_response = SimpleNamespace(
            value=[
                SimpleNamespace(
                    timeseries=[
                        SimpleNamespace(data=slice1_data),
                        SimpleNamespace(data=slice2_data),
                    ]
                )
            ]
        )
        mon.metrics.list.side_effect = [pull_response]  # pull ACTIVE → skip immediately
        findings = find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        assert findings == []  # ACTIVE → skip

    def test_interval_is_pt1h(self, mocker):
        """Metric queries must use PT1H interval (spec 9.2)."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        for call in mon.metrics.list.call_args_list:
            assert call.kwargs.get("interval") == "PT1H"

    def test_aggregation_is_total(self, mocker):
        """Metric queries must use Total aggregation (spec 9.2)."""
        reg = _make_registry("acr1")
        acr, mon = _make_clients(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        find_unused_container_registries(
            subscription_id="sub-123",
            credential=None,
            client=acr,
            monitor_client=mon,
            days_unused=_DAYS,
        )
        for call in mon.metrics.list.call_args_list:
            assert call.kwargs.get("aggregation") == "Total"


# ---------------------------------------------------------------------------
# TestProvisioningState — spec 9.1
# ---------------------------------------------------------------------------


class TestProvisioningState:
    def test_sdk_fallback_succeeded_emits(self, mocker):
        reg = _make_registry("acr1", provisioning_state="Succeeded")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_nested_properties_succeeded_overrides_flat_failed(self, mocker):
        """spec 9.1: properties.provisioning_state takes priority over flat attribute."""
        reg = _make_registry("acr1", provisioning_state="Failed")
        reg.properties = SimpleNamespace(provisioning_state="Succeeded")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_nested_properties_failed_skips_even_if_flat_succeeded(self, mocker):
        reg = _make_registry("acr1", provisioning_state="Succeeded")
        reg.properties = SimpleNamespace(provisioning_state="Failed")
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_nested_properties_none_value_falls_through_to_sdk(self, mocker):
        """None in nested properties.provisioning_state → fall through to SDK attribute."""
        reg = _make_registry("acr1", provisioning_state="Succeeded")
        reg.properties = SimpleNamespace(provisioning_state=None)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestCreationDate — spec 8.4, 8.5
# ---------------------------------------------------------------------------


class TestCreationDate:
    def test_aware_datetime_accepted(self, mocker):
        reg = _make_registry(
            "acr1",
            creation_date=datetime.now(timezone.utc) - timedelta(days=2),
        )
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_naive_datetime_treated_as_utc(self, mocker):
        naive = datetime.now() - timedelta(days=2)  # no tzinfo — treated as UTC
        reg = _make_registry("acr1", creation_date=naive)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_creation_date_from_nested_properties(self, mocker):
        """SDK nested properties.creation_date is also resolved."""
        reg = _make_registry("acr1")
        creation_date = reg.creation_date
        del reg.creation_date
        reg.properties = SimpleNamespace(creation_date=creation_date)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_creation_date_just_before_window_start_emits(self, mocker):
        """Created 1 second before window_start → passes spec 8.5 (<=)."""
        now = datetime.now(timezone.utc)
        creation_date = now - timedelta(days=_DAYS) - timedelta(seconds=1)
        reg = _make_registry("acr1", creation_date=creation_date)
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        assert len(findings) == 1

    def test_creation_date_just_after_window_start_skipped(self, mocker):
        """Created 1 second after window_start → too new → spec 8.5."""
        now = datetime.now(timezone.utc)
        creation_date = now - timedelta(days=_DAYS) + timedelta(seconds=1)
        reg = _make_registry("acr1", creation_date=creation_date)
        findings = _run(mocker, [reg], Exception("should not reach metrics"))
        assert findings == []

    def test_created_at_in_details_is_isoformat(self, mocker):
        reg = _make_registry("acr1")
        findings = _run(mocker, [reg], [_make_metric_response(), _make_metric_response()])
        val = findings[0].details["created_at"]
        assert isinstance(val, str)
        assert "T" in val


# ---------------------------------------------------------------------------
# TestFailureBehavior — spec 13
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_registry_list_exception_propagates(self, mocker):
        """spec 13: registries.list() exception must propagate, not return []."""
        acr = mocker.MagicMock()
        mon = mocker.MagicMock()
        acr.registries.list.side_effect = RuntimeError("API unavailable")
        with pytest.raises(RuntimeError, match="API unavailable"):
            find_unused_container_registries(
                subscription_id="sub-123",
                credential=None,
                client=acr,
                monitor_client=mon,
                days_unused=_DAYS,
            )
