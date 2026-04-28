"""
Tests for gcp.vertex.featurestore.idle rule.

Coverage:
- Legacy featurestore: monitoring confirmed_zero → HIGH confidence / HIGH risk
- Legacy featurestore: positive_activity → no finding
- Legacy featurestore: unresolved coverage → no finding (no age fallback)
- Legacy featurestore: no online serving capacity → no finding
- Legacy featurestore: non-STABLE state → no finding
- Legacy featurestore: UPDATING state → no finding
- Legacy featurestore: invalid mode (both fixedNodeCount + scaling present) → no finding
- Legacy featurestore: autoscaled (scaling.minNodeCount) → finding
- Legacy featurestore: too young for full window → no finding
- Legacy featurestore: future reference_time → no finding
- FeatureOnlineStore (Bigtable): confirmed_zero → HIGH confidence / HIGH risk
- FeatureOnlineStore (Bigtable): positive_activity → no finding
- FeatureOnlineStore (Bigtable): optimized → skipped (out of scope)
- FeatureOnlineStore (Bigtable): maxNodeCount < minNodeCount → skipped
- FeatureOnlineStore (Bigtable): missing autoScaling → skipped
- FeatureOnlineStore: minNodeCount == 0 → skipped
- Region filter: exact equality (not prefix)
- estimated_monthly_cost_usd always None
- Permission error (403) → raises PermissionError
- API not enabled (404) → returns []
- Monitoring client creation failure → no findings (no age fallback)
- Both resource types produce findings independently
- reference_time = max(createTime, updateTime)
- _query_store_activity coverage unit tests
"""

import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from google.api import metric_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.ai.featurestore_idle import (
    _DEFAULT_IDLE_DAYS,
    _LEGACY_METRIC,
    _METRIC_KIND_DELTA,
    _NEW_METRIC,
    _parse_location,
    _parse_resource_id,
    _parse_rfc3339,
    _query_store_activity,
    _resolve_reference_time,
    find_idle_featurestores,
)

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

NOW = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROJECT = "my-project"
_IDLE_DAYS = _DEFAULT_IDLE_DAYS  # 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _make_legacy_store(
    store_id: str = "my-store",
    region: str = "us-central1",
    state: str = "STABLE",
    node_count: int = 1,
    age_days: float = 60.0,
    autoscaled: bool = False,
    update_age_days: float = None,
) -> dict:
    create_dt = NOW - timedelta(days=age_days)
    store: dict = {
        "name": f"projects/{_PROJECT}/locations/{region}/featurestores/{store_id}",
        "state": state,
        "createTime": _iso(create_dt),
    }
    if update_age_days is not None:
        store["updateTime"] = _iso(NOW - timedelta(days=update_age_days))
    if autoscaled:
        store["onlineServingConfig"] = {
            "scaling": {"minNodeCount": node_count, "maxNodeCount": node_count * 2}
        }
    else:
        store["onlineServingConfig"] = {"fixedNodeCount": node_count}
    return store


def _make_new_store(
    store_id: str = "my-online-store",
    region: str = "us-central1",
    state: str = "STABLE",
    min_nodes: int = 1,
    max_nodes: int = None,
    is_optimized: bool = False,
    age_days: float = 60.0,
    update_age_days: float = None,
    missing_autoscaling: bool = False,
) -> dict:
    create_dt = NOW - timedelta(days=age_days)
    store: dict = {
        "name": (f"projects/{_PROJECT}/locations/{region}/featureOnlineStores/{store_id}"),
        "state": state,
        "createTime": _iso(create_dt),
    }
    if update_age_days is not None:
        store["updateTime"] = _iso(NOW - timedelta(days=update_age_days))
    if is_optimized:
        store["optimized"] = {}
    elif not missing_autoscaling:
        effective_max = max_nodes if max_nodes is not None else min_nodes * 2
        store["bigtable"] = {
            "autoScaling": {"minNodeCount": min_nodes, "maxNodeCount": effective_max}
        }
    else:
        store["bigtable"] = {}  # autoScaling absent
    return store


def _run(
    legacy_stores: list = (),
    new_stores: list = (),
    legacy_activities: dict = None,  # store_id → "confirmed_zero"|"positive_activity"|"unresolved"
    new_activities: dict = None,
    region_filter=None,
    idle_days: int = _IDLE_DAYS,
    legacy_list_status: int = 200,
    new_list_status: int = 200,
    monitoring_client_fails: bool = False,
):
    """
    Run find_idle_featurestores with mocked HTTP, mocked _query_store_activity,
    and a fixed 'now'.
    """
    legacy_activities = legacy_activities or {}
    new_activities = new_activities or {}
    credentials = MagicMock()

    def _make_list_resp(status: int, data_key: str, items: list) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = {data_key: list(items)}
        resp.raise_for_status = MagicMock()
        return resp

    legacy_resp = _make_list_resp(legacy_list_status, "featurestores", legacy_stores)
    new_resp = _make_list_resp(new_list_status, "featureOnlineStores", new_stores)

    def _get_side_effect(url, **kwargs):
        if "featureOnlineStores" in url:
            return new_resp
        return legacy_resp

    mock_session = MagicMock()
    mock_session.get.side_effect = _get_side_effect

    def _mock_query(
        client,
        project_id,
        store_id,
        region,
        metric_type,
        resource_type,
        id_label,
        window_start,
        window_end,
        idle_days_arg,
    ):
        if "featureonlinestore" in metric_type:
            return new_activities.get(store_id, "unresolved")
        return legacy_activities.get(store_id, "unresolved")

    monitoring_patch = (
        patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle."
            "monitoring_v3.MetricServiceClient",
            side_effect=Exception("monitoring unavailable"),
        )
        if monitoring_client_fails
        else patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle."
            "monitoring_v3.MetricServiceClient",
            return_value=MagicMock(),
        )
    )

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        monitoring_patch,
        patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle._query_store_activity",
            side_effect=_mock_query,
        ),
        patch("cleancloud.providers.gcp.rules.ai.featurestore_idle.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.fromtimestamp = datetime.fromtimestamp
        findings = find_idle_featurestores(
            project_id=_PROJECT,
            credentials=credentials,
            region_filter=region_filter,
            idle_days=idle_days,
        )
    return findings


# ---------------------------------------------------------------------------
# Unit tests — helper functions
# ---------------------------------------------------------------------------


class TestParseHelpers:
    def test_parse_location(self):
        name = f"projects/{_PROJECT}/locations/us-central1/featurestores/s1"
        assert _parse_location(name) == "us-central1"

    def test_parse_location_missing(self):
        assert _parse_location("bad-name") is None
        assert _parse_location("") is None

    def test_parse_resource_id(self):
        name = f"projects/{_PROJECT}/locations/us-central1/featurestores/my-store"
        assert _parse_resource_id(name) == "my-store"

    def test_parse_rfc3339_valid(self):
        ts = "2025-05-01T12:00:00Z"
        dt = _parse_rfc3339(ts)
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2025 and dt.month == 5 and dt.day == 1

    def test_parse_rfc3339_offset_normalized_to_utc(self):
        """spec 7: non-UTC offsets must be normalized to UTC before comparison."""
        # +05:30 offset — value = 2025-05-01T06:30:00Z in UTC
        ts = "2025-05-01T12:00:00+05:30"
        dt = _parse_rfc3339(ts)
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 6 and dt.minute == 30

    def test_parse_rfc3339_invalid(self):
        assert _parse_rfc3339("not-a-date") is None

    def test_parse_rfc3339_empty(self):
        assert _parse_rfc3339("") is None

    def test_resolve_reference_time_both_present(self):
        create = _iso(NOW - timedelta(days=60))
        update = _iso(NOW - timedelta(days=10))
        ref = _resolve_reference_time(create, update, NOW)
        # max(60 days ago, 10 days ago) = 10 days ago
        assert ref == NOW - timedelta(days=10)

    def test_resolve_reference_time_only_create(self):
        create = _iso(NOW - timedelta(days=45))
        ref = _resolve_reference_time(create, "", NOW)
        assert ref == NOW - timedelta(days=45)

    def test_resolve_reference_time_future_discarded(self):
        create = _iso(NOW - timedelta(days=60))
        update = _iso(NOW + timedelta(days=1))  # future
        ref = _resolve_reference_time(create, update, NOW)
        # future updateTime is discarded, falls back to createTime
        assert ref == NOW - timedelta(days=60)

    def test_resolve_reference_time_both_future(self):
        create = _iso(NOW + timedelta(days=1))
        update = _iso(NOW + timedelta(days=2))
        assert _resolve_reference_time(create, update, NOW) is None

    def test_resolve_reference_time_both_missing(self):
        assert _resolve_reference_time("", "", NOW) is None


# ---------------------------------------------------------------------------
# Unit tests — _query_store_activity
# ---------------------------------------------------------------------------


def _make_mock_point(val: int, seconds_offset: int, window_end: datetime):
    """Build a mock monitoring point with a specific value and timestamp."""
    p = MagicMock()
    p.value.WhichOneof.return_value = "int64_value"
    p.value.int64_value = val
    ts_dt = window_end - timedelta(seconds=seconds_offset)
    p.interval.end_time.seconds = int(ts_dt.timestamp())
    p.interval.end_time.nanos = 0
    return p


class TestQueryStoreActivity:
    _WINDOW_START = NOW - timedelta(days=3)
    _WINDOW_END = NOW

    def _run_query(self, series_list):
        client = MagicMock()
        client.list_time_series.return_value = series_list
        return _query_store_activity(
            client,
            _PROJECT,
            "store1",
            "us-central1",
            _LEGACY_METRIC,
            "aiplatform.googleapis.com/Featurestore",
            "featurestore_id",
            self._WINDOW_START,
            self._WINDOW_END,
            3,
        )

    def _make_series(self, vals):
        """Make a series with one point per aligned bucket, DELTA kind."""
        points = [_make_mock_point(v, i * 86400, self._WINDOW_END) for i, v in enumerate(vals)]
        series = MagicMock()
        series.points = points
        series.metric_kind = _METRIC_KIND_DELTA
        return series

    def test_confirmed_zero_returns_correct(self):
        series = self._make_series([0, 0, 0])
        assert self._run_query([series]) == "confirmed_zero"

    def test_positive_activity_detected(self):
        series = self._make_series([0, 5, 0])
        assert self._run_query([series]) == "positive_activity"

    def test_zero_series_returns_unresolved(self):
        assert self._run_query([]) == "unresolved"

    def test_two_series_returns_unresolved(self):
        s1 = self._make_series([0, 0, 0])
        s2 = self._make_series([0, 0, 0])
        assert self._run_query([s1, s2]) == "unresolved"

    def test_wrong_point_count_returns_unresolved(self):
        series = self._make_series([0, 0])  # 2 points, expected 3
        assert self._run_query([series]) == "unresolved"

    def test_unrecognized_value_type_returns_unresolved(self):
        p = MagicMock()
        p.value.WhichOneof.return_value = "string_value"
        p.interval.end_time.seconds = int(self._WINDOW_END.timestamp())
        p.interval.end_time.nanos = 0
        series = MagicMock()
        series.points = [p, p, p]
        series.metric_kind = _METRIC_KIND_DELTA
        assert self._run_query([series]) == "unresolved"

    def test_future_timestamp_returns_unresolved(self):
        # One point falls outside the expected bucket boundaries
        p_ok = _make_mock_point(0, 86400, self._WINDOW_END)
        p_future = _make_mock_point(0, 0, self._WINDOW_END)
        p_future.interval.end_time.seconds = int(
            (self._WINDOW_END + timedelta(hours=1)).timestamp()
        )
        series = MagicMock()
        series.points = [p_ok, p_ok, p_future]
        series.metric_kind = _METRIC_KIND_DELTA
        assert self._run_query([series]) == "unresolved"

    def test_gap_exceeding_alignment_period_returns_unresolved(self):
        # Points not aligned to expected bucket boundaries (off by 1 second)
        p1 = _make_mock_point(0, 0, self._WINDOW_END)
        p2 = _make_mock_point(0, 86401 + 86400, self._WINDOW_END)  # off by 1s from bucket
        p3 = _make_mock_point(0, 86401 + 86400 * 2, self._WINDOW_END)
        series = MagicMock()
        series.points = [p1, p2, p3]
        series.metric_kind = _METRIC_KIND_DELTA
        assert self._run_query([series]) == "unresolved"

    def test_double_value_type_accepted(self):
        """double_value metric kind is accepted alongside int64_value."""

        # Use distinct aligned bucket timestamps (one point per bucket)
        def _double_point(offset_seconds):
            p = MagicMock()
            p.value.WhichOneof.return_value = "double_value"
            p.value.double_value = 0.0
            ts_dt = self._WINDOW_END - timedelta(seconds=offset_seconds)
            p.interval.end_time.seconds = int(ts_dt.timestamp())
            p.interval.end_time.nanos = 0
            return p

        series = MagicMock()
        series.points = [_double_point(0), _double_point(86400), _double_point(2 * 86400)]
        series.metric_kind = _METRIC_KIND_DELTA
        assert self._run_query([series]) == "confirmed_zero"

    def test_metric_kind_non_delta_returns_unresolved(self):
        """spec 8.3 point 5: GAUGE or CUMULATIVE metric kind must return unresolved."""
        series = self._make_series([0, 0, 0])
        series.metric_kind = int(metric_pb2.MetricDescriptor.MetricKind.GAUGE)
        assert self._run_query([series]) == "unresolved"

    def test_shifted_buckets_return_unresolved(self):
        """spec 8.4 point 3: points not aligned to expected bucket ends are rejected."""
        # Shift all points by +1 second — evenly spaced but wrong boundaries
        series = self._make_series([0, 0, 0])
        for p in series.points:
            p.interval.end_time.seconds += 1
        assert self._run_query([series]) == "unresolved"

    def test_query_exception_propagates(self):
        """spec 11.4: RPC failures propagate rather than silently returning 'unresolved'."""
        client = MagicMock()
        client.list_time_series.side_effect = RuntimeError("network failure")
        with pytest.raises(RuntimeError, match="network failure"):
            _query_store_activity(
                client,
                _PROJECT,
                "store1",
                "us-central1",
                _LEGACY_METRIC,
                "aiplatform.googleapis.com/Featurestore",
                "featurestore_id",
                self._WINDOW_START,
                self._WINDOW_END,
                3,
            )


# ---------------------------------------------------------------------------
# Legacy featurestore tests
# ---------------------------------------------------------------------------


class TestLegacyFeaturestore:
    def test_idle_high_confidence(self):
        store = _make_legacy_store(store_id="s1", node_count=2, age_days=60)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.HIGH
        assert f.rule_id == "gcp.vertex.featurestore.idle"
        assert f.resource_type == "gcp.vertex.featurestore"

    def test_active_store_skipped(self):
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "positive_activity"})
        assert findings == []

    def test_unresolved_coverage_skips_not_falls_back(self):
        """Unresolved monitoring must skip — no age-only fallback (spec 8.5)."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(legacy_stores=[store])  # no activity entry → unresolved
        assert findings == []

    def test_no_online_serving_skipped(self):
        store = _make_legacy_store(store_id="s1", node_count=0, age_days=60)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_non_stable_state_skipped(self):
        store = _make_legacy_store(store_id="s1", state="UPDATING", age_days=60)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_invalid_mode_both_present_skipped(self):
        """Both fixedNodeCount and scaling.minNodeCount materially present → invalid."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        store["onlineServingConfig"] = {
            "fixedNodeCount": 2,
            "scaling": {"minNodeCount": 1},
        }
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_autoscaled_store_included(self):
        store = _make_legacy_store(store_id="s1", node_count=2, age_days=60, autoscaled=True)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert len(findings) == 1
        assert findings[0].details["legacy_serving_mode"] == "autoscaled"
        assert findings[0].details["provisioned_node_floor"] == 2

    def test_autoscaled_zero_min_nodes_excluded(self):
        store = _make_legacy_store(store_id="s1", node_count=0, age_days=60, autoscaled=True)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_too_young_for_full_window_skipped(self):
        """Store created 20 days ago cannot cover a 30-day window."""
        store = _make_legacy_store(store_id="s1", age_days=20)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_old_enough_for_window_included(self):
        store = _make_legacy_store(store_id="s1", age_days=45)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert len(findings) == 1

    def test_reference_time_uses_update_time_when_newer(self):
        """updateTime newer than createTime → reference_time = updateTime."""
        # Store created 90 days ago, updated 20 days ago — too recent for 30-day window
        store = _make_legacy_store(store_id="s1", age_days=90, update_age_days=20)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings == []

    def test_reference_time_create_used_when_no_update(self):
        """No updateTime → reference_time = createTime; 60-day-old store passes."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        assert "updateTime" not in store
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert len(findings) == 1

    def test_monitoring_client_failure_skips_not_fallback(self):
        """Monitoring client creation failure → skip with operational warning (spec 11.4)."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            findings = _run(
                legacy_stores=[store],
                legacy_activities={"s1": "confirmed_zero"},
                monitoring_client_fails=True,
            )
        assert findings == []
        assert any("monitoring client creation failed" in str(w.message) for w in caught)

    def test_malformed_legacy_config_skipped(self):
        """Malformed onlineServingConfig must skip item, not abort the rule (spec 11.3)."""
        bad_store = _make_legacy_store(store_id="bad", age_days=60)
        bad_store["onlineServingConfig"] = {"fixedNodeCount": "not-an-int"}
        good_store = _make_legacy_store(store_id="good", age_days=60)
        findings = _run(
            legacy_stores=[bad_store, good_store],
            legacy_activities={"bad": "confirmed_zero", "good": "confirmed_zero"},
        )
        assert len(findings) == 1
        assert findings[0].details["store_id"] == "good"

    def test_monitoring_query_exception_skips_with_warning(self):
        """Per-store RPC failure → skip store + emit UserWarning (spec 11.4)."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        credentials = MagicMock()

        legacy_resp = MagicMock()
        legacy_resp.status_code = 200
        legacy_resp.json.return_value = {"featurestores": [store]}
        legacy_resp.raise_for_status = MagicMock()
        new_resp = MagicMock()
        new_resp.status_code = 200
        new_resp.json.return_value = {"featureOnlineStores": []}
        new_resp.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.side_effect = lambda url, **kw: (
            new_resp if "featureOnlineStores" in url else legacy_resp
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with (
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle.AuthorizedSession",
                    return_value=mock_session,
                ),
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle"
                    ".monitoring_v3.MetricServiceClient",
                    return_value=MagicMock(),
                ),
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle._query_store_activity",
                    side_effect=RuntimeError("simulated RPC failure"),
                ),
                patch("cleancloud.providers.gcp.rules.ai.featurestore_idle.datetime") as mock_dt,
            ):
                mock_dt.now.return_value = NOW
                mock_dt.fromisoformat = datetime.fromisoformat
                mock_dt.fromtimestamp = datetime.fromtimestamp
                findings = find_idle_featurestores(project_id=_PROJECT, credentials=credentials)

        assert findings == []
        assert any(
            "monitoring query failed" in str(w.message) and "s1" in str(w.message) for w in caught
        )

    def test_permission_error_on_403(self):
        with pytest.raises(PermissionError, match="aiplatform.featurestores.list"):
            _run(legacy_list_status=403)

    def test_api_not_enabled_returns_empty(self):
        findings = _run(legacy_list_status=404)
        assert findings == []

    def test_region_filter_exact_match(self):
        store = _make_legacy_store(store_id="s1", region="us-central1", age_days=60)
        findings = _run(
            legacy_stores=[store],
            legacy_activities={"s1": "confirmed_zero"},
            region_filter="us-central1",
        )
        assert len(findings) == 1

    def test_region_filter_excludes_non_matching(self):
        store = _make_legacy_store(store_id="s1", region="europe-west4", age_days=60)
        findings = _run(
            legacy_stores=[store],
            legacy_activities={"s1": "confirmed_zero"},
            region_filter="us-central1",
        )
        assert findings == []

    def test_region_filter_is_exact_not_prefix(self):
        """region_filter='us' must NOT match 'us-central1' (spec 7: exact equality)."""
        store = _make_legacy_store(store_id="s1", region="us-central1", age_days=60)
        findings = _run(
            legacy_stores=[store],
            legacy_activities={"s1": "confirmed_zero"},
            region_filter="us",
        )
        assert findings == []

    def test_estimated_monthly_cost_always_none(self):
        store = _make_legacy_store(store_id="s1", node_count=3, age_days=60)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        assert findings[0].estimated_monthly_cost_usd is None

    def test_details_fields(self):
        store = _make_legacy_store(store_id="s1", region="us-central1", node_count=2, age_days=45)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        d = findings[0].details
        assert d["store_id"] == "s1"
        assert d["store_family"] == "legacy_featurestore"
        assert d["state"] == "STABLE"
        assert d["region"] == "us-central1"
        assert d["provisioned_node_floor"] == 2
        assert d["metric_type"] == _LEGACY_METRIC
        assert d["metric_coverage_state"] == "full_window"
        assert d["telemetry_state"] == "confirmed_zero"
        assert d["request_count_total"] == 0
        assert d["idle_days_threshold"] == _IDLE_DAYS

    def test_details_fixed_node_count_present(self):
        store = _make_legacy_store(store_id="s1", node_count=1, age_days=60, autoscaled=False)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        d = findings[0].details
        assert d["legacy_serving_mode"] == "fixed"
        assert "fixed_node_count" in d
        assert "scaling_min_node_count" not in d

    def test_details_scaling_min_node_count_present_for_autoscaled(self):
        store = _make_legacy_store(store_id="s1", node_count=2, age_days=60, autoscaled=True)
        findings = _run(legacy_stores=[store], legacy_activities={"s1": "confirmed_zero"})
        d = findings[0].details
        assert d["legacy_serving_mode"] == "autoscaled"
        assert "scaling_min_node_count" in d
        assert "fixed_node_count" not in d

    def test_custom_idle_days_respected(self):
        """idle_days=10: store 15 days old is old enough; store 8 days old is not."""
        old_enough = _make_legacy_store(store_id="s1", age_days=15)
        too_young = _make_legacy_store(store_id="s2", age_days=8)
        findings = _run(
            legacy_stores=[old_enough, too_young],
            legacy_activities={"s1": "confirmed_zero", "s2": "confirmed_zero"},
            idle_days=10,
        )
        assert len(findings) == 1
        assert findings[0].details["store_id"] == "s1"


# ---------------------------------------------------------------------------
# FeatureOnlineStore tests
# ---------------------------------------------------------------------------


class TestFeatureOnlineStore:
    def test_bigtable_store_idle_high_confidence(self):
        store = _make_new_store(store_id="fos1", min_nodes=2, age_days=45)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.HIGH
        assert f.resource_type == "gcp.vertex.feature_online_store"

    def test_active_new_store_skipped(self):
        store = _make_new_store(store_id="fos1", age_days=45)
        findings = _run(new_stores=[store], new_activities={"fos1": "positive_activity"})
        assert findings == []

    def test_unresolved_coverage_skips(self):
        store = _make_new_store(store_id="fos1", age_days=45)
        findings = _run(new_stores=[store])  # no activity entry → unresolved
        assert findings == []

    def test_optimized_store_skipped(self):
        """Optimized (BigQuery-backed) stores are out of scope (spec 9.3)."""
        store = _make_new_store(store_id="fos1", is_optimized=True, age_days=45)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_non_stable_state_skipped(self):
        store = _make_new_store(store_id="fos1", state="UPDATING", age_days=60)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_too_young_for_window_skipped(self):
        store = _make_new_store(store_id="fos1", age_days=20)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_missing_autoscaling_skipped(self):
        """bigtable.autoScaling absent → unusable → skip (spec 7)."""
        store = _make_new_store(store_id="fos1", age_days=60, missing_autoscaling=True)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_min_nodes_zero_skipped(self):
        store = _make_new_store(store_id="fos1", min_nodes=0, age_days=60)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_max_nodes_less_than_min_skipped(self):
        """maxNodeCount < minNodeCount → unusable autoscaling block (spec 7)."""
        store = _make_new_store(store_id="fos1", min_nodes=3, max_nodes=1, age_days=60)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_max_nodes_equal_to_min_accepted(self):
        """maxNodeCount == minNodeCount is valid (single-node floor)."""
        store = _make_new_store(store_id="fos1", min_nodes=1, max_nodes=1, age_days=60)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert len(findings) == 1

    def test_reference_time_uses_update_time_when_newer(self):
        """updateTime newer than createTime → reference_time = updateTime → too young."""
        store = _make_new_store(store_id="fos1", age_days=90, update_age_days=20)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings == []

    def test_permission_error_on_403(self):
        with pytest.raises(PermissionError, match="aiplatform.featureOnlineStores.list"):
            _run(new_list_status=403)

    def test_api_not_enabled_returns_empty(self):
        findings = _run(new_list_status=404)
        assert findings == []

    def test_region_filter_exact_match(self):
        store = _make_new_store(store_id="fos1", region="us-central1", age_days=60)
        findings = _run(
            new_stores=[store],
            new_activities={"fos1": "confirmed_zero"},
            region_filter="us-central1",
        )
        assert len(findings) == 1

    def test_region_filter_excludes(self):
        store = _make_new_store(store_id="fos1", region="europe-west4", age_days=60)
        findings = _run(
            new_stores=[store],
            new_activities={"fos1": "confirmed_zero"},
            region_filter="us-central1",
        )
        assert findings == []

    def test_region_filter_is_exact_not_prefix(self):
        store = _make_new_store(store_id="fos1", region="us-central1", age_days=60)
        findings = _run(
            new_stores=[store],
            new_activities={"fos1": "confirmed_zero"},
            region_filter="us",
        )
        assert findings == []

    def test_estimated_monthly_cost_always_none(self):
        store = _make_new_store(store_id="fos1", min_nodes=3, age_days=60)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        assert findings[0].estimated_monthly_cost_usd is None

    def test_details_fields(self):
        store = _make_new_store(store_id="fos1", region="us-central1", min_nodes=2, age_days=45)
        findings = _run(new_stores=[store], new_activities={"fos1": "confirmed_zero"})
        d = findings[0].details
        assert d["store_id"] == "fos1"
        assert d["store_family"] == "feature_online_store"
        assert d["state"] == "STABLE"
        assert d["region"] == "us-central1"
        assert d["storage_type"] == "bigtable"
        assert d["bigtable_min_node_count"] == 2
        assert d["bigtable_max_node_count"] == 4  # helper sets max = min * 2
        assert d["metric_type"] == _NEW_METRIC
        assert d["metric_coverage_state"] == "full_window"
        assert d["telemetry_state"] == "confirmed_zero"
        assert d["request_count_total"] == 0

    def test_monitoring_client_failure_skips(self):
        """Monitoring client creation failure → skip with operational warning (spec 11.4)."""
        store = _make_new_store(store_id="fos1", age_days=60)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            findings = _run(
                new_stores=[store],
                new_activities={"fos1": "confirmed_zero"},
                monitoring_client_fails=True,
            )
        assert findings == []
        assert any("monitoring client creation failed" in str(w.message) for w in caught)

    def test_malformed_bigtable_config_skipped(self):
        """Malformed bigtable.autoScaling must skip item, not abort the rule (spec 11.3)."""
        bad_store = _make_new_store(store_id="bad", age_days=60)
        bad_store["bigtable"] = {"autoScaling": {"minNodeCount": "not-an-int"}}
        good_store = _make_new_store(store_id="good", min_nodes=1, age_days=60)
        findings = _run(
            new_stores=[bad_store, good_store],
            new_activities={"bad": "confirmed_zero", "good": "confirmed_zero"},
        )
        assert len(findings) == 1
        assert findings[0].details["store_id"] == "good"

    def test_monitoring_query_exception_skips_with_warning(self):
        """Per-store RPC failure → skip store + emit UserWarning (spec 11.4)."""
        store = _make_new_store(store_id="fos1", age_days=60)
        credentials = MagicMock()

        legacy_resp = MagicMock()
        legacy_resp.status_code = 200
        legacy_resp.json.return_value = {"featurestores": []}
        legacy_resp.raise_for_status = MagicMock()
        new_resp = MagicMock()
        new_resp.status_code = 200
        new_resp.json.return_value = {"featureOnlineStores": [store]}
        new_resp.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.side_effect = lambda url, **kw: (
            new_resp if "featureOnlineStores" in url else legacy_resp
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with (
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle.AuthorizedSession",
                    return_value=mock_session,
                ),
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle"
                    ".monitoring_v3.MetricServiceClient",
                    return_value=MagicMock(),
                ),
                patch(
                    "cleancloud.providers.gcp.rules.ai.featurestore_idle._query_store_activity",
                    side_effect=RuntimeError("simulated RPC failure"),
                ),
                patch("cleancloud.providers.gcp.rules.ai.featurestore_idle.datetime") as mock_dt,
            ):
                mock_dt.now.return_value = NOW
                mock_dt.fromisoformat = datetime.fromisoformat
                mock_dt.fromtimestamp = datetime.fromtimestamp
                findings = find_idle_featurestores(project_id=_PROJECT, credentials=credentials)

        assert findings == []
        assert any(
            "monitoring query failed" in str(w.message) and "fos1" in str(w.message) for w in caught
        )


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------


class TestCombined:
    def test_both_types_independent(self):
        legacy = _make_legacy_store(store_id="l1", age_days=60)
        new = _make_new_store(store_id="n1", age_days=45)
        findings = _run(
            legacy_stores=[legacy],
            new_stores=[new],
            legacy_activities={"l1": "confirmed_zero"},
            new_activities={"n1": "confirmed_zero"},
        )
        assert len(findings) == 2
        types = {f.resource_type for f in findings}
        assert types == {"gcp.vertex.featurestore", "gcp.vertex.feature_online_store"}

    def test_no_stores_returns_empty(self):
        assert _run() == []

    def test_one_active_one_idle(self):
        legacy = _make_legacy_store(store_id="l1", age_days=60)
        new = _make_new_store(store_id="n1", age_days=45)
        findings = _run(
            legacy_stores=[legacy],
            new_stores=[new],
            legacy_activities={"l1": "positive_activity"},
            new_activities={"n1": "confirmed_zero"},
        )
        assert len(findings) == 1
        assert findings[0].resource_type == "gcp.vertex.feature_online_store"

    def test_rule_id_attribute(self):
        assert find_idle_featurestores.RULE_ID == "gcp.vertex.featurestore.idle"
