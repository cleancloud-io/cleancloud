"""
Tests for gcp.vertex.featurestore.idle rule.

Coverage:
- Legacy featurestore: monitoring confirms zero requests → HIGH confidence
- Legacy featurestore: age-based fallback → MEDIUM confidence
- Legacy featurestore: active (requests > 0) → no finding
- Legacy featurestore: no online serving (fixedNodeCount=0) → no finding
- Legacy featurestore: non-STABLE state → no finding
- New featureOnlineStore (Bigtable): monitoring idle → HIGH confidence
- New featureOnlineStore (Optimized): idle → finding with estimated cost
- Permission error (403) → raises PermissionError
- API not enabled (404) → returns []
- Region filter: stores in other regions skipped
- Cost: fixedNodeCount × $0.27/hr × 730 h/month
- Monitoring failure → age fallback (no exception raised)
- Node too young + no monitoring → no finding
- Both resource types produce findings independently
- estimated_monthly_cost_usd is always set
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.ai.featurestore_idle import (
    _BIGTABLE_NODE_HOURLY_COST,
    _DEFAULT_IDLE_DAYS,
    _HOURS_PER_MONTH,
    _OPTIMIZED_STORE_MONTHLY_COST,
    _age_days,
    _parse_location,
    _parse_resource_id,
    find_idle_featurestores,
)

# ---------------------------------------------------------------------------
# Constants
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
    display_name: str = "",
    autoscaled: bool = False,
) -> dict:
    create_dt = NOW - timedelta(days=age_days)
    if autoscaled:
        serving_config = {"scaling": {"minNodeCount": node_count, "maxNodeCount": node_count * 2}}
    else:
        serving_config = {"fixedNodeCount": node_count}
    return {
        "name": f"projects/{_PROJECT}/locations/{region}/featurestores/{store_id}",
        "displayName": display_name,
        "state": state,
        "onlineServingConfig": serving_config,
        "createTime": _iso(create_dt),
    }


def _make_new_store(
    store_id: str = "my-online-store",
    region: str = "us-central1",
    state: str = "STABLE",
    min_nodes: int = 1,
    is_optimized: bool = False,
    age_days: float = 60.0,
    display_name: str = "",
) -> dict:
    create_dt = NOW - timedelta(days=age_days)
    store: dict = {
        "name": (f"projects/{_PROJECT}/locations/{region}" f"/featureOnlineStores/{store_id}"),
        "displayName": display_name,
        "state": state,
        "createTime": _iso(create_dt),
    }
    if is_optimized:
        store["optimized"] = {}
    else:
        store["bigtable"] = {
            "autoScaling": {"minNodeCount": min_nodes, "maxNodeCount": min_nodes * 2}
        }
    return store


def _make_monitoring_ts(store_id: str, label_key: str, total_count: int):
    """Build a mock monitoring time-series."""
    point = MagicMock()
    point.value.int64_value = total_count
    ts = MagicMock()
    ts.resource.labels = {label_key: store_id}
    ts.points = [point]
    return ts


def _run(
    legacy_stores: list = (),
    new_stores: list = (),
    legacy_counts: dict[str, int] | None = None,
    new_counts: dict[str, int] | None = None,
    region_filter=None,
    idle_days: int = _IDLE_DAYS,
    legacy_list_status: int = 200,
    new_list_status: int = 200,
    monitoring_raises: Exception | None = None,
):
    """Run find_idle_featurestores with mocked HTTP and monitoring."""
    credentials = MagicMock()

    def _make_list_resp(status: int, data_key: str, items: list) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = {data_key: list(items)}
        return resp

    legacy_resp = _make_list_resp(legacy_list_status, "featurestores", legacy_stores)
    new_resp = _make_list_resp(new_list_status, "featureOnlineStores", new_stores)

    def _get_side_effect(url, **kwargs):
        if "featureOnlineStores" in url:
            return new_resp
        return legacy_resp

    mock_session = MagicMock()
    mock_session.get.side_effect = _get_side_effect

    def _monitoring_side_effect(request=None, **kwargs):
        if monitoring_raises:
            raise monitoring_raises
        metric = (request or {}).get("filter", "")
        if "featureonlinestore" in metric:
            store_counts = new_counts or {}
            label_key = "feature_online_store_id"
        else:
            store_counts = legacy_counts or {}
            label_key = "featurestore_id"
        return [_make_monitoring_ts(sid, label_key, count) for sid, count in store_counts.items()]

    mock_monitoring = MagicMock()
    mock_monitoring.list_time_series.side_effect = _monitoring_side_effect

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.featurestore_idle.monitoring_v3.MetricServiceClient",
            return_value=mock_monitoring,
        ),
        patch("cleancloud.providers.gcp.rules.ai.featurestore_idle.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat = datetime.fromisoformat
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

    def test_parse_resource_id(self):
        name = f"projects/{_PROJECT}/locations/us-central1/featurestores/my-store"
        assert _parse_resource_id(name) == "my-store"

    def test_age_days_valid(self):
        create_dt = NOW - timedelta(days=45)
        age = _age_days(_iso(create_dt), NOW)
        assert age == pytest.approx(45.0, abs=0.01)

    def test_age_days_invalid(self):
        assert _age_days("not-a-date", NOW) is None

    def test_age_days_empty(self):
        assert _age_days("", NOW) is None


# ---------------------------------------------------------------------------
# Integration tests — legacy featurestores
# ---------------------------------------------------------------------------


class TestLegacyFeaturestore:
    def test_idle_high_confidence(self):
        """Monitoring confirms 0 requests → HIGH confidence."""
        store = _make_legacy_store(store_id="s1", node_count=2, age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.HIGH
        assert f.rule_id == "gcp.vertex.featurestore.idle"
        assert f.resource_type == "gcp.vertex.featurestore"

    def test_active_store_skipped(self):
        """Monitoring shows non-zero requests → no finding."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 500})
        assert findings == []

    def test_no_online_serving_skipped(self):
        """fixedNodeCount=0 → no online serving cost, skip."""
        store = _make_legacy_store(store_id="s1", node_count=0, age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert findings == []

    def test_non_stable_state_skipped(self):
        """UPDATING store → not stably billable, skip."""
        store = _make_legacy_store(store_id="s1", state="UPDATING", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert findings == []

    def test_age_based_fallback(self):
        """No monitoring data + old store → LOW confidence (heuristic: age only)."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(legacy_stores=[store])  # no legacy_counts → no monitoring data

        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW
        assert findings[0].risk == RiskLevel.MEDIUM

    def test_store_too_young_no_monitoring(self):
        """No monitoring data + store younger than threshold → no finding."""
        store = _make_legacy_store(store_id="s1", age_days=10)
        findings = _run(legacy_stores=[store])
        assert findings == []

    def test_cost_single_node(self):
        """1-node store: $0.27/hr × 730 h/month."""
        store = _make_legacy_store(store_id="s1", node_count=1, age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})

        expected_monthly = _BIGTABLE_NODE_HOURLY_COST * 1 * _HOURS_PER_MONTH
        assert findings[0].estimated_monthly_cost_usd == pytest.approx(expected_monthly, rel=1e-3)
        assert findings[0].details["bigtable_node_count"] == 1

    def test_cost_three_nodes(self):
        """3-node HA store: $0.27 × 3 × 730 ≈ $591/mo."""
        store = _make_legacy_store(store_id="s1", node_count=3, age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})

        expected_monthly = _BIGTABLE_NODE_HOURLY_COST * 3 * _HOURS_PER_MONTH
        assert findings[0].estimated_monthly_cost_usd == pytest.approx(expected_monthly, rel=1e-3)

    def test_permission_error_on_403(self):
        """403 on legacy list → PermissionError."""
        with pytest.raises(PermissionError, match="aiplatform.featurestores.list"):
            _run(legacy_list_status=403)

    def test_api_not_enabled_returns_empty(self):
        """404 on legacy list → no findings (not an error)."""
        findings = _run(legacy_list_status=404)
        assert findings == []

    def test_region_filter_matches(self):
        store = _make_legacy_store(store_id="s1", region="us-central1", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0}, region_filter="us-central1")
        assert len(findings) == 1

    def test_region_filter_excludes(self):
        store = _make_legacy_store(store_id="s1", region="europe-west4", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0}, region_filter="us-central1")
        assert findings == []

    def test_details_fields(self):
        store = _make_legacy_store(store_id="s1", region="us-central1", node_count=2, age_days=45)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        d = findings[0].details
        assert d["store_id"] == "s1"
        assert d["store_type"] == "legacy_featurestore"
        assert d["region"] == "us-central1"
        assert d["bigtable_node_count"] == 2
        assert d["request_count"] == 0
        assert d["idle_days_threshold"] == _IDLE_DAYS
        assert d["pricing_confidence"] == "published"

    def test_monitoring_error_age_fallback(self):
        """Monitoring raises exception → falls back to age-based detection (LOW confidence)."""
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(
            legacy_stores=[store],
            monitoring_raises=Exception("monitoring down"),
        )
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_estimated_monthly_cost_set(self):
        store = _make_legacy_store(store_id="s1", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert findings[0].estimated_monthly_cost_usd is not None
        assert findings[0].estimated_monthly_cost_usd > 0

    def test_display_name_in_summary(self):
        store = _make_legacy_store(store_id="s1", display_name="prod-features", age_days=60)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert "prod-features" in findings[0].summary

    def test_custom_idle_days(self):
        """Custom idle_days is respected for age-based fallback (LOW confidence)."""
        store = _make_legacy_store(store_id="s1", age_days=15)
        findings = _run(legacy_stores=[store], idle_days=10)
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_autoscaled_store_included(self):
        """Autoscaled legacy store (scaling.minNodeCount) is in scope."""
        store = _make_legacy_store(store_id="s1", node_count=2, age_days=60, autoscaled=True)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.details["bigtable_node_count"] == 2
        assert f.details["bigtable_scaling"] == "autoscaled"
        expected_monthly = _BIGTABLE_NODE_HOURLY_COST * 2 * _HOURS_PER_MONTH
        assert f.estimated_monthly_cost_usd == pytest.approx(expected_monthly, rel=1e-3)

    def test_autoscaled_store_zero_min_nodes_excluded(self):
        """Autoscaled store with minNodeCount=0 has no online serving cost — skip."""
        store = _make_legacy_store(store_id="s1", node_count=0, age_days=60, autoscaled=True)
        findings = _run(legacy_stores=[store], legacy_counts={"s1": 0})
        assert findings == []


# ---------------------------------------------------------------------------
# Integration tests — new featureOnlineStores
# ---------------------------------------------------------------------------


class TestFeatureOnlineStore:
    def test_bigtable_store_idle_high_confidence(self):
        """New Bigtable-backed store: monitoring idle → HIGH confidence."""
        store = _make_new_store(store_id="fos1", min_nodes=2, age_days=45)
        findings = _run(new_stores=[store], new_counts={"fos1": 0})

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.resource_type == "gcp.vertex.feature_online_store"
        assert f.details["store_type"] == "feature_online_store"
        assert f.details["backing"] == "bigtable"

    def test_optimized_store_idle(self):
        """Optimized (BigQuery-backed) store: idle → estimated cost."""
        store = _make_new_store(store_id="fos1", is_optimized=True, age_days=45)
        findings = _run(new_stores=[store], new_counts={"fos1": 0})

        assert len(findings) == 1
        f = findings[0]
        assert f.details["backing"] == "optimized"
        assert f.details["pricing_confidence"] == "estimated"
        assert f.estimated_monthly_cost_usd == pytest.approx(_OPTIMIZED_STORE_MONTHLY_COST)

    def test_active_new_store_skipped(self):
        """New store with non-zero requests → no finding."""
        store = _make_new_store(store_id="fos1", age_days=45)
        findings = _run(new_stores=[store], new_counts={"fos1": 1000})
        assert findings == []

    def test_new_store_permission_error(self):
        """403 on featureOnlineStores list → PermissionError."""
        with pytest.raises(PermissionError, match="aiplatform.featureOnlineStores.list"):
            _run(new_list_status=403)

    def test_new_store_not_enabled(self):
        """404 on featureOnlineStores list → no findings."""
        findings = _run(new_list_status=404)
        assert findings == []

    def test_bigtable_store_cost(self):
        """Bigtable store: minNodeCount × $0.27/hr × 730 h/month."""
        store = _make_new_store(store_id="fos1", min_nodes=3, age_days=45)
        findings = _run(new_stores=[store], new_counts={"fos1": 0})

        expected_monthly = _BIGTABLE_NODE_HOURLY_COST * 3 * _HOURS_PER_MONTH
        assert findings[0].estimated_monthly_cost_usd == pytest.approx(expected_monthly, rel=1e-3)

    def test_new_store_age_fallback(self):
        """No monitoring data + old new store → LOW confidence (heuristic: age only)."""
        store = _make_new_store(store_id="fos1", age_days=45)
        findings = _run(new_stores=[store])  # no new_counts → no monitoring data
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_new_store_too_young(self):
        """New store younger than threshold + no monitoring → no finding."""
        store = _make_new_store(store_id="fos1", age_days=5)
        findings = _run(new_stores=[store])
        assert findings == []

    def test_non_stable_new_store_skipped(self):
        store = _make_new_store(store_id="fos1", state="UPDATING", age_days=60)
        findings = _run(new_stores=[store], new_counts={"fos1": 0})
        assert findings == []

    def test_new_store_region_filter(self):
        store = _make_new_store(store_id="fos1", region="europe-west4", age_days=45)
        findings = _run(new_stores=[store], new_counts={"fos1": 0}, region_filter="us-central1")
        assert findings == []


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------


class TestCombined:
    def test_both_types_independent(self):
        """Legacy and new stores both produce findings independently."""
        legacy = _make_legacy_store(store_id="legacy1", age_days=60)
        new = _make_new_store(store_id="new1", age_days=45)
        findings = _run(
            legacy_stores=[legacy],
            new_stores=[new],
            legacy_counts={"legacy1": 0},
            new_counts={"new1": 0},
        )
        assert len(findings) == 2
        types = {f.resource_type for f in findings}
        assert types == {"gcp.vertex.featurestore", "gcp.vertex.feature_online_store"}

    def test_no_stores_returns_empty(self):
        findings = _run()
        assert findings == []

    def test_one_active_one_idle(self):
        """Active legacy + idle new → only one finding."""
        legacy = _make_legacy_store(store_id="l1", age_days=60)
        new = _make_new_store(store_id="n1", age_days=45)
        findings = _run(
            legacy_stores=[legacy],
            new_stores=[new],
            legacy_counts={"l1": 1000},  # active
            new_counts={"n1": 0},  # idle
        )
        assert len(findings) == 1
        assert findings[0].resource_type == "gcp.vertex.feature_online_store"
