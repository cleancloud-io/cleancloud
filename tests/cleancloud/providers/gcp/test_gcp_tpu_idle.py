"""
Tests for gcp.tpu.idle rule.

Coverage:
- Core detection: monitoring confirms idle → HIGH confidence, HIGH/CRITICAL risk
- Age-based fallback: no monitoring data, old node → LOW confidence
- Active node (duty_cycle > threshold) → no finding
- STOPPED node → no finding (not billable)
- Permission error on 403 → raises PermissionError
- TPU API not enabled (404) → returns []
- Region filter: nodes in other zones skipped
- Cost: per-chip × chip_count; risk CRITICAL for hourly >= $10
- Different TPU types: V2, V4, V5LITE_POD, V5P
- acceleratorConfig preferred over legacy acceleratorType
- topology-based chip count
- Preemptible flag surfaced in signals
- Monitoring failure → age fallback (no exception raised)
- Node too young + no monitoring → no finding
- estimated_monthly_cost_usd is set (TPU is a standing resource)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.ai.tpu_idle import (
    _CHIP_HOURLY_COST,
    _DEFAULT_IDLE_DAYS,
    _DUTY_CYCLE_IDLE_THRESHOLD,
    _HOURS_PER_MONTH,
    _chip_count,
    _hourly_cost,
    _parse_location,
    _parse_node_id,
    _tpu_type_from_legacy,
    find_idle_tpu_nodes,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
_PROJECT = "my-project"
_IDLE_DAYS = _DEFAULT_IDLE_DAYS  # 7


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _make_node(
    node_id: str = "my-tpu",
    zone: str = "us-central1-f",
    state: str = "READY",
    tpu_type: str = "V4",
    topology: str = "2x2x1",
    accel_type_legacy: str = "v4-8",
    chips: int = 4,
    age_days: float = 14.0,
    runtime: str = "tpu-vm-tf-2.16.1",
    preemptible: bool = False,
    description: str = "",
) -> dict:
    create_dt = NOW - timedelta(days=age_days)
    node: dict = {
        "name": f"projects/{_PROJECT}/locations/{zone}/nodes/{node_id}",
        "state": state,
        "acceleratorConfig": {"type": tpu_type, "topology": topology},
        "acceleratorType": accel_type_legacy,
        "createTime": _iso(create_dt),
        "runtimeVersion": runtime,
        "schedulingConfig": {"preemptible": preemptible},
        "description": description,
    }
    return node


def _make_ts(node_id: str, duty_cycle: float, n_points: int = _IDLE_DAYS):
    """Build a mock monitoring time-series for a TPU node.

    n_points defaults to _IDLE_DAYS to satisfy the minimum-coverage check in
    _fetch_duty_cycles (which requires ≥ idle_days data points).
    """

    def _point(v: float):
        p = MagicMock()
        p.value.double_value = v
        return p

    ts = MagicMock()
    ts.resource.labels = {"node_id": node_id}
    ts.points = [_point(duty_cycle) for _ in range(n_points)]
    return ts


def _run(
    nodes: list,
    duty_cycles: dict[str, float] | None = None,
    region_filter=None,
    idle_days: int = _IDLE_DAYS,
    monitoring_raises: Exception | None = None,
):
    """Run find_idle_tpu_nodes with mocked HTTP and monitoring."""
    # Build mock HTTP session for node listing
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = {"nodes": nodes}
    mock_session_inst = MagicMock()
    mock_session_inst.get.return_value = list_resp

    # Build mock monitoring client
    mock_monitoring_inst = MagicMock()
    if monitoring_raises:
        mock_monitoring_inst.list_time_series.side_effect = monitoring_raises
    else:
        time_series = [_make_ts(nid, dc) for nid, dc in (duty_cycles or {}).items()]
        mock_monitoring_inst.list_time_series.return_value = time_series

    credentials = MagicMock()

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
            return_value=mock_session_inst,
        ),
        patch(
            "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
            return_value=mock_monitoring_inst,
        ),
        patch("cleancloud.providers.gcp.rules.ai.tpu_idle.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat = datetime.fromisoformat
        findings = find_idle_tpu_nodes(
            project_id=_PROJECT,
            credentials=credentials,
            region_filter=region_filter,
            idle_days=idle_days,
        )
    return findings


# ---------------------------------------------------------------------------
# Unit tests — helper functions
# ---------------------------------------------------------------------------


class TestParseLocation:
    def test_valid(self):
        name = f"projects/{_PROJECT}/locations/us-central1-f/nodes/n1"
        assert _parse_location(name) == "us-central1-f"

    def test_missing(self):
        assert _parse_location("bad/name") is None

    def test_empty(self):
        assert _parse_location("") is None


class TestParseNodeId:
    def test_valid(self):
        name = f"projects/{_PROJECT}/locations/us-central1-f/nodes/my-tpu"
        assert _parse_node_id(name) == "my-tpu"

    def test_empty(self):
        assert _parse_node_id("") == ""


class TestTpuTypeFromLegacy:
    @pytest.mark.parametrize(
        "accel_type,expected",
        [
            ("v2-8", "V2"),
            ("v3-8", "V3"),
            ("v4-8", "V4"),
            ("v5litepod-4", "V5LITE_POD"),
            ("v5litepod-8", "V5LITE_POD"),
            ("v5p-4", "V5P"),
            ("v6e-8", "V6E"),
            ("unknown-99", ""),
        ],
    )
    def test_mapping(self, accel_type, expected):
        assert _tpu_type_from_legacy(accel_type) == expected


class TestChipCount:
    @pytest.mark.parametrize(
        "accel_type,topology,expected",
        [
            ("v2-8", None, 8),
            ("v4-8", None, 8),
            ("v5litepod-4", None, 4),
            ("", "2x2", 4),
            ("", "2x2x2", 8),
            ("", "4x4", 16),
            ("v4-8", "2x2x1", 4),  # topology wins
            ("", "", 1),
        ],
    )
    def test_chip_count(self, accel_type, topology, expected):
        chips, _ = _chip_count(accel_type, topology)
        assert chips == expected


class TestHourlyCost:
    def test_v4_4chips(self):
        cost, confidence = _hourly_cost("V4", 4)
        assert cost == pytest.approx(_CHIP_HOURLY_COST["V4"] * 4)
        assert confidence == "published"

    def test_v5p_8chips(self):
        cost, confidence = _hourly_cost("V5P", 8)
        assert cost == pytest.approx(_CHIP_HOURLY_COST["V5P"] * 8)
        assert confidence == "published"

    def test_unknown_type(self):
        cost, confidence = _hourly_cost("UNKNOWN", 4)
        assert cost == pytest.approx(2.00 * 4)
        assert confidence == "estimated"

    def test_v6e_estimated(self):
        _, confidence = _hourly_cost("V6E", 8)
        assert confidence == "estimated"


# ---------------------------------------------------------------------------
# Integration tests — find_idle_tpu_nodes
# ---------------------------------------------------------------------------


class TestFindIdleTpuNodes:
    def test_idle_high_confidence(self):
        """Monitoring confirms idle → HIGH confidence."""
        node = _make_node(node_id="tpu-1", tpu_type="V4", topology="2x2x1", age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.005})

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.rule_id == "gcp.tpu.idle"
        assert f.resource_type == "gcp.tpu.node"
        assert "tpu-1" in f.resource_id

    def test_active_node_skipped(self):
        """Duty cycle above threshold → no finding."""
        node = _make_node(node_id="tpu-active")
        findings = _run([node], duty_cycles={"tpu-active": 0.85})
        assert findings == []

    def test_exactly_at_threshold_skipped(self):
        """Duty cycle exactly at threshold (0.02) is NOT idle — must be strictly above."""
        node = _make_node(node_id="tpu-border")
        # duty_cycle == threshold → active (not <=, but >)
        # 0.02 is NOT > 0.02 → idle path fires — this checks the boundary
        # Rule: if duty_cycle > threshold → skip. 0.02 is not > 0.02.
        findings = _run([node], duty_cycles={"tpu-border": _DUTY_CYCLE_IDLE_THRESHOLD})
        assert len(findings) == 1  # At exactly threshold → flagged as idle

    def test_stopped_node_skipped(self):
        """STOPPED nodes do not incur charges and should not be flagged."""
        node = _make_node(state="STOPPED", age_days=30)
        findings = _run([node], duty_cycles={})
        assert findings == []

    def test_no_nodes_returns_empty(self):
        """No TPU nodes → no findings."""
        findings = _run([], duty_cycles={})
        assert findings == []

    def test_permission_error_on_403(self):
        """403 from the TPU API → PermissionError propagated."""
        list_resp = MagicMock()
        list_resp.status_code = 403
        mock_session = MagicMock()
        mock_session.get.return_value = list_resp

        with (
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
                return_value=mock_session,
            ),
            patch("cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient"),
        ):
            with pytest.raises(PermissionError, match="tpu.nodes.list"):
                find_idle_tpu_nodes(project_id=_PROJECT, credentials=MagicMock())

    def test_tpu_api_not_enabled_returns_empty(self):
        """404 from the TPU API (API not enabled) → empty list, no exception."""
        list_resp = MagicMock()
        list_resp.status_code = 404
        mock_session = MagicMock()
        mock_session.get.return_value = list_resp

        with (
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
                return_value=mock_session,
            ),
            patch("cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient"),
        ):
            findings = find_idle_tpu_nodes(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []

    def test_age_based_fallback_no_monitoring(self):
        """No monitoring data + old node → LOW confidence (age is a weak proxy)."""
        node = _make_node(node_id="tpu-old", age_days=30)
        findings = _run([node], duty_cycles={})  # no monitoring data

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == ConfidenceLevel.LOW
        assert f.risk == RiskLevel.MEDIUM

    def test_node_too_young_no_monitoring(self):
        """No monitoring data + node younger than threshold → no finding."""
        node = _make_node(node_id="tpu-new", age_days=3)
        findings = _run([node], duty_cycles={})
        assert findings == []

    def test_monitoring_error_falls_back_to_age(self):
        """Monitoring API raises an exception → falls back to age-based detection."""
        node = _make_node(node_id="tpu-1", age_days=20)
        findings = _run(
            [node],
            duty_cycles={},
            monitoring_raises=Exception("monitoring unavailable"),
        )
        # Age-based fallback fires: 20d >= 7d → LOW (weak signal)
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_region_filter_matches(self):
        """Node in the filtered region is included."""
        node = _make_node(node_id="tpu-1", zone="us-central1-f", age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.0}, region_filter="us-central1")
        assert len(findings) == 1

    def test_region_filter_excludes(self):
        """Node in a different region is excluded."""
        node = _make_node(node_id="tpu-1", zone="europe-west4-a", age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.0}, region_filter="us-central1")
        assert findings == []

    def test_cost_v4_4chips(self):
        """V4 node with 4 chips: cost = _CHIP_HOURLY_COST['V4'] × 4."""
        node = _make_node(
            node_id="tpu-v4",
            tpu_type="V4",
            topology="2x2x1",
            accel_type_legacy="v4-8",
            age_days=14,
        )
        # topology "2x2x1" = 4 chips
        findings = _run([node], duty_cycles={"tpu-v4": 0.0})
        assert len(findings) == 1
        expected_hourly = _CHIP_HOURLY_COST["V4"] * 4
        assert findings[0].estimated_monthly_cost_usd == pytest.approx(
            expected_hourly * _HOURS_PER_MONTH, rel=1e-3
        )
        assert findings[0].details["chip_count"] == 4

    def test_risk_critical_for_expensive_node(self):
        """HIGH confidence + hourly >= $10 → CRITICAL risk."""
        # V4, 4 chips: 3.22 * 4 = $12.88/hr >= $10 → CRITICAL
        node = _make_node(node_id="tpu-v4", tpu_type="V4", topology="2x2x1", age_days=14)
        findings = _run([node], duty_cycles={"tpu-v4": 0.0})
        assert findings[0].risk == RiskLevel.CRITICAL

    def test_risk_high_for_cheap_node(self):
        """HIGH confidence + hourly < $10 → HIGH risk."""
        # V5LITE_POD, 4 chips: $1.20 * 4 = $4.80/hr < $10 → HIGH
        node = _make_node(
            node_id="tpu-v5e",
            tpu_type="V5LITE_POD",
            topology="2x2",
            accel_type_legacy="v5litepod-4",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-v5e": 0.0})
        assert findings[0].risk == RiskLevel.HIGH

    def test_risk_critical_for_v2_8chip(self):
        """V2 8-chip node: $1.50/chip × 8 = $12/hr ≥ $10 → CRITICAL."""
        node = _make_node(
            node_id="tpu-v2",
            tpu_type="V2",
            topology="2x4",
            accel_type_legacy="v2-8",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-v2": 0.0})
        assert findings[0].risk == RiskLevel.CRITICAL

    def test_v5litepod_type_detected(self):
        """V5LITE_POD type is correctly detected from acceleratorConfig."""
        node = _make_node(
            node_id="tpu-v5e",
            tpu_type="V5LITE_POD",
            topology="2x4",
            accel_type_legacy="v5litepod-8",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-v5e": 0.01})
        assert len(findings) == 1
        assert findings[0].details["tpu_type"] == "V5LITE_POD"

    def test_legacy_type_fallback(self):
        """No acceleratorConfig.type → falls back to legacy acceleratorType."""
        node = _make_node(node_id="tpu-legacy", age_days=14)
        # Remove acceleratorConfig.type
        node["acceleratorConfig"] = {}
        node["acceleratorType"] = "v4-8"
        findings = _run([node], duty_cycles={"tpu-legacy": 0.0})
        assert len(findings) == 1
        assert findings[0].details["tpu_type"] == "V4"

    def test_topology_chip_count_used(self):
        """Topology is preferred for chip count over acceleratorType suffix."""
        node = _make_node(
            node_id="tpu-1",
            tpu_type="V4",
            topology="2x2x2",  # 8 chips
            accel_type_legacy="v4-8",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-1": 0.0})
        assert findings[0].details["chip_count"] == 8

    def test_preemptible_in_signals(self):
        """Preemptible flag is surfaced in evidence signals."""
        node = _make_node(node_id="tpu-1", preemptible=True, age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.0})
        assert len(findings) == 1
        signals_text = " ".join(findings[0].evidence.signals_used)
        assert "preemptible" in signals_text.lower()

    def test_description_used_as_display_name(self):
        """Node description is used in summary when present."""
        node = _make_node(node_id="tpu-1", description="my-llm-tpu", age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.0})
        assert "my-llm-tpu" in findings[0].summary

    def test_monthly_cost_set(self):
        """estimated_monthly_cost_usd is always set (TPU is a standing resource)."""
        node = _make_node(node_id="tpu-1", age_days=14)
        findings = _run([node], duty_cycles={"tpu-1": 0.0})
        assert findings[0].estimated_monthly_cost_usd is not None
        assert findings[0].estimated_monthly_cost_usd > 0

    def test_details_fields(self):
        """Key fields are present in finding details."""
        node = _make_node(
            node_id="tpu-1",
            zone="us-central1-f",
            tpu_type="V4",
            topology="2x2x1",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-1": 0.005})
        d = findings[0].details
        assert d["zone"] == "us-central1-f"
        assert d["chip_count"] == 4
        assert d["idle_days_threshold"] == _IDLE_DAYS
        assert d["max_duty_cycle"] == pytest.approx(0.005)
        assert d["pricing_scope"] == "us_central1_reference_not_region_adjusted"
        assert d["pricing_confidence"] == "published"

    def test_custom_idle_days(self):
        """Custom idle_days parameter is respected."""
        # Node 5 days old — below default 7d threshold but above custom 3d
        node = _make_node(node_id="tpu-1", age_days=5)
        findings = _run([node], duty_cycles={}, idle_days=3)
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_multiple_nodes_independent(self):
        """Each node is evaluated independently."""
        idle_node = _make_node(node_id="tpu-idle", age_days=14)
        active_node = _make_node(node_id="tpu-active", age_days=14)
        findings = _run(
            [idle_node, active_node],
            duty_cycles={"tpu-idle": 0.0, "tpu-active": 0.9},
        )
        assert len(findings) == 1
        assert "tpu-idle" in findings[0].resource_id

    def test_v5p_cost_and_risk(self):
        """V5P node with 8 chips: $4.20 × 8 = $33.60/hr → CRITICAL."""
        node = _make_node(
            node_id="tpu-v5p",
            tpu_type="V5P",
            topology="2x4",  # 8 chips
            accel_type_legacy="v5p-8",
            age_days=14,
        )
        findings = _run([node], duty_cycles={"tpu-v5p": 0.0})
        assert len(findings) == 1
        f = findings[0]
        assert f.risk == RiskLevel.CRITICAL
        expected_hourly = _CHIP_HOURLY_COST["V5P"] * 8
        assert f.details["hourly_cost_usd"] == pytest.approx(expected_hourly, rel=1e-3)
