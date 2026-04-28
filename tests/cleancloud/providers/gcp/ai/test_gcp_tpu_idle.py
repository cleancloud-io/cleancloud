"""
Tests for gcp.tpu.idle rule.

Coverage:
- Pre-checks: state, region filter, createTime, standalone (queuedResource, multisliceNode)
- Monitoring client creation failure -> warning, all nodes skip
- Monitoring query exception -> warning, node skips
- _run_zone_diagnostic: returns None (side-effect / diagnostic only), RPC exceptions propagate,
  monitoring IS queried (to surface permission errors per spec 11.1)
- No findings emitted: join (spec 8.3) cannot be proven with documented surfaces
- Permission error on 403 -> raises PermissionError
- TPU API not enabled (404) -> returns []
- RULE_ID attribute set correctly
- Helper functions: _parse_location, _parse_node_id, _zone_to_region, _parse_rfc3339_utc,
  _tpu_type_from_legacy
"""

import warnings
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.providers.gcp.rules.ai.tpu_idle import (
    _DEFAULT_IDLE_DAYS,
    _MONITORING_BUFFER_SECONDS,
    _parse_location,
    _parse_node_id,
    _parse_rfc3339_utc,
    _run_zone_diagnostic,
    _tpu_type_from_legacy,
    _zone_to_region,
    find_idle_tpu_nodes,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
_PROJECT = "my-project"
_IDLE_DAYS = _DEFAULT_IDLE_DAYS  # 7

# Derived window boundaries matching find_idle_tpu_nodes logic for NOW
_WINDOW_END = NOW - timedelta(seconds=_MONITORING_BUFFER_SECONDS)
_WINDOW_START = _WINDOW_END - timedelta(seconds=_IDLE_DAYS * 86400)


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
    age_days: float = 14.0,
    runtime: str = "tpu-vm-tf-2.16.1",
    preemptible: bool = False,
    description: str = "",
    queued_resource: Optional[str] = None,
    multislice_node: Optional[bool] = None,
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
    if queued_resource is not None:
        node["queuedResource"] = queued_resource
    if multislice_node is not None:
        node["multisliceNode"] = multislice_node
    return node


def _make_mock_monitoring_client() -> MagicMock:
    """Return a mock monitoring client that returns an empty series list."""
    client = MagicMock()
    client.list_time_series.return_value = []
    return client


def _run(
    nodes: list,
    region_filter=None,
    idle_days: int = _IDLE_DAYS,
    monitoring_client_fails: bool = False,
) -> list:
    """Run find_idle_tpu_nodes with mocked HTTP session and monitoring client."""
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = {"nodes": nodes}
    mock_session = MagicMock()
    mock_session.get.return_value = list_resp

    if monitoring_client_fails:
        client_patch = patch(
            "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
            side_effect=RuntimeError("client creation failed"),
        )
    else:
        mock_client = _make_mock_monitoring_client()
        client_patch = patch(
            "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
            return_value=mock_client,
        )

    with (
        patch(
            "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
            return_value=mock_session,
        ),
        client_patch,
        patch("cleancloud.providers.gcp.rules.ai.tpu_idle.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat = datetime.fromisoformat
        findings = find_idle_tpu_nodes(
            project_id=_PROJECT,
            credentials=MagicMock(),
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


class TestZoneToRegion:
    @pytest.mark.parametrize(
        "zone,expected",
        [
            ("us-central1-f", "us-central1"),
            ("europe-west4-a", "europe-west4"),
            ("northamerica-northeast1-a", "northamerica-northeast1"),
            ("us-east1-b", "us-east1"),
        ],
    )
    def test_valid_zones(self, zone, expected):
        assert _zone_to_region(zone) == expected

    def test_no_hyphen_returns_none(self):
        assert _zone_to_region("somezonewithouthyphen") is None

    def test_empty_returns_none(self):
        assert _zone_to_region("") is None


class TestParseRfc3339Utc:
    def test_z_suffix(self):
        dt = _parse_rfc3339_utc("2025-05-01T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 10

    def test_offset_normalized_to_utc(self):
        dt = _parse_rfc3339_utc("2025-05-01T12:00:00+05:30")
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 6
        assert dt.minute == 30

    def test_empty_returns_none(self):
        assert _parse_rfc3339_utc("") is None

    def test_none_input_returns_none(self):
        assert _parse_rfc3339_utc(None) is None  # type: ignore[arg-type]

    def test_unparsable_returns_none(self):
        assert _parse_rfc3339_utc("not-a-date") is None


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


# ---------------------------------------------------------------------------
# Unit tests — _run_zone_diagnostic
# ---------------------------------------------------------------------------


class TestQueryNodeActivity:
    _ZONE = "us-central1-f"

    def test_returns_none_side_effect_only(self):
        """Function is diagnostic only (spec 11.1): returns None, not a telemetry verdict."""
        client = _make_mock_monitoring_client()
        result = _run_zone_diagnostic(
            client,
            _PROJECT,
            self._ZONE,
            _WINDOW_START,
            _WINDOW_END,
        )
        assert result is None

    def test_monitoring_is_queried(self):
        """Monitoring IS queried to surface permission and availability errors (spec 11.1)."""
        client = _make_mock_monitoring_client()
        _run_zone_diagnostic(
            client,
            _PROJECT,
            self._ZONE,
            _WINDOW_START,
            _WINDOW_END,
        )
        assert client.list_time_series.called

    def test_rpc_exception_propagates(self):
        """RPC errors propagate to the caller — no swallowing."""
        client = MagicMock()
        client.list_time_series.side_effect = RuntimeError("network error")
        with pytest.raises(RuntimeError, match="network error"):
            _run_zone_diagnostic(
                client,
                _PROJECT,
                self._ZONE,
                _WINDOW_START,
                _WINDOW_END,
            )

    def test_returns_none_regardless_of_series_content(self):
        """Returns None regardless of series content — result is never used for decisions."""
        series = MagicMock()
        series.resource.labels = {"worker_id": "0"}
        pt = MagicMock()
        pt.value.double_value = 0.0
        series.points = [pt]
        client = MagicMock()
        client.list_time_series.return_value = [series]
        result = _run_zone_diagnostic(
            client,
            _PROJECT,
            self._ZONE,
            _WINDOW_START,
            _WINDOW_END,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Integration tests — find_idle_tpu_nodes
# ---------------------------------------------------------------------------


class TestFindIdleTpuNodes:
    # --- No findings emitted ---

    def test_ready_node_no_finding_join_unprovable(self):
        """READY node passes all pre-checks but no finding: join is unprovable (spec 8.3)."""
        node = _make_node(node_id="tpu-1", age_days=14)
        findings = _run([node])
        assert findings == []

    def test_no_nodes_returns_empty(self):
        findings = _run([])
        assert findings == []

    # --- State pre-check ---

    def test_stopped_node_skipped(self):
        node = _make_node(state="STOPPED", age_days=30)
        findings = _run([node])
        assert findings == []

    def test_creating_state_skipped(self):
        node = _make_node(state="CREATING", age_days=30)
        findings = _run([node])
        assert findings == []

    # --- Permission / API availability ---

    def test_permission_error_on_403(self):
        """403 from TPU API -> PermissionError propagated."""
        list_resp = MagicMock()
        list_resp.status_code = 403
        list_resp.json.return_value = {"error": {"details": [{"reason": "PERMISSION_DENIED"}]}}
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
        """404 from TPU API (API not enabled) -> empty list, no exception."""
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

    # --- Region filter ---

    def test_region_filter_exact_match_included_still_no_finding(self):
        """Node in filtered region passes filter but still no finding (join unprovable)."""
        node = _make_node(node_id="tpu-1", zone="us-central1-f", age_days=14)
        findings = _run([node], region_filter="us-central1")
        assert findings == []

    def test_region_filter_exact_match_excluded(self):
        """Node in different region is excluded at region-filter pre-check."""
        node = _make_node(node_id="tpu-1", zone="europe-west4-a", age_days=14)
        findings = _run([node], region_filter="us-central1")
        assert findings == []

    def test_region_filter_prefix_not_matched(self):
        """Region filter is exact: 'us-central1' does not match 'us-central10-a' derived region."""
        node = _make_node(node_id="tpu-1", zone="us-central10-a", age_days=14)
        findings = _run([node], region_filter="us-central1")
        assert findings == []

    # --- Standalone pre-checks ---

    def test_queued_resource_non_empty_skipped(self):
        node = _make_node(
            node_id="tpu-1", age_days=14, queued_resource="projects/p/queuedResources/q"
        )
        findings = _run([node])
        assert findings == []

    def test_queued_resource_empty_passes_precheck(self):
        """Empty queuedResource string is standalone — still no finding due to join."""
        node = _make_node(node_id="tpu-1", age_days=14, queued_resource="")
        findings = _run([node])
        assert findings == []

    def test_multislice_true_skipped(self):
        node = _make_node(node_id="tpu-1", age_days=14, multislice_node=True)
        findings = _run([node])
        assert findings == []

    def test_multislice_false_passes_precheck(self):
        """multisliceNode=False is standalone — still no finding due to join."""
        node = _make_node(node_id="tpu-1", age_days=14, multislice_node=False)
        findings = _run([node])
        assert findings == []

    def test_malformed_queued_resource_skipped(self):
        """Non-string/non-null queuedResource -> skip."""
        node = _make_node(node_id="tpu-1", age_days=14)
        node["queuedResource"] = 12345
        findings = _run([node])
        assert findings == []

    def test_malformed_multislice_skipped(self):
        """Non-bool/non-null multisliceNode -> skip."""
        node = _make_node(node_id="tpu-1", age_days=14)
        node["multisliceNode"] = "yes"
        findings = _run([node])
        assert findings == []

    # --- createTime pre-checks ---

    def test_missing_create_time_skipped(self):
        node = _make_node(node_id="tpu-1", age_days=14)
        del node["createTime"]
        findings = _run([node])
        assert findings == []

    def test_future_create_time_skipped(self):
        node = _make_node(node_id="tpu-1", age_days=-1)
        findings = _run([node])
        assert findings == []

    def test_too_recent_skipped(self):
        """Node created after window_start -> full window not coverable -> skip."""
        node = _make_node(node_id="tpu-1", age_days=3)
        findings = _run([node])
        assert findings == []

    # --- Monitoring failures ---

    def test_monitoring_client_failure_skips_all_with_warning(self):
        """Monitoring client creation failure -> all nodes skip, warning issued."""
        node = _make_node(node_id="tpu-1", age_days=14)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            findings = _run([node], monitoring_client_fails=True)
        assert findings == []
        msgs = " ".join(str(warning.message) for warning in w)
        assert "monitoring client creation failed" in msgs

    def test_monitoring_query_exception_skips_with_warning(self):
        """Query RPC exception for a zone -> node in that zone skips, zone name in warning."""
        node = _make_node(node_id="tpu-1", zone="us-central1-f", age_days=14)
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.json.return_value = {"nodes": [node]}
        mock_session = MagicMock()
        mock_session.get.return_value = list_resp

        failing_client = MagicMock()
        failing_client.list_time_series.side_effect = RuntimeError("rpc failed")

        with (
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
                return_value=mock_session,
            ),
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
                return_value=failing_client,
            ),
            patch("cleancloud.providers.gcp.rules.ai.tpu_idle.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                findings = find_idle_tpu_nodes(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []
        msgs = " ".join(str(warning.message) for warning in w)
        assert "monitoring query failed" in msgs
        assert "us-central1-f" in msgs  # zone-cached path warns on zone, not node ID

    def test_two_nodes_same_zone_single_monitoring_call(self):
        """Two READY nodes in the same zone produce only one monitoring API call."""
        nodes = [
            _make_node(node_id="tpu-a", zone="us-central1-f", age_days=14),
            _make_node(node_id="tpu-b", zone="us-central1-f", age_days=14),
        ]
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.json.return_value = {"nodes": nodes}
        mock_session = MagicMock()
        mock_session.get.return_value = list_resp
        mock_client = _make_mock_monitoring_client()

        with (
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
                return_value=mock_session,
            ),
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
                return_value=mock_client,
            ),
            patch("cleancloud.providers.gcp.rules.ai.tpu_idle.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
            findings = find_idle_tpu_nodes(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []
        assert mock_client.list_time_series.call_count == 1

    def test_zone_error_cached_second_node_skipped_without_second_warning(self):
        """Zone query error is cached; a second node in the same zone skips silently."""
        nodes = [
            _make_node(node_id="tpu-a", zone="us-central1-f", age_days=14),
            _make_node(node_id="tpu-b", zone="us-central1-f", age_days=14),
        ]
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.json.return_value = {"nodes": nodes}
        mock_session = MagicMock()
        mock_session.get.return_value = list_resp
        failing_client = MagicMock()
        failing_client.list_time_series.side_effect = RuntimeError("rpc failed")

        with (
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.AuthorizedSession",
                return_value=mock_session,
            ),
            patch(
                "cleancloud.providers.gcp.rules.ai.tpu_idle.monitoring_v3.MetricServiceClient",
                return_value=failing_client,
            ),
            patch("cleancloud.providers.gcp.rules.ai.tpu_idle.datetime") as mock_dt,
        ):
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                findings = find_idle_tpu_nodes(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []
        zone_warns = [x for x in w if "monitoring query failed" in str(x.message)]
        assert len(zone_warns) == 1  # one warning for the zone, not one per node
        assert "us-central1-f" in str(zone_warns[0].message)
        assert failing_client.list_time_series.call_count == 1  # only one API call

    # --- Miscellaneous ---

    def test_multiple_ready_nodes_no_findings(self):
        """Each READY node passes pre-checks but no findings (join unprovable for all)."""
        nodes = [
            _make_node(node_id="tpu-a", zone="us-central1-f", age_days=14),
            _make_node(node_id="tpu-b", zone="us-central1-b", age_days=20),
        ]
        findings = _run(nodes)
        assert findings == []

    def test_custom_idle_days_still_no_findings(self):
        """Custom idle_days is respected for pre-checks but join still blocks emission."""
        node = _make_node(node_id="tpu-1", age_days=5)
        findings = _run([node], idle_days=3)
        assert findings == []

    def test_rule_id_attribute(self):
        assert find_idle_tpu_nodes.RULE_ID == "gcp.tpu.idle"
