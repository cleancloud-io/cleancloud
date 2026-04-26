"""
Tests for gcp.vertex.workbench.idle rule.

Coverage:
- Core detection: idle CPU instance (MEDIUM risk), idle GPU instance (HIGH risk)
- Skipping: STOPPED instances, young instances, instances with recent activity
- Confidence levels: HIGH (updateTime + age >= threshold), MEDIUM (75% threshold or age-fallback)
- GPU detection: NVIDIA_TESLA_T4, NVIDIA_TESLA_A100, a2-* machines
- Risk levels: CRITICAL (GPU + idle_ratio >= 2.0), HIGH (GPU), MEDIUM (CPU)
- Cost estimation: machine cost, GPU add-on for n1/n2, bundled for a2/g2
- Age-fallback: when updateTime unavailable, confidence capped at MEDIUM
- Region filter: instances outside the filter are skipped
- Both API versions: v1 (User-Managed Notebooks), v2 (Vertex AI Workbench)
- Permission errors: PermissionError raised on 403 from list call
- RULE_METADATA and RULE_ID attributes present
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.ai.workbench_idle import (
    _DEFAULT_MACHINE_MONTHLY_COST,
    _GPU_MONTHLY_COST_EACH,
    _MACHINE_MONTHLY_COST,
    RULE_METADATA,
    _estimate_cost,
    _normalize,
    find_idle_workbench_instances,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROJECT = "my-project"
_LOCATION = "us-central1"
_INSTANCE_ID = "my-workbench-1"
_INSTANCE_NAME = f"projects/{_PROJECT}/locations/{_LOCATION}/instances/{_INSTANCE_ID}"

_OLD_TIME = NOW - timedelta(days=30)
_IDLE_TIME = NOW - timedelta(days=20)
_RECENT_TIME = NOW - timedelta(days=3)
_YOUNG_TIME = NOW - timedelta(days=2)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _v2_instance(
    name: str = _INSTANCE_NAME,
    state: str = "ACTIVE",
    create_time: datetime = _OLD_TIME,
    update_time: datetime = _IDLE_TIME,
    machine_type: str = "n1-standard-4",
    accel_type: str = "",
    accel_count: int = 0,
    labels: dict = None,
) -> dict:
    """Build a minimal v2 Workbench instance response dict."""
    gce: dict = {"machineType": machine_type}
    if accel_type:
        gce["acceleratorConfigs"] = [{"type": accel_type, "coreCount": str(accel_count or 1)}]
    return {
        "name": name,
        "state": state,
        "createTime": _ts(create_time),
        "updateTime": _ts(update_time),
        "gceSetup": gce,
        "labels": labels or {},
        "_api_version": "v2",
    }


def _v1_instance(
    name: str = _INSTANCE_NAME,
    state: str = "ACTIVE",
    create_time: datetime = _OLD_TIME,
    update_time: datetime = _IDLE_TIME,
    machine_type: str = "zones/us-central1-a/machineTypes/n1-standard-4",
    accel_type: str = "",
    accel_count: int = 0,
    labels: dict = None,
) -> dict:
    """Build a minimal v1 User-Managed Notebook instance response dict."""
    inst: dict = {
        "name": name,
        "state": state,
        "createTime": _ts(create_time),
        "updateTime": _ts(update_time),
        "machineType": machine_type,
        "labels": labels or {},
        "_api_version": "v1",
    }
    if accel_type:
        inst["acceleratorConfig"] = {
            "type": accel_type,
            "coreCount": str(accel_count or 1),
        }
    return inst


def _mock_session(instances: list):
    """Return a mock AuthorizedSession that returns the given instance list from v2 API."""
    mock = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"instances": instances}
    mock.get.return_value = response
    return mock


# ---------------------------------------------------------------------------
# _normalize tests
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_v2_basic(self):
        raw = _v2_instance()
        norm = _normalize(raw)
        assert norm["name"] == _INSTANCE_NAME
        assert norm["location"] == _LOCATION
        assert norm["state"] == "ACTIVE"
        assert norm["machine_type"] == "n1-standard-4"
        assert norm["accel_type"] == ""
        assert norm["accel_count"] == 0

    def test_v2_with_gpu(self):
        raw = _v2_instance(accel_type="NVIDIA_TESLA_T4", accel_count=2)
        norm = _normalize(raw)
        assert norm["accel_type"] == "NVIDIA_TESLA_T4"
        assert norm["accel_count"] == 2

    def test_unspecified_accel_normalized_to_empty(self):
        raw = _v2_instance(accel_type="ACCELERATOR_TYPE_UNSPECIFIED")
        norm = _normalize(raw)
        assert norm["accel_type"] == ""

    def test_location_extracted_from_name(self):
        name = "projects/p/locations/europe-west1/instances/i"
        raw = {**_v2_instance(name=name), "name": name}
        norm = _normalize(raw)
        assert norm["location"] == "europe-west1"


# ---------------------------------------------------------------------------
# _estimate_cost tests
# ---------------------------------------------------------------------------


class TestEstimateCost:
    def test_known_cpu_machine(self):
        cost = _estimate_cost("n1-standard-4", "", 0)
        assert cost == _MACHINE_MONTHLY_COST["n1-standard-4"]

    def test_unknown_machine_uses_default(self):
        cost = _estimate_cost("custom-unknown-type", "", 0)
        assert cost == _DEFAULT_MACHINE_MONTHLY_COST

    def test_n1_with_t4_adds_gpu_cost(self):
        base = _MACHINE_MONTHLY_COST["n1-standard-4"]
        gpu = _GPU_MONTHLY_COST_EACH["NVIDIA_TESLA_T4"]
        assert _estimate_cost("n1-standard-4", "NVIDIA_TESLA_T4", 1) == base + gpu

    def test_n1_with_two_t4_doubles_gpu_cost(self):
        base = _MACHINE_MONTHLY_COST["n1-standard-4"]
        gpu = _GPU_MONTHLY_COST_EACH["NVIDIA_TESLA_T4"]
        assert _estimate_cost("n1-standard-4", "NVIDIA_TESLA_T4", 2) == base + gpu * 2

    def test_a2_machine_no_gpu_addon(self):
        # a2-highgpu-1g already bundles A100 cost
        cost = _estimate_cost("a2-highgpu-1g", "NVIDIA_TESLA_A100", 1)
        assert cost == _MACHINE_MONTHLY_COST["a2-highgpu-1g"]

    def test_g2_machine_no_gpu_addon(self):
        cost = _estimate_cost("g2-standard-8", "NVIDIA_L4", 1)
        assert cost == _MACHINE_MONTHLY_COST["g2-standard-8"]

    def test_none_machine_type_uses_default(self):
        cost = _estimate_cost(None, None, 0)
        assert cost == _DEFAULT_MACHINE_MONTHLY_COST


# ---------------------------------------------------------------------------
# find_idle_workbench_instances tests
# ---------------------------------------------------------------------------


class TestFindIdleWorkbenchInstances:
    def _run(self, instances: list, **kwargs):
        with patch(
            "cleancloud.providers.gcp.rules.ai.workbench_idle._list_instances",
            return_value=instances,
        ):
            with patch("cleancloud.providers.gcp.rules.ai.workbench_idle.datetime") as mock_dt:
                mock_dt.now.return_value = NOW
                mock_dt.fromisoformat = datetime.fromisoformat
                return find_idle_workbench_instances(
                    project_id=_PROJECT, credentials=MagicMock(), **kwargs
                )

    def test_idle_cpu_instance_flagged(self):
        findings = self._run([_v2_instance()])
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "gcp.vertex.workbench.idle"
        assert f.provider == "gcp"
        assert f.resource_id == _INSTANCE_NAME
        assert f.region == _LOCATION
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.MEDIUM

    def test_stopped_instance_skipped(self):
        findings = self._run([_v2_instance(state="STOPPED")])
        assert findings == []

    def test_young_instance_skipped(self):
        # age < max(idle_days // 2, 7) = 7 days
        findings = self._run([_v2_instance(create_time=_YOUNG_TIME, update_time=_RECENT_TIME)])
        assert findings == []

    def test_recent_update_time_not_flagged(self):
        # updateTime only 3 days ago — not idle
        findings = self._run([_v2_instance(update_time=_RECENT_TIME)])
        assert findings == []

    def test_gpu_instance_high_risk(self):
        findings = self._run([_v2_instance(accel_type="NVIDIA_TESLA_T4", accel_count=1)])
        assert len(findings) == 1
        assert findings[0].risk == RiskLevel.HIGH

    def test_gpu_instance_critical_risk_when_idle_ratio_ge_2(self):
        # idle_since_days = 30, idle_days = 14 → ratio = 30/14 ≈ 2.14 >= 2.0
        very_idle = NOW - timedelta(days=30)
        findings = self._run(
            [_v2_instance(update_time=very_idle, accel_type="NVIDIA_TESLA_A100", accel_count=1)]
        )
        assert len(findings) == 1
        assert findings[0].risk == RiskLevel.CRITICAL

    def test_medium_confidence_at_75pct_threshold(self):
        # idle_since_days = 11 days → 11/14 = 0.786 >= 0.75
        threshold_medium = NOW - timedelta(days=11)
        findings = self._run([_v2_instance(update_time=threshold_medium)])
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_below_medium_threshold_not_flagged(self):
        # idle_since_days = 9 → 9/14 = 0.64 < 0.75
        recent = NOW - timedelta(days=9)
        findings = self._run([_v2_instance(update_time=recent)])
        assert findings == []

    def test_age_fallback_capped_at_medium(self):
        # v2 instance with no updateTime → age-fallback
        inst = _v2_instance()
        del inst["updateTime"]
        inst.pop("updateTime", None)
        inst["updateTime"] = ""
        findings = self._run([inst])
        # age is 30 days → should be flagged; confidence capped at MEDIUM
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_region_filter_excludes_other_regions(self):
        findings = self._run([_v2_instance()], region_filter="europe-west1")
        assert findings == []

    def test_region_filter_includes_matching_region(self):
        findings = self._run([_v2_instance()], region_filter="us-central1")
        assert len(findings) == 1

    def test_region_filter_case_insensitive(self):
        findings = self._run([_v2_instance()], region_filter="US-CENTRAL1")
        assert len(findings) == 1

    def test_cost_estimate_in_finding(self):
        findings = self._run([_v2_instance(machine_type="n1-standard-4")])
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == _MACHINE_MONTHLY_COST["n1-standard-4"]

    def test_gpu_cost_includes_addon(self):
        findings = self._run(
            [
                _v2_instance(
                    machine_type="n1-standard-4",
                    accel_type="NVIDIA_TESLA_T4",
                    accel_count=1,
                )
            ]
        )
        expected = (
            _MACHINE_MONTHLY_COST["n1-standard-4"] + _GPU_MONTHLY_COST_EACH["NVIDIA_TESLA_T4"]
        )
        assert findings[0].estimated_monthly_cost_usd == expected

    def test_multiple_instances(self):
        inst1 = _v2_instance(name=f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-1")
        inst2 = _v2_instance(name=f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-2")
        findings = self._run([inst1, inst2])
        assert len(findings) == 2

    def test_empty_project_returns_no_findings(self):
        findings = self._run([])
        assert findings == []

    def test_custom_idle_days(self):
        # With idle_days=7, an instance 8 days since updateTime should be flagged
        eight_days_ago = NOW - timedelta(days=8)
        # But age must also be >= threshold_medium (75% of 7 = 5.25 days → 5 days)
        findings = self._run(
            [_v2_instance(update_time=eight_days_ago)],
            idle_days=7,
        )
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_rule_metadata_and_rule_id(self):
        assert RULE_METADATA["id"] == "gcp.vertex.workbench.idle"
        assert RULE_METADATA["category"] == "ai"
        assert find_idle_workbench_instances.RULE_ID == "gcp.vertex.workbench.idle"

    def test_age_fallback_signal_says_age_not_updatetime(self):
        inst = _v2_instance()
        inst["updateTime"] = ""
        findings = self._run([inst])
        assert len(findings) == 1
        signals = findings[0].evidence.signals_used
        activity_signal = next(s for s in signals if "control-plane activity" in s)
        assert "age (fallback)" in activity_signal
        assert "updateTime" not in activity_signal

    def test_normal_signal_credits_updatetime(self):
        findings = self._run([_v2_instance()])
        signals = findings[0].evidence.signals_used
        activity_signal = next(s for s in signals if "control-plane activity" in s)
        assert "updateTime" in activity_signal

    def test_tpu_instance_labelled_tpu_not_gpu(self):
        findings = self._run([_v2_instance(accel_type="TPU_V2", accel_count=1)])
        assert len(findings) == 1
        f = findings[0]
        assert "TPU" in f.title
        assert "GPU" not in f.title
        assert any("TPU-backed" in s for s in f.evidence.signals_used)

    def test_tpu_cost_includes_tpu_addon(self):
        findings = self._run([_v2_instance(accel_type="TPU_V2", accel_count=1)])
        assert len(findings) == 1
        expected = _MACHINE_MONTHLY_COST["n1-standard-4"] + _GPU_MONTHLY_COST_EACH["TPU_V2"]
        assert findings[0].estimated_monthly_cost_usd == expected

    def test_500_from_v2_does_not_abort_scan(self):
        """A transient 500 from the v2 API should return empty results, not raise."""
        mock_session = MagicMock()
        resp_500 = MagicMock()
        resp_500.status_code = 500
        mock_session.get.return_value = resp_500

        with patch(
            "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
            return_value=mock_session,
        ):
            findings = find_idle_workbench_instances(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []


# ---------------------------------------------------------------------------
# _list_instances permission error propagation
# ---------------------------------------------------------------------------


class TestListInstancesPermissionError:
    def test_403_raises_permission_error(self):
        mock_session = MagicMock()
        response = MagicMock()
        response.status_code = 403
        mock_session.get.return_value = response

        with patch(
            "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
            return_value=mock_session,
        ):
            with pytest.raises(PermissionError, match="notebooks.instances.list"):
                find_idle_workbench_instances(project_id=_PROJECT, credentials=MagicMock())

    def test_404_returns_empty(self):
        mock_session = MagicMock()
        response = MagicMock()
        response.status_code = 404
        mock_session.get.return_value = response

        with patch(
            "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
            return_value=mock_session,
        ):
            findings = find_idle_workbench_instances(project_id=_PROJECT, credentials=MagicMock())
        assert findings == []
