"""
Tests for aws.ec2.gpu.idle rule.

Coverage:
- Core detection: idle GPU instance flagged (HIGH confidence when GPU metric available)
- CPU fallback: MEDIUM confidence when NVIDIA CloudWatch agent not installed
- Multi-GPU: MAX statistic used across GPU indices
- Instance state filter: only running instances
- GPU family filter: non-GPU instances skipped
- Age guard: instances younger than idle_days skipped
- Utilisation thresholds: configurable gpu_threshold and cpu_threshold
- Risk levels: CRITICAL (idle_ratio >= 2.0), HIGH otherwise
- Active GPU instance not flagged
- Active CPU instance not flagged (fallback path)
- CloudWatch errors treated as active (safe default)
- Permission errors: PermissionError raised on AccessDenied from describe_instances
- RULE_METADATA and RULE_ID attributes
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ec2_gpu_idle import (
    _DEFAULT_MONTHLY_COST,
    _MONTHLY_COST,
    RULE_METADATA,
    _is_gpu_instance,
    _is_neuron_instance,
    _list_gpu_metrics,
    find_idle_gpu_instances,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_REGION = "us-east-1"
_INSTANCE_ID = "i-0abc1234567890def"
_INSTANCE_TYPE = "p3.2xlarge"


def _make_instance(
    instance_id=_INSTANCE_ID,
    instance_type=_INSTANCE_TYPE,
    age_days=30,
    state="running",
    tags=None,
):
    launch_time = NOW - timedelta(days=age_days)
    return {
        "InstanceId": instance_id,
        "InstanceType": instance_type,
        "State": {"Name": state},
        "LaunchTime": launch_time,
        "Tags": tags or [{"Key": "Name", "Value": "gpu-trainer"}],
    }


def _make_session(instances, gpu_util=None, cpu_util=None, has_gpu_metric=False):
    """
    Build a mock boto3 session.

    gpu_util: if not None, NVIDIA CloudWatch agent metrics are available with this max value.
    cpu_util: avg CPU utilisation returned from AWS/EC2 namespace.
    has_gpu_metric: whether ListMetrics returns NVIDIA metrics.
    """
    session = MagicMock()

    # EC2 client
    ec2 = MagicMock()
    paginator = MagicMock()
    reservations = [{"Instances": instances}] if instances else []
    paginator.paginate.return_value = [{"Reservations": reservations}]
    ec2.get_paginator.return_value = paginator

    # CloudWatch client
    cw = MagicMock()

    # ListMetrics for GPU probe
    if has_gpu_metric:
        cw.list_metrics.return_value = {
            "Metrics": [
                {
                    "Namespace": "CWAgent",
                    "MetricName": "nvidia_smi_utilization_gpu",
                    "Dimensions": [
                        {"Name": "InstanceId", "Value": _INSTANCE_ID},
                        {"Name": "gpu_id", "Value": "0"},
                    ],
                }
            ]
        }
    else:
        cw.list_metrics.return_value = {"Metrics": []}

    # GetMetricStatistics for GPU utilisation
    if gpu_util is not None:
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Maximum": gpu_util, "Timestamp": NOW}]
        }
    elif cpu_util is not None:
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Maximum": cpu_util, "Timestamp": NOW}]
        }
    else:
        cw.get_metric_statistics.return_value = {"Datapoints": []}

    def _client(service, **kwargs):
        if service == "ec2":
            return ec2
        if service == "cloudwatch":
            return cw
        return MagicMock()

    session.client.side_effect = _client
    return session


def _run(instances, gpu_util=None, cpu_util=None, has_gpu_metric=False, **kwargs):
    session = _make_session(
        instances, gpu_util=gpu_util, cpu_util=cpu_util, has_gpu_metric=has_gpu_metric
    )
    with patch("cleancloud.providers.aws.rules.ec2_gpu_idle.datetime") as mock_dt:
        mock_dt.now.return_value = NOW
        mock_dt.fromisoformat = datetime.fromisoformat
        return find_idle_gpu_instances(session, _REGION, **kwargs)


# ---------------------------------------------------------------------------
# _is_gpu_instance
# ---------------------------------------------------------------------------


class TestIsGpuInstance:
    def test_p3_is_gpu(self):
        assert _is_gpu_instance("p3.2xlarge")

    def test_p4d_is_gpu(self):
        assert _is_gpu_instance("p4d.24xlarge")

    def test_g4dn_is_gpu(self):
        assert _is_gpu_instance("g4dn.xlarge")

    def test_g5_is_gpu(self):
        assert _is_gpu_instance("g5.12xlarge")

    def test_trn1_is_gpu(self):
        assert _is_gpu_instance("trn1.2xlarge")

    def test_inf2_is_gpu(self):
        assert _is_gpu_instance("inf2.xlarge")

    def test_t3_is_not_gpu(self):
        assert not _is_gpu_instance("t3.large")

    def test_m5_is_not_gpu(self):
        assert not _is_gpu_instance("m5.4xlarge")

    def test_c5_is_not_gpu(self):
        assert not _is_gpu_instance("c5.xlarge")


# ---------------------------------------------------------------------------
# _list_gpu_metrics
# ---------------------------------------------------------------------------


class TestListGpuMetrics:
    def test_returns_metrics_list_when_found(self):
        cw = MagicMock()
        metrics = [{"MetricName": "nvidia_smi_utilization_gpu", "Dimensions": []}]
        cw.list_metrics.return_value = {"Metrics": metrics}
        assert _list_gpu_metrics(cw, "i-abc") == metrics

    def test_returns_empty_list_when_no_metrics(self):
        cw = MagicMock()
        cw.list_metrics.return_value = {"Metrics": []}
        assert _list_gpu_metrics(cw, "i-abc") == []

    def test_returns_empty_list_on_client_error(self):
        cw = MagicMock()
        cw.list_metrics.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListMetrics"
        )
        assert _list_gpu_metrics(cw, "i-abc") == []


# ---------------------------------------------------------------------------
# _is_neuron_instance
# ---------------------------------------------------------------------------


class TestIsNeuronInstance:
    def test_trn1_is_neuron(self):
        assert _is_neuron_instance("trn1.2xlarge")

    def test_trn2_is_neuron(self):
        assert _is_neuron_instance("trn2.48xlarge")

    def test_inf2_is_neuron(self):
        assert _is_neuron_instance("inf2.xlarge")

    def test_dl1_is_neuron(self):
        assert _is_neuron_instance("dl1.24xlarge")

    def test_p3_is_not_neuron(self):
        assert not _is_neuron_instance("p3.2xlarge")

    def test_g5_is_not_neuron(self):
        assert not _is_neuron_instance("g5.xlarge")


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


class TestFindIdleGpuInstances:
    def test_idle_gpu_instance_flagged_high_confidence(self):
        """GPU metric available, utilisation below threshold → HIGH confidence."""
        # age=7, idle_days=7 → idle_ratio=1.0 < 2.0 → HIGH risk (not CRITICAL)
        findings = _run([_make_instance(age_days=7)], gpu_util=2.0, has_gpu_metric=True)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.ec2.gpu.idle"
        assert f.provider == "aws"
        assert f.resource_id == _INSTANCE_ID
        assert f.region == _REGION
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.HIGH

    def test_idle_gpu_instance_cpu_fallback_medium_confidence(self):
        """No GPU metric → CPU fallback → MEDIUM confidence."""
        findings = _run([_make_instance()], cpu_util=5.0, has_gpu_metric=False)
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_active_gpu_instance_not_flagged(self):
        """GPU utilisation above threshold → not flagged."""
        findings = _run([_make_instance()], gpu_util=50.0, has_gpu_metric=True)
        assert findings == []

    def test_active_cpu_fallback_not_flagged(self):
        """CPU utilisation above threshold in fallback path → not flagged."""
        findings = _run([_make_instance()], cpu_util=25.0, has_gpu_metric=False)
        assert findings == []

    def test_non_gpu_instance_skipped(self):
        findings = _run(
            [_make_instance(instance_type="m5.4xlarge")],
            gpu_util=0.0,
            has_gpu_metric=True,
        )
        assert findings == []

    def test_stopped_instance_skipped(self):
        findings = _run([_make_instance(state="stopped")], gpu_util=0.0, has_gpu_metric=True)
        assert findings == []

    def test_young_instance_skipped(self):
        """Instance younger than idle_days (7) is skipped."""
        findings = _run([_make_instance(age_days=3)], gpu_util=0.0, has_gpu_metric=True)
        assert findings == []

    def test_exactly_at_idle_days_not_skipped(self):
        findings = _run([_make_instance(age_days=7)], gpu_util=0.0, has_gpu_metric=True)
        assert len(findings) == 1

    def test_critical_risk_when_idle_ratio_ge_2(self):
        """idle_ratio = age_days / idle_days. age=30, idle_days=7 → 30/7 ≈ 4.3 >= 2."""
        findings = _run([_make_instance(age_days=30)], gpu_util=1.0, has_gpu_metric=True)
        assert len(findings) == 1
        assert findings[0].risk == RiskLevel.CRITICAL

    def test_high_risk_when_idle_ratio_lt_2(self):
        """age=7, idle_days=7 → ratio=1.0 < 2 → HIGH."""
        findings = _run([_make_instance(age_days=7)], gpu_util=1.0, has_gpu_metric=True)
        assert len(findings) == 1
        assert findings[0].risk == RiskLevel.HIGH

    def test_empty_instances_returns_no_findings(self):
        findings = _run([])
        assert findings == []

    def test_cost_estimate_in_finding(self):
        findings = _run(
            [_make_instance(instance_type="p3.2xlarge")],
            gpu_util=0.0,
            has_gpu_metric=True,
        )
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == _MONTHLY_COST["p3.2xlarge"]

    def test_unknown_instance_type_uses_default_cost(self):
        # p3.custom matches the p3. GPU family prefix but is not in the cost table
        findings = _run(
            [_make_instance(instance_type="p3.custom")],
            gpu_util=0.0,
            has_gpu_metric=True,
        )
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == _DEFAULT_MONTHLY_COST

    def test_gpu_signal_in_signals_used(self):
        findings = _run([_make_instance()], gpu_util=2.5, has_gpu_metric=True)
        signals = findings[0].evidence.signals_used
        assert any("GPU" in s for s in signals)

    def test_cpu_fallback_signal_in_signals_used(self):
        findings = _run([_make_instance()], cpu_util=5.0, has_gpu_metric=False)
        signals = findings[0].evidence.signals_used
        assert any("CWAgent nvidia_smi_utilization_gpu metric not found" in s for s in signals)

    def test_neuron_instance_uses_neuron_signal_text(self):
        findings = _run(
            [_make_instance(instance_type="trn1.2xlarge")],
            cpu_util=5.0,
            has_gpu_metric=False,
        )
        assert len(findings) == 1
        signals = findings[0].evidence.signals_used
        assert any("Neuron instance" in s for s in signals)
        assert not any("NVIDIA CloudWatch agent" in s for s in signals)

    def test_g6e_cost_not_default(self):
        findings = _run([_make_instance(instance_type="g6e.48xlarge")], cpu_util=5.0)
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == 18_000.0

    def test_trn2_cost_not_default(self):
        findings = _run([_make_instance(instance_type="trn2.48xlarge")], cpu_util=5.0)
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd == 110_000.0

    def test_custom_gpu_threshold(self):
        """gpu_threshold=10 → instance at 8% GPU util flagged."""
        findings = _run([_make_instance()], gpu_util=8.0, has_gpu_metric=True, gpu_threshold=10.0)
        assert len(findings) == 1

    def test_custom_cpu_threshold(self):
        """cpu_threshold=20 → instance at 15% CPU flagged."""
        findings = _run([_make_instance()], cpu_util=15.0, has_gpu_metric=False, cpu_threshold=20.0)
        assert len(findings) == 1

    def test_cloudwatch_error_treated_as_active(self):
        """CloudWatch failure on GPU stats → None returned → instance not flagged."""
        session = _make_session([_make_instance()], has_gpu_metric=True)
        cw = session.client("cloudwatch")
        # list_metrics returns metrics but get_metric_statistics raises
        cw.list_metrics.return_value = {
            "Metrics": [
                {
                    "Namespace": "CWAgent",
                    "MetricName": "nvidia_smi_utilization_gpu",
                    "Dimensions": [{"Name": "InstanceId", "Value": _INSTANCE_ID}],
                }
            ]
        }
        cw.get_metric_statistics.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "throttled"}},
            "GetMetricStatistics",
        )
        with patch("cleancloud.providers.aws.rules.ec2_gpu_idle.datetime") as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
            findings = find_idle_gpu_instances(session, _REGION)
        assert findings == []

    def test_permission_error_on_describe_instances(self):
        session = MagicMock()
        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInstances",
        )
        ec2.get_paginator.return_value = paginator
        session.client.return_value = ec2

        with pytest.raises(PermissionError, match="ec2:DescribeInstances"):
            find_idle_gpu_instances(session, _REGION)

    def test_details_include_idle_signal_source(self):
        findings = _run([_make_instance()], gpu_util=1.0, has_gpu_metric=True)
        assert findings[0].details["idle_signal"] == "gpu_utilisation"

    def test_details_include_cpu_fallback_signal_source(self):
        findings = _run([_make_instance()], cpu_util=5.0, has_gpu_metric=False)
        assert findings[0].details["idle_signal"] == "cpu_utilisation_fallback"

    def test_details_include_gpu_metric_available_flag(self):
        findings = _run([_make_instance()], gpu_util=1.0, has_gpu_metric=True)
        assert findings[0].details["gpu_metric_available"] is True

    def test_rule_metadata_and_rule_id(self):
        assert RULE_METADATA["id"] == "aws.ec2.gpu.idle"
        assert RULE_METADATA["category"] == "ai"
        assert find_idle_gpu_instances.RULE_ID == "aws.ec2.gpu.idle"

    def test_multiple_gpu_instances(self):
        inst1 = _make_instance(instance_id="i-aaa", instance_type="p3.2xlarge")
        inst2 = _make_instance(instance_id="i-bbb", instance_type="g5.xlarge")
        session = MagicMock()
        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Reservations": [{"Instances": [inst1, inst2]}]}]
        ec2.get_paginator.return_value = paginator
        cw = MagicMock()
        cw.list_metrics.return_value = {"Metrics": []}
        cw.get_metric_statistics.return_value = {"Datapoints": [{"Maximum": 3.0, "Timestamp": NOW}]}

        def _client(service, **kwargs):
            return ec2 if service == "ec2" else cw

        session.client.side_effect = _client
        with patch("cleancloud.providers.aws.rules.ec2_gpu_idle.datetime") as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat = datetime.fromisoformat
            findings = find_idle_gpu_instances(session, _REGION)
        assert len(findings) == 2
