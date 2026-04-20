"""Tests for cleancloud/providers/aws/rules/elb_idle.py

Covers all spec acceptance scenarios:
  Must emit / Must skip / Must fail / Normalization / Traffic signals /
  Confidence model / Cost model / Evidence contract / Title-and-reason contract /
  Backend enrichment / Pagination / NLB missing-datapoints behaviour
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.elb_idle import find_idle_load_balancers

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_ACCOUNT = "123456789012"
_THRESHOLD = 14


def _now():
    return datetime.now(timezone.utc)


def _make_session(elbv2, elb, cloudwatch):
    session = MagicMock()

    def _client(service_name, *args, **kwargs):
        if service_name == "elbv2":
            return elbv2
        if service_name == "elb":
            return elb
        if service_name == "cloudwatch":
            return cloudwatch
        raise ValueError(f"Unexpected service: {service_name}")

    session.client.side_effect = _client
    return session


def _elbv2_lb(
    name="test-alb",
    lb_type="application",
    age_days=20,
    state="active",
    arn_suffix=None,
):
    suffix = arn_suffix if arn_suffix is not None else f"app/{name}/abc123"
    arn = f"arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/{suffix}"
    if lb_type == "network":
        suffix = arn_suffix if arn_suffix is not None else f"net/{name}/abc123"
        arn = f"arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/{suffix}"
    return {
        "LoadBalancerArn": arn,
        "LoadBalancerName": name,
        "Type": lb_type,
        "CreatedTime": _now() - timedelta(days=age_days),
        "State": {"Code": state},
        "DNSName": f"{name}.{_REGION}.elb.amazonaws.com",
        "VpcId": "vpc-12345",
        "Scheme": "internet-facing",
    }


def _clb(name="test-clb", age_days=20, instances=None):
    return {
        "LoadBalancerName": name,
        "CreatedTime": _now() - timedelta(days=age_days),
        "DNSName": f"{name}.{_REGION}.elb.amazonaws.com",
        "VPCId": "vpc-12345",
        "Scheme": "internet-facing",
        "Instances": instances if instances is not None else [],
    }


def _setup_elbv2(elbv2, lbs, tg_pages=None, target_health=None):
    """Configure elbv2 mock with LB and target-group paginators."""
    lb_pag = MagicMock()
    lb_pag.paginate.return_value = [{"LoadBalancers": lbs}]

    tg_pag = MagicMock()
    tg_pag.paginate.return_value = tg_pages if tg_pages is not None else [{"TargetGroups": []}]

    def _pag(name):
        if name == "describe_load_balancers":
            return lb_pag
        if name == "describe_target_groups":
            return tg_pag
        raise ValueError(f"Unexpected paginator: {name}")

    elbv2.get_paginator.side_effect = _pag

    if target_health is not None:
        elbv2.describe_target_health.return_value = target_health
    else:
        elbv2.describe_target_health.return_value = {"TargetHealthDescriptions": []}


def _setup_clb(elb, lbs):
    pag = elb.get_paginator.return_value
    pag.paginate.return_value = [{"LoadBalancerDescriptions": lbs}]


def _cw_no_traffic():
    """CloudWatch mock returning empty datapoints for all metrics."""
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {"Datapoints": []}
    return cw


def _cw_nlb_zero_traffic(num_datapoints=None):
    """NLB needs enough zero-valued datapoints to satisfy full-window completeness.

    Spec requires at least expected_days - 1 datapoints. Default to _THRESHOLD
    datapoints so the completeness check (>= _THRESHOLD - 1) passes.
    """
    n = num_datapoints if num_datapoints is not None else _THRESHOLD
    cw = MagicMock()

    def _side(**kwargs):
        stat = kwargs.get("Statistics", ["Sum"])[0]
        return {"Datapoints": [{stat: 0}] * n}

    cw.get_metric_statistics.side_effect = _side
    return cw


def _cw_metric_with_signal(
    trigger_metric: str, trigger_stat: str = "Sum", trigger_value: float = 100.0
):
    """CloudWatch mock that returns traffic only for the specified metric."""
    cw = MagicMock()

    def _side(**kwargs):
        if kwargs.get("MetricName") == trigger_metric:
            return {"Datapoints": [{trigger_stat: trigger_value}]}
        stat = kwargs.get("Statistics", ["Sum"])[0]
        return {"Datapoints": [{stat: 0}]}

    cw.get_metric_statistics.side_effect = _side
    return cw


def _cw_nlb_missing_metric(missing_metric: str):
    """NLB CloudWatch mock where one metric returns no datapoints (FAIL RULE).

    Non-missing metrics return full-window coverage (_THRESHOLD datapoints)
    so the completeness check passes for those metrics before we reach the
    missing one.
    """
    cw = MagicMock()

    def _side(**kwargs):
        metric = kwargs.get("MetricName", "")
        stat = kwargs.get("Statistics", ["Sum"])[0]
        if metric == missing_metric:
            return {"Datapoints": []}
        return {"Datapoints": [{stat: 0}] * _THRESHOLD}

    cw.get_metric_statistics.side_effect = _side
    return cw


def _cw_error(metric_name: str = None):
    """CloudWatch mock that raises ClientError for the given metric (or all)."""
    cw = MagicMock()
    err = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "x"}}, "GetMetricStatistics"
    )

    def _side(**kwargs):
        if metric_name is None or kwargs.get("MetricName") == metric_name:
            raise err
        stat = kwargs.get("Statistics", ["Sum"])[0]
        return {"Datapoints": [{stat: 0}]}

    cw.get_metric_statistics.side_effect = _side
    return cw


def _run(session, threshold=_THRESHOLD):
    return find_idle_load_balancers(session, _REGION, idle_days_threshold=threshold)


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_idle_alb_zero_targets_emits_high(self):
        """ALB older than threshold, active, no traffic, no targets → EMIT HIGH."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="idle-alb", age_days=20)])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.elbv2.alb.idle"
        assert f.confidence.value == "high"
        assert f.risk.value == "medium"

    def test_idle_alb_with_targets_emits_medium(self):
        """ALB older than threshold, no traffic, but registered targets → EMIT MEDIUM."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(
            elbv2,
            [_elbv2_lb(name="idle-alb-targets", age_days=20)],
            tg_pages=[{"TargetGroups": [{"TargetGroupArn": "arn:tg:1"}]}],
            target_health={"TargetHealthDescriptions": [{"Target": {"Id": "i-1"}}]},
        )
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"
        assert findings[0].details["has_registered_targets"] is True

    def test_idle_nlb_active_impaired_zero_traffic_with_targets_emits_medium(self):
        """NLB in active_impaired state, zero NLB traffic with valid datapoints, has targets → EMIT MEDIUM."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        nlb = _elbv2_lb(name="idle-nlb", lb_type="network", age_days=20, state="active_impaired")
        _setup_elbv2(
            elbv2,
            [nlb],
            tg_pages=[{"TargetGroups": [{"TargetGroupArn": "arn:tg:1"}]}],
            target_health={"TargetHealthDescriptions": [{"Target": {"Id": "i-1"}}]},
        )
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.elbv2.nlb.idle"
        assert f.confidence.value == "medium"

    def test_idle_nlb_no_targets_emits_high(self):
        """NLB older than threshold, zero NLB traffic with valid datapoints, no targets → EMIT HIGH."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        nlb = _elbv2_lb(name="idle-nlb", lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        assert findings[0].rule_id == "aws.elbv2.nlb.idle"
        assert findings[0].confidence.value == "high"

    def test_idle_clb_no_instances_emits_high(self):
        """CLB older than threshold, no traffic, no instances → EMIT HIGH."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(name="idle-clb", age_days=20)])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.elb.clb.idle"
        assert f.resource_type == "aws.elb.load_balancer"
        assert f.resource_id == "idle-clb"
        assert f.confidence.value == "high"

    def test_idle_clb_with_instances_emits_medium(self):
        """CLB no traffic but has registered instances → EMIT MEDIUM."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(name="idle-clb", age_days=20, instances=[{"InstanceId": "i-1"}])])

        findings = _run(_make_session(elbv2, elb, cw))

        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"
        assert findings[0].details["registered_instance_count"] == 1


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_gateway_lb_skipped(self):
        """ELBv2 with Type='gateway' must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb = _elbv2_lb(name="gwlb", lb_type="gateway", age_days=20)
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_unknown_type_skipped(self):
        """ELBv2 with an unrecognised Type must be skipped as unsupported."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb = _elbv2_lb(name="mystery", lb_type="classic_compat", age_days=20)
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_alb_younger_than_threshold_skipped(self):
        """ALB younger than idle_days_threshold is skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="new-alb", age_days=5)])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_clb_younger_than_threshold_skipped(self):
        """CLB younger than idle_days_threshold is skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(name="new-clb", age_days=3)])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_alb_in_provisioning_state_skipped(self):
        """ELBv2 in 'provisioning' state must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="prov-alb", age_days=20, state="provisioning")])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_alb_in_failed_state_skipped(self):
        """ELBv2 in 'failed' state must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="failed-alb", age_days=20, state="failed")])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_elbv2_unparsable_arn_dimension_skipped(self):
        """ELBv2 ARN without 'loadbalancer/' cannot yield a CW dimension → SKIP ITEM."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        # Build a LB with a raw bad ARN
        lb = {
            "LoadBalancerArn": "bad-arn-no-loadbalancer-segment",
            "LoadBalancerName": "bad-lb",
            "Type": "application",
            "CreatedTime": _now() - timedelta(days=20),
            "State": {"Code": "active"},
            "DNSName": "bad.dns",
            "VpcId": "vpc-1",
            "Scheme": "internet-facing",
        }
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_elbv2_missing_arn_skipped(self):
        """ELBv2 without LoadBalancerArn must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb = {
            "LoadBalancerName": "no-arn",
            "Type": "application",
            "CreatedTime": _now() - timedelta(days=20),
            "State": {"Code": "active"},
        }
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_elbv2_missing_created_time_skipped(self):
        """ELBv2 without CreatedTime must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb = {
            "LoadBalancerArn": f"arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/no-time/abc",
            "LoadBalancerName": "no-time",
            "Type": "application",
            "State": {"Code": "active"},
        }
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_clb_missing_name_skipped(self):
        """CLB without LoadBalancerName must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        lb = {"CreatedTime": _now() - timedelta(days=20), "Instances": []}
        _setup_clb(elb, [lb])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_clb_missing_created_time_skipped(self):
        """CLB without CreatedTime must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        lb = {"LoadBalancerName": "no-time", "Instances": []}
        _setup_clb(elb, [lb])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_non_dict_elbv2_item_skipped(self):
        """Non-dict ELBv2 item must be skipped without raising."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb_pag = MagicMock()
        lb_pag.paginate.return_value = [{"LoadBalancers": ["not-a-dict"]}]
        tg_pag = MagicMock()
        tg_pag.paginate.return_value = [{"TargetGroups": []}]
        elbv2.get_paginator.side_effect = lambda n: (
            lb_pag if n == "describe_load_balancers" else tg_pag
        )
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_non_dict_clb_item_skipped(self):
        """Non-dict CLB item must be skipped without raising."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        pag = elb.get_paginator.return_value
        pag.paginate.return_value = [{"LoadBalancerDescriptions": ["not-a-dict"]}]

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []


# ---------------------------------------------------------------------------
# TestTrafficSignals
# ---------------------------------------------------------------------------


class TestTrafficSignals:
    """Each traffic metric independently causes a skip when > 0."""

    # --- ALB ---

    def test_alb_request_count_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_metric_with_signal("RequestCount")
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    def test_alb_processed_bytes_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_metric_with_signal("ProcessedBytes")
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    def test_alb_active_connection_count_triggers_skip(self):
        """ActiveConnectionCount is the third ALB signal; > 0 must prevent emission."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_metric_with_signal("ActiveConnectionCount")
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    # --- NLB ---

    @staticmethod
    def _nlb_traffic_cw(trigger_metric, trigger_stat):
        """Return full-window datapoints for all metrics; trigger metric has traffic."""
        cw = MagicMock()

        def _side(**kwargs):
            metric = kwargs.get("MetricName", "")
            stat = kwargs.get("Statistics", ["Sum"])[0]
            if metric == trigger_metric:
                return {"Datapoints": [{trigger_stat: 1}] * _THRESHOLD}
            return {"Datapoints": [{stat: 0}] * _THRESHOLD}

        cw.get_metric_statistics.side_effect = _side
        return cw

    def test_nlb_new_flow_count_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = TestTrafficSignals._nlb_traffic_cw("NewFlowCount", "Sum")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    def test_nlb_processed_bytes_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = TestTrafficSignals._nlb_traffic_cw("ProcessedBytes", "Sum")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    def test_nlb_active_flow_count_triggers_skip(self):
        """ActiveFlowCount Maximum is the third NLB signal; > 0 must prevent emission."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = TestTrafficSignals._nlb_traffic_cw("ActiveFlowCount", "Maximum")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw)) == []

    # --- CLB ---

    def test_clb_request_count_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_metric_with_signal("RequestCount")
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])
        assert _run(_make_session(elbv2, elb, cw)) == []

    def test_clb_estimated_processed_bytes_triggers_skip(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_metric_with_signal("EstimatedProcessedBytes")
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])
        assert _run(_make_session(elbv2, elb, cw)) == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_elbv2_inventory_client_error_raises(self):
        """ELBv2 DescribeLoadBalancers failure raises (FAIL RULE)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        exc = ClientError(
            {"Error": {"Code": "InternalError", "Message": "x"}}, "DescribeLoadBalancers"
        )
        lb_pag = MagicMock()
        lb_pag.paginate.side_effect = exc
        elbv2.get_paginator.return_value = lb_pag
        _setup_clb(elb, [])

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

    def test_elbv2_inventory_bootocore_error_raises(self):
        """ELBv2 inventory BotoCoreError propagates (FAIL RULE)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb_pag = MagicMock()
        lb_pag.paginate.side_effect = BotoCoreError()
        elbv2.get_paginator.return_value = lb_pag
        _setup_clb(elb, [])

        with pytest.raises(BotoCoreError):
            _run(_make_session(elbv2, elb, cw))

    def test_clb_inventory_client_error_raises(self):
        """CLB DescribeLoadBalancers failure raises (FAIL RULE)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        exc = ClientError(
            {"Error": {"Code": "InternalError", "Message": "x"}}, "DescribeLoadBalancers"
        )
        pag = elb.get_paginator.return_value
        pag.paginate.side_effect = exc

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

    def test_alb_cloudwatch_error_raises(self):
        """CloudWatch error during ALB metric read raises (FAIL RULE, no LOW finding)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_error()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

    def test_clb_cloudwatch_error_raises(self):
        """CloudWatch error during CLB metric read raises (FAIL RULE)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_error()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

    def test_cloudwatch_permission_error_raises(self):
        """CloudWatch AccessDenied raises PermissionError (FAIL RULE)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetMetricStatistics"
        )
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        with pytest.raises(PermissionError):
            _run(_make_session(elbv2, elb, cw))

    def test_nlb_missing_new_flow_count_raises(self):
        """NLB with missing NewFlowCount datapoints raises RuntimeError (FAIL RULE)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_missing_metric("NewFlowCount")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        with pytest.raises(RuntimeError):
            _run(_make_session(elbv2, elb, cw))

    def test_nlb_missing_processed_bytes_raises(self):
        """NLB with missing ProcessedBytes datapoints raises RuntimeError (FAIL RULE)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_missing_metric("ProcessedBytes")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        with pytest.raises(RuntimeError):
            _run(_make_session(elbv2, elb, cw))

    def test_nlb_missing_active_flow_count_raises(self):
        """NLB with missing ActiveFlowCount datapoints raises RuntimeError (FAIL RULE)."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_missing_metric("ActiveFlowCount")
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        with pytest.raises(RuntimeError):
            _run(_make_session(elbv2, elb, cw))

    # --- Gap 2: NLB insufficient datapoints (partial coverage) also FAIL RULE ---

    def test_nlb_insufficient_new_flow_count_coverage_raises(self):
        """NLB NewFlowCount with only 1 datapoint (far below window) raises RuntimeError."""
        elbv2, elb = MagicMock(), MagicMock()
        # 1 datapoint for a 14-day window is incomplete coverage
        cw = _cw_nlb_zero_traffic(num_datapoints=1)
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        with pytest.raises(RuntimeError, match="NewFlowCount"):
            _run(_make_session(elbv2, elb, cw))

    def test_nlb_one_below_expected_days_raises(self):
        """Spec requires full-window coverage; expected_days - 1 datapoints is a gap → FAIL RULE."""
        elbv2, elb = MagicMock(), MagicMock()
        # 13 datapoints for a 14-day window → 1-day gap → FAIL RULE (no tolerance)
        cw = _cw_nlb_zero_traffic(num_datapoints=_THRESHOLD - 1)
        nlb = _elbv2_lb(lb_type="network", age_days=20)
        _setup_elbv2(elbv2, [nlb])
        _setup_clb(elb, [])

        with pytest.raises(RuntimeError):
            _run(_make_session(elbv2, elb, cw))

    def test_no_low_confidence_finding_on_metric_failure(self):
        """Metric failure must never produce a LOW-confidence finding."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_error()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        # Must raise, not emit
        with pytest.raises(Exception):
            findings = _run(_make_session(elbv2, elb, cw))
            # If somehow no raise, ensure no LOW finding
            for f in findings:
                assert f.confidence.value != "low", "LOW confidence finding must never be emitted"


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_alb_lb_family_assigned(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="alb1", lb_type="application", age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["lb_family"] == "alb"

    def test_nlb_lb_family_assigned(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="nlb1", lb_type="network", age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["lb_family"] == "nlb"

    def test_clb_lb_family_assigned(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(name="clb1", age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["lb_family"] == "clb"

    def test_clb_uses_vpcid_key(self):
        """CLB spec uses 'VPCId' (capital), not 'VpcId'."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(name="vpc-clb", age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["vpc_id"] == "vpc-12345"

    def test_elbv2_state_code_captured(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="a", age_days=20, state="active")])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["state_code"] == "active"

    def test_age_days_exact_threshold_emits(self):
        """age_days == idle_days_threshold exactly — must emit (>= check, not >)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="exact", age_days=_THRESHOLD)])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 1

    def test_age_days_one_below_threshold_skips(self):
        """age_days == threshold - 1 must be skipped."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="almost", age_days=_THRESHOLD - 1)])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == []

    def test_alb_active_impaired_passes_state_check(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="imp", age_days=20, state="active_impaired")])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 1

    # --- Gap 1: naive CreatedTime must be SKIP, not coerced ---

    def test_elbv2_naive_created_time_skipped(self):
        """ELBv2 with a naive (tz-unaware) CreatedTime must be skipped, not coerced to UTC."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb = {
            "LoadBalancerArn": f"arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/naive/abc",
            "LoadBalancerName": "naive-alb",
            "Type": "application",
            # Naive datetime — no tzinfo
            "CreatedTime": datetime.now() - timedelta(days=30),
            "State": {"Code": "active"},
            "DNSName": "naive.elb.amazonaws.com",
            "VpcId": "vpc-1",
            "Scheme": "internet-facing",
        }
        _setup_elbv2(elbv2, [lb])
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == [], "Naive ELBv2 CreatedTime must cause SKIP, not emit"

    def test_clb_naive_created_time_skipped(self):
        """CLB with a naive (tz-unaware) CreatedTime must be skipped, not coerced to UTC."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        lb = {
            "LoadBalancerName": "naive-clb",
            # Naive datetime — no tzinfo
            "CreatedTime": datetime.now() - timedelta(days=30),
            "DNSName": "naive.elb.amazonaws.com",
            "VPCId": "vpc-1",
            "Scheme": "internet-facing",
            "Instances": [],
        }
        _setup_clb(elb, [lb])

        findings = _run(_make_session(elbv2, elb, cw))
        assert findings == [], "Naive CLB CreatedTime must cause SKIP, not emit"

    def test_clb_load_balancer_arn_always_null(self):
        """CLB details must have load_balancer_arn = None (CLBs have no ARN)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["load_balancer_arn"] is None


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_alb_no_targets_high(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw))[0].confidence.value == "high"

    def test_alb_with_targets_medium(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(
            elbv2,
            [_elbv2_lb(age_days=20)],
            tg_pages=[{"TargetGroups": [{"TargetGroupArn": "arn:tg:1"}]}],
            target_health={"TargetHealthDescriptions": [{"Target": {"Id": "i-1"}}]},
        )
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw))[0].confidence.value == "medium"

    def test_alb_enrichment_failure_medium(self):
        """When target-group enrichment fails, confidence degrades to MEDIUM (not HIGH)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb_pag = MagicMock()
        lb_pag.paginate.return_value = [{"LoadBalancers": [_elbv2_lb(age_days=20)]}]
        tg_pag = MagicMock()
        tg_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "x"}}, "DescribeTargetGroups"
        )

        def _pag(name):
            if name == "describe_load_balancers":
                return lb_pag
            return tg_pag

        elbv2.get_paginator.side_effect = _pag
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"

    def test_clb_no_instances_high(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])
        assert _run(_make_session(elbv2, elb, cw))[0].confidence.value == "high"

    def test_clb_with_instances_medium(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20, instances=[{"InstanceId": "i-1"}])])
        assert _run(_make_session(elbv2, elb, cw))[0].confidence.value == "medium"

    def test_no_low_confidence_ever_emitted(self):
        """Confidence must only be HIGH or MEDIUM — never LOW."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [_clb(age_days=20)])

        for f in _run(_make_session(elbv2, elb, cw)):
            assert f.confidence.value != "low"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_alb_estimated_cost_null(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw))[0].estimated_monthly_cost_usd is None

    def test_nlb_estimated_cost_null(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(lb_type="network", age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw))[0].estimated_monthly_cost_usd is None

    def test_clb_estimated_cost_null(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])
        assert _run(_make_session(elbv2, elb, cw))[0].estimated_monthly_cost_usd is None

    def test_no_hardcoded_cost_string_in_details(self):
        """Details must not contain any hardcoded cost string like '~$16-22/month'."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [_clb(age_days=20)])

        for f in _run(_make_session(elbv2, elb, cw)):
            details_str = str(f.details)
            assert "$" not in details_str, "Hardcoded cost string found in details"


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    """Every emitted finding must include all required evidence/details fields."""

    _ALB_REQUIRED = {
        "evaluation_path",
        "lb_family",
        "resource_id",
        "load_balancer_name",
        "load_balancer_arn",
        "scheme",
        "dns_name",
        "vpc_id",
        "created_time",
        "age_days",
        "idle_days_threshold",
        "traffic_window_days",
        "traffic_signals_checked",
        "traffic_detected",
        "state_code",
        "has_registered_targets",
        "registered_target_count",
        "target_group_count",
    }

    _CLB_REQUIRED = {
        "evaluation_path",
        "lb_family",
        "resource_id",
        "load_balancer_name",
        "load_balancer_arn",
        "scheme",
        "dns_name",
        "vpc_id",
        "created_time",
        "age_days",
        "idle_days_threshold",
        "traffic_window_days",
        "traffic_signals_checked",
        "traffic_detected",
        "has_registered_instances",
        "registered_instance_count",
    }

    def test_alb_required_details_present(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        for key in self._ALB_REQUIRED:
            assert key in f.details, f"Missing required details key: {key}"

    def test_clb_required_details_present(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        for key in self._CLB_REQUIRED:
            assert key in f.details, f"Missing required details key: {key}"

    def test_evaluation_path_exact_value(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["evaluation_path"] == "idle-load-balancer-review-candidate"

    def test_traffic_detected_always_false(self):
        """traffic_detected must always be False for emitted findings."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [_clb(age_days=20)])

        for f in _run(_make_session(elbv2, elb, cw)):
            assert f.details["traffic_detected"] is False

    def test_alb_traffic_signals_checked_contains_active_connection_count(self):
        """ALB traffic_signals_checked must include ActiveConnectionCount:Sum."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert "ActiveConnectionCount:Sum" in f.details["traffic_signals_checked"]

    def test_nlb_traffic_signals_checked_contains_active_flow_count(self):
        """NLB traffic_signals_checked must include ActiveFlowCount:Maximum."""
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(lb_type="network", age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert "ActiveFlowCount:Maximum" in f.details["traffic_signals_checked"]

    def test_clb_traffic_signals_checked_contains_estimated_bytes(self):
        """CLB traffic_signals_checked must include EstimatedProcessedBytes:Sum."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert "EstimatedProcessedBytes:Sum" in f.details["traffic_signals_checked"]

    def test_idle_days_threshold_in_details(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=30)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw), threshold=14)[0]
        assert f.details["idle_days_threshold"] == 14
        assert f.details["traffic_window_days"] == 14


# ---------------------------------------------------------------------------
# TestTitleAndReasonContract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_alb_title(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.title == "Idle ALB review candidate"

    def test_nlb_title(self):
        elbv2, elb = MagicMock(), MagicMock()
        cw = _cw_nlb_zero_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(lb_type="network", age_days=20)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.title == "Idle NLB review candidate"

    def test_clb_title(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.title == "Idle CLB review candidate"

    def test_alb_reason_contains_threshold(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=30)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw), threshold=21)[0]
        assert "21" in f.reason
        assert "ALB" in f.reason

    def test_nlb_reason_contains_threshold(self):
        elbv2, elb = MagicMock(), MagicMock()
        # Provide 21 datapoints so completeness check passes for threshold=21
        cw = _cw_nlb_zero_traffic(num_datapoints=21)
        _setup_elbv2(elbv2, [_elbv2_lb(lb_type="network", age_days=30)])
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw), threshold=21)[0]
        assert "NLB" in f.reason
        assert "21" in f.reason

    def test_clb_reason_contains_threshold(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=30)])

        f = _run(_make_session(elbv2, elb, cw), threshold=21)[0]
        assert "CLB" in f.reason
        assert "21" in f.reason

    def test_title_does_not_claim_safe_to_delete(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [_clb(age_days=20)])

        for f in _run(_make_session(elbv2, elb, cw)):
            assert "safe" not in f.title.lower()
            assert "delete" not in f.title.lower()


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_alb_risk_medium(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(age_days=20)])
        _setup_clb(elb, [])
        assert _run(_make_session(elbv2, elb, cw))[0].risk.value == "medium"

    def test_clb_risk_medium(self):
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(elb, [_clb(age_days=20)])
        assert _run(_make_session(elbv2, elb, cw))[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# TestBackendEnrichment
# ---------------------------------------------------------------------------


class TestBackendEnrichment:
    def test_target_enrichment_failure_does_not_fail_rule(self):
        """Target-group enrichment failure must not raise — finding still emitted."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb_pag = MagicMock()
        lb_pag.paginate.return_value = [{"LoadBalancers": [_elbv2_lb(age_days=20)]}]
        tg_pag = MagicMock()
        tg_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailableException", "Message": "x"}},
            "DescribeTargetGroups",
        )

        def _pag(name):
            return lb_pag if name == "describe_load_balancers" else tg_pag

        elbv2.get_paginator.side_effect = _pag
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        # Enrichment failure → finding still emitted, no exception
        assert len(findings) == 1

    def test_clb_instances_from_normalized_item(self):
        """CLB backend context comes directly from the Instances field."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])
        _setup_clb(
            elb, [_clb(age_days=20, instances=[{"InstanceId": "i-1"}, {"InstanceId": "i-2"}])]
        )

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["registered_instance_count"] == 2
        assert f.details["has_registered_instances"] is True

    def test_enrichment_failure_counts_are_none_not_zero(self):
        """Gap 3: when enrichment fails, registered_target_count and target_group_count
        must be None (unknown), not silently set to 0 (which would look like zero targets)."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        lb_pag = MagicMock()
        lb_pag.paginate.return_value = [{"LoadBalancers": [_elbv2_lb(age_days=20)]}]
        tg_pag = MagicMock()
        tg_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailableException", "Message": "x"}},
            "DescribeTargetGroups",
        )

        def _pag(name):
            return lb_pag if name == "describe_load_balancers" else tg_pag

        elbv2.get_paginator.side_effect = _pag
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 1
        f = findings[0]
        assert f.details["has_registered_targets"] is None
        assert f.details["registered_target_count"] is None, "Must be None, not 0"
        assert f.details["target_group_count"] is None, "Must be None, not 0"

    def test_unhealthy_targets_count_as_registered(self):
        """Any non-empty TargetHealthDescriptions entry counts as a registered target."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(
            elbv2,
            [_elbv2_lb(age_days=20)],
            tg_pages=[{"TargetGroups": [{"TargetGroupArn": "arn:tg:1"}]}],
            target_health={
                "TargetHealthDescriptions": [
                    {"Target": {"Id": "i-1"}, "TargetHealth": {"State": "unhealthy"}}
                ]
            },
        )
        _setup_clb(elb, [])

        f = _run(_make_session(elbv2, elb, cw))[0]
        assert f.details["has_registered_targets"] is True
        assert f.confidence.value == "medium"


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_elbv2_multiple_pages_all_processed(self):
        """ELBv2 paginator with two pages — both pages' LBs are evaluated."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()

        lb_pag = MagicMock()
        lb_pag.paginate.return_value = [
            {"LoadBalancers": [_elbv2_lb(name="alb1", age_days=20)]},
            {"LoadBalancers": [_elbv2_lb(name="alb2", age_days=25)]},
        ]
        tg_pag = MagicMock()
        tg_pag.paginate.return_value = [{"TargetGroups": []}]
        elbv2.get_paginator.side_effect = lambda n: (
            lb_pag if n == "describe_load_balancers" else tg_pag
        )
        _setup_clb(elb, [])

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 2

    def test_clb_multiple_pages_all_processed(self):
        """CLB paginator with two pages — both pages' LBs are evaluated."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [])

        pag = elb.get_paginator.return_value
        pag.paginate.return_value = [
            {"LoadBalancerDescriptions": [_clb(name="clb1", age_days=20)]},
            {"LoadBalancerDescriptions": [_clb(name="clb2", age_days=25)]},
        ]

        findings = _run(_make_session(elbv2, elb, cw))
        assert len(findings) == 2

    def test_both_branches_run(self):
        """ALB and CLB findings are both collected in a single call."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()
        _setup_elbv2(elbv2, [_elbv2_lb(name="idle-alb", age_days=20)])
        _setup_clb(elb, [_clb(name="idle-clb", age_days=20)])

        findings = _run(_make_session(elbv2, elb, cw))
        rule_ids = {f.rule_id for f in findings}
        assert "aws.elbv2.alb.idle" in rule_ids
        assert "aws.elb.clb.idle" in rule_ids


# ---------------------------------------------------------------------------
# TestBranchIsolation
# ---------------------------------------------------------------------------


class TestBranchIsolation:
    """ELBv2 and CLB branches must run independently.

    A failure in one branch must not prevent the other branch from being evaluated.
    Both branches are always attempted; the first exception is re-raised afterward.
    """

    def test_elbv2_failure_does_not_prevent_clb_evaluation(self):
        """ELBv2 inventory failure → CLB paginator is still called."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()

        # Make ELBv2 inventory fail
        exc = ClientError(
            {"Error": {"Code": "InternalError", "Message": "x"}}, "DescribeLoadBalancers"
        )
        lb_pag = MagicMock()
        lb_pag.paginate.side_effect = exc
        elbv2.get_paginator.return_value = lb_pag

        # CLB has a valid idle LB
        _setup_clb(elb, [_clb(name="surviving-clb", age_days=20)])

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

        # CLB paginator must have been called despite ELBv2 failure
        elb.get_paginator.assert_called()

    def test_clb_failure_does_not_prevent_elbv2_evaluation(self):
        """CLB inventory failure → ELBv2 paginator was still called and evaluated."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()

        # ELBv2 has a valid idle ALB
        _setup_elbv2(elbv2, [_elbv2_lb(name="surviving-alb", age_days=20)])

        # Make CLB inventory fail
        exc = ClientError(
            {"Error": {"Code": "InternalError", "Message": "x"}}, "DescribeLoadBalancers"
        )
        clb_pag = elb.get_paginator.return_value
        clb_pag.paginate.side_effect = exc

        with pytest.raises(ClientError):
            _run(_make_session(elbv2, elb, cw))

        # ELBv2 paginator must have been called (its branch completed)
        elbv2.get_paginator.assert_called()

    def test_elbv2_and_clb_both_fail_raises_elbv2_exception(self):
        """When both branches fail, the ELBv2 exception (first) is re-raised."""
        elbv2, elb, cw = MagicMock(), MagicMock(), _cw_no_traffic()

        elbv2_exc = ClientError(
            {"Error": {"Code": "ELBv2Error", "Message": "x"}}, "DescribeLoadBalancers"
        )
        clb_exc = ClientError(
            {"Error": {"Code": "CLBError", "Message": "x"}}, "DescribeLoadBalancers"
        )

        lb_pag = MagicMock()
        lb_pag.paginate.side_effect = elbv2_exc
        elbv2.get_paginator.return_value = lb_pag

        clb_pag = elb.get_paginator.return_value
        clb_pag.paginate.side_effect = clb_exc

        with pytest.raises(ClientError) as exc_info:
            _run(_make_session(elbv2, elb, cw))

        # Must be the ELBv2 exception (first branch failure)
        assert exc_info.value.response["Error"]["Code"] == "ELBv2Error"
