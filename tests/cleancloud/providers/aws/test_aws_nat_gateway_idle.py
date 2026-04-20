"""Tests for aws.ec2.nat_gateway.idle rule.

Covers all acceptance scenarios from docs/specs/aws/nat_gateway_idle.md §15
and the normalization, evidence, confidence, cost, risk, title/reason,
failure, and pagination contracts.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways

_REGION = "us-east-1"
_THRESHOLD = 14


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(ec2: MagicMock, cw: MagicMock) -> MagicMock:
    session = MagicMock()

    def _client(service, **kwargs):
        if service == "ec2":
            return ec2
        if service == "cloudwatch":
            return cw
        raise ValueError(f"Unexpected service: {service}")

    session.client.side_effect = _client
    return session


def _setup_ec2(nat_gws: list) -> MagicMock:
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"NatGateways": nat_gws}]
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    return ec2


def _nat_gw(
    gw_id: str = "nat-aabbccdd",
    state: str = "available",
    age_days: int = 20,
    **extra,
) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "NatGatewayId": gw_id,
        "State": state,
        "CreateTime": now - timedelta(days=age_days),
        "VpcId": "vpc-test",
        "SubnetId": "subnet-test",
        "ConnectivityType": "public",
    }
    base.update(extra)
    return base


def _cw_zero_traffic(num_datapoints: int = 1) -> MagicMock:
    """CloudWatch mock that returns `num_datapoints` zero-valued datapoints for every metric."""
    cw = MagicMock()

    def _get_stats(**kwargs):
        stat = kwargs["Statistics"][0]
        return {"Datapoints": [{stat: 0.0} for _ in range(num_datapoints)]}

    cw.get_metric_statistics.side_effect = _get_stats
    return cw


def _cw_no_datapoints() -> MagicMock:
    """CloudWatch mock that returns empty datapoints for every metric."""
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {"Datapoints": []}
    return cw


def _cw_with_traffic(trigger_metric: str, trigger_stat: str, value: float) -> MagicMock:
    """CloudWatch mock that returns traffic on one specific metric."""
    cw = MagicMock()

    def _get_stats(**kwargs):
        metric = kwargs["MetricName"]
        stat = kwargs["Statistics"][0]
        if metric == trigger_metric:
            return {"Datapoints": [{stat: value}]}
        return {
            "Datapoints": [
                {"Sum": 0.0, "Maximum": 0.0}.get(stat, 0.0) and {stat: 0.0} or {stat: 0.0}
            ]
        }

    cw.get_metric_statistics.side_effect = _get_stats
    return cw


def _cw_active_connection(value: float = 5.0) -> MagicMock:
    """CloudWatch mock where ActiveConnectionCount Maximum > 0."""
    cw = MagicMock()

    def _get_stats(**kwargs):
        metric = kwargs["MetricName"]
        if metric == "ActiveConnectionCount":
            return {"Datapoints": [{"Maximum": value}]}
        return {"Datapoints": [{"Sum": 0.0}]}

    cw.get_metric_statistics.side_effect = _get_stats
    return cw


def _cw_error(code: str = "Throttling") -> MagicMock:
    cw = MagicMock()
    cw.get_metric_statistics.side_effect = ClientError(
        {"Error": {"Code": code, "Message": "test"}}, "GetMetricStatistics"
    )
    return cw


def _run(session: MagicMock, threshold: int = _THRESHOLD) -> list:
    return find_idle_nat_gateways(session, _REGION, idle_days_threshold=threshold)


def _client_error(code: str = "SomeError") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "DescribeNatGateways")


# ---------------------------------------------------------------------------
# §15 Must Emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_available_old_enough_zero_traffic_no_route_ref_high(self):
        """Scenario 1: Available, old, zero traffic, no route ref → EMIT HIGH."""
        ec2 = _setup_ec2([_nat_gw("nat-1", age_days=20)])
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1
        assert findings[0].resource_id == "nat-1"
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_available_old_enough_zero_traffic_route_ref_medium(self):
        """Scenario 2: Available, old, zero traffic, route table still references → EMIT MEDIUM."""
        ec2 = _setup_ec2([_nat_gw("nat-2", age_days=20)])
        ec2.describe_route_tables.return_value = {"RouteTables": [{"RouteTableId": "rtb-abc"}]}
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_available_old_enough_zero_traffic_rt_lookup_failed_medium(self):
        """Scenario 3a: DescribeRouteTables ClientError → EMIT MEDIUM, context unavailable."""
        ec2 = _setup_ec2([_nat_gw("nat-3", age_days=20)])
        ec2.describe_route_tables.side_effect = _client_error("AccessDenied")
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_available_old_enough_zero_traffic_rt_botocore_error_medium(self):
        """Scenario 3b: DescribeRouteTables BotoCoreError → EMIT MEDIUM, context unavailable."""
        ec2 = _setup_ec2([_nat_gw("nat-3b", age_days=20)])
        ec2.describe_route_tables.side_effect = BotoCoreError()
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM
        assert findings[0].details["route_table_referenced"] is None

    def test_rt_any_exception_degrades_gracefully(self):
        """Any exception from DescribeRouteTables degrades context — scan never blows up."""
        ec2 = _setup_ec2([_nat_gw("nat-rtexc", age_days=20)])
        ec2.describe_route_tables.side_effect = RuntimeError("unexpected")
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.MEDIUM
        assert findings[0].details["route_table_referenced"] is None


# ---------------------------------------------------------------------------
# §15 Must Skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_state_pending_skipped(self):
        """Scenario 4a: State pending → SKIP."""
        ec2 = _setup_ec2([_nat_gw("nat-pend", state="pending")])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_state_failed_skipped(self):
        ec2 = _setup_ec2([_nat_gw("nat-fail", state="failed")])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_state_deleting_skipped(self):
        ec2 = _setup_ec2([_nat_gw("nat-del", state="deleting")])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_state_deleted_skipped(self):
        ec2 = _setup_ec2([_nat_gw("nat-deld", state="deleted")])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_too_young_skipped(self):
        """Scenario 5: Available but younger than threshold → SKIP."""
        ec2 = _setup_ec2([_nat_gw("nat-young", age_days=5)])
        assert _run(_make_session(ec2, _cw_zero_traffic()), threshold=14) == []

    def test_bytes_out_to_destination_nonzero_skipped(self):
        """Scenario 6: BytesOutToDestination Sum > 0 → SKIP."""
        ec2 = _setup_ec2([_nat_gw("nat-bytes")])
        cw = MagicMock()

        def _get_stats(**kwargs):
            metric = kwargs["MetricName"]
            stat = kwargs["Statistics"][0]
            if metric == "BytesOutToDestination":
                return {"Datapoints": [{"Sum": 100.0}]}
            return {"Datapoints": [{stat: 0.0}]}

        cw.get_metric_statistics.side_effect = _get_stats
        assert _run(_make_session(ec2, cw)) == []

    def test_bytes_in_from_source_nonzero_skipped(self):
        ec2 = _setup_ec2([_nat_gw("nat-bifs")])
        cw = MagicMock()

        def _get_stats(**kwargs):
            metric = kwargs["MetricName"]
            stat = kwargs["Statistics"][0]
            if metric == "BytesInFromSource":
                return {"Datapoints": [{"Sum": 1.0}]}
            return {"Datapoints": [{stat: 0.0}]}

        cw.get_metric_statistics.side_effect = _get_stats
        assert _run(_make_session(ec2, cw)) == []

    def test_active_connection_count_nonzero_skipped(self):
        """Scenario 7: ActiveConnectionCount Maximum > 0 → SKIP."""
        ec2 = _setup_ec2([_nat_gw("nat-acc")])
        cw = _cw_active_connection(value=3.0)
        assert _run(_make_session(ec2, cw)) == []

    def test_missing_create_time_skipped(self):
        """Scenario 8a: Missing CreateTime → SKIP."""
        gw = {"NatGatewayId": "nat-noct", "State": "available"}
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_naive_create_time_skipped(self):
        """Scenario 8b: Naive (timezone-unaware) CreateTime → SKIP."""
        gw = _nat_gw("nat-naive")
        gw["CreateTime"] = datetime.now()  # naive, no tzinfo
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_future_create_time_skipped(self):
        """Scenario 8c: Future CreateTime → SKIP."""
        gw = _nat_gw("nat-future")
        gw["CreateTime"] = datetime.now(timezone.utc) + timedelta(days=10)
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_no_datapoints_any_metric_skipped(self):
        """Scenario 9: Any required metric returns no datapoints → SKIP ITEM."""
        ec2 = _setup_ec2([_nat_gw("nat-nodata")])
        cw = _cw_no_datapoints()
        assert _run(_make_session(ec2, cw)) == []

    def test_partial_datapoints_missing_one_metric_skipped(self):
        """If one metric has no datapoints but others do → SKIP ITEM."""
        ec2 = _setup_ec2([_nat_gw("nat-partial")])
        cw = MagicMock()
        call_count = [0]

        def _get_stats(**kwargs):
            call_count[0] += 1
            # First metric returns data; second metric returns nothing
            if call_count[0] == 1:
                return {"Datapoints": [{"Sum": 0.0}]}
            return {"Datapoints": []}

        cw.get_metric_statistics.side_effect = _get_stats
        assert _run(_make_session(ec2, cw)) == []


# ---------------------------------------------------------------------------
# §15 Must Fail
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_nat_gateways_client_error_raises(self):
        """Scenario 10: DescribeNatGateways ClientError → FAIL RULE."""
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("InternalServerError")
        with pytest.raises(ClientError):
            _run(_make_session(ec2, _cw_zero_traffic()))

    def test_describe_nat_gateways_unauthorized_raises_permission_error(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("UnauthorizedOperation")
        with pytest.raises(PermissionError):
            _run(_make_session(ec2, _cw_zero_traffic()))

    def test_describe_nat_gateways_botocore_error_raises(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            _run(_make_session(ec2, _cw_zero_traffic()))

    def test_cloudwatch_client_error_raises(self):
        """Scenario 11: CloudWatch metric fetch ClientError → FAIL RULE."""
        ec2 = _setup_ec2([_nat_gw("nat-cwerr")])
        cw = _cw_error("InternalServerError")
        with pytest.raises(ClientError):
            _run(_make_session(ec2, cw))

    def test_cloudwatch_botocore_error_raises(self):
        ec2 = _setup_ec2([_nat_gw("nat-cwboto")])
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            _run(_make_session(ec2, cw))

    def test_cloudwatch_unauthorized_raises_permission_error(self):
        ec2 = _setup_ec2([_nat_gw("nat-cwunauth")])
        cw = _cw_error("UnauthorizedOperation")
        with pytest.raises(PermissionError):
            _run(_make_session(ec2, cw))

    def test_cloudwatch_throttle_raises_not_low_confidence(self):
        """Throttling error must raise (FAIL RULE), NOT produce a LOW-confidence finding."""
        ec2 = _setup_ec2([_nat_gw("nat-throttle")])
        cw = _cw_error("Throttling")
        with pytest.raises(ClientError):
            _run(_make_session(ec2, cw))


# ---------------------------------------------------------------------------
# §15 Must NOT Happen
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    def test_low_confidence_never_emitted(self):
        """LOW confidence finding must never be emitted."""
        ec2 = _setup_ec2([_nat_gw("nat-nolow")])
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        for f in findings:
            assert f.confidence != ConfidenceLevel.LOW

    def test_missing_datapoints_not_treated_as_zero(self):
        """Missing datapoints → SKIP ITEM, not zero traffic → no finding."""
        ec2 = _setup_ec2([_nat_gw("nat-nodata2")])
        cw = _cw_no_datapoints()
        assert _run(_make_session(ec2, cw)) == []

    def test_cost_is_none(self):
        """estimated_monthly_cost_usd must always be None."""
        ec2 = _setup_ec2([_nat_gw("nat-cost")])
        cw = _cw_zero_traffic()
        f = _run(_make_session(ec2, cw))[0]
        assert f.estimated_monthly_cost_usd is None

    def test_route_table_absence_not_substitute_for_cloudwatch(self):
        """Route-table absence must not compensate for missing CloudWatch evidence."""
        ec2 = _setup_ec2([_nat_gw("nat-rt-subst")])
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        cw = _cw_no_datapoints()  # No CW data → must skip
        assert _run(_make_session(ec2, cw)) == []


# ---------------------------------------------------------------------------
# Normalization contract
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_non_dict_item_skipped(self):
        ec2 = MagicMock()
        paginator = MagicMock()
        ec2.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NatGateways": ["not-a-dict", None, 42]}]
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_missing_nat_gateway_id_skipped(self):
        gw = {"State": "available", "CreateTime": datetime.now(timezone.utc) - timedelta(days=20)}
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_empty_string_nat_gateway_id_skipped(self):
        gw = _nat_gw("nat-x")
        gw["NatGatewayId"] = ""
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_missing_state_skipped(self):
        gw = {
            "NatGatewayId": "nat-nostate",
            "CreateTime": datetime.now(timezone.utc) - timedelta(days=20),
        }
        ec2 = _setup_ec2([gw])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_age_exactly_at_threshold_emits(self):
        """age_days == threshold → eligible (>= check)."""
        ec2 = _setup_ec2([_nat_gw("nat-exact", age_days=_THRESHOLD)])
        cw = _cw_zero_traffic()
        findings = _run(_make_session(ec2, cw))
        assert len(findings) == 1

    def test_age_one_below_threshold_skipped(self):
        ec2 = _setup_ec2([_nat_gw("nat-below", age_days=_THRESHOLD - 1)])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_tags_absent_yields_empty_list(self):
        gw = _nat_gw("nat-notag")
        gw.pop("Tags", None)
        ec2 = _setup_ec2([gw])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["tag_set"] == []

    def test_tags_list_preserved(self):
        tags = [{"Key": "Name", "Value": "my-nat"}]
        ec2 = _setup_ec2([_nat_gw("nat-tag", Tags=tags)])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["tag_set"] == tags

    def test_nat_gateway_addresses_absent_yields_empty_list(self):
        gw = _nat_gw("nat-noaddr")
        gw.pop("NatGatewayAddresses", None)
        ec2 = _setup_ec2([gw])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["nat_gateway_addresses"] == []

    def test_connectivity_type_null_when_absent(self):
        gw = _nat_gw("nat-notype")
        gw.pop("ConnectivityType", None)
        ec2 = _setup_ec2([gw])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["connectivity_type"] is None


# ---------------------------------------------------------------------------
# Evidence contract (§11)
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_required_details_fields_present(self):
        ec2 = _setup_ec2([_nat_gw("nat-evid")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        d = f.details
        required = [
            "evaluation_path",
            "nat_gateway_id",
            "normalized_state",
            "create_time",
            "age_days",
            "idle_days_threshold",
            "connectivity_type",
            "availability_mode",
            "vpc_id",
            "subnet_id",
            "bytes_out_to_destination",
            "bytes_in_from_source",
            "bytes_in_from_destination",
            "bytes_out_to_source",
            "active_connection_count_max",
        ]
        for field in required:
            assert field in d, f"Required field '{field}' missing"

    def test_evaluation_path_exact(self):
        ec2 = _setup_ec2([_nat_gw("nat-ep")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["evaluation_path"] == "idle-nat-gateway-review-candidate"

    def test_normalized_state_is_available(self):
        ec2 = _setup_ec2([_nat_gw("nat-ns")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["normalized_state"] == "available"

    def test_all_metric_values_zero_in_details(self):
        ec2 = _setup_ec2([_nat_gw("nat-mv")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        d = f.details
        assert d["bytes_out_to_destination"] == 0.0
        assert d["bytes_in_from_source"] == 0.0
        assert d["bytes_in_from_destination"] == 0.0
        assert d["bytes_out_to_source"] == 0.0
        assert d["active_connection_count_max"] == 0.0

    def test_route_table_referenced_false_in_details(self):
        ec2 = _setup_ec2([_nat_gw("nat-rtf")])
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["route_table_referenced"] is False

    def test_route_table_referenced_true_in_details(self):
        ec2 = _setup_ec2([_nat_gw("nat-rtt")])
        ec2.describe_route_tables.return_value = {"RouteTables": [{"RouteTableId": "rtb-x"}]}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["route_table_referenced"] is True

    def test_route_table_referenced_none_when_check_fails(self):
        ec2 = _setup_ec2([_nat_gw("nat-rtn")])
        ec2.describe_route_tables.side_effect = _client_error("AccessDenied")
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.details["route_table_referenced"] is None

    def test_idle_days_threshold_in_details(self):
        ec2 = _setup_ec2([_nat_gw("nat-thresh", age_days=30)])
        f = _run(_make_session(ec2, _cw_zero_traffic()), threshold=21)[0]
        assert f.details["idle_days_threshold"] == 21

    def test_active_connection_count_max_in_details(self):
        ec2 = _setup_ec2([_nat_gw("nat-acc")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert "active_connection_count_max" in f.details


# ---------------------------------------------------------------------------
# Confidence model (§12)
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_when_no_route_ref(self):
        ec2 = _setup_ec2([_nat_gw("nat-ch")])
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.confidence == ConfidenceLevel.HIGH

    def test_medium_when_route_table_referenced(self):
        ec2 = _setup_ec2([_nat_gw("nat-cm-rt")])
        ec2.describe_route_tables.return_value = {"RouteTables": [{"RouteTableId": "rtb-x"}]}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.confidence == ConfidenceLevel.MEDIUM

    def test_medium_when_route_table_check_fails(self):
        ec2 = _setup_ec2([_nat_gw("nat-cm-fail")])
        ec2.describe_route_tables.side_effect = _client_error("AccessDenied")
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.confidence == ConfidenceLevel.MEDIUM

    def test_low_confidence_never_emitted(self):
        ec2 = _setup_ec2([_nat_gw("nat-nolow")])
        cw = _cw_zero_traffic()
        for f in _run(_make_session(ec2, cw)):
            assert f.confidence != ConfidenceLevel.LOW


# ---------------------------------------------------------------------------
# Cost model (§11.2)
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self):
        ec2 = _setup_ec2([_nat_gw("nat-cost")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.estimated_monthly_cost_usd is None

    def test_no_hardcoded_cost_in_details(self):
        """No dollar-amount cost estimate should appear in details."""
        ec2 = _setup_ec2([_nat_gw("nat-nodetcost")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        detail_str = str(f.details).lower()
        assert "$32" not in detail_str
        assert "estimated_monthly_cost" not in f.details


# ---------------------------------------------------------------------------
# Risk model (§14)
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_medium_no_route_ref(self):
        ec2 = _setup_ec2([_nat_gw("nat-risk1")])
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.risk == RiskLevel.MEDIUM

    def test_risk_is_medium_with_route_ref(self):
        ec2 = _setup_ec2([_nat_gw("nat-risk2")])
        ec2.describe_route_tables.return_value = {"RouteTables": [{"RouteTableId": "rtb-x"}]}
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.risk == RiskLevel.MEDIUM

    def test_risk_never_high(self):
        ec2 = _setup_ec2([_nat_gw("nat-nohigh")])
        for f in _run(_make_session(ec2, _cw_zero_traffic())):
            assert f.risk != RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Title and reason contract (§13)
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title_exact(self):
        ec2 = _setup_ec2([_nat_gw("nat-title")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.title == "Idle NAT Gateway review candidate"

    def test_reason_contains_threshold(self):
        ec2 = _setup_ec2([_nat_gw("nat-reason", age_days=30)])
        f = _run(_make_session(ec2, _cw_zero_traffic()), threshold=21)[0]
        assert "21" in f.reason

    def test_title_does_not_claim_safe_to_delete(self):
        ec2 = _setup_ec2([_nat_gw("nat-safe")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert "delete" not in f.title.lower()
        assert "safe" not in f.title.lower()


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_all_evaluated(self):
        ec2 = MagicMock()
        paginator = MagicMock()
        ec2.get_paginator.return_value = paginator
        ec2.describe_route_tables.return_value = {"RouteTables": []}
        paginator.paginate.return_value = [
            {"NatGateways": [_nat_gw("nat-p1")]},
            {"NatGateways": [_nat_gw("nat-p2")]},
            {"NatGateways": [_nat_gw("nat-p3", state="deleted")]},
        ]
        findings = _run(_make_session(ec2, _cw_zero_traffic()))
        ids = {f.resource_id for f in findings}
        assert "nat-p1" in ids
        assert "nat-p2" in ids
        assert "nat-p3" not in ids

    def test_empty_page_yields_no_findings(self):
        ec2 = _setup_ec2([])
        assert _run(_make_session(ec2, _cw_zero_traffic())) == []

    def test_paginator_called_with_correct_operation(self):
        ec2 = _setup_ec2([])
        _run(_make_session(ec2, _cw_zero_traffic()))
        ec2.get_paginator.assert_called_once_with("describe_nat_gateways")


# ---------------------------------------------------------------------------
# Additional correctness
# ---------------------------------------------------------------------------


class TestCorrectness:
    def test_resource_id_matches_nat_gateway_id(self):
        ec2 = _setup_ec2([_nat_gw("nat-rid")])
        f = _run(_make_session(ec2, _cw_zero_traffic()))[0]
        assert f.resource_id == "nat-rid"
        assert f.details["nat_gateway_id"] == "nat-rid"

    def test_rule_id_correct(self):
        ec2 = _setup_ec2([_nat_gw("nat-ruleid")])
        assert _run(_make_session(ec2, _cw_zero_traffic()))[0].rule_id == "aws.ec2.nat_gateway.idle"

    def test_provider_is_aws(self):
        ec2 = _setup_ec2([_nat_gw("nat-prov")])
        assert _run(_make_session(ec2, _cw_zero_traffic()))[0].provider == "aws"

    def test_active_connection_count_metric_is_checked(self):
        """ActiveConnectionCount must be in the required metrics; missing data → SKIP."""
        ec2 = _setup_ec2([_nat_gw("nat-acccheck")])
        cw = MagicMock()
        metrics_queried = []

        def _get_stats(**kwargs):
            metrics_queried.append(kwargs["MetricName"])
            return {
                "Datapoints": [
                    {"Sum": 0.0, "Maximum": 0.0}.get(kwargs["Statistics"][0], 0.0)
                    and {"Sum": 0.0}
                    or {kwargs["Statistics"][0]: 0.0}
                ]
            }

        cw.get_metric_statistics.side_effect = _get_stats
        _run(_make_session(ec2, cw))
        assert "ActiveConnectionCount" in metrics_queried

    def test_five_metrics_queried_per_nat_gateway(self):
        """Exactly 5 CloudWatch metric calls must be made per evaluated NAT Gateway."""
        ec2 = _setup_ec2([_nat_gw("nat-5m")])
        cw = _cw_zero_traffic()
        _run(_make_session(ec2, cw))
        assert cw.get_metric_statistics.call_count == 5

    def test_connectivity_type_private_emits(self):
        ec2 = _setup_ec2([_nat_gw("nat-priv", ConnectivityType="private")])
        findings = _run(_make_session(ec2, _cw_zero_traffic()))
        assert len(findings) == 1
        assert findings[0].details["connectivity_type"] == "private"

    def test_multiple_available_old_zero_traffic_nat_gws_all_emit(self):
        nat_gws = [_nat_gw(f"nat-multi-{i}", age_days=20) for i in range(3)]
        ec2 = _setup_ec2(nat_gws)
        findings = _run(_make_session(ec2, _cw_zero_traffic()))
        assert len(findings) == 3
