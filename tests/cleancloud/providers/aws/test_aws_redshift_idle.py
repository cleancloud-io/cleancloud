"""
Tests for aws.redshift.cluster.idle rule.

Test class overview:
    TestMustEmit              — canonical detection path
    TestMustSkip              — all exclusion rules
    TestMustFailRule          — required API failure behaviour
    TestNormalization         — _normalize_cluster field extraction
    TestConfidenceModel       — HIGH with corroboration, MEDIUM without
    TestRiskModel             — HIGH for 4+ nodes, MEDIUM otherwise
    TestEvidenceContract      — signals_used, signals_not_checked, evaluation_path
    TestRuleMetadata          — rule_id, category, service, cost_impact
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.redshift_idle import (
    _normalize_cluster,
    find_idle_redshift_clusters,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _old() -> datetime:
    """30 days ago — always older than the default 14-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=30)


def _young() -> datetime:
    """5 days ago — always younger than the default 14-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=5)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _make_cluster(**overrides) -> dict:
    """Return a minimal valid DescribeClusters item."""
    base = {
        "ClusterIdentifier": "test-cluster",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "ClusterCreateTime": _old(),
        "NodeType": "dc2.large",
        "NumberOfNodes": 2,
        "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:123456789012:namespace:test",
        "Endpoint": {"Address": "test.us-east-1.redshift.amazonaws.com", "Port": 5439},
        "TotalStorageCapacityInMegaBytes": 640000,
    }
    base.update(overrides)
    return base


def _zero_connections_response() -> dict:
    return {"Datapoints": [{"Sum": 0.0}]}


def _nonzero_connections_response(val: float = 5.0) -> dict:
    return {"Datapoints": [{"Sum": val}]}


def _no_datapoints_response() -> dict:
    return {"Datapoints": []}


def _setup(
    mock_boto3_session,
    clusters: list,
    cw_responses=None,
    cw_side_effect=None,
):
    """Wire up Redshift paginator and CloudWatch mock."""
    redshift = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Clusters": clusters}]
    redshift.get_paginator.return_value = paginator

    cloudwatch = MagicMock()
    if cw_side_effect is not None:
        cloudwatch.get_metric_statistics.side_effect = cw_side_effect
    elif cw_responses is not None:
        cloudwatch.get_metric_statistics.side_effect = cw_responses
    else:
        # Default: zero connections, zero IOPS
        cloudwatch.get_metric_statistics.return_value = _zero_connections_response()

    def client_side_effect(service, **kwargs):
        if service == "redshift":
            return redshift
        if service == "cloudwatch":
            return cloudwatch
        raise ValueError(f"Unexpected service: {service}")

    mock_boto3_session.client.side_effect = client_side_effect
    return redshift, cloudwatch


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_canonical_idle_cluster_emits(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 1
        f = findings[0]
        assert f.provider == "aws"
        assert f.rule_id == "aws.redshift.cluster.idle"
        assert f.resource_type == "aws.redshift.cluster"
        assert f.region == _REGION

    def test_resource_id_uses_namespace_arn(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].resource_id == ("arn:aws:redshift:us-east-1:123456789012:namespace:test")

    def test_resource_id_falls_back_to_identifier(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterNamespaceArn=None)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].resource_id == "test-cluster"

    def test_details_required_fields_present(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "evaluation_path",
            "cluster_identifier",
            "resource_id",
            "cluster_status",
            "cluster_create_time",
            "cluster_age_days",
            "node_type",
            "number_of_nodes",
            "idle_days_threshold",
            "evaluation_window_start",
            "evaluation_window_end",
            "database_connections_sum",
            "is_idle",
        ):
            assert key in d, f"Missing required detail key: {key}"

    def test_details_optional_fields_present(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "cluster_availability_status",
            "cluster_endpoint_address",
            "cluster_endpoint_port",
            "read_iops_sum",
            "write_iops_sum",
            "total_storage_capacity_mb",
        ):
            assert key in d, f"Missing optional detail key: {key}"


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_paused_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(ClusterStatus="paused")])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_creating_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(ClusterStatus="creating")])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_deleting_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(ClusterStatus="deleting")])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_modifying_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(ClusterStatus="modifying")])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_unavailable_availability_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterAvailabilityStatus="Unavailable")],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_maintenance_availability_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterAvailabilityStatus="Maintenance")],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_failed_availability_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterAvailabilityStatus="Failed")],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_young_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(ClusterCreateTime=_young())])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_nonzero_connections(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_responses=[_nonzero_connections_response()],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_no_datapoints(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_responses=[_no_datapoints_response()],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_identifier(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterIdentifier=None)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterStatus=None)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_create_time(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterCreateTime=None)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_naive_create_time(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterCreateTime=datetime(2024, 1, 1))],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_future_create_time(self, mock_boto3_session):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterCreateTime=future)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_null_availability_status_does_not_skip(self, mock_boto3_session):
        """When ClusterAvailabilityStatus is absent, the cluster is not skipped."""
        _setup(
            mock_boto3_session,
            [_make_cluster(ClusterAvailabilityStatus=None)],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_clusters_permission_error(self, mock_boto3_session):
        redshift = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = _client_error("AccessDenied")
        redshift.get_paginator.return_value = paginator
        mock_boto3_session.client.side_effect = lambda s, **kw: redshift

        with pytest.raises(PermissionError, match="redshift:DescribeClusters"):
            find_idle_redshift_clusters(mock_boto3_session, _REGION)

    def test_cloudwatch_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_side_effect=_client_error("AccessDenied"),
        )
        with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
            find_idle_redshift_clusters(mock_boto3_session, _REGION)

    def test_cloudwatch_request_failure_raises(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_side_effect=BotoCoreError(),
        )
        with pytest.raises(BotoCoreError):
            find_idle_redshift_clusters(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_valid_cluster_normalizes(self):
        n = _normalize_cluster(_make_cluster(), _now())
        assert n is not None
        assert n["cluster_identifier"] == "test-cluster"
        assert n["cluster_status"] == "available"
        assert n["node_type"] == "dc2.large"
        assert n["number_of_nodes"] == 2
        assert n["cluster_endpoint_address"] == "test.us-east-1.redshift.amazonaws.com"
        assert n["cluster_endpoint_port"] == 5439

    def test_non_dict_returns_none(self):
        assert _normalize_cluster("not a dict", _now()) is None

    def test_missing_identifier_returns_none(self):
        assert _normalize_cluster(_make_cluster(ClusterIdentifier=None), _now()) is None

    def test_missing_status_returns_none(self):
        assert _normalize_cluster(_make_cluster(ClusterStatus=None), _now()) is None

    def test_naive_create_time_returns_none(self):
        assert (
            _normalize_cluster(_make_cluster(ClusterCreateTime=datetime(2024, 1, 1)), _now())
            is None
        )

    def test_bool_number_of_nodes_treated_as_none(self):
        n = _normalize_cluster(_make_cluster(NumberOfNodes=True), _now())
        assert n is not None
        assert n["number_of_nodes"] is None

    def test_missing_endpoint_degrades_to_null(self):
        n = _normalize_cluster(_make_cluster(Endpoint=None), _now())
        assert n is not None
        assert n["cluster_endpoint_address"] is None
        assert n["cluster_endpoint_port"] is None

    def test_cluster_age_days_not_negative(self):
        slightly_future = datetime.now(timezone.utc) + timedelta(seconds=100)
        n = _normalize_cluster(_make_cluster(ClusterCreateTime=slightly_future), _now())
        assert n is not None
        assert n["cluster_age_days"] >= 0


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_confidence_with_zero_iops(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_responses=[
                _zero_connections_response(),  # DatabaseConnections
                _zero_connections_response(),  # ReadIOPS
                _zero_connections_response(),  # WriteIOPS
            ],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_secondary_missing(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_responses=[
                _zero_connections_response(),  # DatabaseConnections
                _no_datapoints_response(),  # ReadIOPS (missing)
                _no_datapoints_response(),  # WriteIOPS (missing)
            ],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "medium"

    def test_medium_confidence_when_secondary_nonzero(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_cluster()],
            cw_responses=[
                _zero_connections_response(),  # DatabaseConnections
                _nonzero_connections_response(10),  # ReadIOPS (nonzero)
                _zero_connections_response(),  # WriteIOPS
            ],
        )
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_high_risk_large_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(NumberOfNodes=4)])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "high"

    def test_medium_risk_small_cluster(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(NumberOfNodes=2)])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "medium"

    def test_medium_risk_when_nodes_missing(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster(NumberOfNodes=None)])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_evaluation_path(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].details["evaluation_path"] == ("idle-redshift-cluster-review-candidate")

    def test_signals_not_checked(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        snc = findings[0].evidence.signals_not_checked
        assert any("business value" in s.lower() for s in snc)
        assert any("pausing or deleting" in s.lower() for s in snc)

    def test_is_idle_always_true_in_emitted_finding(self, mock_boto3_session):
        _setup(mock_boto3_session, [_make_cluster()])
        findings = find_idle_redshift_clusters(mock_boto3_session, _REGION)
        assert findings[0].details["is_idle"] is True


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        from cleancloud.providers.aws.rules.redshift_idle import RULE_METADATA

        assert RULE_METADATA["id"] == "aws.redshift.cluster.idle"

    def test_category(self):
        from cleancloud.providers.aws.rules.redshift_idle import RULE_METADATA

        assert RULE_METADATA["category"] == "hygiene"

    def test_service(self):
        from cleancloud.providers.aws.rules.redshift_idle import RULE_METADATA

        assert RULE_METADATA["service"] == "redshift"

    def test_cost_impact(self):
        from cleancloud.providers.aws.rules.redshift_idle import RULE_METADATA

        assert RULE_METADATA["cost_impact"] == "high"
