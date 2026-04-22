"""
Tests for aws.rds.instance.idle rule.

Test class overview:
    TestMustEmit              — canonical detection path
    TestMustSkip              — all exclusion rules
    TestMustFailRule          — required API failure behaviour
    TestNormalization         — _normalize_db_instance field extraction
    TestCloudWatchContract    — metric name, statistic, period, dimension
    TestEvidenceContract      — signals_used, signals_not_checked, evaluation_path
    TestConfidenceModel       — always MEDIUM
    TestCostModel             — estimated_monthly_cost_usd always None
    TestRiskModel             — always MEDIUM
    TestTitleAndReasonContract — exact title and evaluation_path
    TestPagination            — multi-page exhaustion
    TestStandaloneScope       — all three scope exclusion fields
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.rds_idle import (
    _normalize_db_instance,
    find_idle_rds_instances,
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


def _botocore_error() -> BotoCoreError:
    return BotoCoreError()


def _make_instance(**overrides) -> dict:
    """Return a minimal valid DescribeDBInstances item."""
    base = {
        "DBInstanceIdentifier": "test-db",
        "DBInstanceStatus": "available",
        "InstanceCreateTime": _old(),
        "Engine": "mysql",
        "EngineVersion": "8.0.35",
        "DBInstanceClass": "db.t3.medium",
        "MultiAZ": False,
        "AllocatedStorage": 100,
        "StorageType": "gp2",
        "DBClusterIdentifier": None,
        "ReadReplicaSourceDBInstanceIdentifier": None,
        "ReadReplicaSourceDBClusterIdentifier": None,
        "TagList": [],
    }
    base.update(overrides)
    return base


def _zero_connections_response() -> dict:
    """CloudWatch response: datapoints present, all Maximum == 0."""
    return {"Datapoints": [{"Maximum": 0.0}]}


def _nonzero_connections_response(val: float = 5.0) -> dict:
    return {"Datapoints": [{"Maximum": val}]}


def _no_datapoints_response() -> dict:
    return {"Datapoints": []}


def _setup(
    mock_boto3_session,
    instances: list,
    cw_response=None,
    cw_side_effect=None,
):
    """Wire up RDS paginator and CloudWatch mock, return (rds, cloudwatch)."""
    rds = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"DBInstances": instances}]
    rds.get_paginator.return_value = paginator

    cloudwatch = MagicMock()
    if cw_side_effect is not None:
        cloudwatch.get_metric_statistics.side_effect = cw_side_effect
    elif cw_response is not None:
        cloudwatch.get_metric_statistics.return_value = cw_response

    def client_side_effect(service, **kwargs):
        if service == "rds":
            return rds
        if service == "cloudwatch":
            return cloudwatch
        raise ValueError(f"Unexpected service: {service}")

    mock_boto3_session.client.side_effect = client_side_effect
    return rds, cloudwatch


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_standalone_available_old_zero_connections_emits(self, mock_boto3_session):
        """Canonical path: standalone, available, old enough, zero DatabaseConnections."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        f = findings[0]
        assert f.provider == "aws"
        assert f.rule_id == "aws.rds.instance.idle"
        assert f.resource_type == "aws.rds.instance"
        assert f.resource_id == "test-db"
        assert f.region == _REGION

    def test_multiple_datapoints_all_zero_emits(self, mock_boto3_session):
        """Multiple datapoints all Maximum == 0 → EMIT."""
        resp = {
            "Datapoints": [
                {"Maximum": 0.0},
                {"Maximum": 0.0},
                {"Maximum": 0.0},
            ]
        }
        _setup(mock_boto3_session, [_make_instance()], cw_response=resp)
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_details_database_connections_max_zero(self, mock_boto3_session):
        """Emitted finding must include database_connections_max == 0.0."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].details["database_connections_max"] == 0.0

    def test_details_required_fields_present(self, mock_boto3_session):
        """All required details fields from spec 11.1 must be present."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "evaluation_path",
            "db_instance_id",
            "normalized_status",
            "instance_create_time",
            "age_days",
            "idle_days_threshold",
            "engine",
            "engine_version",
            "db_instance_class",
            "database_connections_max",
        ):
            assert key in d, f"Missing required detail key: {key}"

    def test_optional_context_fields_present(self, mock_boto3_session):
        """Optional context fields from spec 11.1 must be present in details."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "db_cluster_identifier",
            "read_replica_source_db_instance_identifier",
            "read_replica_source_db_cluster_identifier",
            "multi_az",
            "allocated_storage_gib",
            "storage_type",
            "tag_set",
        ):
            assert key in d, f"Missing optional context detail: {key}"


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_non_available_status_skipped(self, mock_boto3_session):
        for status in ("stopped", "stopping", "creating", "modifying", "backing-up"):
            _setup(
                mock_boto3_session,
                [_make_instance(DBInstanceStatus=status)],
                cw_response=_zero_connections_response(),
            )
            findings = find_idle_rds_instances(mock_boto3_session, _REGION)
            assert findings == [], f"Expected skip for status={status}"

    def test_cluster_member_skipped(self, mock_boto3_session):
        """DB cluster member (DBClusterIdentifier present) → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance(DBClusterIdentifier="my-cluster")],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_read_replica_db_instance_source_skipped(self, mock_boto3_session):
        """ReadReplicaSourceDBInstanceIdentifier present → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance(ReadReplicaSourceDBInstanceIdentifier="source-db")],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_read_replica_db_cluster_source_skipped(self, mock_boto3_session):
        """ReadReplicaSourceDBClusterIdentifier present → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance(ReadReplicaSourceDBClusterIdentifier="source-cluster")],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_too_young_skipped(self, mock_boto3_session):
        """Instance younger than idle_days_threshold → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance(InstanceCreateTime=_young())],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_exactly_at_threshold_emits(self, mock_boto3_session):
        """age_days == idle_days_threshold satisfies >= check → EMIT."""
        # Use 14 days + 1 hour to ensure floor(total_seconds / 86400) == 14
        at_threshold = datetime.now(timezone.utc) - timedelta(days=14, hours=1)
        _setup(
            mock_boto3_session,
            [_make_instance(InstanceCreateTime=at_threshold)],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_no_datapoints_skipped(self, mock_boto3_session):
        """DatabaseConnections returns no datapoints → SKIP ITEM (not LOW finding)."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_no_datapoints_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_nonzero_connections_skipped(self, mock_boto3_session):
        """DatabaseConnections Maximum > 0 → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_nonzero_connections_response(val=1.0),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_any_nonzero_datapoint_skipped(self, mock_boto3_session):
        """Multiple datapoints — one is nonzero → SKIP ITEM."""
        resp = {
            "Datapoints": [
                {"Maximum": 0.0},
                {"Maximum": 3.0},
            ]
        }
        _setup(mock_boto3_session, [_make_instance()], cw_response=resp)
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_missing_db_instance_identifier_skipped(self, mock_boto3_session):
        """Missing DBInstanceIdentifier → SKIP ITEM."""
        item = _make_instance()
        del item["DBInstanceIdentifier"]
        _setup(mock_boto3_session, [item], cw_response=_zero_connections_response())
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_missing_status_skipped(self, mock_boto3_session):
        """Missing DBInstanceStatus → SKIP ITEM."""
        item = _make_instance()
        del item["DBInstanceStatus"]
        _setup(mock_boto3_session, [item], cw_response=_zero_connections_response())
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_missing_create_time_skipped(self, mock_boto3_session):
        """Missing InstanceCreateTime → SKIP ITEM."""
        item = _make_instance()
        del item["InstanceCreateTime"]
        _setup(mock_boto3_session, [item], cw_response=_zero_connections_response())
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_naive_create_time_skipped(self, mock_boto3_session):
        """Naive InstanceCreateTime (no tzinfo) → SKIP ITEM."""
        naive = _old().replace(tzinfo=None)
        _setup(
            mock_boto3_session,
            [_make_instance(InstanceCreateTime=naive)],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_future_create_time_skipped(self, mock_boto3_session):
        """InstanceCreateTime in the future → SKIP ITEM."""
        future = datetime.now(timezone.utc) + timedelta(days=1)
        _setup(
            mock_boto3_session,
            [_make_instance(InstanceCreateTime=future)],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_non_dict_item_skipped(self, mock_boto3_session):
        """Non-dict items in DBInstances list → silently skipped."""
        _setup(
            mock_boto3_session,
            [None, "string", 42, _make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_empty_db_instances_no_findings(self, mock_boto3_session):
        _setup(mock_boto3_session, [], cw_response=_zero_connections_response())
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_db_instances_access_denied_raises_permission_error(self, mock_boto3_session):
        rds = MagicMock()
        rds.get_paginator.side_effect = _client_error("AccessDenied")
        cloudwatch = MagicMock()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        with pytest.raises(PermissionError, match="rds:DescribeDBInstances"):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_describe_db_instances_unauthorized_raises_permission_error(self, mock_boto3_session):
        rds = MagicMock()
        rds.get_paginator.side_effect = _client_error("UnauthorizedOperation")
        cloudwatch = MagicMock()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        with pytest.raises(PermissionError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_describe_db_instances_other_client_error_propagates(self, mock_boto3_session):
        rds = MagicMock()
        rds.get_paginator.side_effect = _client_error("InternalServerError")
        cloudwatch = MagicMock()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        with pytest.raises(ClientError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_describe_db_instances_botocore_error_propagates(self, mock_boto3_session):
        rds = MagicMock()
        rds.get_paginator.side_effect = _botocore_error()
        cloudwatch = MagicMock()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        with pytest.raises(BotoCoreError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_cloudwatch_access_denied_raises_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_side_effect=_client_error("AccessDenied"),
        )
        with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_cloudwatch_unauthorized_raises_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_side_effect=_client_error("UnauthorizedOperation"),
        )
        with pytest.raises(PermissionError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_cloudwatch_throttle_raises_not_skipped(self, mock_boto3_session):
        """Throttling is a required-call failure → FAIL RULE, not SKIP or LOW confidence."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_side_effect=_client_error("ThrottlingException"),
        )
        with pytest.raises(ClientError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_cloudwatch_internal_error_raises(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_side_effect=_client_error("InternalServerError"),
        )
        with pytest.raises(ClientError):
            find_idle_rds_instances(mock_boto3_session, _REGION)

    def test_cloudwatch_botocore_error_raises(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_side_effect=_botocore_error(),
        )
        with pytest.raises(BotoCoreError):
            find_idle_rds_instances(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_string_fields_extracted(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(), now)
        assert n is not None
        assert n["db_instance_id"] == "test-db"
        assert n["normalized_status"] == "available"
        assert n["engine"] == "mysql"
        assert n["engine_version"] == "8.0.35"
        assert n["db_instance_class"] == "db.t3.medium"
        assert n["storage_type"] == "gp2"

    def test_age_days_computed(self):
        now = _now()
        create_time = now - timedelta(days=20)
        n = _normalize_db_instance(_make_instance(InstanceCreateTime=create_time), now)
        assert n is not None
        assert n["age_days"] == 20

    def test_multi_az_bool_preserved(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(MultiAZ=True), now)
        assert n["multi_az"] is True

    def test_multi_az_non_bool_nulled(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(MultiAZ="yes"), now)
        assert n["multi_az"] is None

    def test_allocated_storage_int_preserved(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(AllocatedStorage=200), now)
        assert n["allocated_storage_gib"] == 200

    def test_allocated_storage_non_int_nulled(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(AllocatedStorage="200"), now)
        assert n["allocated_storage_gib"] is None

    def test_tag_list_preserved(self):
        now = _now()
        tags = [{"Key": "env", "Value": "dev"}]
        n = _normalize_db_instance(_make_instance(TagList=tags), now)
        assert n["tag_set"] == tags

    def test_tag_list_absent_defaults_to_empty_list(self):
        now = _now()
        item = _make_instance()
        del item["TagList"]
        n = _normalize_db_instance(item, now)
        assert n["tag_set"] == []

    def test_scope_fields_null_when_absent(self):
        now = _now()
        n = _normalize_db_instance(_make_instance(), now)
        assert n["db_cluster_identifier"] is None
        assert n["read_replica_source_db_instance_identifier"] is None
        assert n["read_replica_source_db_cluster_identifier"] is None

    def test_scope_fields_extracted_when_present(self):
        now = _now()
        n = _normalize_db_instance(
            _make_instance(
                DBClusterIdentifier="my-cluster",
                ReadReplicaSourceDBInstanceIdentifier="source-db",
                ReadReplicaSourceDBClusterIdentifier="source-cluster",
            ),
            now,
        )
        assert n["db_cluster_identifier"] == "my-cluster"
        assert n["read_replica_source_db_instance_identifier"] == "source-db"
        assert n["read_replica_source_db_cluster_identifier"] == "source-cluster"

    def test_empty_string_db_instance_id_returns_none(self):
        now = _now()
        result = _normalize_db_instance(_make_instance(DBInstanceIdentifier=""), now)
        assert result is None

    def test_non_dict_returns_none(self):
        now = _now()
        assert _normalize_db_instance(None, now) is None
        assert _normalize_db_instance("string", now) is None
        assert _normalize_db_instance(42, now) is None

    def test_naive_create_time_returns_none(self):
        now = _now()
        naive = _old().replace(tzinfo=None)
        result = _normalize_db_instance(_make_instance(InstanceCreateTime=naive), now)
        assert result is None

    def test_future_create_time_returns_none(self):
        now = _now()
        future = now + timedelta(days=1)
        result = _normalize_db_instance(_make_instance(InstanceCreateTime=future), now)
        assert result is None

    def test_non_datetime_create_time_returns_none(self):
        now = _now()
        result = _normalize_db_instance(
            _make_instance(InstanceCreateTime="2025-01-01T00:00:00Z"), now
        )
        assert result is None

    def test_resource_id_equals_db_instance_id(self):
        n = _normalize_db_instance(_make_instance(), _now())
        assert n["resource_id"] == n["db_instance_id"] == "test-db"


# ---------------------------------------------------------------------------
# TestCloudWatchContract
# ---------------------------------------------------------------------------


class TestCloudWatchContract:
    def test_database_connections_maximum_statistic_used(self, mock_boto3_session):
        """Spec requires DatabaseConnections with Maximum statistic — not Sum."""
        _, cw = _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        find_idle_rds_instances(mock_boto3_session, _REGION)
        call_kwargs = cw.get_metric_statistics.call_args[1]
        assert call_kwargs["MetricName"] == "DatabaseConnections"
        assert call_kwargs["Statistics"] == ["Maximum"]

    def test_correct_namespace(self, mock_boto3_session):
        _, cw = _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        find_idle_rds_instances(mock_boto3_session, _REGION)
        assert cw.get_metric_statistics.call_args[1]["Namespace"] == "AWS/RDS"

    def test_correct_dimension(self, mock_boto3_session):
        _, cw = _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        find_idle_rds_instances(mock_boto3_session, _REGION)
        dims = cw.get_metric_statistics.call_args[1]["Dimensions"]
        assert dims == [{"Name": "DBInstanceIdentifier", "Value": "test-db"}]

    def test_period_is_idle_days_times_86400(self, mock_boto3_session):
        """Period = idle_days_threshold * 86400 satisfies all CW retention constraints."""
        _, cw = _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        find_idle_rds_instances(mock_boto3_session, _REGION, idle_days_threshold=14)
        assert cw.get_metric_statistics.call_args[1]["Period"] == 14 * 86400

    def test_exactly_one_metric_queried(self, mock_boto3_session):
        """Only DatabaseConnections — no CPU or I/O metrics."""
        _, cw = _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        find_idle_rds_instances(mock_boto3_session, _REGION)
        assert cw.get_metric_statistics.call_count == 1

    def test_missing_datapoints_not_treated_as_zero(self, mock_boto3_session):
        """Empty datapoints list must not be interpreted as zero connections."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_no_datapoints_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_no_cpu_or_io_gates(self, mock_boto3_session):
        """CPU and storage I/O are not eligibility gates — zero connections alone emits."""
        call_metrics = []

        def cw_side_effect(**kwargs):
            call_metrics.append(kwargs["MetricName"])
            return _zero_connections_response()

        _setup(mock_boto3_session, [_make_instance()], cw_side_effect=cw_side_effect)
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        assert "CPUUtilization" not in call_metrics
        assert "ReadIOPS" not in call_metrics
        assert "WriteIOPS" not in call_metrics


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _get_finding(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        return findings[0]

    def test_evaluation_path(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        assert f.details["evaluation_path"] == "idle-rds-instance-review-candidate"

    def test_signals_used_not_empty(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        assert len(f.evidence.signals_used) >= 1

    def test_signals_used_mentions_available_status(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        combined = " ".join(f.evidence.signals_used)
        assert "available" in combined

    def test_signals_used_mentions_standalone(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        combined = " ".join(f.evidence.signals_used)
        assert "standalone" in combined.lower() or "read replica" in combined.lower()

    def test_signals_used_mentions_database_connections(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        combined = " ".join(f.evidence.signals_used)
        assert "DatabaseConnections" in combined

    def test_signals_not_checked_mentions_proxy_layers(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        combined = " ".join(f.evidence.signals_not_checked)
        assert any(term in combined for term in ("RDS Proxy", "PgBouncer", "connection pool"))

    def test_time_window_matches_threshold(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION, idle_days_threshold=30)
        assert "30" in findings[0].evidence.time_window

    def test_normalized_status_in_details(self, mock_boto3_session):
        f = self._get_finding(mock_boto3_session)
        assert f.details["normalized_status"] == "available"


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_always_medium_confidence(self, mock_boto3_session):
        """Spec 12: MEDIUM confidence when datapoints present and all zero."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "medium"

    def test_no_low_confidence_path(self, mock_boto3_session):
        """There is no LOW-confidence finding path — missing datapoints → SKIP ITEM."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_no_datapoints_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        # Must be empty — not a LOW-confidence finding
        assert findings == []


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_usd_is_none(self, mock_boto3_session):
        """Spec 7: no hardcoded cost estimates → estimated_monthly_cost_usd = None."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].estimated_monthly_cost_usd is None

    def test_no_cost_fields_in_details(self, mock_boto3_session):
        """No compute/storage cost fields should appear in details."""
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in d:
            assert "cost" not in key.lower(), f"Unexpected cost field: {key}"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_always_medium_risk(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# TestTitleAndReasonContract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title_exact(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].title == "Idle RDS instance review candidate"

    def test_rule_id_exact(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].rule_id == "aws.rds.instance.idle"

    def test_resource_type_exact(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            [_make_instance()],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings[0].resource_type == "aws.rds.instance"


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_all_processed(self, mock_boto3_session):
        """All pages must be exhausted — findings from both pages are emitted."""
        rds = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"DBInstances": [_make_instance(DBInstanceIdentifier="db-1")]},
            {"DBInstances": [_make_instance(DBInstanceIdentifier="db-2")]},
            {"DBInstances": [_make_instance(DBInstanceIdentifier="db-3")]},
        ]
        rds.get_paginator.return_value = paginator

        cloudwatch = MagicMock()
        cloudwatch.get_metric_statistics.return_value = _zero_connections_response()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        ids = {f.resource_id for f in findings}
        assert ids == {"db-1", "db-2", "db-3"}

    def test_mixed_instances_across_pages(self, mock_boto3_session):
        """Active and idle instances can be mixed across pages."""
        rds = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"DBInstances": [_make_instance(DBInstanceIdentifier="idle-db")]},
            {
                "DBInstances": [
                    _make_instance(
                        DBInstanceIdentifier="active-db",
                        DBInstanceStatus="stopped",
                    )
                ]
            },
        ]
        rds.get_paginator.return_value = paginator

        cloudwatch = MagicMock()
        cloudwatch.get_metric_statistics.return_value = _zero_connections_response()

        def client_side_effect(service, **kwargs):
            return rds if service == "rds" else cloudwatch

        mock_boto3_session.client.side_effect = client_side_effect
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        assert findings[0].resource_id == "idle-db"


# ---------------------------------------------------------------------------
# TestStandaloneScope
# ---------------------------------------------------------------------------


class TestStandaloneScope:
    def test_all_three_scope_fields_independently_exclude(self, mock_boto3_session):
        """Each standalone-scope exclusion field independently causes SKIP ITEM."""
        scope_cases = [
            {"DBClusterIdentifier": "cluster-a"},
            {"ReadReplicaSourceDBInstanceIdentifier": "source-instance"},
            {"ReadReplicaSourceDBClusterIdentifier": "source-cluster"},
        ]
        for overrides in scope_cases:
            _setup(
                mock_boto3_session,
                [_make_instance(**overrides)],
                cw_response=_zero_connections_response(),
            )
            findings = find_idle_rds_instances(mock_boto3_session, _REGION)
            assert findings == [], f"Expected skip for scope overrides={overrides}"

    def test_standalone_with_none_scope_fields_emits(self, mock_boto3_session):
        """Explicit None values for all scope fields → standalone → EMIT."""
        _setup(
            mock_boto3_session,
            [
                _make_instance(
                    DBClusterIdentifier=None,
                    ReadReplicaSourceDBInstanceIdentifier=None,
                    ReadReplicaSourceDBClusterIdentifier=None,
                )
            ],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_read_replica_source_cluster_identifier_field_checked(self, mock_boto3_session):
        """ReadReplicaSourceDBClusterIdentifier is the third scope field — must be checked."""
        _setup(
            mock_boto3_session,
            [_make_instance(ReadReplicaSourceDBClusterIdentifier="my-source-cluster")],
            cw_response=_zero_connections_response(),
        )
        findings = find_idle_rds_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_custom_threshold(self, mock_boto3_session):
        """idle_days_threshold parameter controls age gate correctly."""
        create_time = datetime.now(timezone.utc) - timedelta(days=20)
        _setup(
            mock_boto3_session,
            [_make_instance(InstanceCreateTime=create_time)],
            cw_response=_zero_connections_response(),
        )
        # 30-day threshold: 20 days < 30 → SKIP
        findings_30 = find_idle_rds_instances(mock_boto3_session, _REGION, idle_days_threshold=30)
        assert findings_30 == []

        # 14-day threshold: 20 days >= 14 → EMIT
        findings_14 = find_idle_rds_instances(mock_boto3_session, _REGION, idle_days_threshold=14)
        assert len(findings_14) == 1
