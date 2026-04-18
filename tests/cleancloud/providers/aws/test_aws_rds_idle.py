from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cleancloud.providers.aws.rules.rds_idle import find_idle_rds_instances


def _make_rds_paginator(mock_boto3_session, instances):
    rds = mock_boto3_session._rds
    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [{"DBInstances": instances}]
    return rds


def _make_cw_side_effect(responses_by_db_and_metric):
    """Build a side_effect that routes by (db_id, metric_name)."""

    def side_effect(**kwargs):
        db_id = kwargs["Dimensions"][0]["Value"]
        metric = kwargs["MetricName"]
        return responses_by_db_and_metric.get(
            (db_id, metric),
            responses_by_db_and_metric.get(db_id, {"Datapoints": []}),
        )

    return side_effect


def test_find_idle_rds_instances(mock_boto3_session):
    region = "us-east-1"
    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)
    recent_date = now - timedelta(days=5)

    rds = _make_rds_paginator(
        mock_boto3_session,
        [
            # Idle instance (30 days old, no connections) — should be flagged
            {
                "DBInstanceIdentifier": "idle-db",
                "DBInstanceStatus": "available",
                "InstanceCreateTime": old_date,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "mysql",
                "EngineVersion": "8.0.35",
                "MultiAZ": False,
                "AllocatedStorage": 100,
                "ReadReplicaSourceDBInstanceIdentifier": None,
                "DBClusterIdentifier": None,
                "TagList": [{"Key": "env", "Value": "dev"}],
            },
            # Active instance (has connections) — should NOT be flagged
            {
                "DBInstanceIdentifier": "active-db",
                "DBInstanceStatus": "available",
                "InstanceCreateTime": old_date,
                "DBInstanceClass": "db.r5.large",
                "Engine": "postgres",
                "EngineVersion": "15.4",
                "MultiAZ": True,
                "AllocatedStorage": 200,
                "ReadReplicaSourceDBInstanceIdentifier": None,
                "DBClusterIdentifier": None,
                "TagList": [],
            },
            # Young instance (5 days old) — should NOT be flagged
            {
                "DBInstanceIdentifier": "young-db",
                "DBInstanceStatus": "available",
                "InstanceCreateTime": recent_date,
                "DBInstanceClass": "db.t3.micro",
                "Engine": "mysql",
                "EngineVersion": "8.0.35",
                "MultiAZ": False,
                "AllocatedStorage": 20,
                "ReadReplicaSourceDBInstanceIdentifier": None,
                "DBClusterIdentifier": None,
                "TagList": [],
            },
            # Read replica — should NOT be flagged
            {
                "DBInstanceIdentifier": "replica-db",
                "DBInstanceStatus": "available",
                "InstanceCreateTime": old_date,
                "DBInstanceClass": "db.t3.medium",
                "Engine": "mysql",
                "EngineVersion": "8.0.35",
                "MultiAZ": False,
                "AllocatedStorage": 100,
                "ReadReplicaSourceDBInstanceIdentifier": "source-db",
                "DBClusterIdentifier": None,
                "TagList": [],
            },
            # Aurora cluster member — should NOT be flagged
            {
                "DBInstanceIdentifier": "aurora-db",
                "DBInstanceStatus": "available",
                "InstanceCreateTime": old_date,
                "DBInstanceClass": "db.r5.large",
                "Engine": "aurora-mysql",
                "EngineVersion": "8.0.mysql_aurora.3.04.0",
                "MultiAZ": False,
                "AllocatedStorage": 0,
                "ReadReplicaSourceDBInstanceIdentifier": None,
                "DBClusterIdentifier": "my-aurora-cluster",
                "TagList": [],
            },
        ],
    )

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.side_effect = _make_cw_side_effect(
        {
            # idle-db: zero connections + low CPU + zero IO — all three signals agree
            ("idle-db", "DatabaseConnections"): {"Datapoints": [{"Sum": 0}]},
            ("idle-db", "CPUUtilization"): {"Datapoints": [{"Maximum": 2.0}]},
            ("idle-db", "ReadIOPS"): {"Datapoints": [{"Sum": 0}]},
            ("idle-db", "WriteIOPS"): {"Datapoints": [{"Sum": 0}]},
            # active-db: has connections
            ("active-db", "DatabaseConnections"): {"Datapoints": [{"Sum": 500}]},
        }
    )

    findings = find_idle_rds_instances(mock_boto3_session, region)
    db_ids = {f.resource_id for f in findings}

    assert "idle-db" in db_ids
    assert "active-db" not in db_ids
    assert "young-db" not in db_ids
    assert "replica-db" not in db_ids
    assert "aurora-db" not in db_ids

    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "aws"
    assert finding.rule_id == "aws.rds.instance.idle"
    assert finding.resource_type == "aws.rds.instance"
    assert finding.confidence.value == "medium"  # three-signal: connections + CPU + IO
    assert finding.risk.value == "high"
    assert finding.details["engine"] == "mysql 8.0.35"
    assert finding.details["instance_class"] == "db.t3.medium"
    assert finding.details["connections_14d"] == 0
    assert finding.details["allocated_storage_gb"] == 100
    assert "~$49/month" in finding.details["estimated_compute_cost"]
    assert finding.estimated_monthly_cost_usd is not None
    assert finding.estimated_monthly_cost_usd > 0
    assert finding.details["tags"] == {"env": "dev"}
    assert "cluster_id" not in finding.details
    assert "peak_cpu_pct" in finding.details


def test_find_idle_rds_instances_empty(mock_boto3_session):
    region = "us-east-1"
    rds = mock_boto3_session._rds

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [{"DBInstances": []}]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )

    findings = find_idle_rds_instances(mock_boto3_session, region)
    assert findings == []


def test_find_idle_rds_instances_custom_threshold(mock_boto3_session):
    region = "us-east-1"
    rds = mock_boto3_session._rds
    now = datetime.now(timezone.utc)
    creation_date = now - timedelta(days=20)

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-db",
                    "DBInstanceStatus": "available",
                    "InstanceCreateTime": creation_date,
                    "DBInstanceClass": "db.t3.small",
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                    "MultiAZ": False,
                    "AllocatedStorage": 50,
                    "ReadReplicaSourceDBInstanceIdentifier": None,
                    "DBClusterIdentifier": None,
                    "TagList": [],
                },
            ]
        }
    ]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.side_effect = _make_cw_side_effect(
        {
            ("test-db", "DatabaseConnections"): {"Datapoints": [{"Sum": 0}]},
            ("test-db", "CPUUtilization"): {"Datapoints": [{"Maximum": 1.0}]},
        }
    )

    # With 30-day threshold, should NOT be flagged (only 20 days old)
    findings_30 = find_idle_rds_instances(mock_boto3_session, region, idle_days=30)
    assert len(findings_30) == 0

    # With 14-day threshold, should be flagged (20 > 14)
    findings_14 = find_idle_rds_instances(mock_boto3_session, region, idle_days=14)
    assert len(findings_14) == 1
    assert findings_14[0].resource_id == "test-db"


def test_find_idle_rds_instances_with_connections(mock_boto3_session):
    """RDS instance with connections should not be flagged."""
    region = "us-east-1"
    rds = mock_boto3_session._rds
    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "active-db",
                    "DBInstanceStatus": "available",
                    "InstanceCreateTime": old_date,
                    "DBInstanceClass": "db.r5.large",
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                    "MultiAZ": True,
                    "AllocatedStorage": 200,
                    "ReadReplicaSourceDBInstanceIdentifier": None,
                    "DBClusterIdentifier": None,
                    "TagList": [],
                },
            ]
        }
    ]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {
        "Datapoints": [{"Sum": 150}, {"Sum": 200}]
    }

    findings = find_idle_rds_instances(mock_boto3_session, region)
    assert findings == []


def test_find_idle_rds_no_datapoints_skipped(mock_boto3_session):
    """Instance where CW returns zero datapoints should be skipped (no metric visibility)."""
    region = "us-east-1"
    rds = mock_boto3_session._rds
    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "no-data-db",
                    "DBInstanceStatus": "available",
                    "InstanceCreateTime": old_date,
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.35",
                    "MultiAZ": False,
                    "AllocatedStorage": 100,
                    "ReadReplicaSourceDBInstanceIdentifier": None,
                    "DBClusterIdentifier": None,
                    "TagList": [],
                },
            ]
        }
    ]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    # No datapoints at all — metric has no visibility
    cloudwatch_mock.get_metric_statistics.return_value = {"Datapoints": []}

    findings = find_idle_rds_instances(mock_boto3_session, region)
    # Zero datapoints → LOW-confidence "requires verification" finding (not silently skipped)
    assert len(findings) == 1
    assert findings[0].confidence.value == "low"
    assert findings[0].risk.value == "medium"
    assert "Requires" in findings[0].title or "Verification" in findings[0].title
    assert findings[0].details.get("connections_datapoints") == 0


def test_find_idle_rds_low_confidence_without_cpu(mock_boto3_session):
    """Instance with zero connections but no CPU data should be LOW confidence."""
    region = "us-east-1"
    rds = mock_boto3_session._rds
    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "idle-no-cpu",
                    "DBInstanceStatus": "available",
                    "InstanceCreateTime": old_date,
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.35",
                    "MultiAZ": False,
                    "AllocatedStorage": 100,
                    "ReadReplicaSourceDBInstanceIdentifier": None,
                    "DBClusterIdentifier": None,
                    "TagList": [],
                },
            ]
        }
    ]

    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.side_effect = _make_cw_side_effect(
        {
            # Connections: zero (has datapoints)
            ("idle-no-cpu", "DatabaseConnections"): {"Datapoints": [{"Sum": 0}]},
            # CPU: no data available
            ("idle-no-cpu", "CPUUtilization"): {"Datapoints": []},
        }
    )

    findings = find_idle_rds_instances(mock_boto3_session, region)
    assert len(findings) == 1
    assert findings[0].confidence.value == "low"
