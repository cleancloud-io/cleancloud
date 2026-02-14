from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cleancloud.providers.aws.rules.rds_idle import find_idle_rds_instances


def test_find_idle_rds_instances(mock_boto3_session):
    region = "us-east-1"
    rds = mock_boto3_session._rds

    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=30)
    recent_date = now - timedelta(days=5)

    # Mock paginator for describe_db_instances
    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                # Idle instance (30 days old, no connections) - should be flagged
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
                # Active instance (has connections) - should NOT be flagged
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
                # Young instance (5 days old) - should NOT be flagged
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
                # Read replica - should NOT be flagged
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
                # Aurora cluster member - should NOT be flagged
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
                # Tagged with 'keep' - should NOT be flagged
                {
                    "DBInstanceIdentifier": "keep-db",
                    "DBInstanceStatus": "available",
                    "InstanceCreateTime": old_date,
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.35",
                    "MultiAZ": False,
                    "AllocatedStorage": 100,
                    "ReadReplicaSourceDBInstanceIdentifier": None,
                    "DBClusterIdentifier": None,
                    "TagList": [{"Key": "Keep", "Value": "true"}],
                },
            ]
        }
    ]

    # Mock CloudWatch client
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )

    # Mock CloudWatch metrics
    def mock_get_metric_statistics(**kwargs):
        db_id = kwargs["Dimensions"][0]["Value"]
        if db_id == "idle-db":
            return {"Datapoints": []}
        elif db_id == "active-db":
            return {"Datapoints": [{"Sum": 500}]}
        else:
            return {"Datapoints": []}

    cloudwatch_mock.get_metric_statistics.side_effect = mock_get_metric_statistics

    findings = find_idle_rds_instances(mock_boto3_session, region)
    db_ids = {f.resource_id for f in findings}

    # Should flag idle instance
    assert "idle-db" in db_ids

    # Should NOT flag active instance (has connections)
    assert "active-db" not in db_ids

    # Should NOT flag young instance
    assert "young-db" not in db_ids

    # Should NOT flag read replica
    assert "replica-db" not in db_ids

    # Should NOT flag Aurora cluster member
    assert "aurora-db" not in db_ids

    # Should NOT flag keep-tagged instance
    assert "keep-db" not in db_ids

    # Verify finding details
    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "aws"
    assert finding.rule_id == "aws.rds.instance.idle"
    assert finding.resource_type == "aws.rds.instance"
    assert finding.confidence.value == "high"
    assert finding.risk.value == "high"
    assert finding.details["engine"] == "mysql 8.0.35"
    assert finding.details["instance_class"] == "db.t3.medium"
    assert finding.details["connections_14d"] == 0
    assert finding.details["allocated_storage_gb"] == 100
    assert "~$49/month" in finding.details["estimated_monthly_cost"]
    assert finding.details["tags"] == {"env": "dev"}
    assert "cluster_id" not in finding.details


def test_find_idle_rds_instances_empty(mock_boto3_session):
    region = "us-east-1"
    rds = mock_boto3_session._rds

    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [{"DBInstances": []}]

    # Mock CloudWatch client (needed even for empty results)
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
    # Instance is 20 days old
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

    # Mock CloudWatch - no connections
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {"Datapoints": []}

    # With 30-day threshold, should NOT be flagged (only 20 days old)
    findings_30 = find_idle_rds_instances(mock_boto3_session, region, days_idle=30)
    assert len(findings_30) == 0

    # With 14-day threshold, should be flagged (20 > 14)
    findings_14 = find_idle_rds_instances(mock_boto3_session, region, days_idle=14)
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

    # Mock CloudWatch - has connections
    cloudwatch_mock = MagicMock()
    mock_boto3_session.client.side_effect = lambda service, **kwargs: (
        rds if service == "rds" else cloudwatch_mock
    )
    cloudwatch_mock.get_metric_statistics.return_value = {
        "Datapoints": [
            {"Sum": 150},
            {"Sum": 200},
        ]
    }

    findings = find_idle_rds_instances(mock_boto3_session, region)
    assert findings == []
