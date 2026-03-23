from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.rds_snapshot_old import find_old_rds_snapshots


def _make_snapshot(
    snapshot_id: str,
    age_days: int,
    size_gb: int = 100,
    db_instance_id: str = "mydb",
    engine: str = "mysql",
    status: str = "available",
    tags: list = None,
) -> dict:
    create_time = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {
        "DBSnapshotIdentifier": snapshot_id,
        "DBInstanceIdentifier": db_instance_id,
        "SnapshotCreateTime": create_time,
        "AllocatedStorage": size_gb,
        "Engine": engine,
        "Status": status,
        "TagList": tags or [],
    }


def _setup_paginator(rds, snapshots: list) -> None:
    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [{"DBSnapshots": snapshots}]


class TestFindOldRdsSnapshots:
    def test_old_snapshot_flagged(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-old", age_days=100)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "snap-old"
        assert f.rule_id == "aws.rds.snapshot.old"
        assert f.provider == "aws"
        assert f.resource_type == "aws.rds.snapshot"
        assert f.risk == RiskLevel.LOW
        assert f.confidence == ConfidenceLevel.HIGH

    def test_recent_snapshot_not_flagged(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-recent", age_days=30)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_exactly_at_threshold_flagged(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-exact", age_days=90)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert len(findings) == 1

    def test_custom_threshold(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-60d", age_days=60)])

        assert find_old_rds_snapshots(mock_boto3_session, "us-east-1", days_old=90) == []
        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1", days_old=30)
        assert len(findings) == 1

    def test_cost_estimate(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-cost", age_days=100, size_gb=200)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        # 200 GB * $0.095/GB-month = $19.00
        assert findings[0].estimated_monthly_cost_usd == 19.0

    def test_zero_size_no_cost(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-nosize", age_days=100, size_gb=0)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert findings[0].estimated_monthly_cost_usd is None

    def test_non_available_snapshot_skipped(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-creating", age_days=100, status="creating")])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_details_populated(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(
            rds,
            [
                _make_snapshot(
                    "snap-detail",
                    age_days=120,
                    size_gb=50,
                    db_instance_id="prod-db",
                    engine="postgres",
                )
            ],
        )

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        d = findings[0].details
        assert d["db_instance_id"] == "prod-db"
        assert d["engine"] == "postgres"
        assert d["size_gb"] == 50
        assert d["age_days"] == 120
        assert d["age_threshold_days"] == 90

    def test_tags_in_details(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        tags = [{"Key": "env", "Value": "prod"}]
        _setup_paginator(rds, [_make_snapshot("snap-tagged", age_days=100, tags=tags)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert findings[0].details["tags"] == {"env": "prod"}

    def test_no_tags_not_in_details(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-notags", age_days=100)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert "tags" not in findings[0].details

    def test_empty_account(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_multiple_snapshots_only_old_flagged(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(
            rds,
            [
                _make_snapshot("snap-old-1", age_days=100),
                _make_snapshot("snap-old-2", age_days=200),
                _make_snapshot("snap-recent", age_days=10),
            ],
        )

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}
        assert "snap-old-1" in ids
        assert "snap-old-2" in ids
        assert "snap-recent" not in ids

    def test_permission_error_raised(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "DescribeDBSnapshots",
        )
        paginator = rds.get_paginator.return_value
        paginator.paginate.side_effect = error

        with pytest.raises(PermissionError, match="rds:DescribeDBSnapshots"):
            find_old_rds_snapshots(mock_boto3_session, "us-east-1")

    def test_evidence_signals_populated(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot("snap-ev", age_days=100, size_gb=50)])

        findings = find_old_rds_snapshots(mock_boto3_session, "us-east-1")
        signals = findings[0].evidence.signals_used
        assert any("100 days" in s for s in signals)
        assert any("$0.095/GB-month" in s for s in signals)
        assert findings[0].evidence.signals_not_checked
