from datetime import datetime, timedelta, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ec2_stopped import (
    _parse_stop_time,
    find_stopped_ec2_instances,
)


def _stopped_reason(dt: datetime) -> str:
    """Format a datetime into the AWS StateTransitionReason format."""
    return f"User initiated ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC)"


def _make_instance(
    instance_id: str,
    stop_time: datetime | None,
    instance_type: str = "t3.medium",
    volume_ids: list | None = None,
    tags: list | None = None,
) -> dict:
    reason = _stopped_reason(stop_time) if stop_time is not None else "Server.InternalError"
    return {
        "InstanceId": instance_id,
        "InstanceType": instance_type,
        "StateTransitionReason": reason,
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": vid}} for vid in (volume_ids or [])
        ],
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "Tags": tags or [],
    }


def _setup_paginator(ec2, instances: list) -> None:
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"Reservations": [{"Instances": instances}]}]


def _setup_volumes(ec2, volumes: dict) -> None:
    """volumes: {volume_id: size_gb}"""
    ec2.describe_volumes.return_value = {
        "Volumes": [{"VolumeId": vid, "Size": size} for vid, size in volumes.items()]
    }


class TestFindStoppedEC2Instances:
    def test_stopped_long_enough_is_flagged(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=45)

        _setup_paginator(ec2, [_make_instance("i-old", stop_time, volume_ids=["vol-1"])])
        _setup_volumes(ec2, {"vol-1": 100})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "i-old"
        assert f.rule_id == "aws.ec2.instance.stopped"
        assert f.provider == "aws"
        assert f.resource_type == "aws.ec2.instance"
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.risk == RiskLevel.MEDIUM

    def test_stopped_recently_not_flagged(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=10)

        _setup_paginator(ec2, [_make_instance("i-recent", stop_time)])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_unparseable_nonempty_reason_flagged_at_medium_confidence(self, mock_boto3_session):
        """Instances with non-empty but unparseable stop reason are flagged at MEDIUM confidence."""
        ec2 = mock_boto3_session._ec2
        # _make_instance with stop_time=None uses "Server.InternalError" as reason
        _setup_paginator(ec2, [_make_instance("i-unknown", stop_time=None)])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "i-unknown"
        assert f.confidence == ConfidenceLevel.MEDIUM
        assert "days_stopped" not in f.details
        assert "stop_time" not in f.details
        assert any("stop duration unknown" in s.lower() for s in f.evidence.signals_used)
        assert any("may be recent or long-lived" in s for s in f.evidence.signals_used)

    def test_empty_reason_skipped(self, mock_boto3_session):
        """Instances with an empty StateTransitionReason are skipped — likely very recent stop."""
        ec2 = mock_boto3_session._ec2
        instance = _make_instance("i-brand-new", stop_time=None)
        instance["StateTransitionReason"] = ""  # empty = AWS hasn't populated it yet
        _setup_paginator(ec2, [instance])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_ebs_cost_estimate(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)

        _setup_paginator(
            ec2,
            [_make_instance("i-cost", stop_time, volume_ids=["vol-a", "vol-b"])],
        )
        _setup_volumes(ec2, {"vol-a": 100, "vol-b": 50})  # 150 GB total

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        # 150 GB × $0.10/GB-month = $15.00
        assert f.estimated_monthly_cost_usd == 15.0
        assert f.details["total_ebs_gb"] == 150
        assert f.details["attached_volume_ids"] == ["vol-a", "vol-b"]

    def test_no_ebs_volumes_cost_is_none(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)

        _setup_paginator(ec2, [_make_instance("i-novolume", stop_time, volume_ids=[])])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None
        assert findings[0].details["total_ebs_gb"] == 0

    def test_days_stopped_in_details(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=60)

        _setup_paginator(ec2, [_make_instance("i-detail", stop_time)])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].details["days_stopped"] == 60
        assert findings[0].details["days_stopped_threshold"] == 30

    def test_tags_included_in_details(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)
        tags = [{"Key": "env", "Value": "dev"}, {"Key": "team", "Value": "backend"}]

        _setup_paginator(ec2, [_make_instance("i-tagged", stop_time, tags=tags)])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].details["tags"] == {"env": "dev", "team": "backend"}

    def test_multiple_instances_only_old_flagged(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)

        instances = [
            _make_instance("i-old-1", now - timedelta(days=45)),
            _make_instance("i-old-2", now - timedelta(days=90)),
            _make_instance("i-recent", now - timedelta(days=5)),
            _make_instance("i-unparseable", stop_time=None),
        ]
        _setup_paginator(ec2, instances)
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}

        assert "i-old-1" in ids
        assert "i-old-2" in ids
        assert "i-recent" not in ids
        assert "i-unparseable" in ids  # flagged at MEDIUM — stop duration unknown

    def test_custom_threshold(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=20)

        _setup_paginator(ec2, [_make_instance("i-20d", stop_time)])
        _setup_volumes(ec2, {})

        # With default 30-day threshold: not flagged
        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1", max_age_days=30)
        assert findings == []

        # With 14-day threshold: flagged
        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1", max_age_days=14)
        assert len(findings) == 1
        assert findings[0].resource_id == "i-20d"

    def test_empty_account(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_paginator(ec2, [])
        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_permission_error_raised(self, mock_boto3_session):
        from botocore.exceptions import ClientError

        ec2 = mock_boto3_session._ec2
        error = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
            "DescribeInstances",
        )
        paginator = ec2.get_paginator.return_value
        paginator.paginate.side_effect = error

        import pytest

        with pytest.raises(PermissionError, match="ec2:DescribeInstances"):
            find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

    def test_summary_mentions_ebs_charges(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)

        _setup_paginator(ec2, [_make_instance("i-summary", stop_time, volume_ids=["vol-x"])])
        _setup_volumes(ec2, {"vol-x": 50})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")
        assert "EBS" in findings[0].summary or "storage" in findings[0].summary.lower()

    def test_ebs_pricing_transparency_signal(self, mock_boto3_session):
        """When cost is estimated, a pricing transparency signal should be present."""
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)

        _setup_paginator(ec2, [_make_instance("i-cost-sig", stop_time, volume_ids=["vol-z"])])
        _setup_volumes(ec2, {"vol-z": 100})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        signals = findings[0].evidence.signals_used
        assert any("$0.10/GB-month" in s for s in signals)

    def test_instance_initiated_stop_reason_parsed(self, mock_boto3_session):
        """Instances stopped via OS-level shutdown (Instance initiated) should be flagged."""
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)
        reason = f"Instance initiated ({stop_time.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
        instance = _make_instance("i-os-stop", stop_time)
        instance["StateTransitionReason"] = reason

        _setup_paginator(ec2, [instance])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_scheduled_stop_reason_parsed(self, mock_boto3_session):
        """Instances stopped by AWS scheduled maintenance should be flagged."""
        ec2 = mock_boto3_session._ec2
        now = datetime.now(timezone.utc)
        stop_time = now - timedelta(days=40)
        reason = f"Server.ScheduledStop ({stop_time.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
        instance = _make_instance("i-scheduled", stop_time)
        instance["StateTransitionReason"] = reason

        _setup_paginator(ec2, [instance])
        _setup_volumes(ec2, {})

        findings = find_stopped_ec2_instances(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.HIGH


class TestParseStopTime:
    def test_user_initiated(self):
        reason = "User initiated (2026-01-15 10:30:00 UTC)"
        result = _parse_stop_time(reason)
        assert result is not None
        assert result.year == 2026
        assert result.month == 1
        assert result.day == 15
        assert result.tzinfo == timezone.utc

    def test_instance_initiated(self):
        reason = "Instance initiated (2026-02-20 14:00:00 UTC)"
        result = _parse_stop_time(reason)
        assert result is not None
        assert result.year == 2026
        assert result.month == 2

    def test_server_scheduled_stop(self):
        reason = "Server.ScheduledStop (2026-03-01 08:00:00 UTC)"
        result = _parse_stop_time(reason)
        assert result is not None
        assert result.month == 3

    def test_empty_string(self):
        assert _parse_stop_time("") is None

    def test_server_internal_error(self):
        assert _parse_stop_time("Server.InternalError") is None

    def test_spot_interruption(self):
        assert _parse_stop_time("Server.SpotInstanceShutdown") is None

    def test_malformed_date(self):
        assert _parse_stop_time("User initiated (not-a-date UTC)") is None
