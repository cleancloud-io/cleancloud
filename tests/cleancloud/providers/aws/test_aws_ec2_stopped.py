import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ec2_stopped import find_stopped_ec2_instances

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_ACCOUNT_ID = "123456789012"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _instance(
    instance_id: str,
    state: str = "stopped",
    instance_type: str = "t3.medium",
    az: str = "us-east-1a",
    volume_ids: list | None = None,
    tags: list | None = None,
    state_transition_reason: str = "",
    state_reason_code: str | None = None,
    state_reason_message: str = "",
    hibernation_configured: bool | None = None,
    root_device_type: str | None = None,
) -> dict:
    raw: dict = {
        "InstanceId": instance_id,
        "State": {"Name": state},
        "InstanceType": instance_type,
        "Placement": {"AvailabilityZone": az},
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": vid}} for vid in (volume_ids or [])
        ],
        "Tags": tags or [],
        "StateTransitionReason": state_transition_reason,
    }
    if state_reason_code or state_reason_message:
        raw["StateReason"] = {"Code": state_reason_code or "", "Message": state_reason_message}
    if hibernation_configured is not None:
        raw["HibernationOptions"] = {"Configured": hibernation_configured}
    if root_device_type is not None:
        raw["RootDeviceType"] = root_device_type
    return raw


def _ct_event(
    instance_id: str,
    event_name: str,
    event_time: datetime,
    region: str = _REGION,
    event_id: str | None = None,
    account_id: str = _ACCOUNT_ID,
) -> dict:
    eid = event_id or f"evt-{instance_id}-{event_name}"
    ct = {
        "eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": event_name,
        "awsRegion": region,
        "recipientAccountId": account_id,
        "requestParameters": {"instancesSet": {"items": [{"instanceId": instance_id}]}},
    }
    return {"EventId": eid, "CloudTrailEvent": json.dumps(ct)}


def _setup_ec2(ec2, instances: list) -> None:
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"Reservations": [{"Instances": instances}]}]


def _setup_cloudtrail(ct, stop_events: list, start_events: list | None = None) -> None:
    """Wire cloudtrail paginator to return stop/start events per LookupAttributes."""
    start_events = start_events or []
    paginator = MagicMock()
    ct.get_paginator.return_value = paginator

    def paginate_side_effect(**kwargs):
        attrs = kwargs.get("LookupAttributes", [{}])
        name = attrs[0].get("AttributeValue") if attrs else None
        if name == "StopInstances":
            return [{"Events": stop_events}]
        if name == "StartInstances":
            return [{"Events": start_events}]
        return [{"Events": []}]

    paginator.paginate.side_effect = paginate_side_effect


def _run(
    mock_boto3_session,
    instances: list,
    stop_events: list,
    start_events: list | None = None,
    stopped_age_threshold_days: int = 30,
    cloudtrail_lookup_days: int = 90,
) -> list:
    _setup_ec2(mock_boto3_session._ec2, instances)
    _setup_cloudtrail(mock_boto3_session._cloudtrail, stop_events, start_events)
    mock_boto3_session._ec2.describe_volumes.return_value = {"Volumes": []}
    return find_stopped_ec2_instances(
        mock_boto3_session,
        _REGION,
        stopped_age_threshold_days=stopped_age_threshold_days,
        cloudtrail_lookup_days=cloudtrail_lookup_days,
    )


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_stopped_instance_meets_threshold(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-001")],
            stop_events=[_ct_event("i-001", "StopInstances", stop_time)],
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "i-001"
        assert f.rule_id == "aws.ec2.instance.stopped"
        assert f.provider == "aws"
        assert f.resource_type == "aws.ec2.instance"
        assert f.region == _REGION

    def test_exactly_at_threshold_emits(self, mock_boto3_session):
        now = _now()
        # 30 days ago → stopped_age_days == 30 → meets threshold of 30
        stop_time = now - timedelta(days=30, seconds=1)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-002")],
            stop_events=[_ct_event("i-002", "StopInstances", stop_time)],
        )
        assert len(findings) == 1

    def test_with_attached_ebs_volumes(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        mock_boto3_session._ec2.describe_volumes.return_value = {
            "Volumes": [
                {"VolumeId": "vol-aaa", "Size": 100},
                {"VolumeId": "vol-bbb", "Size": 50},
            ]
        }
        _setup_ec2(
            mock_boto3_session._ec2,
            [_instance("i-003", volume_ids=["vol-aaa", "vol-bbb"])],
        )
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-003", "StopInstances", stop_time)],
        )
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        assert findings[0].details["attached_volume_ids"] == ["vol-aaa", "vol-bbb"]
        assert findings[0].details["attached_volume_count"] == 2
        assert findings[0].details["total_ebs_gib"] == 150

    def test_multiple_instances_all_eligible(self, mock_boto3_session):
        now = _now()
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-a"), _instance("i-b")],
            stop_events=[
                _ct_event("i-a", "StopInstances", now - timedelta(days=35)),
                _ct_event("i-b", "StopInstances", now - timedelta(days=60)),
            ],
        )
        ids = {f.resource_id for f in findings}
        assert "i-a" in ids
        assert "i-b" in ids

    def test_custom_threshold_respected(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=20)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-thresh")],
            stop_events=[_ct_event("i-thresh", "StopInstances", stop_time)],
            stopped_age_threshold_days=14,
        )
        assert len(findings) == 1
        assert findings[0].details["stopped_age_threshold_days"] == 14

    def test_cloudtrail_lookup_window_days_in_details(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=35)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-win")],
            stop_events=[_ct_event("i-win", "StopInstances", stop_time)],
            cloudtrail_lookup_days=90,
        )
        assert findings[0].details["cloudtrail_lookup_window_days"] == 90


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_no_cloudtrail_stop_event(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-nostop")],
            stop_events=[],
        )
        assert findings == []

    def test_stop_event_below_threshold(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=10)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-young")],
            stop_events=[_ct_event("i-young", "StopInstances", stop_time)],
        )
        assert findings == []

    def test_non_stopped_state_skipped(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-run", state="running")],
            stop_events=[_ct_event("i-run", "StopInstances", stop_time)],
        )
        assert findings == []

    def test_missing_instance_id_skipped(self, mock_boto3_session):
        now = _now()
        raw = {"State": {"Name": "stopped"}, "InstanceType": "t3.micro"}
        _setup_ec2(mock_boto3_session._ec2, [raw])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-000", "StopInstances", now - timedelta(days=40))],
        )
        mock_boto3_session._ec2.describe_volumes.return_value = {"Volumes": []}
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_missing_state_skipped(self, mock_boto3_session):
        now = _now()
        raw = {"InstanceId": "i-nostate"}
        _setup_ec2(mock_boto3_session._ec2, [raw])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-nostate", "StopInstances", now - timedelta(days=40))],
        )
        mock_boto3_session._ec2.describe_volumes.return_value = {"Volumes": []}
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert findings == []

    def test_empty_instance_list(self, mock_boto3_session):
        findings = _run(mock_boto3_session, instances=[], stop_events=[])
        assert findings == []

    def test_stop_event_for_different_instance_not_used(self, mock_boto3_session):
        now = _now()
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-target")],
            stop_events=[_ct_event("i-other", "StopInstances", now - timedelta(days=45))],
        )
        assert findings == []

    def test_stop_event_from_wrong_region_skipped(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        # Event is in eu-west-1 but we're scanning us-east-1
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-wr")],
            stop_events=[_ct_event("i-wr", "StopInstances", stop_time, region="eu-west-1")],
        )
        assert findings == []

    def test_future_stop_event_skipped(self, mock_boto3_session):
        now = _now()
        future_time = now + timedelta(hours=1)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-future")],
            stop_events=[_ct_event("i-future", "StopInstances", future_time)],
        )
        assert findings == []

    def test_lookup_window_shorter_than_threshold_emits_nothing(self, mock_boto3_session):
        """Lookup window < threshold: emit no findings regardless of CloudTrail events."""
        now = _now()
        stop_time = now - timedelta(days=20)
        # threshold=30, lookup_days=14 — window cannot prove 30-day stopped duration
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-shortwin")],
            stop_events=[_ct_event("i-shortwin", "StopInstances", stop_time)],
            stopped_age_threshold_days=30,
            cloudtrail_lookup_days=14,
        )
        assert findings == []

    def test_lookup_window_equal_to_threshold_proceeds(self, mock_boto3_session):
        """Lookup window == threshold is sufficient — rule proceeds normally."""
        now = _now()
        stop_time = now - timedelta(days=30, seconds=1)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-equalwin")],
            stop_events=[_ct_event("i-equalwin", "StopInstances", stop_time)],
            stopped_age_threshold_days=30,
            cloudtrail_lookup_days=30,
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_instances_unauthorized(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        error = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInstances",
        )
        ec2.get_paginator.return_value.paginate.side_effect = error
        with pytest.raises(PermissionError, match="ec2:DescribeInstances"):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)

    def test_describe_instances_client_error_propagates(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        error = ClientError(
            {"Error": {"Code": "InvalidParameterValue", "Message": "bad param"}},
            "DescribeInstances",
        )
        ec2.get_paginator.return_value.paginate.side_effect = error
        with pytest.raises(ClientError):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)

    def test_describe_instances_botocore_error_propagates(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.return_value.paginate.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)

    def test_cloudtrail_unauthorized(self, mock_boto3_session):
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-001")])
        ct = mock_boto3_session._cloudtrail
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "LookupEvents",
        )
        ct.get_paginator.return_value.paginate.side_effect = error
        with pytest.raises(PermissionError, match="cloudtrail:LookupEvents"):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)

    def test_cloudtrail_client_error_propagates(self, mock_boto3_session):
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-001")])
        ct = mock_boto3_session._cloudtrail
        error = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "throttled"}},
            "LookupEvents",
        )
        ct.get_paginator.return_value.paginate.side_effect = error
        with pytest.raises(ClientError):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)

    def test_cloudtrail_botocore_error_propagates(self, mock_boto3_session):
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-001")])
        ct = mock_boto3_session._cloudtrail
        ct.get_paginator.return_value.paginate.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            find_stopped_ec2_instances(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_nested_state_name(self, mock_boto3_session):
        """State.Name is read from nested dict."""
        now = _now()
        stop_time = now - timedelta(days=40)
        raw = {"InstanceId": "i-n1", "State": {"Name": "stopped"}}
        _setup_ec2(mock_boto3_session._ec2, [raw])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-n1", "StopInstances", stop_time)],
        )
        mock_boto3_session._ec2.describe_volumes.return_value = {"Volumes": []}
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_placement_az_extracted(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-az", az="us-east-1b")],
            stop_events=[_ct_event("i-az", "StopInstances", stop_time)],
        )
        assert findings[0].details["availability_zone"] == "us-east-1b"

    def test_block_device_volume_ids_extracted(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-vols", volume_ids=["vol-x", "vol-y"])],
            stop_events=[_ct_event("i-vols", "StopInstances", stop_time)],
        )
        assert findings[0].details["attached_volume_ids"] == ["vol-x", "vol-y"]
        assert findings[0].details["attached_volume_count"] == 2

    def test_hibernation_configured_true(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-hib", hibernation_configured=True)],
            stop_events=[_ct_event("i-hib", "StopInstances", stop_time)],
        )
        assert findings[0].details["hibernation_configured"] is True

    def test_hibernation_absent_not_in_details(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-nohib")],
            stop_events=[_ct_event("i-nohib", "StopInstances", stop_time)],
        )
        assert "hibernation_configured" not in findings[0].details

    def test_state_reason_code_in_details(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[
                _instance(
                    "i-code",
                    state_reason_code="Client.UserInitiatedShutdown",
                    state_reason_message="User initiated stop",
                )
            ],
            stop_events=[_ct_event("i-code", "StopInstances", stop_time)],
        )
        assert findings[0].details["stop_reason_code"] == "Client.UserInitiatedShutdown"

    def test_state_transition_reason_diagnostic_only(self, mock_boto3_session):
        """StateTransitionReason is captured as context but never used for eligibility."""
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[
                _instance(
                    "i-str",
                    state_transition_reason="User initiated (2026-01-01 00:00:00 UTC)",
                )
            ],
            stop_events=[_ct_event("i-str", "StopInstances", stop_time)],
        )
        assert findings[0].details["stop_reason_text"] == "User initiated (2026-01-01 00:00:00 UTC)"

    def test_tags_normalized(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[
                _instance(
                    "i-tags",
                    tags=[{"Key": "env", "Value": "dev"}, {"Key": "team", "Value": "backend"}],
                )
            ],
            stop_events=[_ct_event("i-tags", "StopInstances", stop_time)],
        )
        assert findings[0].details["tags"] == {"env": "dev", "team": "backend"}

    def test_root_device_type_in_details(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-rdt", root_device_type="ebs")],
            stop_events=[_ct_event("i-rdt", "StopInstances", stop_time)],
        )
        assert findings[0].details["root_device_type"] == "ebs"

    def test_bdm_without_ebs_key_not_included(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        raw = {
            "InstanceId": "i-bdm",
            "State": {"Name": "stopped"},
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1"},  # no Ebs key
                {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeId": "vol-real"}},
            ],
        }
        _setup_ec2(mock_boto3_session._ec2, [raw])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-bdm", "StopInstances", stop_time)],
        )
        mock_boto3_session._ec2.describe_volumes.return_value = {"Volumes": []}
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert findings[0].details["attached_volume_ids"] == ["vol-real"]


# ---------------------------------------------------------------------------
# TestRestartCycle
# ---------------------------------------------------------------------------


class TestRestartCycle:
    def test_stop_then_start_then_stop_uses_latest_stop(self, mock_boto3_session):
        """stop1 → start1 → stop2: stop2 is valid, stop1 is stale."""
        now = _now()
        stop1 = now - timedelta(days=80)
        start1 = now - timedelta(days=60)
        stop2 = now - timedelta(days=40)

        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-cycle")],
            stop_events=[
                _ct_event("i-cycle", "StopInstances", stop1, event_id="evt-stop1"),
                _ct_event("i-cycle", "StopInstances", stop2, event_id="evt-stop2"),
            ],
            start_events=[
                _ct_event("i-cycle", "StartInstances", start1, event_id="evt-start1"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].details["stopped_age_days"] == int(
            (now - stop2).total_seconds() // 86400
        )

    def test_stop_then_start_no_second_stop_skips(self, mock_boto3_session):
        """stop1 → start1: no qualifying stop remains → SKIP."""
        now = _now()
        stop1 = now - timedelta(days=80)
        start1 = now - timedelta(days=20)

        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-norestart")],
            stop_events=[_ct_event("i-norestart", "StopInstances", stop1)],
            start_events=[_ct_event("i-norestart", "StartInstances", start1)],
        )
        assert findings == []

    def test_multiple_stops_no_starts_uses_latest(self, mock_boto3_session):
        """Two stop events with no starts → use the later one."""
        now = _now()
        stop1 = now - timedelta(days=60)
        stop2 = now - timedelta(days=35)

        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-twostops")],
            stop_events=[
                _ct_event("i-twostops", "StopInstances", stop1, event_id="evt-s1"),
                _ct_event("i-twostops", "StopInstances", stop2, event_id="evt-s2"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].details["stopped_age_days"] == int(
            (now - stop2).total_seconds() // 86400
        )

    def test_start_after_latest_stop_nullifies_all(self, mock_boto3_session):
        """stop1 → stop2 → start1: both stops are before the start → SKIP."""
        now = _now()
        stop1 = now - timedelta(days=80)
        stop2 = now - timedelta(days=50)
        start1 = now - timedelta(days=10)

        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-allstale")],
            stop_events=[
                _ct_event("i-allstale", "StopInstances", stop1, event_id="s1"),
                _ct_event("i-allstale", "StopInstances", stop2, event_id="s2"),
            ],
            start_events=[_ct_event("i-allstale", "StartInstances", start1)],
        )
        assert findings == []


# ---------------------------------------------------------------------------
# TestCloudTrailParsing
# ---------------------------------------------------------------------------


class TestCloudTrailParsing:
    def test_malformed_json_event_ignored(self, mock_boto3_session):
        bad_event = {"EventId": "bad-evt", "CloudTrailEvent": "not-json"}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-bad")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_missing_cloudtrail_event_key_ignored(self, mock_boto3_session):
        bad_event = {"EventId": "no-ct"}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-noct")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_missing_request_parameters_ignored(self, mock_boto3_session):
        ct = json.dumps(
            {
                "eventTime": "2026-01-01T00:00:00Z",
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
            }
        )
        bad_event = {"EventId": "no-rp", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-norp")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_missing_instances_set_ignored(self, mock_boto3_session):
        ct = json.dumps(
            {
                "eventTime": "2026-01-01T00:00:00Z",
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {},
            }
        )
        bad_event = {"EventId": "no-is", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-nois")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_event_id_deduplication(self, mock_boto3_session):
        """Duplicate eventId across pages must be deduplicated."""
        now = _now()
        stop_time = now - timedelta(days=40)
        evt = _ct_event("i-dup", "StopInstances", stop_time, event_id="evt-dedup")
        # Same eventId twice
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-dup")],
            stop_events=[evt, evt],
        )
        # Still emits one finding; no crash from duplicate
        assert len(findings) == 1

    def test_missing_event_id_skipped(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        ct = json.dumps(
            {
                "eventTime": stop_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-noid"}]}},
            }
        )
        bad_event = {"CloudTrailEvent": ct}  # no EventId
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-noid")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_multi_instance_stop_event_expanded(self, mock_boto3_session):
        """A single StopInstances event covering multiple instances is expanded correctly."""
        now = _now()
        stop_time = now - timedelta(days=40)
        ct = json.dumps(
            {
                "eventTime": stop_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {
                    "instancesSet": {"items": [{"instanceId": "i-m1"}, {"instanceId": "i-m2"}]}
                },
            }
        )
        multi_event = {"EventId": "evt-multi", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-m1"), _instance("i-m2")],
            stop_events=[multi_event],
        )
        assert {f.resource_id for f in findings} == {"i-m1", "i-m2"}

    def test_no_timezone_event_time_ignored(self, mock_boto3_session):
        """Event with timezone-less eventTime must be ignored."""
        ct = json.dumps(
            {
                "eventTime": "2026-01-01T00:00:00",  # no tz
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-notz"}]}},
            }
        )
        bad_event = {"EventId": "evt-notz", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-notz")],
            stop_events=[bad_event],
        )
        assert findings == []


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_finding_always_high_confidence(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-conf")],
            stop_events=[_ct_event("i-conf", "StopInstances", stop_time)],
        )
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_no_medium_confidence_emitted(self, mock_boto3_session):
        """No finding should ever have MEDIUM confidence."""
        now = _now()
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-med")],
            stop_events=[_ct_event("i-med", "StopInstances", now - timedelta(days=45))],
        )
        for f in findings:
            assert f.confidence != ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_medium(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-risk")],
            stop_events=[_ct_event("i-risk", "StopInstances", stop_time)],
        )
        assert findings[0].risk == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self, mock_boto3_session):
        """No flat EBS cost estimate — estimated_monthly_cost_usd must be None."""
        now = _now()
        mock_boto3_session._ec2.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-big", "Size": 1000}]
        }
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-cost", volume_ids=["vol-big"])])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-cost", "StopInstances", now - timedelta(days=40))],
        )
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_all_required_fields_present(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-ev", volume_ids=["vol-1"])],
            stop_events=[_ct_event("i-ev", "StopInstances", stop_time)],
        )
        d = findings[0].details
        required = [
            "evaluation_path",
            "instance_id",
            "normalized_state",
            "trusted_stop_timestamp_source",
            "trusted_stop_event_time_source",
            "trusted_stop_time",
            "trusted_stop_event_name",
            "trusted_stop_event_id",
            "trusted_stop_event_account_id",
            "stopped_age_days",
            "stopped_age_threshold_days",
            "instance_type",
            "availability_zone",
            "attached_volume_ids",
            "attached_volume_count",
        ]
        for field in required:
            assert field in d, f"Missing required field: {field}"

    def test_evaluation_path_exact_value(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-path")],
            stop_events=[_ct_event("i-path", "StopInstances", stop_time)],
        )
        assert findings[0].details["evaluation_path"] == "stopped-instance-review-candidate"

    def test_normalized_state_always_stopped(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-state")],
            stop_events=[_ct_event("i-state", "StopInstances", stop_time)],
        )
        assert findings[0].details["normalized_state"] == "stopped"

    def test_trusted_stop_source_cloudtrail(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-src")],
            stop_events=[_ct_event("i-src", "StopInstances", stop_time)],
        )
        assert findings[0].details["trusted_stop_timestamp_source"] == "cloudtrail"
        assert findings[0].details["trusted_stop_event_time_source"] == "cloudtrail_lookup"

    def test_trusted_stop_event_name_always_stop_instances(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-evn")],
            stop_events=[_ct_event("i-evn", "StopInstances", stop_time)],
        )
        assert findings[0].details["trusted_stop_event_name"] == "StopInstances"

    def test_trusted_stop_event_id_matches(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-eid")],
            stop_events=[
                _ct_event("i-eid", "StopInstances", stop_time, event_id="my-event-id-123")
            ],
        )
        assert findings[0].details["trusted_stop_event_id"] == "my-event-id-123"

    def test_trusted_stop_event_account_id_present(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-acct")],
            stop_events=[_ct_event("i-acct", "StopInstances", stop_time)],
        )
        assert findings[0].details["trusted_stop_event_account_id"] == _ACCOUNT_ID

    def test_stopped_age_days_correct(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=45)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-age")],
            stop_events=[_ct_event("i-age", "StopInstances", stop_time)],
        )
        expected = int((now - stop_time).total_seconds() // 86400)
        assert findings[0].details["stopped_age_days"] == expected

    def test_signals_not_checked_include_blind_spots(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-blind")],
            stop_events=[_ct_event("i-blind", "StopInstances", stop_time)],
        )
        snc = " ".join(findings[0].evidence.signals_not_checked).lower()
        assert "reactivation" in snc or "warm-standby" in snc
        assert "dr" in snc or "migration" in snc
        assert "elastic ip" in snc or "eip" in snc

    def test_empty_tags_not_in_details(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-notags")],
            stop_events=[_ct_event("i-notags", "StopInstances", stop_time)],
        )
        assert "tags" not in findings[0].details


# ---------------------------------------------------------------------------
# TestTitleAndReasonContract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-title")],
            stop_events=[_ct_event("i-title", "StopInstances", stop_time)],
        )
        assert findings[0].title == "Stopped EC2 instance review candidate"

    def test_reason_contains_stopped_age_and_threshold(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-reason")],
            stop_events=[_ct_event("i-reason", "StopInstances", stop_time)],
        )
        reason = findings[0].reason
        assert "stopped" in reason.lower()
        assert "cloudtrail" in reason.lower()
        assert "30" in reason  # threshold

    def test_summary_contains_instance_id(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-sum")],
            stop_events=[_ct_event("i-sum", "StopInstances", stop_time)],
        )
        assert "i-sum" in findings[0].summary

    def test_title_does_not_say_safe_to_terminate(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-safe")],
            stop_events=[_ct_event("i-safe", "StopInstances", stop_time)],
        )
        combined = (findings[0].title + findings[0].summary + findings[0].reason).lower()
        assert "safe to terminate" not in combined
        assert "safe to delete" not in combined


# ---------------------------------------------------------------------------
# TestEBSEnrichment
# ---------------------------------------------------------------------------


class TestEBSEnrichment:
    def test_describe_volumes_failure_does_not_fail_rule(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        mock_boto3_session._ec2.describe_volumes.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeVolumes"
        )
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-novol", volume_ids=["vol-x"])])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-novol", "StopInstances", stop_time)],
        )
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        # No total_ebs_gib since enrichment failed but volumes exist
        # (sizes default to 0 sum → total_ebs_gib == 0)

    def test_no_volumes_total_ebs_gib_absent(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-novols")],
            stop_events=[_ct_event("i-novols", "StopInstances", stop_time)],
        )
        assert "total_ebs_gib" not in findings[0].details

    def test_volumes_enriched_with_sizes(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        mock_boto3_session._ec2.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-e", "Size": 200}]
        }
        _setup_ec2(mock_boto3_session._ec2, [_instance("i-enrich", volume_ids=["vol-e"])])
        _setup_cloudtrail(
            mock_boto3_session._cloudtrail,
            [_ct_event("i-enrich", "StopInstances", stop_time)],
        )
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert findings[0].details["total_ebs_gib"] == 200


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_ec2_pages(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        ct = mock_boto3_session._cloudtrail
        ec2 = mock_boto3_session._ec2

        # Two pages of reservations
        ec2.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [_instance("i-p1")]}]},
            {"Reservations": [{"Instances": [_instance("i-p2")]}]},
        ]
        _setup_cloudtrail(
            ct,
            [
                _ct_event("i-p1", "StopInstances", stop_time, event_id="ep1"),
                _ct_event("i-p2", "StopInstances", stop_time, event_id="ep2"),
            ],
        )
        ec2.describe_volumes.return_value = {"Volumes": []}
        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert {f.resource_id for f in findings} == {"i-p1", "i-p2"}

    def test_multiple_cloudtrail_pages(self, mock_boto3_session):
        now = _now()
        stop_time = now - timedelta(days=40)
        ec2 = mock_boto3_session._ec2
        ct = mock_boto3_session._cloudtrail

        _setup_ec2(ec2, [_instance("i-ctp")])
        ec2.describe_volumes.return_value = {"Volumes": []}

        # Two pages for StopInstances, first empty, second has the event
        paginator = MagicMock()
        ct.get_paginator.return_value = paginator

        def paginate_side_effect(**kwargs):
            attrs = kwargs.get("LookupAttributes", [{}])
            name = attrs[0].get("AttributeValue") if attrs else None
            if name == "StopInstances":
                return [
                    {"Events": []},
                    {"Events": [_ct_event("i-ctp", "StopInstances", stop_time)]},
                ]
            return [{"Events": []}]

        paginator.paginate.side_effect = paginate_side_effect

        findings = find_stopped_ec2_instances(mock_boto3_session, _REGION)
        assert len(findings) == 1
        assert findings[0].resource_id == "i-ctp"


# ---------------------------------------------------------------------------
# TestEventNameValidation (Fix 1)
# ---------------------------------------------------------------------------


class TestEventNameValidation:
    def test_mismatched_event_name_in_payload_ignored(self, mock_boto3_session):
        """CloudTrailEvent JSON with eventName != lookup filter must be ignored."""
        now = _now()
        stop_time = now - timedelta(days=40)
        # Build a StopInstances-shaped event but inject wrong eventName in the JSON
        ct = json.dumps(
            {
                "eventTime": stop_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "RunInstances",  # mismatched — not StopInstances
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-mismatch"}]}},
            }
        )
        bad_event = {"EventId": "evt-mismatch", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-mismatch")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_missing_event_name_in_payload_ignored(self, mock_boto3_session):
        """CloudTrailEvent JSON without eventName key must be ignored."""
        now = _now()
        stop_time = now - timedelta(days=40)
        ct = json.dumps(
            {
                "eventTime": stop_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                # eventName absent
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-noname"}]}},
            }
        )
        bad_event = {"EventId": "evt-noname", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-noname")],
            stop_events=[bad_event],
        )
        assert findings == []

    def test_correct_event_name_accepted(self, mock_boto3_session):
        """CloudTrailEvent with eventName == 'StopInstances' is accepted."""
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-goodname")],
            stop_events=[_ct_event("i-goodname", "StopInstances", stop_time)],
        )
        assert len(findings) == 1

    def test_start_instances_event_name_accepted_as_start(self, mock_boto3_session):
        """StartInstances event with correct eventName is used for restart-cycle resolution."""
        now = _now()
        stop1 = now - timedelta(days=80)
        start1 = now - timedelta(days=10)  # recent start → stop1 is stale

        # Build StartInstances event with correct eventName
        ct = json.dumps(
            {
                "eventTime": start1.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "StartInstances",
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-startname"}]}},
            }
        )
        start_event = {"EventId": "evt-start", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-startname")],
            stop_events=[_ct_event("i-startname", "StopInstances", stop1)],
            start_events=[start_event],
        )
        # stop1 < start1 → stale → no qualifying stop → no finding
        assert findings == []

    def test_start_instances_event_with_wrong_name_not_used_for_restart(self, mock_boto3_session):
        """StartInstances event payload with wrong eventName is ignored → stale stop survives."""
        now = _now()
        stop1 = now - timedelta(days=80)
        start1 = now - timedelta(days=10)

        # Build a 'start event' that has wrong eventName in the payload
        ct = json.dumps(
            {
                "eventTime": start1.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "TerminateInstances",  # wrong name
                "awsRegion": _REGION,
                "recipientAccountId": _ACCOUNT_ID,
                "requestParameters": {
                    "instancesSet": {"items": [{"instanceId": "i-badstartname"}]}
                },
            }
        )
        bad_start_event = {"EventId": "evt-badstart", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-badstartname")],
            stop_events=[_ct_event("i-badstartname", "StopInstances", stop1)],
            start_events=[bad_start_event],
        )
        # Bad start event is ignored → stop1 remains qualifying → finding emitted
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestAccountEnforcement (Fix 2)
# ---------------------------------------------------------------------------


class TestAccountEnforcement:
    def test_matching_account_accepted(self, mock_boto3_session):
        """Event with recipientAccountId matching scanned account is accepted."""
        now = _now()
        stop_time = now - timedelta(days=40)
        # _ACCOUNT_ID matches the conftest STS mock ("123456789012")
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-match")],
            stop_events=[_ct_event("i-match", "StopInstances", stop_time, account_id=_ACCOUNT_ID)],
        )
        assert len(findings) == 1

    def test_mismatched_account_rejected(self, mock_boto3_session):
        """Event with recipientAccountId not matching scanned account must be rejected."""
        now = _now()
        stop_time = now - timedelta(days=40)
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-xacct")],
            stop_events=[
                _ct_event("i-xacct", "StopInstances", stop_time, account_id="999999999999")
            ],
        )
        assert findings == []

    def test_absent_recipient_account_id_accepted(self, mock_boto3_session):
        """Event without recipientAccountId in JSON is not rejected by account check."""
        now = _now()
        stop_time = now - timedelta(days=40)
        ct = json.dumps(
            {
                "eventTime": stop_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "StopInstances",
                "awsRegion": _REGION,
                # recipientAccountId absent
                "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-noacct"}]}},
            }
        )
        event = {"EventId": "evt-noacct", "CloudTrailEvent": ct}
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-noacct")],
            stop_events=[event],
        )
        assert len(findings) == 1

    def test_sts_failure_proceeds_without_account_enforcement(self, mock_boto3_session):
        """When STS is unavailable, scanned_account_id is None — account check is skipped."""
        now = _now()
        stop_time = now - timedelta(days=40)
        mock_boto3_session._sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetCallerIdentity"
        )
        # Event from a different account — normally would be rejected, but STS
        # failure means we can't enforce → event is accepted
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-stsdown")],
            stop_events=[
                _ct_event("i-stsdown", "StopInstances", stop_time, account_id="999999999999")
            ],
        )
        assert len(findings) == 1

    def test_sts_botocore_error_proceeds_without_enforcement(self, mock_boto3_session):
        """BotoCoreError from STS also degrades gracefully."""
        now = _now()
        stop_time = now - timedelta(days=40)
        mock_boto3_session._sts.get_caller_identity.side_effect = BotoCoreError()
        findings = _run(
            mock_boto3_session,
            instances=[_instance("i-bce")],
            stop_events=[_ct_event("i-bce", "StopInstances", stop_time, account_id="999999999999")],
        )
        assert len(findings) == 1
