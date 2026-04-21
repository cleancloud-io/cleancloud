"""
Tests for aws.resource.untagged rule.

Test class overview:
    TestMustEmit                — canonical detection path for each family
    TestMustSkip                — all exclusion rules per family
    TestMustFailRule            — required inventory API failure behaviour
    TestNormalizationEbs        — _normalize_ebs_volume field extraction
    TestNormalizationS3         — _normalize_s3_bucket field extraction
    TestNormalizationLogGroup   — _normalize_log_group field extraction
    TestS3TagContract           — GetBucketTagging semantics
    TestLogGroupTagContract     — ListTagsForResource semantics
    TestConfidenceModel         — always HIGH
    TestRiskModel               — always MEDIUM
    TestCostModel               — estimated_monthly_cost_usd always None
    TestDetailsContract         — evaluation_path and all required detail fields
    TestEvidenceContract        — signals_used, signals_not_checked, tag_source_api
    TestPagination              — multi-page exhaustion for each family
"""

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.untagged_resources import (
    _normalize_ebs_volume,
    _normalize_log_group,
    _normalize_s3_bucket,
    find_untagged_resources,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _old() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=30)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _botocore_error() -> BotoCoreError:
    return BotoCoreError()


# ---------------------------------------------------------------------------
# Per-family item builders
# ---------------------------------------------------------------------------


def _make_volume(**overrides) -> dict:
    base = {
        "VolumeId": "vol-test",
        "Tags": [],
        "AvailabilityZone": "us-east-1a",
        "Size": 100,
        "VolumeType": "gp3",
        "State": "in-use",
        "Encrypted": True,
        "CreateTime": _old(),
    }
    base.update(overrides)
    return base


def _make_bucket(**overrides) -> dict:
    base = {
        "Name": "test-bucket",
        "BucketRegion": "us-east-1",
        "CreationDate": _old(),
    }
    base.update(overrides)
    return base


def _make_log_group(**overrides) -> dict:
    base = {
        "logGroupName": "/aws/lambda/test",
        "logGroupArn": "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/test",
        "logGroupClass": "STANDARD",
        "creationTime": int((_old()).timestamp() * 1000),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Mock setup helpers
# ---------------------------------------------------------------------------


def _setup_ebs(session, volumes: list) -> None:
    ec2 = session._ec2
    ec2.get_paginator.return_value.paginate.return_value = [{"Volumes": volumes}]


def _setup_s3_empty(session) -> None:
    s3 = session._s3
    s3.get_paginator.return_value.paginate.return_value = [{"Buckets": []}]


def _setup_logs_empty(session) -> None:
    logs = session._logs
    logs.get_paginator.return_value.paginate.return_value = [{"logGroups": []}]


def _setup_ebs_empty(session) -> None:
    ec2 = session._ec2
    ec2.get_paginator.return_value.paginate.return_value = [{"Volumes": []}]


def _setup_s3(session, buckets: list, tag_count: int = 0) -> None:
    s3 = session._s3
    s3.get_paginator.return_value.paginate.return_value = [{"Buckets": buckets}]
    if tag_count == 0:
        # Default: NoSuchTagSet → untagged
        s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
    else:
        s3.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(tag_count)]
        }


def _setup_logs(session, log_groups: list, tag_count: int = 0) -> None:
    logs = session._logs
    logs.get_paginator.return_value.paginate.return_value = [{"logGroups": log_groups}]
    logs.list_tags_for_resource.return_value = {
        "tags": {f"k{i}": f"v{i}" for i in range(tag_count)}
    }


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_ebs_volume_no_tags_emits(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume(Tags=[])])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        ebs_findings = [f for f in findings if f.resource_type == "aws.ebs.volume"]
        assert len(ebs_findings) == 1
        assert ebs_findings[0].resource_id == "vol-test"
        assert ebs_findings[0].rule_id == "aws.resource.untagged"

    def test_ebs_volume_tags_absent_from_dict_emits(self, mock_boto3_session):
        """EBS volume with Tags key absent (not returned) → untagged."""
        vol = _make_volume()
        del vol["Tags"]
        _setup_ebs(mock_boto3_session, [vol])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        assert any(f.resource_type == "aws.ebs.volume" for f in findings)

    def test_ebs_volume_tags_none_emits(self, mock_boto3_session):
        """EBS volume with Tags=None → non-list treated as empty → untagged."""
        _setup_ebs(mock_boto3_session, [_make_volume(Tags=None)])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        assert any(f.resource_type == "aws.ebs.volume" for f in findings)

    def test_s3_bucket_no_such_tag_set_emits(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=0)
        _setup_logs_empty(mock_boto3_session)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        s3_findings = [f for f in findings if f.resource_type == "aws.s3.bucket"]
        assert len(s3_findings) == 1
        assert s3_findings[0].resource_id == "test-bucket"

    def test_s3_bucket_empty_tag_set_emits(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.return_value = {"TagSet": []}
        _setup_logs_empty(mock_boto3_session)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        assert any(f.resource_type == "aws.s3.bucket" for f in findings)

    def test_log_group_empty_tags_map_emits(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        lg_findings = [f for f in findings if f.resource_type == "aws.cloudwatch.log_group"]
        assert len(lg_findings) == 1
        assert lg_findings[0].resource_id == "/aws/lambda/test"

    def test_all_three_families_emit(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=0)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        findings = find_untagged_resources(mock_boto3_session, _REGION)

        families = {f.resource_type for f in findings}
        assert "aws.ebs.volume" in families
        assert "aws.s3.bucket" in families
        assert "aws.cloudwatch.log_group" in families

    def test_empty_account_emits_nothing(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        assert find_untagged_resources(mock_boto3_session, _REGION) == []


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_ebs_volume_with_tags_skipped(self, mock_boto3_session):
        _setup_ebs(
            mock_boto3_session,
            [_make_volume(Tags=[{"Key": "env", "Value": "prod"}])],
        )
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert findings == []

    def test_ebs_volume_missing_volume_id_skipped(self, mock_boto3_session):
        vol = _make_volume()
        del vol["VolumeId"]
        _setup_ebs(mock_boto3_session, [vol])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert findings == []

    def test_ebs_volume_empty_volume_id_skipped(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume(VolumeId="")])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert findings == []

    def test_s3_bucket_with_tags_skipped(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=1)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_s3_bucket_missing_name_skipped(self, mock_boto3_session):
        bucket = _make_bucket()
        del bucket["Name"]
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [bucket]}]
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_s3_bucket_get_tagging_non_nosuchtagset_error_skipped(self, mock_boto3_session):
        """GetBucketTagging failure other than NoSuchTagSet → SKIP ITEM."""
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.side_effect = _client_error("AccessDenied")
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_s3_bucket_get_tagging_botocore_error_skipped(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.side_effect = _botocore_error()
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_log_group_with_tags_skipped(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=1)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []

    def test_log_group_missing_name_skipped(self, mock_boto3_session):
        lg = _make_log_group()
        del lg["logGroupName"]
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [lg]}]

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []

    def test_log_group_missing_arn_skipped(self, mock_boto3_session):
        """Log group without an ARN cannot have ListTagsForResource called → SKIP ITEM."""
        lg = _make_log_group()
        del lg["logGroupArn"]
        lg.pop("arn", None)
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [lg]}]
        logs.list_tags_for_resource.return_value = {"tags": {}}

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []

    def test_log_group_list_tags_failure_skipped(self, mock_boto3_session):
        """ListTagsForResource failure → SKIP ITEM."""
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [_make_log_group()]}]
        logs.list_tags_for_resource.side_effect = _client_error("AccessDenied")

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []

    def test_log_group_list_tags_botocore_failure_skipped(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [_make_log_group()]}]
        logs.list_tags_for_resource.side_effect = _botocore_error()

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_volumes_access_denied_raises_permission_error(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError, match="ec2:DescribeVolumes"):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_describe_volumes_botocore_error_propagates(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.return_value.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_describe_volumes_other_client_error_propagates(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("InternalError")

        with pytest.raises(ClientError):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_list_buckets_access_denied_raises_permission_error(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError, match="s3:ListAllMyBuckets"):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_list_buckets_botocore_error_propagates(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_describe_log_groups_access_denied_raises_permission_error(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError, match="logs:DescribeLogGroups"):
            find_untagged_resources(mock_boto3_session, _REGION)

    def test_describe_log_groups_botocore_error_propagates(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_untagged_resources(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalizationEbs
# ---------------------------------------------------------------------------


class TestNormalizationEbs:
    def test_non_dict_returns_none(self):
        assert _normalize_ebs_volume("bad", _now()) is None
        assert _normalize_ebs_volume(None, _now()) is None

    def test_missing_volume_id_returns_none(self):
        vol = _make_volume()
        del vol["VolumeId"]
        assert _normalize_ebs_volume(vol, _now()) is None

    def test_empty_volume_id_returns_none(self):
        assert _normalize_ebs_volume(_make_volume(VolumeId=""), _now()) is None

    def test_resource_id_set(self):
        n = _normalize_ebs_volume(_make_volume(VolumeId="vol-abc"), _now())
        assert n["resource_id"] == "vol-abc"

    def test_empty_tags_list_tag_count_zero(self):
        n = _normalize_ebs_volume(_make_volume(Tags=[]), _now())
        assert n["current_tag_count"] == 0

    def test_tags_present_tag_count_nonzero(self):
        n = _normalize_ebs_volume(_make_volume(Tags=[{"Key": "env", "Value": "prod"}]), _now())
        assert n["current_tag_count"] == 1

    def test_tags_none_treated_as_empty(self):
        n = _normalize_ebs_volume(_make_volume(Tags=None), _now())
        assert n["current_tag_count"] == 0

    def test_tags_absent_treated_as_empty(self):
        vol = _make_volume()
        del vol["Tags"]
        n = _normalize_ebs_volume(vol, _now())
        assert n["current_tag_count"] == 0

    def test_tags_non_list_string_treated_as_empty(self):
        n = _normalize_ebs_volume(_make_volume(Tags="invalid"), _now())
        assert n["current_tag_count"] == 0

    def test_age_days_computed_from_create_time(self):
        ct = _now() - timedelta(days=45)
        n = _normalize_ebs_volume(_make_volume(CreateTime=ct), _now())
        assert n["age_days"] == 45

    def test_naive_create_time_age_null(self):
        naive = datetime.now() - timedelta(days=10)
        n = _normalize_ebs_volume(_make_volume(CreateTime=naive), _now())
        assert n["create_time_utc"] is None
        assert n["age_days"] is None

    def test_missing_create_time_age_null(self):
        vol = _make_volume()
        del vol["CreateTime"]
        n = _normalize_ebs_volume(vol, _now())
        assert n["age_days"] is None

    def test_resource_arn_always_none(self):
        n = _normalize_ebs_volume(_make_volume(), _now())
        assert n["resource_arn"] is None


# ---------------------------------------------------------------------------
# TestNormalizationS3
# ---------------------------------------------------------------------------


class TestNormalizationS3:
    def test_non_dict_returns_none(self):
        assert _normalize_s3_bucket("bad", _now()) is None

    def test_missing_name_returns_none(self):
        bucket = _make_bucket()
        del bucket["Name"]
        assert _normalize_s3_bucket(bucket, _now()) is None

    def test_empty_name_returns_none(self):
        assert _normalize_s3_bucket(_make_bucket(Name=""), _now()) is None

    def test_resource_id_set(self):
        n = _normalize_s3_bucket(_make_bucket(Name="my-bucket"), _now())
        assert n["resource_id"] == "my-bucket"

    def test_native_region_from_bucket_region(self):
        n = _normalize_s3_bucket(_make_bucket(BucketRegion="eu-west-1"), _now())
        assert n["native_region"] == "eu-west-1"

    def test_native_region_null_when_absent(self):
        bucket = _make_bucket()
        del bucket["BucketRegion"]
        n = _normalize_s3_bucket(bucket, _now())
        assert n["native_region"] is None

    def test_resource_arn_from_bucket_arn(self):
        n = _normalize_s3_bucket(_make_bucket(BucketArn="arn:aws:s3:::my-bucket"), _now())
        assert n["resource_arn"] == "arn:aws:s3:::my-bucket"

    def test_resource_arn_null_when_absent(self):
        bucket = _make_bucket()
        bucket.pop("BucketArn", None)
        n = _normalize_s3_bucket(bucket, _now())
        assert n["resource_arn"] is None

    def test_age_days_computed_from_creation_date(self):
        ct = _now() - timedelta(days=60)
        n = _normalize_s3_bucket(_make_bucket(CreationDate=ct), _now())
        assert n["age_days"] == 60

    def test_naive_creation_date_age_null(self):
        naive = datetime.now() - timedelta(days=10)
        n = _normalize_s3_bucket(_make_bucket(CreationDate=naive), _now())
        assert n["age_days"] is None


# ---------------------------------------------------------------------------
# TestNormalizationLogGroup
# ---------------------------------------------------------------------------


class TestNormalizationLogGroup:
    def test_non_dict_returns_none(self):
        assert _normalize_log_group("bad", _now()) is None

    def test_missing_name_returns_none(self):
        lg = _make_log_group()
        del lg["logGroupName"]
        assert _normalize_log_group(lg, _now()) is None

    def test_empty_name_returns_none(self):
        assert _normalize_log_group(_make_log_group(logGroupName=""), _now()) is None

    def test_resource_id_set(self):
        n = _normalize_log_group(_make_log_group(logGroupName="/my/group"), _now())
        assert n["resource_id"] == "/my/group"

    def test_resource_arn_from_log_group_arn(self):
        n = _normalize_log_group(
            _make_log_group(logGroupArn="arn:aws:logs:us-east-1:123:log-group:/x"), _now()
        )
        assert n["resource_arn"] == "arn:aws:logs:us-east-1:123:log-group:/x"

    def test_resource_arn_falls_back_to_arn_field(self):
        lg = _make_log_group()
        del lg["logGroupArn"]
        lg["arn"] = "arn:aws:logs:us-east-1:123:log-group:/x"
        n = _normalize_log_group(lg, _now())
        assert n["resource_arn"] == "arn:aws:logs:us-east-1:123:log-group:/x"

    def test_resource_arn_null_when_both_absent(self):
        lg = _make_log_group()
        del lg["logGroupArn"]
        lg.pop("arn", None)
        n = _normalize_log_group(lg, _now())
        assert n["resource_arn"] is None

    def test_age_computed_from_creation_time_millis(self):
        ct = _now() - timedelta(days=10)
        n = _normalize_log_group(_make_log_group(creationTime=int(ct.timestamp() * 1000)), _now())
        assert n["age_days"] == 10

    def test_missing_creation_time_age_null(self):
        lg = _make_log_group()
        del lg["creationTime"]
        n = _normalize_log_group(lg, _now())
        assert n["age_days"] is None

    def test_tags_not_sourced_from_log_group_item(self):
        """DescribeLogGroups items do not carry tags; tags key is ignored in normalization."""
        lg = _make_log_group()
        lg["tags"] = {"env": "prod"}  # simulate erroneous tags in inventory item
        n = _normalize_log_group(lg, _now())
        assert "current_tag_count" not in n  # tags not normalized from inventory item


# ---------------------------------------------------------------------------
# TestS3TagContract
# ---------------------------------------------------------------------------


class TestS3TagContract:
    def test_no_such_tag_set_means_untagged(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert len(findings) == 1

    def test_empty_tag_set_means_untagged(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.return_value = {"TagSet": []}
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert len(findings) == 1

    def test_non_nosuchtagset_error_skips_bucket(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.side_effect = _client_error("InternalError")
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_tag_with_empty_value_still_counts_as_tagged(self, mock_boto3_session):
        """A tag entry with an empty value is still a tag — resource is tagged."""
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "owner", "Value": ""}]}
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []

    def test_non_list_tag_set_skips_bucket(self, mock_boto3_session):
        """Malformed TagSet (non-list) → tag visibility unavailable → SKIP ITEM."""
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [_make_bucket()]}]
        s3.get_bucket_tagging.return_value = {"TagSet": "not-a-list"}
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings == []


# ---------------------------------------------------------------------------
# TestLogGroupTagContract
# ---------------------------------------------------------------------------


class TestLogGroupTagContract:
    def test_list_tags_for_resource_called_with_arn(self, mock_boto3_session):
        """ListTagsForResource must be called with the log group ARN."""
        arn = "arn:aws:logs:us-east-1:123:log-group:/test"
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [
            {"logGroups": [_make_log_group(logGroupArn=arn)]}
        ]
        logs.list_tags_for_resource.return_value = {"tags": {}}

        find_untagged_resources(mock_boto3_session, _REGION)

        logs.list_tags_for_resource.assert_called_once_with(resourceArn=arn)

    def test_tags_from_describe_log_groups_not_used(self, mock_boto3_session):
        """DescribeLogGroups tags field must NOT be the tag source."""
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        lg = _make_log_group()
        # Inject tags directly into the inventory item — must be ignored
        lg["tags"] = {"env": "prod", "owner": "team"}
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [lg]}]
        # ListTagsForResource says no tags
        logs.list_tags_for_resource.return_value = {"tags": {}}

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]

        # Despite inventory tags, ListTagsForResource says untagged → must emit
        assert len(findings) == 1

    def test_empty_tags_map_means_untagged(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert len(findings) == 1

    def test_non_dict_tags_payload_skips_log_group(self, mock_boto3_session):
        """Malformed tags response (non-dict) → tag visibility unavailable → SKIP ITEM."""
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [{"logGroups": [_make_log_group()]}]
        logs.list_tags_for_resource.return_value = {"tags": ["not", "a", "dict"]}

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings == []


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_ebs_confidence_high(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_s3_confidence_high(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=0)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_log_group_confidence_high(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert findings[0].confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_all_families_risk_medium(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=0)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        for f in find_untagged_resources(mock_boto3_session, _REGION):
            assert f.risk == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_all_families_cost_none(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3(mock_boto3_session, [_make_bucket()], tag_count=0)
        _setup_logs(mock_boto3_session, [_make_log_group()], tag_count=0)

        for f in find_untagged_resources(mock_boto3_session, _REGION):
            assert f.estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def _ebs_details(self, mock_boto3_session) -> dict:
        _setup_ebs(mock_boto3_session, [_make_volume(VolumeId="vol-d")])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)
        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        return findings[0].details

    def _s3_details(self, mock_boto3_session) -> dict:
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3(mock_boto3_session, [_make_bucket(Name="d-bucket")], tag_count=0)
        _setup_logs_empty(mock_boto3_session)
        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        return findings[0].details

    def _lg_details(self, mock_boto3_session) -> dict:
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        _setup_logs(mock_boto3_session, [_make_log_group(logGroupName="/d/group")], tag_count=0)
        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        return findings[0].details

    def test_ebs_evaluation_path(self, mock_boto3_session):
        assert (
            self._ebs_details(mock_boto3_session)["evaluation_path"]
            == "untagged-supported-resource"
        )

    def test_ebs_resource_family(self, mock_boto3_session):
        assert self._ebs_details(mock_boto3_session)["resource_family"] == "ebs_volume"

    def test_ebs_resource_id(self, mock_boto3_session):
        assert self._ebs_details(mock_boto3_session)["resource_id"] == "vol-d"

    def test_ebs_current_tag_count_zero(self, mock_boto3_session):
        assert self._ebs_details(mock_boto3_session)["current_tag_count"] == 0

    def test_ebs_tag_source_api(self, mock_boto3_session):
        assert self._ebs_details(mock_boto3_session)["tag_source_api"] == "ec2:DescribeVolumes"

    def test_s3_evaluation_path(self, mock_boto3_session):
        assert (
            self._s3_details(mock_boto3_session)["evaluation_path"] == "untagged-supported-resource"
        )

    def test_s3_resource_family(self, mock_boto3_session):
        assert self._s3_details(mock_boto3_session)["resource_family"] == "s3_bucket"

    def test_s3_resource_id(self, mock_boto3_session):
        assert self._s3_details(mock_boto3_session)["resource_id"] == "d-bucket"

    def test_s3_tag_source_api(self, mock_boto3_session):
        assert self._s3_details(mock_boto3_session)["tag_source_api"] == "s3:GetBucketTagging"

    def test_lg_evaluation_path(self, mock_boto3_session):
        assert (
            self._lg_details(mock_boto3_session)["evaluation_path"] == "untagged-supported-resource"
        )

    def test_lg_resource_family(self, mock_boto3_session):
        assert self._lg_details(mock_boto3_session)["resource_family"] == "cloudwatch_log_group"

    def test_lg_resource_id(self, mock_boto3_session):
        assert self._lg_details(mock_boto3_session)["resource_id"] == "/d/group"

    def test_lg_tag_source_api(self, mock_boto3_session):
        assert self._lg_details(mock_boto3_session)["tag_source_api"] == "logs:ListTagsForResource"


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_signals_used_mention_tag_source(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        signals = findings[0].evidence.signals_used

        assert any("ec2:DescribeVolumes" in s or "tag" in s.lower() for s in signals)

    def test_signals_not_checked_populated(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert len(findings[0].evidence.signals_not_checked) > 0

    def test_signals_not_checked_mention_tag_policy(self, mock_boto3_session):
        _setup_ebs(mock_boto3_session, [_make_volume()])
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        not_checked = findings[0].evidence.signals_not_checked
        assert any("policy" in s.lower() or "tag" in s.lower() for s in not_checked)


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_ebs_multi_page_exhausted(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.return_value.paginate.return_value = [
            {"Volumes": [_make_volume(VolumeId="vol-1")]},
            {"Volumes": [_make_volume(VolumeId="vol-2")]},
            {"Volumes": [_make_volume(VolumeId="vol-3")]},
        ]
        _setup_s3_empty(mock_boto3_session)
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.ebs.volume"
        ]
        assert len(findings) == 3

    def test_s3_multi_page_exhausted(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [
            {"Buckets": [_make_bucket(Name="b-1")]},
            {"Buckets": [_make_bucket(Name="b-2")]},
        ]
        s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
        _setup_logs_empty(mock_boto3_session)

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.s3.bucket"
        ]
        assert len(findings) == 2

    def test_log_group_multi_page_exhausted(self, mock_boto3_session):
        _setup_ebs_empty(mock_boto3_session)
        _setup_s3_empty(mock_boto3_session)
        logs = mock_boto3_session._logs
        logs.get_paginator.return_value.paginate.return_value = [
            {"logGroups": [_make_log_group(logGroupName="/a")]},
            {"logGroups": [_make_log_group(logGroupName="/b")]},
        ]
        logs.list_tags_for_resource.return_value = {"tags": {}}

        findings = [
            f
            for f in find_untagged_resources(mock_boto3_session, _REGION)
            if f.resource_type == "aws.cloudwatch.log_group"
        ]
        assert len(findings) == 2

    def test_s3_paginator_used_not_list_buckets_directly(self, mock_boto3_session):
        """S3 list_buckets must use paginator, not direct list_buckets() call."""
        _setup_ebs_empty(mock_boto3_session)
        s3 = mock_boto3_session._s3
        s3.get_paginator.return_value.paginate.return_value = [{"Buckets": []}]
        _setup_logs_empty(mock_boto3_session)

        find_untagged_resources(mock_boto3_session, _REGION)

        s3.get_paginator.assert_called_once_with("list_buckets")
        s3.list_buckets.assert_not_called()
