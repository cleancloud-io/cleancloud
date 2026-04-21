"""
Tests for aws.rds.snapshot.old rule.

Test class overview:
    TestMustEmit                 — canonical detection path
    TestMustSkip                 — all exclusion rules
    TestMustFailRule             — required API failure behaviour
    TestNormalization            — _normalize_snapshot field extraction
    TestRestoreSharingContract   — DescribeDBSnapshotAttributes interpretation
    TestAgeTimestampContract     — OriginalSnapshotCreateTime vs SnapshotCreateTime
    TestEvidenceContract         — signals_used, signals_not_checked, evaluation_path
    TestConfidenceModel          — always LOW
    TestCostModel                — estimated_monthly_cost_usd always None
    TestRiskModel                — always LOW
    TestDetailsContract          — evaluation_path and all required detail fields
    TestPagination               — multi-page exhaustion
"""

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.rds_snapshot_old import (
    _normalize_snapshot,
    find_old_rds_snapshots,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_DEFAULT_MAX_AGE = 90


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _old() -> datetime:
    """120 days ago — always older than the default 90-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=120)


def _young() -> datetime:
    """30 days ago — always younger than the default 90-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=30)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _botocore_error() -> BotoCoreError:
    return BotoCoreError()


def _make_snapshot(**overrides) -> dict:
    """Return a minimal valid DescribeDBSnapshots item for a manual snapshot."""
    base = {
        "DBSnapshotIdentifier": "snap-test",
        "SnapshotType": "manual",
        "Status": "available",
        "SnapshotCreateTime": _old(),
        "DBInstanceIdentifier": "mydb",
        "Engine": "mysql",
        "EngineVersion": "8.0.35",
        "AllocatedStorage": 100,
        "StorageType": "gp2",
        "TagList": [],
    }
    base.update(overrides)
    return base


def _setup_paginator(rds, snapshots: list) -> None:
    paginator = rds.get_paginator.return_value
    paginator.paginate.return_value = [{"DBSnapshots": snapshots}]


def _restore_response(values: list) -> dict:
    """Build a DescribeDBSnapshotAttributes response with given restore values."""
    return {
        "DBSnapshotAttributesResult": {
            "DBSnapshotIdentifier": "snap-test",
            "DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": values}],
        }
    }


def _no_restore_response() -> dict:
    """Build a DescribeDBSnapshotAttributes response with no restore attribute."""
    return {
        "DBSnapshotAttributesResult": {
            "DBSnapshotIdentifier": "snap-test",
            "DBSnapshotAttributes": [],
        }
    }


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_canonical_emit(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "snap-test"
        assert f.rule_id == "aws.rds.snapshot.old"
        assert f.provider == "aws"
        assert f.resource_type == "aws.rds.snapshot"
        assert f.region == _REGION

    def test_exactly_at_threshold_emitted(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(
            rds,
            [_make_snapshot(SnapshotCreateTime=_now() - timedelta(days=_DEFAULT_MAX_AGE))],
        )
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 1

    def test_custom_max_age_threshold_respected(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        snap = _make_snapshot(SnapshotCreateTime=_now() - timedelta(days=60))
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION, max_age_days=90) == []

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION, max_age_days=30)
        assert len(findings) == 1

    def test_no_restore_attribute_in_response_emits(self, mock_boto3_session):
        """If the restore attribute is absent entirely, snapshot has no external sharing."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _no_restore_response()

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 1

    def test_multiple_old_snapshots_all_emitted(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(
            rds,
            [
                _make_snapshot(DBSnapshotIdentifier="snap-a"),
                _make_snapshot(DBSnapshotIdentifier="snap-b"),
            ],
        )
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 2
        ids = {f.resource_id for f in findings}
        assert ids == {"snap-a", "snap-b"}

    def test_empty_account_emits_nothing(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_recent_snapshot(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(SnapshotCreateTime=_young())])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_missing_snapshot_identifier(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        snap = _make_snapshot()
        del snap["DBSnapshotIdentifier"]
        _setup_paginator(rds, [snap])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_empty_snapshot_identifier(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(DBSnapshotIdentifier="")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_missing_snapshot_type(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        snap = _make_snapshot()
        del snap["SnapshotType"]
        _setup_paginator(rds, [snap])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_non_manual_snapshot_type(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(SnapshotType="automated")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_awsbackup_snapshot_type(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(SnapshotType="awsbackup")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_missing_status(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        snap = _make_snapshot()
        del snap["Status"]
        _setup_paginator(rds, [snap])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_non_available_status_creating(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(Status="creating")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_non_available_status_copying(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(Status="copying")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_missing_both_age_timestamps(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        snap = _make_snapshot()
        del snap["SnapshotCreateTime"]
        _setup_paginator(rds, [snap])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_non_datetime_age_timestamp(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(SnapshotCreateTime="2020-01-01")])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_non_datetime_original_create_time_no_fallback(self, mock_boto3_session):
        """Present but non-datetime OriginalSnapshotCreateTime → skip item, not fall back."""
        rds = mock_boto3_session._rds
        snap = _make_snapshot(
            OriginalSnapshotCreateTime="2020-01-01",
            SnapshotCreateTime=_old(),
        )
        _setup_paginator(rds, [snap])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_naive_datetime_snapshot_create_time(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        naive_ts = datetime.now() - timedelta(days=200)  # no tzinfo
        _setup_paginator(rds, [_make_snapshot(SnapshotCreateTime=naive_ts)])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_future_snapshot_create_time(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        future_ts = _now() + timedelta(days=10)
        _setup_paginator(rds, [_make_snapshot(SnapshotCreateTime=future_ts)])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_restore_sharing_client_error(self, mock_boto3_session):
        """DescribeDBSnapshotAttributes ClientError → SKIP ITEM (not optimistically private)."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.side_effect = _client_error("AccessDenied")

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_restore_sharing_botocore_error(self, mock_boto3_session):
        """DescribeDBSnapshotAttributes BotoCoreError → SKIP ITEM."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.side_effect = _botocore_error()

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_public_snapshot_restore_all(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response(["all"])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_externally_shared_snapshot(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response(["123456789012"])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_skip_snapshot_shared_to_multiple_accounts(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response(
            ["111111111111", "222222222222"]
        )

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_db_snapshots_access_denied_raises_permission_error(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        paginator = rds.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError, match="rds:DescribeDBSnapshots"):
            find_old_rds_snapshots(mock_boto3_session, _REGION)

    def test_describe_db_snapshots_unauthorized_raises_permission_error(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        paginator = rds.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("UnauthorizedOperation")

        with pytest.raises(PermissionError, match="rds:DescribeDBSnapshots"):
            find_old_rds_snapshots(mock_boto3_session, _REGION)

    def test_describe_db_snapshots_other_client_error_propagates(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        paginator = rds.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("InternalError")

        with pytest.raises(ClientError):
            find_old_rds_snapshots(mock_boto3_session, _REGION)

    def test_describe_db_snapshots_botocore_error_propagates(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        paginator = rds.get_paginator.return_value
        paginator.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_old_rds_snapshots(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_non_dict_returns_none(self):
        assert _normalize_snapshot("not-a-dict", _now()) is None
        assert _normalize_snapshot(None, _now()) is None
        assert _normalize_snapshot([], _now()) is None

    def test_missing_identifier_returns_none(self):
        snap = _make_snapshot()
        del snap["DBSnapshotIdentifier"]
        assert _normalize_snapshot(snap, _now()) is None

    def test_empty_identifier_returns_none(self):
        assert _normalize_snapshot(_make_snapshot(DBSnapshotIdentifier=""), _now()) is None

    def test_missing_snapshot_type_returns_none(self):
        snap = _make_snapshot()
        del snap["SnapshotType"]
        assert _normalize_snapshot(snap, _now()) is None

    def test_missing_status_returns_none(self):
        snap = _make_snapshot()
        del snap["Status"]
        assert _normalize_snapshot(snap, _now()) is None

    def test_missing_both_timestamps_returns_none(self):
        snap = _make_snapshot()
        del snap["SnapshotCreateTime"]
        assert _normalize_snapshot(snap, _now()) is None

    def test_naive_snapshot_create_time_returns_none(self):
        naive = datetime.now() - timedelta(days=200)
        assert _normalize_snapshot(_make_snapshot(SnapshotCreateTime=naive), _now()) is None

    def test_future_snapshot_create_time_returns_none(self):
        future = _now() + timedelta(days=5)
        assert _normalize_snapshot(_make_snapshot(SnapshotCreateTime=future), _now()) is None

    def test_original_snapshot_create_time_naive_no_fallback(self):
        """Present but naive OriginalSnapshotCreateTime → skip item; no fallback to SnapshotCreateTime."""
        naive_original = datetime.now() - timedelta(days=200)  # naive
        snap = _make_snapshot(
            OriginalSnapshotCreateTime=naive_original,
            SnapshotCreateTime=_old(),  # valid, but should not be used
        )
        assert _normalize_snapshot(snap, _now()) is None

    def test_original_snapshot_create_time_future_no_fallback(self):
        """Present but future OriginalSnapshotCreateTime → skip item; no fallback to SnapshotCreateTime."""
        future_original = _now() + timedelta(days=10)
        snap = _make_snapshot(
            OriginalSnapshotCreateTime=future_original,
            SnapshotCreateTime=_old(),  # valid, but should not be used
        )
        assert _normalize_snapshot(snap, _now()) is None

    def test_original_snapshot_create_time_string_no_fallback(self):
        """Present but non-datetime OriginalSnapshotCreateTime → skip item; no fallback."""
        snap = _make_snapshot(
            OriginalSnapshotCreateTime="2020-01-01",
            SnapshotCreateTime=_old(),  # valid, but should not be used
        )
        assert _normalize_snapshot(snap, _now()) is None

    def test_original_snapshot_create_time_absent_uses_snapshot_create_time(self):
        """None (absent) OriginalSnapshotCreateTime → fall back to SnapshotCreateTime."""
        old_create = _now() - timedelta(days=120)
        snap = _make_snapshot(SnapshotCreateTime=old_create)
        snap.pop("OriginalSnapshotCreateTime", None)  # ensure key is absent
        n = _normalize_snapshot(snap, _now())
        assert n is not None
        assert n["age_days"] == 120

    def test_string_snapshot_create_time_returns_none(self):
        assert _normalize_snapshot(_make_snapshot(SnapshotCreateTime="2020-01-01"), _now()) is None

    def test_resource_id_and_db_snapshot_id_set(self):
        n = _normalize_snapshot(_make_snapshot(DBSnapshotIdentifier="snap-xyz"), _now())
        assert n is not None
        assert n["resource_id"] == "snap-xyz"
        assert n["db_snapshot_id"] == "snap-xyz"

    def test_snapshot_type_normalized(self):
        n = _normalize_snapshot(_make_snapshot(SnapshotType="manual"), _now())
        assert n["snapshot_type"] == "manual"

    def test_status_normalized(self):
        n = _normalize_snapshot(_make_snapshot(Status="available"), _now())
        assert n["normalized_status"] == "available"

    def test_age_days_computed_from_snapshot_create_time(self):
        create_time = _now() - timedelta(days=100)
        n = _normalize_snapshot(_make_snapshot(SnapshotCreateTime=create_time), _now())
        assert n is not None
        assert n["age_days"] == 100

    def test_optional_context_fields_null_when_absent(self):
        snap = _make_snapshot()
        for key in [
            "DBInstanceIdentifier",
            "DBSnapshotArn",
            "DbiResourceId",
            "Engine",
            "EngineVersion",
            "StorageType",
            "SnapshotTarget",
            "SourceRegion",
            "SourceDBSnapshotIdentifier",
            "KmsKeyId",
        ]:
            snap.pop(key, None)

        n = _normalize_snapshot(snap, _now())
        assert n is not None
        assert n["db_instance_id"] is None
        assert n["db_snapshot_arn"] is None
        assert n["dbi_resource_id"] is None
        assert n["engine"] is None
        assert n["engine_version"] is None
        assert n["storage_type"] is None
        assert n["snapshot_target"] is None
        assert n["source_region"] is None
        assert n["source_db_snapshot_identifier"] is None
        assert n["kms_key_id"] is None

    def test_allocated_storage_int_only(self):
        n = _normalize_snapshot(_make_snapshot(AllocatedStorage=200), _now())
        assert n["allocated_storage_gib"] == 200

        n2 = _normalize_snapshot(_make_snapshot(AllocatedStorage="200"), _now())
        assert n2["allocated_storage_gib"] is None

    def test_encrypted_bool_only(self):
        n = _normalize_snapshot(_make_snapshot(Encrypted=True), _now())
        assert n["encrypted"] is True

        n2 = _normalize_snapshot(_make_snapshot(Encrypted="true"), _now())
        assert n2["encrypted"] is None

    def test_tag_set_defaults_to_empty_list(self):
        snap = _make_snapshot()
        del snap["TagList"]
        n = _normalize_snapshot(snap, _now())
        assert n["tag_set"] == []

    def test_tag_set_non_list_defaults_to_empty_list(self):
        n = _normalize_snapshot(_make_snapshot(TagList="bad"), _now())
        assert n["tag_set"] == []

    def test_tag_set_list_preserved(self):
        tags = [{"Key": "env", "Value": "prod"}]
        n = _normalize_snapshot(_make_snapshot(TagList=tags), _now())
        assert n["tag_set"] == tags


# ---------------------------------------------------------------------------
# TestRestoreSharingContract
# ---------------------------------------------------------------------------


class TestRestoreSharingContract:
    def test_describe_db_snapshot_attributes_called_per_candidate(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(
            rds,
            [
                _make_snapshot(DBSnapshotIdentifier="snap-1"),
                _make_snapshot(DBSnapshotIdentifier="snap-2"),
            ],
        )
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert rds.describe_db_snapshot_attributes.call_count == 2
        calls = {
            call.kwargs.get("DBSnapshotIdentifier") or call.args[0]
            for call in rds.describe_db_snapshot_attributes.call_args_list
        }
        assert "snap-1" in calls
        assert "snap-2" in calls

    def test_restore_all_means_public_skip(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response(["all"])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_restore_account_id_means_external_share_skip(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response(["987654321098"])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_restore_empty_list_emits(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_client_error_on_describe_attributes_skips_item(self, mock_boto3_session):
        """ClientError from DescribeDBSnapshotAttributes → SKIP ITEM, not FAIL RULE."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.side_effect = _client_error("InsufficientPrivileges")

        result = find_old_rds_snapshots(mock_boto3_session, _REGION)
        assert result == []

    def test_botocore_error_on_describe_attributes_skips_item(self, mock_boto3_session):
        """BotoCoreError from DescribeDBSnapshotAttributes → SKIP ITEM, not FAIL RULE."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.side_effect = _botocore_error()

        result = find_old_rds_snapshots(mock_boto3_session, _REGION)
        assert result == []

    def test_non_api_exception_on_describe_attributes_propagates(self, mock_boto3_session):
        """Non-API exceptions from DescribeDBSnapshotAttributes propagate rather than silently skip."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.side_effect = RuntimeError("unexpected bug")

        with pytest.raises(RuntimeError):
            find_old_rds_snapshots(mock_boto3_session, _REGION)

    def test_describe_attributes_not_called_for_skipped_items(self, mock_boto3_session):
        """DescribeDBSnapshotAttributes must not be called for items excluded before the check."""
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(Status="creating")])

        find_old_rds_snapshots(mock_boto3_session, _REGION)

        rds.describe_db_snapshot_attributes.assert_not_called()


# ---------------------------------------------------------------------------
# TestAgeTimestampContract
# ---------------------------------------------------------------------------


class TestAgeTimestampContract:
    def test_original_snapshot_create_time_takes_precedence(self, mock_boto3_session):
        """If OriginalSnapshotCreateTime is old but SnapshotCreateTime is recent, must emit."""
        rds = mock_boto3_session._rds
        original_time = _now() - timedelta(days=200)  # old
        copy_time = _now() - timedelta(days=5)  # recent copy
        snap = _make_snapshot(
            SnapshotCreateTime=copy_time,
            OriginalSnapshotCreateTime=original_time,
        )
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 1
        assert findings[0].details["age_days"] == 200

    def test_snapshot_create_time_used_when_original_absent(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        create_time = _now() - timedelta(days=150)
        snap = _make_snapshot(SnapshotCreateTime=create_time)
        snap.pop("OriginalSnapshotCreateTime", None)
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 1
        assert findings[0].details["age_days"] == 150

    def test_recent_original_snapshot_create_time_skips(self, mock_boto3_session):
        """If OriginalSnapshotCreateTime is recent, skip even if SnapshotCreateTime is old."""
        rds = mock_boto3_session._rds
        snap = _make_snapshot(
            OriginalSnapshotCreateTime=_young(),  # recent
            SnapshotCreateTime=_old(),  # old, but not the trusted source
        )
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_naive_original_snapshot_create_time_skips_item(self, mock_boto3_session):
        """OriginalSnapshotCreateTime present but naive → skip item, no fallback."""
        rds = mock_boto3_session._rds
        naive_original = datetime.now() - timedelta(days=200)  # naive, no tzinfo
        old_create = _now() - timedelta(days=120)
        snap = _make_snapshot(
            OriginalSnapshotCreateTime=naive_original,
            SnapshotCreateTime=old_create,
        )
        _setup_paginator(rds, [snap])

        # Present but malformed original → skip item; no silent downgrade to SnapshotCreateTime
        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []

    def test_future_original_snapshot_create_time_skips_item(self, mock_boto3_session):
        """OriginalSnapshotCreateTime present but future → skip item, no fallback."""
        rds = mock_boto3_session._rds
        future_original = _now() + timedelta(days=10)
        old_create = _now() - timedelta(days=120)
        snap = _make_snapshot(
            OriginalSnapshotCreateTime=future_original,
            SnapshotCreateTime=old_create,
        )
        _setup_paginator(rds, [snap])

        # Present but future original → skip item; no silent downgrade to SnapshotCreateTime
        assert find_old_rds_snapshots(mock_boto3_session, _REGION) == []


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_signals_used_mention_manual_type(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        signals = findings[0].evidence.signals_used

        assert any("manual" in s for s in signals)

    def test_signals_used_mention_available_status(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        signals = findings[0].evidence.signals_used

        assert any("available" in s for s in signals)

    def test_signals_used_mention_age_threshold(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        signals = findings[0].evidence.signals_used

        assert any(str(_DEFAULT_MAX_AGE) in s for s in signals)

    def test_signals_used_mention_no_public_external_access(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        signals = findings[0].evidence.signals_used

        assert any("restore" in s.lower() or "public" in s.lower() for s in signals)

    def test_signals_not_checked_populated(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings[0].evidence.signals_not_checked) > 0

    def test_signals_not_checked_mention_compliance(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        not_checked = findings[0].evidence.signals_not_checked

        assert any("compliance" in s.lower() or "legal" in s.lower() for s in not_checked)

    def test_signals_not_checked_mention_disaster_recovery(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        not_checked = findings[0].evidence.signals_not_checked

        assert any("disaster" in s.lower() or "recovery" in s.lower() for s in not_checked)


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_always_low(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings[0].confidence == ConfidenceLevel.LOW

    def test_confidence_not_medium_or_high(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        c = findings[0].confidence

        assert c != ConfidenceLevel.MEDIUM
        assert c != ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(AllocatedStorage=500)])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings[0].estimated_monthly_cost_usd is None

    def test_cost_none_even_with_large_storage(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(AllocatedStorage=10000)])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_always_low(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings[0].risk == RiskLevel.LOW

    def test_risk_not_medium_or_high(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot()])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)
        r = findings[0].risk

        assert r != RiskLevel.MEDIUM
        assert r != RiskLevel.HIGH


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def _emit(self, mock_boto3_session, **snap_overrides):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [_make_snapshot(**snap_overrides)])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])
        return find_old_rds_snapshots(mock_boto3_session, _REGION)[0].details

    def test_evaluation_path(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert d["evaluation_path"] == "old-manual-rds-snapshot-review-candidate"

    def test_db_snapshot_id_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session, DBSnapshotIdentifier="snap-abc")
        assert d["db_snapshot_id"] == "snap-abc"

    def test_snapshot_type_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert d["snapshot_type"] == "manual"

    def test_normalized_status_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert d["normalized_status"] == "available"

    def test_trusted_snapshot_age_time_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert "trusted_snapshot_age_time" in d
        assert isinstance(d["trusted_snapshot_age_time"], str)

    def test_age_days_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert "age_days" in d
        assert isinstance(d["age_days"], int)
        assert d["age_days"] > 0

    def test_max_age_days_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session)
        assert d["max_age_days"] == _DEFAULT_MAX_AGE

    def test_db_instance_id_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session, DBInstanceIdentifier="prod-db")
        assert d["db_instance_id"] == "prod-db"

    def test_engine_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session, Engine="postgres")
        assert d["engine"] == "postgres"

    def test_engine_version_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session, EngineVersion="15.2")
        assert d["engine_version"] == "15.2"

    def test_allocated_storage_gib_present(self, mock_boto3_session):
        d = self._emit(mock_boto3_session, AllocatedStorage=200)
        assert d["allocated_storage_gib"] == 200

    def test_tag_set_present(self, mock_boto3_session):
        tags = [{"Key": "project", "Value": "test"}]
        d = self._emit(mock_boto3_session, TagList=tags)
        assert d["tag_set"] == tags

    def test_db_instance_id_null_when_absent(self, mock_boto3_session):
        snap = _make_snapshot()
        del snap["DBInstanceIdentifier"]
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])
        d = find_old_rds_snapshots(mock_boto3_session, _REGION)[0].details
        assert d["db_instance_id"] is None

    def test_no_hardcoded_sentinel_for_db_instance_id(self, mock_boto3_session):
        snap = _make_snapshot()
        del snap["DBInstanceIdentifier"]
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [snap])
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])
        d = find_old_rds_snapshots(mock_boto3_session, _REGION)[0].details
        assert d["db_instance_id"] != "unknown"


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multi_page_exhausted(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        pages = [
            {"DBSnapshots": [_make_snapshot(DBSnapshotIdentifier="snap-1")]},
            {"DBSnapshots": [_make_snapshot(DBSnapshotIdentifier="snap-2")]},
            {"DBSnapshots": [_make_snapshot(DBSnapshotIdentifier="snap-3")]},
        ]
        paginator = rds.get_paginator.return_value
        paginator.paginate.return_value = pages
        rds.describe_db_snapshot_attributes.return_value = _restore_response([])

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert len(findings) == 3
        ids = {f.resource_id for f in findings}
        assert ids == {"snap-1", "snap-2", "snap-3"}

    def test_paginator_called_with_manual_snapshot_type(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        _setup_paginator(rds, [])

        find_old_rds_snapshots(mock_boto3_session, _REGION)

        paginator = rds.get_paginator.return_value
        paginator.paginate.assert_called_once_with(SnapshotType="manual")

    def test_empty_pages_produce_no_findings(self, mock_boto3_session):
        rds = mock_boto3_session._rds
        pages = [{"DBSnapshots": []}, {"DBSnapshots": []}]
        paginator = rds.get_paginator.return_value
        paginator.paginate.return_value = pages

        findings = find_old_rds_snapshots(mock_boto3_session, _REGION)

        assert findings == []
