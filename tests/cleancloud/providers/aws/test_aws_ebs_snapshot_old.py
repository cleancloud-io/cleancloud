"""
Tests for aws.ebs.snapshot.old rule.

Every test references its governing spec section in
docs/specs/aws/ebs_snapshot_old.md
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)
_MAX_AGE = 90  # default threshold


def _snap(
    snap_id,
    age_days,
    state="completed",
    storage_tier=None,
    volume_size=10,
    volume_id="vol-12345",
    tags=None,
    full_snapshot_size_bytes=None,
):
    """Build a minimal snapshot dict."""
    d = {
        "SnapshotId": snap_id,
        "StartTime": _NOW - timedelta(days=age_days),
        "State": state,
        "VolumeSize": volume_size,
        "VolumeId": volume_id,
        "Tags": tags or [],
    }
    if storage_tier is not None:
        d["StorageTier"] = storage_tier
    if full_snapshot_size_bytes is not None:
        d["FullSnapshotSizeInBytes"] = full_snapshot_size_bytes
    return d


def _run(
    mock_boto3_session,
    snapshots,
    ami_images=None,
    ami_index_raises=False,
    sharing_perms=None,
    sharing_raises=False,
    max_age_days=_MAX_AGE,
):
    """Wire up all mocks and run find_old_ebs_snapshots."""
    ec2 = mock_boto3_session._ec2

    snap_paginator = MagicMock()
    snap_paginator.paginate.return_value = [{"Snapshots": snapshots}]

    ami_paginator = MagicMock()
    if ami_index_raises:
        ami_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeImages"
        )
    else:
        ami_paginator.paginate.return_value = [{"Images": ami_images or []}]

    def _get_paginator(name):
        if name == "describe_snapshots":
            return snap_paginator
        if name == "describe_images":
            return ami_paginator
        raise ValueError(f"Unexpected paginator: {name}")

    ec2.get_paginator.side_effect = _get_paginator

    if sharing_raises:
        ec2.describe_snapshot_attribute.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeSnapshotAttribute",
        )
    else:
        ec2.describe_snapshot_attribute.return_value = {
            "CreateVolumePermissions": sharing_perms if sharing_perms is not None else []
        }

    return find_old_ebs_snapshots(mock_boto3_session, "us-east-1", max_age_days=max_age_days)


def _ami_with_snap(snap_id):
    """Build a minimal AMI dict referencing the given snapshot ID."""
    return {
        "ImageId": "ami-12345",
        "BlockDeviceMappings": [{"Ebs": {"SnapshotId": snap_id}}],
    }


# ---------------------------------------------------------------------------
# §15 Must emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    """Spec §15 — must emit."""

    def test_old_completed_standard_no_blockers(self, mock_boto3_session):
        """Completed, standard, old, no AMI link, not shared, not backup → emit (§15 scenario 1)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "snap-old"

    def test_older_snapshot_emits(self, mock_boto3_session):
        """Snapshots well beyond threshold also emit."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-very-old", age_days=365)],
        )
        assert len(findings) == 1

    def test_multiple_old_unlinked_snapshots_all_emit(self, mock_boto3_session):
        """All qualifying snapshots in one page emit."""
        findings = _run(
            mock_boto3_session,
            [
                _snap("snap-1", age_days=100),
                _snap("snap-2", age_days=200),
            ],
        )
        ids = {f.resource_id for f in findings}
        assert "snap-1" in ids
        assert "snap-2" in ids


# ---------------------------------------------------------------------------
# §15 Must skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    """Spec §15 — must skip."""

    def test_skip_younger_than_threshold(self, mock_boto3_session):
        """Snapshot younger than max_age_days → skip (§15 must-skip 1)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-new", age_days=_MAX_AGE - 1)],
        )
        assert findings == []

    def test_skip_exactly_at_threshold_minus_one(self, mock_boto3_session):
        """age_days == max_age_days - 1 → skip."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-edge", age_days=89)],
            max_age_days=90,
        )
        assert findings == []

    def test_skip_exactly_at_threshold(self, mock_boto3_session):
        """age_days == max_age_days → emit (boundary: >= not >)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-boundary", age_days=90)],
            max_age_days=90,
        )
        assert len(findings) == 1

    @pytest.mark.parametrize("state", ["pending", "error", "recoverable", "recovering"])
    def test_skip_non_completed_state(self, mock_boto3_session, state):
        """State other than completed → skip (§15 must-skip 2, §5A.1)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-bad-state", age_days=_MAX_AGE, state=state)],
        )
        assert findings == [], f"Expected skip for state={state}"

    def test_skip_archive_storage_tier(self, mock_boto3_session):
        """StorageTier == archive → skip (§15 must-skip 3, §5A.2)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-archive", age_days=_MAX_AGE, storage_tier="archive")],
        )
        assert findings == []

    def test_skip_ami_linked(self, mock_boto3_session):
        """AMI-linked snapshot → skip (§15 must-skip 4, §5A.4)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-ami", age_days=_MAX_AGE)],
            ami_images=[_ami_with_snap("snap-ami")],
        )
        assert findings == []

    def test_skip_shared_publicly(self, mock_boto3_session):
        """Snapshot shared publicly (group=all) → skip (§15 must-skip 5, §5A.5)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-public", age_days=_MAX_AGE)],
            sharing_perms=[{"Group": "all"}],
        )
        assert findings == []

    def test_skip_shared_to_external_account(self, mock_boto3_session):
        """Snapshot shared to external UserId → skip (§15 must-skip 6, §5A.5)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-shared", age_days=_MAX_AGE)],
            sharing_perms=[{"UserId": "123456789012"}],
        )
        assert findings == []

    def test_skip_backup_managed_aws_backup_tag(self, mock_boto3_session):
        """aws:backup: tag → skip (§15 must-skip 7, §5A.6)."""
        findings = _run(
            mock_boto3_session,
            [
                _snap(
                    "snap-backup",
                    age_days=_MAX_AGE,
                    tags=[{"Key": "aws:backup:source-resource-id", "Value": "vol-abc"}],
                )
            ],
        )
        assert findings == []

    def test_dlm_tag_does_not_suppress(self, mock_boto3_session):
        """aws:dlm: tag must NOT suppress finding — DLM is not in scope for this spec (§4, §5A.6).

        Only explicit aws:backup: tags are defined as the backup_managed exclusion signal.
        """
        findings = _run(
            mock_boto3_session,
            [
                _snap(
                    "snap-dlm",
                    age_days=_MAX_AGE,
                    tags=[{"Key": "aws:dlm:lifecycle-policy-id", "Value": "policy-abc"}],
                )
            ],
        )
        assert len(findings) == 1

    def test_skip_malformed_no_snapshot_id(self, mock_boto3_session):
        """Missing SnapshotId → skip (§15 must-skip 8, §3)."""
        bad = {
            "StartTime": _NOW - timedelta(days=_MAX_AGE),
            "State": "completed",
            "VolumeSize": 10,
            "Tags": [],
        }
        findings = _run(mock_boto3_session, [bad])
        assert findings == []

    def test_skip_malformed_no_start_time(self, mock_boto3_session):
        """Missing StartTime → skip (§15 must-skip 9, §3)."""
        bad = {
            "SnapshotId": "snap-no-time",
            "State": "completed",
            "VolumeSize": 10,
            "Tags": [],
        }
        findings = _run(mock_boto3_session, [bad])
        assert findings == []

    def test_skip_when_ami_index_fails(self, mock_boto3_session):
        """AMI index build failure → all candidates skip (§15 must-skip 10, §10)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
            ami_index_raises=True,
        )
        assert findings == []

    def test_skip_when_sharing_check_fails(self, mock_boto3_session):
        """External sharing check failure → that snapshot skips (§15 must-skip 11, §10)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
            sharing_raises=True,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# §15 Must NOT happen
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    """Spec §15 — must-not-happen scenarios."""

    def test_no_cost_estimate_from_volume_size(self, mock_boto3_session):
        """estimated_monthly_cost_usd must be None — not derived from VolumeSize (§9, §15)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE, volume_size=500)],
        )
        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_ami_linked_snapshot_not_emitted(self, mock_boto3_session):
        """AMI-linked snapshot must never appear in findings (§15 must-not-happen 3)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-ami-linked", age_days=_MAX_AGE)],
            ami_images=[_ami_with_snap("snap-ami-linked")],
        )
        assert findings == []

    def test_public_snapshot_not_emitted(self, mock_boto3_session):
        """Publicly shared snapshot must never appear in findings (§15 must-not-happen 4)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-pub", age_days=_MAX_AGE)],
            sharing_perms=[{"Group": "all"}],
        )
        assert findings == []

    def test_archived_snapshot_not_emitted(self, mock_boto3_session):
        """Archive-tier snapshot must never appear in findings (§15 must-not-happen 5)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-arc", age_days=_MAX_AGE, storage_tier="archive")],
        )
        assert findings == []

    def test_missing_ami_visibility_not_treated_as_no_blockers(self, mock_boto3_session):
        """AMI check failure must cause skip, not optimistic emission (§10, §15 must-not-happen 6)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
            ami_index_raises=True,
        )
        assert findings == []

    def test_missing_sharing_visibility_not_treated_as_no_blockers(self, mock_boto3_session):
        """Sharing check failure must cause skip, not optimistic emission (§10)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
            sharing_raises=True,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# §7 Confidence model
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    """Spec §7 — confidence must always be LOW."""

    def test_confidence_is_low(self, mock_boto3_session):
        """All emitted findings carry LOW confidence (§7)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE)],
        )
        assert findings[0].confidence == ConfidenceLevel.LOW


# ---------------------------------------------------------------------------
# §8 Risk model
# ---------------------------------------------------------------------------


class TestRiskModel:
    """Spec §8 — risk must always be LOW."""

    def test_risk_is_low_regardless_of_volume_size(self, mock_boto3_session):
        """Risk is LOW regardless of volume size (§8 — do not infer risk from age alone)."""
        for size in (1, 100, 1000, 10000):
            findings = _run(
                mock_boto3_session,
                [_snap(f"snap-{size}", age_days=_MAX_AGE, volume_size=size)],
            )
            assert findings[0].risk == RiskLevel.LOW, f"Expected LOW risk for volume_size={size}"


# ---------------------------------------------------------------------------
# §12 Evidence contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    """Spec §12 — all evidence fields must be present (null allowed, never omitted)."""

    def _finding(self, mock_boto3_session, **kwargs):
        findings = _run(
            mock_boto3_session,
            [_snap("snap-old", age_days=_MAX_AGE, **kwargs)],
        )
        assert len(findings) == 1
        return findings[0]

    def test_evaluation_path(self, mock_boto3_session):
        """evaluation_path must be exactly 'old-snapshot-review-candidate' (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["evaluation_path"] == "old-snapshot-review-candidate"

    def test_snapshot_id_present(self, mock_boto3_session):
        """snapshot_id must be present (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["snapshot_id"] == "snap-old"

    def test_start_time_present_and_iso(self, mock_boto3_session):
        """start_time must be ISO-8601 string (§12)."""
        f = self._finding(mock_boto3_session)
        assert isinstance(f.details["start_time"], str)
        assert "T" in f.details["start_time"]

    def test_age_days_present(self, mock_boto3_session):
        """age_days must be present (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["age_days"] == _MAX_AGE

    def test_status_present(self, mock_boto3_session):
        """status must be present (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["status"] == "completed"

    def test_storage_tier_present(self, mock_boto3_session):
        """storage_tier must be present (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["storage_tier"] == "standard"

    def test_ami_linked_check_false(self, mock_boto3_session):
        """ami_linked_check must be False when check passed (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["ami_linked_check"] is False

    def test_create_volume_permission_check_false(self, mock_boto3_session):
        """create_volume_permission_check must be False when check passed (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["create_volume_permission_check"] is False

    def test_backup_managed_check_unknown(self, mock_boto3_session):
        """backup_managed_check must be 'unknown' when no backup tags found (§12, §4).

        Tag-only negative is not proof of non-Backup ownership (spec §4: lack of
        evidence is not proof of non-Backup ownership).
        """
        f = self._finding(mock_boto3_session)
        assert f.details["backup_managed_check"] == "unknown"

    def test_volume_id_present(self, mock_boto3_session):
        """volume_id must be present (§12)."""
        f = self._finding(mock_boto3_session)
        assert f.details["volume_id"] == "vol-12345"

    def test_volume_id_null_when_absent(self, mock_boto3_session):
        """volume_id is null when not returned by API (§12)."""
        findings = _run(
            mock_boto3_session,
            [
                {
                    "SnapshotId": "snap-old",
                    "StartTime": _NOW - timedelta(days=_MAX_AGE),
                    "State": "completed",
                    "Tags": [],
                    # VolumeId and VolumeSize intentionally absent
                }
            ],
        )
        assert len(findings) == 1
        assert "volume_id" in findings[0].details
        assert findings[0].details["volume_id"] is None

    def test_volume_size_gib_present(self, mock_boto3_session):
        """volume_size_gib must be present (§12)."""
        f = self._finding(mock_boto3_session, volume_size=20)
        assert f.details["volume_size_gib"] == 20

    def test_volume_size_gib_null_when_absent(self, mock_boto3_session):
        """volume_size_gib is null when not in API response (§12)."""
        findings = _run(
            mock_boto3_session,
            [
                {
                    "SnapshotId": "snap-old",
                    "StartTime": _NOW - timedelta(days=_MAX_AGE),
                    "State": "completed",
                    "VolumeId": "vol-abc",
                    "Tags": [],
                }
            ],
        )
        assert len(findings) == 1
        assert "volume_size_gib" in findings[0].details
        assert findings[0].details["volume_size_gib"] is None

    def test_full_snapshot_size_bytes_present_when_returned(self, mock_boto3_session):
        """full_snapshot_size_bytes populated when returned by API (§12)."""
        f = self._finding(mock_boto3_session, full_snapshot_size_bytes=1_000_000)
        assert f.details["full_snapshot_size_bytes"] == 1_000_000

    def test_full_snapshot_size_bytes_null_when_absent(self, mock_boto3_session):
        """full_snapshot_size_bytes is null when absent (§12)."""
        f = self._finding(mock_boto3_session)
        assert "full_snapshot_size_bytes" in f.details
        assert f.details["full_snapshot_size_bytes"] is None

    def test_no_required_field_omitted(self, mock_boto3_session):
        """All required details fields must be present; none may be omitted (§12)."""
        f = self._finding(mock_boto3_session)
        required = {
            "evaluation_path",
            "snapshot_id",
            "start_time",
            "age_days",
            "status",
            "storage_tier",
            "ami_linked_check",
            "create_volume_permission_check",
            "backup_managed_check",
            "volume_id",
            "volume_size_gib",
            "full_snapshot_size_bytes",
        }
        for field in required:
            assert field in f.details, f"Missing required details field: {field}"


# ---------------------------------------------------------------------------
# §13 Title and reason contract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    """Spec §13 — exact title and reason strings; forbidden language."""

    def test_title_is_exact(self, mock_boto3_session):
        """Title must be exactly 'Old EBS snapshot review candidate' (§13)."""
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        assert findings[0].title == "Old EBS snapshot review candidate"

    def test_reason_is_exact(self, mock_boto3_session):
        """Reason must match spec §13."""
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        assert findings[0].reason == (
            "Snapshot exceeds age threshold and no AMI linkage, external sharing, "
            "or explicit AWS Backup-managed signal was found"
        )

    def test_title_not_unused(self, mock_boto3_session):
        """Title must not call snapshot 'unused' (§13)."""
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        assert "unused" not in findings[0].title.lower()

    def test_reason_not_safe_to_delete(self, mock_boto3_session):
        """Reason must not say 'safe to delete' (§13)."""
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        assert "safe to delete" not in findings[0].reason.lower()

    def test_summary_not_guaranteed_cost_savings(self, mock_boto3_session):
        """Summary must not imply guaranteed cost savings (§13)."""
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        summary_lower = findings[0].summary.lower()
        assert "guaranteed" not in summary_lower
        assert "save" not in summary_lower


# ---------------------------------------------------------------------------
# §11 Blind spots / signals_not_checked
# ---------------------------------------------------------------------------


class TestBlindSpots:
    """Spec §11 — signals_not_checked must disclose defined blind spots."""

    def _not_checked(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_snap("snap-old", age_days=_MAX_AGE)])
        return " ".join(findings[0].evidence.signals_not_checked).lower()

    def test_dr_intent_disclosed(self, mock_boto3_session):
        """Disaster recovery intent blind spot must be disclosed (§11)."""
        assert "disaster recovery" in self._not_checked(mock_boto3_session)

    def test_deletion_cost_disclaimer_disclosed(self, mock_boto3_session):
        """Deletion might not reduce cost must be disclosed (§11)."""
        nc = self._not_checked(mock_boto3_session)
        assert "might not reduce" in nc or "not reduce" in nc

    def test_backup_management_blind_spot_disclosed(self, mock_boto3_session):
        """AWS Backup management limitation must be disclosed (§11)."""
        assert "backup" in self._not_checked(mock_boto3_session)

    def test_cross_account_ami_blind_spot_disclosed(self, mock_boto3_session):
        """Cross-account AMI reference blind spot must be disclosed (§11)."""
        assert "cross-account" in self._not_checked(mock_boto3_session)


# ---------------------------------------------------------------------------
# §10 Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    """Spec §10 — must paginate DescribeSnapshots until exhausted."""

    def test_multi_page_all_findings_collected(self, mock_boto3_session):
        """Findings from all snapshot pages are returned (§10)."""
        ec2 = mock_boto3_session._ec2

        snap_paginator = MagicMock()
        snap_paginator.paginate.return_value = [
            {"Snapshots": [_snap("snap-page1", age_days=_MAX_AGE)]},
            {"Snapshots": [_snap("snap-page2", age_days=_MAX_AGE + 10)]},
        ]

        ami_paginator = MagicMock()
        ami_paginator.paginate.return_value = [{"Images": []}]

        def _get_paginator(name):
            return snap_paginator if name == "describe_snapshots" else ami_paginator

        ec2.get_paginator.side_effect = _get_paginator
        ec2.describe_snapshot_attribute.return_value = {"CreateVolumePermissions": []}

        findings = find_old_ebs_snapshots(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}
        assert "snap-page1" in ids
        assert "snap-page2" in ids


# ---------------------------------------------------------------------------
# §5 Scope — mixed scenarios
# ---------------------------------------------------------------------------


class TestScope:
    """Spec §3, §5 — scope enforcement across mixed snapshot sets."""

    def test_only_eligible_snapshots_emit_from_mixed_set(self, mock_boto3_session):
        """Mixed set: only old, completed, standard, unlinked, private snaps emit."""
        findings = _run(
            mock_boto3_session,
            [
                _snap("snap-ok", age_days=_MAX_AGE),
                _snap("snap-young", age_days=_MAX_AGE - 1),
                _snap("snap-pending", age_days=_MAX_AGE, state="pending"),
                _snap("snap-archive", age_days=_MAX_AGE, storage_tier="archive"),
                _snap("snap-ami-linked", age_days=_MAX_AGE),
                _snap(
                    "snap-backup",
                    age_days=_MAX_AGE,
                    tags=[{"Key": "aws:backup:source-resource-id", "Value": "v"}],
                ),
            ],
            ami_images=[_ami_with_snap("snap-ami-linked")],
        )
        ids = {f.resource_id for f in findings}
        assert ids == {"snap-ok"}

    def test_standard_tier_absent_treated_as_standard(self, mock_boto3_session):
        """Absent StorageTier treated as standard — snapshot is eligible (§3)."""
        findings = _run(
            mock_boto3_session,
            [_snap("snap-no-tier", age_days=_MAX_AGE, storage_tier=None)],
        )
        assert len(findings) == 1

    def test_unrelated_user_tags_do_not_suppress(self, mock_boto3_session):
        """Non-backup user tags must not suppress findings (§5A.6 — only backup tags suppress)."""
        findings = _run(
            mock_boto3_session,
            [
                _snap(
                    "snap-tagged",
                    age_days=_MAX_AGE,
                    tags=[{"Key": "Environment", "Value": "prod"}],
                )
            ],
        )
        assert len(findings) == 1
