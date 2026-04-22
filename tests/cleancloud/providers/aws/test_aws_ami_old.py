"""
Tests for aws.ec2.ami.old — derived from rule spec v4.

Every test references the spec section it validates.
Helpers are minimal: only mock what the test scenario requires.
"""

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.ami_old import find_old_amis

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)


def _ami(
    ami_id: str = "ami-test",
    age_days: int = 200,
    state: str = "available",
    deprecated_days_ago: int | None = None,
    name: str = "test-image",
    block_devices: list | None = None,
    tags: list | None = None,
) -> dict:
    creation = NOW - timedelta(days=age_days)
    ami = {
        "ImageId": ami_id,
        "Name": name,
        "CreationDate": creation.isoformat(),
        "State": state,
        "PlatformDetails": "Linux/UNIX",
        "Architecture": "x86_64",
        "RootDeviceType": "ebs",
        "BlockDeviceMappings": block_devices or [],
        "Tags": tags or [],
    }
    if deprecated_days_ago is not None:
        dep_time = NOW - timedelta(days=deprecated_days_ago)
        ami["DeprecationTime"] = dep_time.isoformat()
    return ami


def _ebs_device(snapshot_id: str = "snap-1", volume_gb: int = 100) -> dict:
    return {"Ebs": {"SnapshotId": snapshot_id, "VolumeSize": volume_gb}}


def _setup_images(ec2, images: list) -> None:
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"Images": images}]


def _no_last_launched(ec2) -> None:
    ec2.describe_image_attribute.return_value = {"LastLaunchedTime": {}}


def _last_launched_days_ago(ec2, days: int) -> None:
    ts = (NOW - timedelta(days=days)).isoformat()
    ec2.describe_image_attribute.return_value = {"LastLaunchedTime": {"Value": ts}}


def _no_active_instances(ec2) -> None:
    ec2.describe_instances.return_value = {"Reservations": []}


def _active_instances_exist(ec2) -> None:
    ec2.describe_instances.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": "i-abc"}]}]
    }


def _instance_check_fails(ec2) -> None:
    ec2.describe_instances.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
        "DescribeInstances",
    )


def _no_lt_refs(ec2) -> None:
    ec2.describe_launch_templates.return_value = {"LaunchTemplates": []}


def _lt_refs(ec2, ami_id: str, lt_id: str = "lt-aaa") -> None:
    """Simulate one LT whose $Default/$Latest version references ami_id."""
    ec2.describe_launch_templates.return_value = {"LaunchTemplates": [{"LaunchTemplateId": lt_id}]}
    ec2.describe_launch_template_versions.return_value = {
        "LaunchTemplateVersions": [
            {
                "LaunchTemplateId": lt_id,
                "LaunchTemplateData": {"ImageId": ami_id},
            }
        ]
    }


def _no_lc_refs(autoscaling) -> None:
    autoscaling.describe_launch_configurations.return_value = {"LaunchConfigurations": []}


def _lc_refs(autoscaling, ami_id: str, lc_name: str = "lc-aaa") -> None:
    autoscaling.describe_launch_configurations.return_value = {
        "LaunchConfigurations": [{"ImageId": ami_id, "LaunchConfigurationName": lc_name}]
    }


def _lt_check_fails(ec2) -> None:
    ec2.describe_launch_templates.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "DescribeLaunchTemplates",
    )


def _lc_check_fails(autoscaling) -> None:
    autoscaling.describe_launch_configurations.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "DescribeLaunchConfigurations",
    )


# ---------------------------------------------------------------------------
# 18 — MUST EMIT
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_deprecated_available_no_active_instances(self, mock_boto3_session):
        """Spec 18: deprecated, available, no active instances → finding emitted."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=10)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence.value == "high"  # spec 8
        assert f.risk.value == "medium"  # spec 9: deprecated without active → MEDIUM
        assert f.title == "Deprecated AMI"  # spec 16

    def test_deprecated_available_with_active_instances(self, mock_boto3_session):
        """Spec 18: deprecated, available, active instances → HIGH confidence, HIGH risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=10)])
        _no_last_launched(ec2)
        _active_instances_exist(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence.value == "high"  # spec 8
        assert f.risk.value == "high"  # spec 9: deprecated + active
        assert f.title == "Deprecated AMI Still In Use"  # spec 16

    def test_non_deprecated_age_and_stale_launch(self, mock_boto3_session):
        """Spec 18: non-deprecated, age >= 180, stale launch >= 180, no exclusions → finding."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)  # stale
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence.value == "medium"  # spec 8: score 2, no contextual downgrade
        assert f.risk.value == "medium"  # spec 9: score 2 guardrail
        assert f.title == "Unused AMI"  # spec 16

    def test_non_deprecated_age_only(self, mock_boto3_session):
        """Spec 18: non-deprecated, age-only stale (score 1) → LOW confidence, LOW risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)  # unknown, not stale
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence.value == "low"  # spec 8: score 1
        assert f.risk.value == "low"  # spec 9
        assert f.title == "AMI Older Than 180 Days"  # spec 16


# ---------------------------------------------------------------------------
# 18 — MUST SKIP
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_non_deprecated_recently_launched(self, mock_boto3_session):
        """Spec 18: non-deprecated, recently launched → skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 10)  # within recently_active_days=30
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_non_deprecated_active_instances_exist(self, mock_boto3_session):
        """Spec 18: non-deprecated, active instances exist → skip (hard exclusion)."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _active_instances_exist(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_non_deprecated_score_zero(self, mock_boto3_session):
        """Spec 18: non-deprecated, score == 0 (age < threshold, no stale launch) → skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=50)])  # below 180d threshold
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_malformed_ami_without_image_id(self, mock_boto3_session):
        """Spec 18: malformed AMI without ImageId → skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        bad = _ami()
        del bad["ImageId"]
        _setup_images(ec2, [bad])
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_non_available_state_skipped(self, mock_boto3_session):
        """Spec 3: only state=available is evaluated."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        for state in ("pending", "deregistered", "failed", "error", "invalid"):
            _setup_images(ec2, [_ami(age_days=200, state=state)])
            _no_lt_refs(ec2)
            _no_lc_refs(autoscaling)
            assert find_old_amis(mock_boto3_session, "us-east-1") == [], state

    def test_missing_creation_date_skipped(self, mock_boto3_session):
        """Spec 3: AMI with missing CreationDate → skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami = _ami()
        del ami["CreationDate"]
        _setup_images(ec2, [ami])
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        assert find_old_amis(mock_boto3_session, "us-east-1") == []


# ---------------------------------------------------------------------------
# 18 — MUST NOT HAPPEN
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    def test_lt_alone_does_not_create_finding(self, mock_boto3_session):
        """Spec 18: LT/LC alone must never create a finding (score == 0 → skip)."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-young", age_days=10)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _lt_refs(ec2, ami_id="ami-young")
        _no_lc_refs(autoscaling)

        assert find_old_amis(mock_boto3_session, "us-east-1") == []

    def test_missing_last_launched_does_not_trigger_exclusion(self, mock_boto3_session):
        """Spec 18 / 5.A: missing lastLaunchedTime must NOT exclude a finding."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)  # unknown — must not trigger exclusion
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1  # must emit despite missing lastLaunchedTime

    def test_contextual_signals_do_not_stack_multiple_downgrades(self, mock_boto3_session):
        """Spec 18: contextual signals max 1 downgrade total — LT + LC together = still 1."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-ref", age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2 → base MEDIUM
        _no_active_instances(ec2)
        _lt_refs(ec2, ami_id="ami-ref")
        _lc_refs(autoscaling, ami_id="ami-ref")

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        # MEDIUM downgraded once → LOW; must NOT go below LOW
        assert findings[0].confidence.value == "low"

    def test_cost_does_not_affect_risk(self, mock_boto3_session):
        """Spec 12: cost is informational only — large snapshot must NOT change risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        large_disk = _ebs_device("snap-big", volume_gb=2000)
        _setup_images(ec2, [_ami(age_days=200, block_devices=[large_disk])])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        # score == 1 → LOW risk; cost must not inflate it
        assert findings[0].risk.value == "low"

    def test_absence_of_active_instance_data_not_treated_as_none(self, mock_boto3_session):
        """Spec 13: instance check failure ≠ 'no instances'. Borderline score → skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)  # score == 1 (age only)
        _instance_check_fails(ec2)  # unknown — not "no instances"
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        # score == 1 + instance check failed → borderline → must skip
        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert findings == []


# ---------------------------------------------------------------------------
# 18 — MUST DEGRADE
# ---------------------------------------------------------------------------


class TestMustDegrade:
    def test_describe_image_attribute_unavailable(self, mock_boto3_session):
        """Spec 13: DescribeImageAttribute failure → finding still emitted, noted in evidence."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        ec2.describe_image_attribute.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeImageAttribute",
        )
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert any(
            "ec2:DescribeImageAttribute" in s for s in findings[0].evidence.signals_not_checked
        )

    def test_describe_instances_unavailable_score_2_still_emits(self, mock_boto3_session):
        """Spec 13: instance check failure + score 2 → emit (not borderline), apply downgrade."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2
        _instance_check_fails(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        # Score 2, but instance check failed → contextual downgrade
        assert f.confidence.value == "low"  # MEDIUM downgraded to LOW
        assert f.risk.value == "medium"  # guardrail: score 2 → risk >= MEDIUM
        assert any("ec2:DescribeInstances" in s for s in f.evidence.signals_not_checked)

    def test_lt_lookup_unavailable(self, mock_boto3_session):
        """Spec 13: LT lookup failure → finding still emitted, noted in evidence."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _lt_check_fails(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert any("DescribeLaunchTemplates" in s for s in findings[0].evidence.signals_not_checked)
        assert findings[0].details["launch_template_refs"] == []

    def test_lc_lookup_unavailable(self, mock_boto3_session):
        """Spec 13: LC lookup failure → finding still emitted, noted in evidence."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _lc_check_fails(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert any(
            "DescribeLaunchConfigurations" in s for s in findings[0].evidence.signals_not_checked
        )
        assert findings[0].details["launch_config_refs"] == []

    def test_describe_images_failure_raises_permission_error(self, mock_boto3_session):
        """Spec 13: DescribeImages failure → PermissionError raised."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        paginator = ec2.get_paginator.return_value
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeImages",
        )
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        with pytest.raises(PermissionError, match="ec2:DescribeImages"):
            find_old_amis(mock_boto3_session, "us-east-1")


# ---------------------------------------------------------------------------
# 5 — Signal model details
# ---------------------------------------------------------------------------


class TestSignalModel:
    def test_deprecated_path_ignores_recently_launched(self, mock_boto3_session):
        """Spec 5.A / 7: EXCLUSION_RULES do NOT apply to deprecated AMIs."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _last_launched_days_ago(ec2, 5)  # recently launched — must NOT suppress
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value == "high"

    def test_deprecated_path_ignores_active_instance_exclusion(self, mock_boto3_session):
        """Spec 7: deprecated + active instances → emit HIGH, not skip."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _active_instances_exist(ec2)  # must NOT suppress for deprecated
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value == "high"
        assert findings[0].risk.value == "high"

    def test_future_deprecation_time_is_path_b(self, mock_boto3_session):
        """Spec 7: DeprecationTime in the future → treat as non-deprecated (Path B)."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami = _ami(ami_id="ami-future", age_days=200)
        ami["DeprecationTime"] = (NOW + timedelta(days=30)).isoformat()
        _setup_images(ec2, [ami])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value != "high"  # Path B, not Path A

    def test_invalid_deprecation_time_is_path_b(self, mock_boto3_session):
        """Spec 7: invalid/unparseable DeprecationTime → treat as non-deprecated."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami = _ami(ami_id="ami-baddep", age_days=200)
        ami["DeprecationTime"] = "not-a-date"
        _setup_images(ec2, [ami])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value != "high"

    def test_lt_refs_cause_contextual_downgrade(self, mock_boto3_session):
        """Spec 11: LT refs → max 1 confidence downgrade (MEDIUM → LOW)."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-lt", age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2, base = MEDIUM
        _no_active_instances(ec2)
        _lt_refs(ec2, ami_id="ami-lt")
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value == "low"  # downgraded from MEDIUM

    def test_lc_refs_cause_contextual_downgrade(self, mock_boto3_session):
        """Spec 11: LC refs → max 1 confidence downgrade (MEDIUM → LOW)."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-lc", age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2, base = MEDIUM
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _lc_refs(autoscaling, ami_id="ami-lc")

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value == "low"  # downgraded from MEDIUM

    def test_lt_refs_on_score_1_does_not_downgrade_below_low(self, mock_boto3_session):
        """Spec 8: contextual signals never increase confidence; LOW stays LOW."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-s1", age_days=200)])
        _no_last_launched(ec2)  # score = 1, base = LOW
        _no_active_instances(ec2)
        _lt_refs(ec2, ami_id="ami-s1")
        _no_lc_refs(autoscaling)

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert findings[0].confidence.value == "low"  # already LOW, cannot go lower

    def test_deprecated_contextual_signals_do_not_change_confidence(self, mock_boto3_session):
        """Spec 7: contextual signals do NOT modify confidence for deprecated AMIs."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(ami_id="ami-dep", deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _lt_refs(ec2, ami_id="ami-dep")
        _lc_refs(autoscaling, ami_id="ami-dep")

        findings = find_old_amis(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        # Contextual signals must not downgrade HIGH
        assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# 9 — Risk model
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_deprecated_active_is_high_risk(self, mock_boto3_session):
        """Spec 9: deprecated + active instances → HIGH risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _active_instances_exist(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.risk.value == "high"

    def test_deprecated_no_active_is_medium_risk(self, mock_boto3_session):
        """Spec 9: deprecated + no active instances → MEDIUM risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.risk.value == "medium"

    def test_score_2_guardrail_risk_is_medium(self, mock_boto3_session):
        """Spec 9 guardrail: score == 2 → risk MUST be >= MEDIUM."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.risk.value == "medium"

    def test_score_1_is_low_risk(self, mock_boto3_session):
        """Spec 9: score 1 → LOW risk."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.risk.value == "low"


# ---------------------------------------------------------------------------
# 16 — Title contract
# ---------------------------------------------------------------------------


class TestTitleContract:
    def test_deprecated_active_title(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _active_instances_exist(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        assert (
            find_old_amis(mock_boto3_session, "us-east-1")[0].title == "Deprecated AMI Still In Use"
        )

    def test_deprecated_only_title(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        assert find_old_amis(mock_boto3_session, "us-east-1")[0].title == "Deprecated AMI"

    def test_stale_launch_title(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        assert find_old_amis(mock_boto3_session, "us-east-1")[0].title == "Unused AMI"

    def test_age_only_title(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        assert find_old_amis(mock_boto3_session, "us-east-1")[0].title == "AMI Older Than 180 Days"


# ---------------------------------------------------------------------------
# 15 — Evidence contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _base_finding(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        return find_old_amis(mock_boto3_session, "us-east-1")[0]

    def test_evaluation_path_is_exactly_scored(self, mock_boto3_session):
        """Spec 17: evaluation path must be exactly 'scored' for Path B."""
        f = self._base_finding(mock_boto3_session)
        assert any("evaluation_path: scored" in s for s in f.evidence.signals_used)

    def test_evaluation_path_is_exactly_deprecated(self, mock_boto3_session):
        """Spec 17: evaluation path must be exactly 'deprecated' for Path A."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [_ami(deprecated_days_ago=5)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert any("evaluation_path: deprecated" in s for s in f.evidence.signals_used)

    def test_all_evidence_fields_present(self, mock_boto3_session):
        """Spec 15: all fields must exist (null allowed, never omitted)."""
        f = self._base_finding(mock_boto3_session)
        required = [
            "evaluation_path",
            "age:",
            "deprecated:",
            "last_launched:",
            "active_instances:",
            "lt_refs:",
            "lc_refs:",
            "snapshots:",
        ]
        for keyword in required:
            assert any(keyword in s for s in f.evidence.signals_used), keyword

    def test_permanent_blind_spots_always_present(self, mock_boto3_session):
        """Spec 14: blind spots must always be in signals_not_checked."""
        f = self._base_finding(mock_boto3_session)
        combined = " ".join(f.evidence.signals_not_checked)
        assert "LT/LC reference does not prove active ASG usage" in combined
        assert "compliance" in combined.lower()

    def test_last_launched_unknown_phrasing(self, mock_boto3_session):
        """Spec 14: 'no record' must not imply 'never launched'."""
        f = self._base_finding(mock_boto3_session)
        last_launched_signal = next(s for s in f.evidence.signals_used if "last_launched" in s)
        assert "unknown" in last_launched_signal or "null" in last_launched_signal
        # Must not claim the AMI was never launched
        assert (
            "proof of non-use" in last_launched_signal
            or "absence of record" in last_launched_signal
        )

    def test_instance_check_failure_phrasing(self, mock_boto3_session):
        """Spec 13: instance check failure must not imply 'no instances'."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2 (not borderline)
        _instance_check_fails(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        instance_signal = next(s for s in f.evidence.signals_used if "active_instances" in s)
        assert "unknown" in instance_signal
        # Must not imply the result is "no instances"
        assert "proof of absence" in instance_signal or "absence of check" in instance_signal


# ---------------------------------------------------------------------------
# 12 — Cost model
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_cost_is_upper_bound_estimate(self, mock_boto3_session):
        """Spec 12: cost uses declared EBS volume size; required warning included."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        bd = _ebs_device("snap-1", 200)
        _setup_images(ec2, [_ami(age_days=200, block_devices=[bd])])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.estimated_monthly_cost_usd == 10.0  # 200 GB * $0.05
        cost_str = f.details["estimated_monthly_cost"]
        assert cost_str is not None
        assert "upper bound" in cost_str
        assert "≠" in cost_str or "actual" in cost_str  # billing disclaimer

    def test_no_snapshots_cost_is_none(self, mock_boto3_session):
        """Spec 12: no EBS snapshots → cost is None."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200, block_devices=[])])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.estimated_monthly_cost_usd is None
        assert f.details["estimated_monthly_cost"] is None


# ---------------------------------------------------------------------------
# 3 — Scope / parametrize
# ---------------------------------------------------------------------------


class TestScope:
    def test_custom_threshold(self, mock_boto3_session):
        """Spec 4: max_age_days is configurable."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=100)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        assert find_old_amis(mock_boto3_session, "us-east-1", max_age_days=180) == []
        assert len(find_old_amis(mock_boto3_session, "us-east-1", max_age_days=90)) == 1

    def test_empty_account(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling
        _setup_images(ec2, [])
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)
        assert find_old_amis(mock_boto3_session, "us-east-1") == []

    def test_finding_fields(self, mock_boto3_session):
        """Core finding fields match spec 4 canonical definitions."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.provider == "aws"
        assert f.rule_id == "aws.ec2.ami.old"
        assert f.resource_type == "aws.ec2.ami"
        assert f.resource_id == "ami-test"
        assert f.region == "us-east-1"
        assert f.details["age_days"] >= 200
        assert f.details["state"] == "available"


# ---------------------------------------------------------------------------
# Regression tests for the four spec mismatches fixed in review
# ---------------------------------------------------------------------------


class TestSpecMismatchFixes:
    # Fix #1 — unknown active-instance state must not leak into "Unused AMI"

    def test_score2_instance_check_failed_title_is_not_unused(self, mock_boto3_session):
        """Fix #1: score==2 + instance check failed → title must NOT be 'Unused AMI'."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2
        _instance_check_fails(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        # "Unused AMI" implies no active instances — we cannot know that
        assert f.title != "Unused AMI"
        assert f.title == "AMI Older Than 180 Days"

    def test_score2_instance_check_failed_active_instances_found_is_none(self, mock_boto3_session):
        """Fix #1: instance check failed → details['active_instances_found'] must be None."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2
        _instance_check_fails(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        # Must be None (unknown), not False (which implies "no instances")
        assert f.details["active_instances_found"] is None
        assert f.details["instance_check_failed"] is True

    def test_instance_check_ok_active_instances_found_is_bool(self, mock_boto3_session):
        """Fix #1 (complement): when check succeeds, active_instances_found is a bool."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.details["active_instances_found"] is False  # confirmed, not unknown
        assert f.details["instance_check_failed"] is False

    # Fix #2 — future DeprecationTime must be surfaced, not silently dropped

    def test_future_deprecation_time_in_evidence(self, mock_boto3_session):
        """Fix #2: future DeprecationTime must appear in evidence, not as 'not set'."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami = _ami(ami_id="ami-future", age_days=200)
        future_date = NOW + timedelta(days=30)
        ami["DeprecationTime"] = future_date.isoformat()
        _setup_images(ec2, [ami])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        dep_signal = next(s for s in f.evidence.signals_used if "deprecated" in s)
        assert "future" in dep_signal
        assert future_date.strftime("%Y-%m-%d") in dep_signal
        # Must not report "not set"
        assert "not set" not in dep_signal

    def test_future_deprecation_time_in_details(self, mock_boto3_session):
        """Fix #2: future DeprecationTime must be stored in details, not None."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami = _ami(ami_id="ami-future2", age_days=200)
        future_date = NOW + timedelta(days=30)
        ami["DeprecationTime"] = future_date.isoformat()
        _setup_images(ec2, [ami])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        assert f.details["deprecation_time"] is not None
        assert future_date.strftime("%Y-%m-%d") in f.details["deprecation_time"]

    # Fix #3 — partial LT/LC index data must not be discarded

    def test_lt_partial_index_refs_still_used(self, mock_boto3_session):
        """Fix #3: refs found before LT guard truncation must still appear in output."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        ami_id = "ami-partial"
        _setup_images(ec2, [_ami(ami_id=ami_id, age_days=200)])
        _last_launched_days_ago(ec2, 200)  # score = 2, base MEDIUM
        _no_active_instances(ec2)

        # 1001 LTs → guard truncates to 1000. lt-500 (within first 1000) refs the AMI.
        ec2.describe_launch_templates.return_value = {
            "LaunchTemplates": [{"LaunchTemplateId": f"lt-{i}"} for i in range(1001)]
        }

        def _versions_side_effect(**kwargs):
            lt_id = kwargs.get("LaunchTemplateId", "")
            if lt_id == "lt-500":
                return {
                    "LaunchTemplateVersions": [
                        {"LaunchTemplateId": lt_id, "LaunchTemplateData": {"ImageId": ami_id}}
                    ]
                }
            return {"LaunchTemplateVersions": []}

        ec2.describe_launch_template_versions.side_effect = _versions_side_effect
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        # Ref found before truncation must not be silently dropped
        assert "lt-500" in f.details["launch_template_refs"]
        # Partial index still triggers contextual downgrade
        assert f.confidence.value == "low"  # MEDIUM downgraded

    # Fix #4 — lastLaunchedTime coverage date is April 2017

    def test_last_launched_coverage_date_in_evidence(self, mock_boto3_session):
        """Fix #4: evidence must reference April 2017, not May 2021."""
        ec2 = mock_boto3_session._ec2
        autoscaling = mock_boto3_session._autoscaling

        _setup_images(ec2, [_ami(age_days=200)])
        _no_last_launched(ec2)
        _no_active_instances(ec2)
        _no_lt_refs(ec2)
        _no_lc_refs(autoscaling)

        f = find_old_amis(mock_boto3_session, "us-east-1")[0]
        all_text = " ".join(f.evidence.signals_used + f.evidence.signals_not_checked)
        assert "April 2017" in all_text
        assert "May 2021" not in all_text
