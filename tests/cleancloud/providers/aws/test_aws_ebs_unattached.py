"""
Tests for aws.ebs.unattached rule.

Every test references its governing spec section in
docs/specs/aws/ebs_unattached.md
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)
_MIN_AGE = 7  # default threshold


def _vol(
    volume_id="vol-abc123",
    state="available",
    age_days=30,
    size_gib=100,
    volume_type="gp3",
    availability_zone="us-east-1a",
    attachments=None,
    operator=None,
    encrypted=True,
    multi_attach_enabled=False,
    iops=3000,
    throughput=None,
    snapshot_id=None,
):
    """Build a minimal boto3-style volume dict."""
    d = {
        "VolumeId": volume_id,
        "State": state,
        "CreateTime": _NOW - timedelta(days=age_days),
        "Size": size_gib,
        "VolumeType": volume_type,
        "AvailabilityZone": availability_zone,
        "Attachments": attachments if attachments is not None else [],
        "Encrypted": encrypted,
        "MultiAttachEnabled": multi_attach_enabled,
        "Iops": iops,
    }
    if operator is not None:
        d["Operator"] = operator
    if throughput is not None:
        d["Throughput"] = throughput
    if snapshot_id is not None:
        d["SnapshotId"] = snapshot_id
    return d


def _run(mock_boto3_session, volumes, min_age_days=_MIN_AGE):
    """Wire up paginator mock and call find_unattached_ebs_volumes."""
    ec2 = mock_boto3_session._ec2
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Volumes": volumes}]
    ec2.get_paginator.return_value = paginator
    return find_unattached_ebs_volumes(
        mock_boto3_session, "us-east-1", min_unattached_age_days=min_age_days
    )


def _find(findings, volume_id):
    return next((f for f in findings if f.resource_id == volume_id), None)


# ---------------------------------------------------------------------------
# 15 Must emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_emit_available_unattached_old_volume(self, mock_boto3_session):
        """Spec 15: available, attachment_count==0, age>=threshold, service_managed false."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert len(findings) == 1
        assert findings[0].resource_id == "vol-abc123"

    def test_emit_when_service_managed_check_false(self, mock_boto3_session):
        """Spec 4: service_managed_check == false → continue evaluation → emit."""
        vol = _vol(operator={"Managed": False, "Principal": "some-service"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1

    def test_emit_when_service_managed_check_unknown(self, mock_boto3_session):
        """Spec 4: service_managed_check == unknown (no Operator key) → not excluded → emit."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        f = findings[0]
        assert f.details["service_managed_check"] == "unknown"

    def test_emit_at_exactly_threshold_age(self, mock_boto3_session):
        """Spec 4: age == threshold exactly should emit."""
        findings = _run(mock_boto3_session, [_vol(age_days=_MIN_AGE)])
        assert len(findings) == 1

    def test_emit_with_custom_threshold(self, mock_boto3_session):
        """Spec 3: min_unattached_age_days is configurable."""
        findings = _run(mock_boto3_session, [_vol(age_days=3)], min_age_days=3)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 15 Must skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    @pytest.mark.parametrize(
        "state",
        ["creating", "in-use", "deleting", "deleted", "error"],
    )
    def test_skip_non_available_states(self, mock_boto3_session, state):
        """Spec 5A: normalized_status != available → SKIP."""
        findings = _run(mock_boto3_session, [_vol(state=state, age_days=30)])
        assert findings == []

    def test_skip_attachment_count_greater_than_zero(self, mock_boto3_session):
        """Spec 5A: any returned attachment entry → SKIP."""
        attachment = {
            "VolumeId": "vol-abc123",
            "InstanceId": "i-12345",
            "Device": "/dev/sda1",
            "State": "attached",
            "AttachTime": _NOW - timedelta(days=10),
        }
        findings = _run(mock_boto3_session, [_vol(attachments=[attachment], age_days=30)])
        assert findings == []

    def test_skip_service_managed_true(self, mock_boto3_session):
        """Spec 5A: service_managed_check == True → SKIP."""
        vol = _vol(operator={"Managed": True, "Principal": "ec2.amazonaws.com"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_younger_than_threshold(self, mock_boto3_session):
        """Spec 5A: age < threshold → SKIP."""
        findings = _run(mock_boto3_session, [_vol(age_days=_MIN_AGE - 1)])
        assert findings == []

    def test_skip_age_zero(self, mock_boto3_session):
        """Spec 5A: brand-new volume → SKIP."""
        findings = _run(mock_boto3_session, [_vol(age_days=0)])
        assert findings == []

    def test_skip_malformed_missing_volume_id(self, mock_boto3_session):
        """Spec 10: VolumeId absent → SKIP item."""
        vol = _vol(age_days=30)
        del vol["VolumeId"]
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_malformed_missing_state(self, mock_boto3_session):
        """Spec 10: State absent → SKIP item."""
        vol = _vol(age_days=30)
        del vol["State"]
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_malformed_missing_create_time(self, mock_boto3_session):
        """Spec 10: CreateTime absent → SKIP item."""
        vol = _vol(age_days=30)
        del vol["CreateTime"]
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_create_time_not_datetime(self, mock_boto3_session):
        """Spec 10: CreateTime is not a datetime (e.g. ISO string) → SKIP item.

        Prevents crash in (now - create_time).days and create_time.isoformat().
        """
        vol = _vol(age_days=30)
        vol["CreateTime"] = "2025-01-01T00:00:00Z"  # string, not datetime
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_attachment_with_null_instance_id(self, mock_boto3_session):
        """Spec 5C: attachment entry present even with null instanceId → attachment_count > 0 → SKIP.

        Must NOT treat missing instanceId as proof of no attachment (spec 5C hard rule).
        """
        attachment = {
            "VolumeId": "vol-abc123",
            "InstanceId": None,  # AWS-managed resource may omit instanceId
            "Device": None,
            "State": "attached",
            "AttachTime": _NOW - timedelta(days=5),
        }
        findings = _run(mock_boto3_session, [_vol(attachments=[attachment], age_days=30)])
        assert findings == []

    def test_skip_only_attached_volume_passes_through(self, mock_boto3_session):
        """Mixed: attached volume skipped, unattached old volume emitted."""
        vols = [
            _vol(volume_id="vol-attached", state="in-use", age_days=30),
            _vol(volume_id="vol-free", state="available", age_days=30),
        ]
        findings = _run(mock_boto3_session, vols)
        ids = {f.resource_id for f in findings}
        assert "vol-free" in ids
        assert "vol-attached" not in ids


# ---------------------------------------------------------------------------
# 15 Must not happen
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    def test_no_flat_cost_estimate(self, mock_boto3_session):
        """Spec 9: estimated_monthly_cost_usd must be None (flat rate invalid across types)."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].estimated_monthly_cost_usd is None

    def test_missing_instance_id_in_attachment_not_treated_as_unattached(self, mock_boto3_session):
        """Spec 5C: attachment entry with null instanceId must cause SKIP, not emit."""
        attachment = {"VolumeId": "vol-abc123", "InstanceId": None, "State": "attached"}
        findings = _run(mock_boto3_session, [_vol(attachments=[attachment], age_days=30)])
        assert findings == []

    def test_missing_operator_key_yields_unknown_not_false(self, mock_boto3_session):
        """Spec 12: operator absent → service_managed_check must be 'unknown', not False."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_service_managed_true_never_emitted(self, mock_boto3_session):
        """Spec 15 must not happen: service-managed volumes are not emitted."""
        vol = _vol(operator={"Managed": True}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_non_available_state_never_emitted(self, mock_boto3_session):
        """Spec 15: attached/transitional volumes not emitted."""
        for state in ["in-use", "creating", "deleting", "deleted", "error"]:
            findings = _run(mock_boto3_session, [_vol(state=state, age_days=30)])
            assert findings == [], f"Expected no findings for state={state!r}"


# ---------------------------------------------------------------------------
# 4 Normalization contract
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_attachments_key_absent_normalizes_to_empty(self, mock_boto3_session):
        """Spec 4: missing Attachments key → normalized_attachments=[] → attachment_count=0."""
        vol = _vol(age_days=30)
        del vol["Attachments"]
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["attachment_count"] == 0

    def test_attachments_null_normalizes_to_empty(self, mock_boto3_session):
        """Spec 4: Attachments=None → normalized to [] → attachment_count=0."""
        vol = _vol(age_days=30)
        vol["Attachments"] = None
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["attachment_count"] == 0

    def test_operator_absent_gives_unknown(self, mock_boto3_session):
        """Spec 4: Operator key absent → service_managed_check='unknown'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_operator_managed_true_gives_true(self, mock_boto3_session):
        """Spec 4: Operator.Managed==True → service_managed_check=True → SKIP."""
        vol = _vol(operator={"Managed": True}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_operator_managed_false_gives_false(self, mock_boto3_session):
        """Spec 4: Operator.Managed==False → service_managed_check=False → emit."""
        vol = _vol(operator={"Managed": False, "Principal": "svc"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] is False

    def test_operator_principal_captured(self, mock_boto3_session):
        """Spec 12: operator_principal must be captured in details."""
        vol = _vol(operator={"Managed": False, "Principal": "ec2.amazonaws.com"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert findings[0].details["operator_principal"] == "ec2.amazonaws.com"

    def test_operator_principal_null_when_absent(self, mock_boto3_session):
        """Spec 12: operator_principal must be null when not in operator block."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["operator_principal"] is None

    def test_contextual_fields_null_when_absent(self, mock_boto3_session):
        """Spec 12: optional contextual fields must be explicit null, not omitted."""
        vol = _vol(age_days=30)
        # Remove optional contextual fields
        for key in ("Iops", "Throughput", "SnapshotId", "MultiAttachEnabled"):
            vol.pop(key, None)
        findings = _run(mock_boto3_session, [vol])
        d = findings[0].details
        assert "iops" in d
        assert "throughput_mibps" in d
        assert "snapshot_id" in d
        assert "multi_attach_enabled" in d

    def test_throughput_captured_when_present(self, mock_boto3_session):
        """Spec 12: throughput_mibps captured from Throughput field."""
        vol = _vol(age_days=30, throughput=125)
        findings = _run(mock_boto3_session, [vol])
        assert findings[0].details["throughput_mibps"] == 125

    def test_snapshot_id_captured_when_present(self, mock_boto3_session):
        """Spec 12: snapshot_id captured from SnapshotId field."""
        vol = _vol(age_days=30, snapshot_id="snap-abc")
        findings = _run(mock_boto3_session, [vol])
        assert findings[0].details["snapshot_id"] == "snap-abc"

    # --- Attachment flattening (spec 4 normalization contract) ---

    def test_dict_attachment_flattened_to_one_element_list(self, mock_boto3_session):
        """Spec 4: Attachments is a dict (single-attachment or wrapper) → flatten to [dict]
        → attachment_count=1 → excluded by attachment_count > 0 rule, not normalization skip."""
        vol = _vol(age_days=30)
        vol["Attachments"] = {"VolumeId": "vol-abc123", "State": "attached"}
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_skip_scalar_attachments(self, mock_boto3_session):
        """Spec 4/10: Attachments is a scalar (string) → cannot flatten → SKIP item."""
        vol = _vol(age_days=30)
        vol["Attachments"] = "attaching"
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    # --- Operator metadata unwrapping (spec 4 normalization contract) ---

    def test_operator_not_dict_gives_unknown(self, mock_boto3_session):
        """Spec 4: Operator value is not a dict → service_managed_check='unknown', not skip."""
        vol = _vol(age_days=30)
        vol["Operator"] = "ec2.amazonaws.com"  # non-dict string
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_operator_managed_wrapped_true(self, mock_boto3_session):
        """Spec 4: Operator.Managed is wrapped dict with Value=True → True → SKIP."""
        vol = _vol(operator={"Managed": {"Value": True}}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert findings == []

    def test_operator_managed_wrapped_false(self, mock_boto3_session):
        """Spec 4: Operator.Managed is wrapped dict with Value=False → False → emit."""
        vol = _vol(operator={"Managed": {"Value": False}}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] is False

    def test_operator_managed_wrapped_ambiguous_gives_unknown(self, mock_boto3_session):
        """Spec 4: Operator.Managed wrapped but no recognizable bool → unknown → emit."""
        vol = _vol(operator={"Managed": {"Value": None}}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_operator_principal_wrapped_unwrapped_to_string(self, mock_boto3_session):
        """Spec 4: Operator.Principal is wrapped dict → unwrap to string."""
        vol = _vol(
            operator={"Managed": False, "Principal": {"Value": "svc.amazonaws.com"}},
            age_days=30,
        )
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["operator_principal"] == "svc.amazonaws.com"

    def test_operator_principal_non_string_non_dict_gives_null(self, mock_boto3_session):
        """Spec 4: Operator.Principal is unrecognized type → null."""
        vol = _vol(operator={"Managed": False, "Principal": 12345}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["operator_principal"] is None


# ---------------------------------------------------------------------------
# 7 Confidence model
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_is_medium(self, mock_boto3_session):
        """Spec 7: emitted findings must use MEDIUM confidence."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# 8 Risk model
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_low(self, mock_boto3_session):
        """Spec 8: emitted findings must use LOW risk."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# 12 Evidence contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_all_required_detail_fields_present(self, mock_boto3_session):
        """Spec 12: all required detail fields must be present on emitted findings."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        d = findings[0].details
        required = [
            "evaluation_path",
            "volume_id",
            "create_time",
            "age_days",
            "normalized_status",
            "attachment_count",
            "service_managed_check",
            "operator_principal",
            "availability_zone",
            "size_gib",
            "volume_type",
            "multi_attach_enabled",
            "iops",
            "throughput_mibps",
            "encrypted",
            "snapshot_id",
        ]
        for field in required:
            assert field in d, f"Missing required detail field: {field!r}"

    def test_evaluation_path_value(self, mock_boto3_session):
        """Spec 12: evaluation_path must be exactly 'unattached-volume-review-candidate'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["evaluation_path"] == "unattached-volume-review-candidate"

    def test_normalized_status_is_available(self, mock_boto3_session):
        """Spec 12: normalized_status must be 'available' for emitted findings."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["normalized_status"] == "available"

    def test_attachment_count_is_zero(self, mock_boto3_session):
        """Spec 12: attachment_count must be 0 for emitted findings."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["attachment_count"] == 0

    def test_create_time_is_iso8601(self, mock_boto3_session):
        """Spec 12: create_time must be ISO-8601 string."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        # If isoformat() succeeded, this is a valid ISO-8601 string.
        assert isinstance(findings[0].details["create_time"], str)
        assert "T" in findings[0].details["create_time"]

    def test_age_days_is_integer(self, mock_boto3_session):
        """Spec 12: age_days must be a non-negative integer."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        age = findings[0].details["age_days"]
        assert isinstance(age, int)
        assert age >= 0

    def test_service_managed_check_unknown_string(self, mock_boto3_session):
        """Spec 12: service_managed_check must be 'unknown' (not False) when operator absent."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_signals_not_checked_present(self, mock_boto3_session):
        """Spec 11: blind spots must be disclosed in signals_not_checked."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        snc = findings[0].evidence.signals_not_checked
        assert isinstance(snc, list)
        assert len(snc) > 0

    def test_volume_id_in_details(self, mock_boto3_session):
        """Spec 12: volume_id must match resource_id."""
        findings = _run(mock_boto3_session, [_vol(volume_id="vol-xyz", age_days=30)])
        assert findings[0].details["volume_id"] == "vol-xyz"
        assert findings[0].resource_id == "vol-xyz"


# ---------------------------------------------------------------------------
# 13 Title and reason contract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title(self, mock_boto3_session):
        """Spec 13: title must be exactly 'Unattached EBS volume review candidate'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].title == "Unattached EBS volume review candidate"

    def test_reason(self, mock_boto3_session):
        """Spec 13: reason must match canonical wording."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].reason == (
            "Volume has normalized attachment_count == 0 and the "
            "service-managed exclusion did not match"
        )

    def test_title_not_unused(self, mock_boto3_session):
        """Spec 13: title must not call volume 'unused'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert "unused" not in findings[0].title.lower()

    def test_title_not_orphaned(self, mock_boto3_session):
        """Spec 13: title must not call volume 'orphaned'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert "orphaned" not in findings[0].title.lower()

    def test_title_not_safe_to_delete(self, mock_boto3_session):
        """Spec 13: title must not call volume 'safe to delete'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert "safe to delete" not in findings[0].title.lower()


# ---------------------------------------------------------------------------
# 9 Cost model
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_no_cost_estimate(self, mock_boto3_session):
        """Spec 9: estimated_monthly_cost_usd must be None (flat rate invalid)."""
        for vtype in ("gp2", "gp3", "io1", "io2", "sc1", "st1", "standard"):
            findings = _run(mock_boto3_session, [_vol(age_days=30, volume_type=vtype)])
            assert (
                findings[0].estimated_monthly_cost_usd is None
            ), f"expected None cost for volume_type={vtype!r}"

    def test_size_gib_present_as_context(self, mock_boto3_session):
        """Spec 9: size_gib available as non-billing context."""
        findings = _run(mock_boto3_session, [_vol(age_days=30, size_gib=500)])
        assert findings[0].details["size_gib"] == 500


# ---------------------------------------------------------------------------
# 10 Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multi_page_pagination(self, mock_boto3_session):
        """Spec 10: must paginate fully — findings collected across all pages."""
        ec2 = mock_boto3_session._ec2
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Volumes": [_vol(volume_id="vol-page1", age_days=30)]},
            {"Volumes": [_vol(volume_id="vol-page2", age_days=30)]},
            {"Volumes": [_vol(volume_id="vol-page3", age_days=30)]},
        ]
        ec2.get_paginator.return_value = paginator
        findings = find_unattached_ebs_volumes(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}
        assert ids == {"vol-page1", "vol-page2", "vol-page3"}

    def test_empty_page_returns_no_findings(self, mock_boto3_session):
        """Spec 10: empty pages produce no findings."""
        ec2 = mock_boto3_session._ec2
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Volumes": []}, {"Volumes": []}]
        ec2.get_paginator.return_value = paginator
        findings = find_unattached_ebs_volumes(mock_boto3_session, "us-east-1")
        assert findings == []


# ---------------------------------------------------------------------------
# 10 Failure behavior
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_unauthorized_operation_raises_permission_error(self, mock_boto3_session):
        """Spec 10: ec2:DescribeVolumes unavailable → PermissionError."""
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeVolumes",
        )
        with pytest.raises(PermissionError):
            find_unattached_ebs_volumes(mock_boto3_session, "us-east-1")

    def test_access_denied_raises_permission_error(self, mock_boto3_session):
        """AccessDenied is also a canonical permission error → PermissionError."""
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeVolumes",
        )
        with pytest.raises(PermissionError):
            find_unattached_ebs_volumes(mock_boto3_session, "us-east-1")

    def test_other_client_error_re_raised(self, mock_boto3_session):
        """Spec 10: non-auth ClientError re-raised without wrapping."""
        ec2 = mock_boto3_session._ec2
        ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "oops"}},
            "DescribeVolumes",
        )
        with pytest.raises(ClientError):
            find_unattached_ebs_volumes(mock_boto3_session, "us-east-1")

    def test_malformed_volume_skipped_others_emit(self, mock_boto3_session):
        """Spec 10: malformed item skipped; other valid items still processed."""
        malformed = _vol(age_days=30)
        del malformed["VolumeId"]
        valid = _vol(volume_id="vol-good", age_days=30)
        findings = _run(mock_boto3_session, [malformed, valid])
        assert len(findings) == 1
        assert findings[0].resource_id == "vol-good"


# ---------------------------------------------------------------------------
# 4 service_managed_check semantics
# ---------------------------------------------------------------------------


class TestServiceManagedCheck:
    def test_operator_managed_true_skips(self, mock_boto3_session):
        """Spec 4: service_managed_check=True → SKIP."""
        vol = _vol(operator={"Managed": True, "Principal": "svc.amazon.com"}, age_days=30)
        assert _run(mock_boto3_session, [vol]) == []

    def test_operator_managed_false_emits(self, mock_boto3_session):
        """Spec 4: service_managed_check=False → emit; service_managed_check=False in details."""
        vol = _vol(operator={"Managed": False, "Principal": "svc.amazon.com"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] is False

    def test_operator_key_absent_emits_with_unknown(self, mock_boto3_session):
        """Spec 4: no Operator key → service_managed_check='unknown' → emit."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] == "unknown"

    def test_operator_present_managed_key_absent_gives_unknown(self, mock_boto3_session):
        """Spec 4: Operator present but no Managed key → service_managed_check='unknown'."""
        vol = _vol(operator={"Principal": "svc.amazon.com"}, age_days=30)
        findings = _run(mock_boto3_session, [vol])
        assert len(findings) == 1
        assert findings[0].details["service_managed_check"] == "unknown"


# ---------------------------------------------------------------------------
# 2 Scope / provider metadata
# ---------------------------------------------------------------------------


class TestScope:
    def test_provider_is_aws(self, mock_boto3_session):
        """Finding provider must be 'aws'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].provider == "aws"

    def test_rule_id(self, mock_boto3_session):
        """Finding rule_id must be 'aws.ebs.unattached'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].rule_id == "aws.ebs.unattached"

    def test_resource_type(self, mock_boto3_session):
        """Finding resource_type must be 'aws.ebs.volume'."""
        findings = _run(mock_boto3_session, [_vol(age_days=30)])
        assert findings[0].resource_type == "aws.ebs.volume"

    def test_region_propagated(self, mock_boto3_session):
        """Region passed to the function must appear in the finding."""
        ec2 = mock_boto3_session._ec2
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Volumes": [_vol(age_days=30)]}]
        ec2.get_paginator.return_value = paginator
        findings = find_unattached_ebs_volumes(mock_boto3_session, "eu-west-1")
        assert findings[0].region == "eu-west-1"

    def test_multi_volume_multiple_findings(self, mock_boto3_session):
        """Multiple eligible volumes produce multiple findings."""
        vols = [
            _vol(volume_id="vol-a", age_days=30),
            _vol(volume_id="vol-b", age_days=60),
        ]
        findings = _run(mock_boto3_session, vols)
        ids = {f.resource_id for f in findings}
        assert ids == {"vol-a", "vol-b"}
