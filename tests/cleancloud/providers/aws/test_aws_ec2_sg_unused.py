"""
Tests for aws.ec2.security_group.unused rule.

Every test references its governing spec section in
docs/specs/aws/ec2_sg_unused.md
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ec2_sg_unused import find_unused_security_groups

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sg(
    sg_id: str,
    name: str = "",
    vpc_id: str = "vpc-123",
    description: str = "",
    inbound: list | None = None,
    outbound: list | None = None,
    tags: list | None = None,
) -> dict:
    return {
        "GroupId": sg_id,
        "GroupName": name or sg_id,
        "VpcId": vpc_id,
        "Description": description,
        "IpPermissions": inbound if inbound is not None else [],
        "IpPermissionsEgress": (outbound if outbound is not None else [{"IpProtocol": "-1"}]),
        "Tags": tags or [],
    }


def _make_eni(sg_ids: list, eni_id: str | None = None) -> dict:
    eid = eni_id or f"eni-{''.join(sg_ids) or 'empty'}"
    return {
        "NetworkInterfaceId": eid,
        "Groups": [{"GroupId": sg_id} for sg_id in sg_ids],
    }


def _setup_paginators(
    ec2,
    sgs: list,
    enis: list,
    vpc_names: dict | None = None,
) -> None:
    sg_paginator = MagicMock()
    eni_paginator = MagicMock()
    sg_paginator.paginate.return_value = [{"SecurityGroups": sgs}]
    eni_paginator.paginate.return_value = [{"NetworkInterfaces": enis}]

    def _get_paginator(name):
        if name == "describe_security_groups":
            return sg_paginator
        if name == "describe_network_interfaces":
            return eni_paginator
        raise ValueError(f"Unexpected paginator: {name}")

    ec2.get_paginator.side_effect = _get_paginator

    vpcs = [
        {"VpcId": vid, "Tags": [{"Key": "Name", "Value": vname}]}
        for vid, vname in (vpc_names or {}).items()
    ]
    ec2.describe_vpcs.return_value = {"Vpcs": vpcs}


def _run(mock_boto3_session, sgs, enis=None, vpc_names=None):
    ec2 = mock_boto3_session._ec2
    _setup_paginators(ec2, sgs, enis or [], vpc_names=vpc_names)
    return find_unused_security_groups(mock_boto3_session, "us-east-1")


# ---------------------------------------------------------------------------
# §15 Must emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_unused_sg_emitted(self, mock_boto3_session):
        """Spec §15: non-default SG with no ENI associations → emit."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1", "my-sg")], enis=[])
        assert len(findings) == 1
        assert findings[0].resource_id == "sg-1"

    def test_emit_when_referenced_by_other_sg(self, mock_boto3_session):
        """Spec §5/§15: referenced_by_other_sg must not suppress a finding."""
        sg_ref = _make_sg(
            "sg-ref",
            inbound=[{"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-target"}]}],
        )
        sg_target = _make_sg("sg-target", "target-sg")
        findings = _run(mock_boto3_session, [sg_ref, sg_target], enis=[_make_eni(["sg-ref"])])
        ids = {f.resource_id for f in findings}
        assert "sg-target" in ids

    def test_emit_when_has_rules(self, mock_boto3_session):
        """Spec §5/§15: rule_count > 0 must not suppress a finding."""
        inbound = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": []}]
        findings = _run(mock_boto3_session, [_make_sg("sg-rules", inbound=inbound)])
        assert len(findings) == 1

    def test_emit_when_has_tags(self, mock_boto3_session):
        """Spec §5/§15: tags must not suppress a finding."""
        sg = _make_sg("sg-tagged", tags=[{"Key": "env", "Value": "prod"}])
        findings = _run(mock_boto3_session, [sg])
        assert len(findings) == 1

    def test_emit_when_service_managed_prefix(self, mock_boto3_session):
        """Spec §6.5/§15: service-managed name hint must not suppress a finding."""
        findings = _run(mock_boto3_session, [_make_sg("sg-eks", "eks-cluster")])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# §15 Must skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_default_sg(self, mock_boto3_session):
        """Spec §8: GroupName == 'default' → SKIP."""
        findings = _run(mock_boto3_session, [_make_sg("sg-d", "default")])
        assert findings == []

    def test_skip_sg_with_eni_association(self, mock_boto3_session):
        """Spec §8: attached_eni_count > 0 → SKIP."""
        findings = _run(
            mock_boto3_session,
            [_make_sg("sg-used", "used-sg")],
            enis=[_make_eni(["sg-used"])],
        )
        assert findings == []

    def test_skip_malformed_sg_missing_group_id(self, mock_boto3_session):
        """Spec §8/§9: sg_id absent → SKIP item."""
        sg = {"GroupName": "no-id-sg", "VpcId": "vpc-1", "IpPermissions": [], "Tags": []}
        findings = _run(mock_boto3_session, [sg])
        assert findings == []

    def test_skip_malformed_but_emit_valid(self, mock_boto3_session):
        """Spec §9: malformed SG skipped; other valid SGs still emitted."""
        malformed = {"GroupName": "no-id", "VpcId": "vpc-1", "IpPermissions": [], "Tags": []}
        valid = _make_sg("sg-good", "good-sg")
        findings = _run(mock_boto3_session, [malformed, valid])
        assert len(findings) == 1
        assert findings[0].resource_id == "sg-good"

    def test_skip_sg_attached_via_multiple_enis(self, mock_boto3_session):
        """Spec §8: SG referenced by multiple ENIs still excluded."""
        findings = _run(
            mock_boto3_session,
            [_make_sg("sg-shared", "shared-sg")],
            enis=[
                _make_eni(["sg-shared"], eni_id="eni-1"),
                _make_eni(["sg-shared"], eni_id="eni-2"),
            ],
        )
        assert findings == []

    def test_mix_used_unused_default(self, mock_boto3_session):
        """Combined: in-use skipped, default skipped, unused emitted."""
        sgs = [
            _make_sg("sg-used", "used"),
            _make_sg("sg-free", "free"),
            _make_sg("sg-def", "default"),
        ]
        findings = _run(mock_boto3_session, sgs, enis=[_make_eni(["sg-used"])])
        ids = {f.resource_id for f in findings}
        assert ids == {"sg-free"}


# ---------------------------------------------------------------------------
# §6.4 Reference parsing — context-only, must degrade safely
# ---------------------------------------------------------------------------


class TestReferenceParsingDegradation:
    def test_non_dict_rule_entry_skipped_finding_still_emitted(self, mock_boto3_session):
        """Spec §6.4/§5C: non-dict rule entry must be skipped; referenced_by_other_sg is
        context-only and must not abort baseline eligibility detection."""
        sg = _make_sg("sg-target", "target")
        # Inject a non-dict (string) into the ingress rules of the referencing SG.
        sg_ref = {
            "GroupId": "sg-ref",
            "GroupName": "ref-sg",
            "VpcId": "vpc-1",
            "Description": "",
            "IpPermissions": ["not-a-dict-rule"],  # malformed rule entry
            "IpPermissionsEgress": [],
            "Tags": [],
        }
        findings = _run(mock_boto3_session, [sg, sg_ref], enis=[_make_eni(["sg-ref"])])
        # sg-target must still be emitted despite the malformed rule entry.
        ids = {f.resource_id for f in findings}
        assert "sg-target" in ids

    def test_non_dict_pair_entry_skipped_finding_still_emitted(self, mock_boto3_session):
        """Spec §6.4: non-dict UserIdGroupPairs entry must be skipped without aborting the rule."""
        sg = _make_sg("sg-target", "target")
        sg_ref = {
            "GroupId": "sg-ref",
            "GroupName": "ref-sg",
            "VpcId": "vpc-1",
            "Description": "",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": ["not-a-dict-pair"],  # malformed pair entry
                }
            ],
            "IpPermissionsEgress": [],
            "Tags": [],
        }
        findings = _run(mock_boto3_session, [sg, sg_ref], enis=[_make_eni(["sg-ref"])])
        ids = {f.resource_id for f in findings}
        assert "sg-target" in ids


# ---------------------------------------------------------------------------
# §15 Must fail rule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_sg_pagination_failure_fails_rule(self, mock_boto3_session):
        """Spec §9: DescribeSecurityGroups failure → FAIL RULE."""
        ec2 = mock_boto3_session._ec2
        sg_pag = MagicMock()
        sg_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeSecurityGroups",
        )
        ec2.get_paginator.return_value = sg_pag
        with pytest.raises(PermissionError, match="ec2:DescribeSecurityGroups"):
            find_unused_security_groups(mock_boto3_session, "us-east-1")

    def test_eni_pagination_failure_fails_rule(self, mock_boto3_session):
        """Spec §9: DescribeNetworkInterfaces failure → FAIL RULE."""
        ec2 = mock_boto3_session._ec2
        sg_pag = MagicMock()
        sg_pag.paginate.return_value = [{"SecurityGroups": [_make_sg("sg-1")]}]
        eni_pag = MagicMock()
        eni_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeNetworkInterfaces",
        )

        def _get_pag(name):
            if name == "describe_security_groups":
                return sg_pag
            return eni_pag

        ec2.get_paginator.side_effect = _get_pag
        ec2.describe_vpcs.return_value = {"Vpcs": []}
        with pytest.raises(PermissionError, match="ec2:DescribeNetworkInterfaces"):
            find_unused_security_groups(mock_boto3_session, "us-east-1")

    def test_eni_missing_network_interface_id_fails_rule(self, mock_boto3_session):
        """Spec §9: ENI missing NetworkInterfaceId → cannot deduplicate → FAIL RULE."""
        malformed_eni = {"Groups": [{"GroupId": "sg-1"}]}  # no NetworkInterfaceId
        with pytest.raises(RuntimeError, match="ENI payload shape"):
            _run(mock_boto3_session, [_make_sg("sg-1")], enis=[malformed_eni])

    def test_eni_missing_groups_key_fails_rule(self, mock_boto3_session):
        """Spec §9: ENI missing Groups/GroupSet key → cannot determine membership → FAIL RULE."""
        malformed_eni = {"NetworkInterfaceId": "eni-abc"}  # no Groups key
        with pytest.raises(RuntimeError, match="ENI payload shape"):
            _run(mock_boto3_session, [_make_sg("sg-1")], enis=[malformed_eni])

    def test_eni_non_list_groups_fails_rule(self, mock_boto3_session):
        """Spec §9: ENI Groups is not a list → malformed membership → FAIL RULE."""
        malformed_eni = {"NetworkInterfaceId": "eni-abc", "Groups": "sg-1"}
        with pytest.raises(RuntimeError, match="ENI payload shape"):
            _run(mock_boto3_session, [_make_sg("sg-1")], enis=[malformed_eni])

    def test_eni_non_dict_group_entry_fails_rule(self, mock_boto3_session):
        """Spec §9: non-dict group entry inside ENI Groups → membership corruption → FAIL RULE.

        Silently skipping would undercount associations and create false positives.
        """
        malformed_eni = {"NetworkInterfaceId": "eni-abc", "Groups": ["not-a-dict"]}
        with pytest.raises(RuntimeError, match="ENI payload shape"):
            _run(mock_boto3_session, [_make_sg("sg-1")], enis=[malformed_eni])

    def test_non_auth_client_error_re_raised(self, mock_boto3_session):
        """Non-auth ClientError propagates as-is."""
        ec2 = mock_boto3_session._ec2
        sg_pag = MagicMock()
        sg_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "oops"}},
            "DescribeSecurityGroups",
        )
        ec2.get_paginator.return_value = sg_pag
        with pytest.raises(ClientError):
            find_unused_security_groups(mock_boto3_session, "us-east-1")


# ---------------------------------------------------------------------------
# §6 Normalization contract
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_sg_id_from_group_id(self, mock_boto3_session):
        """Spec §6.3: sg_id derived from GroupId."""
        findings = _run(mock_boto3_session, [_make_sg("sg-abc")])
        assert findings[0].resource_id == "sg-abc"
        assert findings[0].details["sg_id"] == "sg-abc"

    def test_attached_eni_count_from_distinct_enis(self, mock_boto3_session):
        """Spec §6.2: attached_eni_count counts distinct ENI IDs."""
        # Two ENIs with same SG → sg excluded (count > 0)
        findings = _run(
            mock_boto3_session,
            [_make_sg("sg-1"), _make_sg("sg-2")],
            enis=[
                _make_eni(["sg-1"], eni_id="eni-a"),
                _make_eni(["sg-1"], eni_id="eni-b"),
            ],
        )
        ids = {f.resource_id for f in findings}
        assert "sg-1" not in ids
        assert "sg-2" in ids

    def test_referenced_by_other_sg_from_ingress(self, mock_boto3_session):
        """Spec §6.4: referenced_by_other_sg detected from ingress UserIdGroupPairs."""
        sg_a = _make_sg(
            "sg-a",
            inbound=[{"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-b"}]}],
        )
        sg_b = _make_sg("sg-b", "target")
        findings = _run(mock_boto3_session, [sg_a, sg_b], enis=[_make_eni(["sg-a"])])
        assert findings[0].resource_id == "sg-b"
        assert findings[0].details["referenced_by_other_sg"] is True

    def test_referenced_by_other_sg_from_egress(self, mock_boto3_session):
        """Spec §6.4: referenced_by_other_sg detected from egress UserIdGroupPairs."""
        sg_egress = _make_sg(
            "sg-egress",
            outbound=[{"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-target"}]}],
        )
        sg_target = _make_sg("sg-target", "target")
        findings = _run(
            mock_boto3_session,
            [sg_egress, sg_target],
            enis=[_make_eni(["sg-egress"])],
        )
        assert findings[0].resource_id == "sg-target"
        assert findings[0].details["referenced_by_other_sg"] is True

    def test_cidr_rules_do_not_set_referenced_by_other_sg(self, mock_boto3_session):
        """Spec §6.4: CIDR ranges must not contribute to referenced_by_other_sg."""
        sg = _make_sg(
            "sg-cidr",
            inbound=[{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        findings = _run(mock_boto3_session, [sg])
        assert findings[0].details["referenced_by_other_sg"] is False

    def test_is_default_group_false_for_emitted(self, mock_boto3_session):
        """Spec §12: is_default_group must be False for all emitted findings."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1", "my-sg")])
        assert findings[0].details["is_default_group"] is False

    def test_eni_groups_empty_list_not_fail(self, mock_boto3_session):
        """Spec §9: ENI with empty Groups list is valid — contributes 0 associations."""
        eni = {"NetworkInterfaceId": "eni-empty", "Groups": []}
        findings = _run(mock_boto3_session, [_make_sg("sg-1")], enis=[eni])
        assert len(findings) == 1  # SG still unattached


# ---------------------------------------------------------------------------
# §7 Confidence model
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_is_medium_for_plain_sg(self, mock_boto3_session):
        """Spec §7: MEDIUM confidence for all emitted findings."""
        sg = _make_sg("sg-plain", "plain", outbound=[])
        findings = _run(mock_boto3_session, [sg])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_confidence_is_medium_not_high_even_when_no_rules_no_tags(self, mock_boto3_session):
        """Spec §7: HIGH must not be used — MEDIUM is the mandatory default."""
        sg = _make_sg("sg-empty", "orphan-sg", outbound=[], tags=[])
        findings = _run(mock_boto3_session, [sg])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM
        assert findings[0].confidence != ConfidenceLevel.HIGH

    def test_confidence_is_medium_when_referenced(self, mock_boto3_session):
        """Spec §7: referenced_by_other_sg must not affect confidence."""
        sg_ref = _make_sg(
            "sg-ref",
            inbound=[{"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-t"}]}],
        )
        sg_t = _make_sg("sg-t", outbound=[])
        findings = _run(mock_boto3_session, [sg_ref, sg_t], enis=[_make_eni(["sg-ref"])])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_confidence_is_medium_when_service_managed_hint(self, mock_boto3_session):
        """Spec §7/§6.5: service-managed hint must not affect confidence."""
        findings = _run(mock_boto3_session, [_make_sg("sg-eks", "eks-cluster", outbound=[])])
        assert findings[0].confidence == ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# §8 Risk model
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_low(self, mock_boto3_session):
        """Spec §8: emitted findings must use LOW risk."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# §12 Evidence contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_all_required_detail_fields_present(self, mock_boto3_session):
        """Spec §12: all required detail fields must be present on emitted findings."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1", "my-sg")])
        d = findings[0].details
        required = [
            "evaluation_path",
            "sg_id",
            "sg_name",
            "vpc_id",
            "attached_eni_count",
            "referenced_by_other_sg",
            "rule_count",
            "description",
            "is_default_group",
            "region_scope_only",
        ]
        for field in required:
            assert field in d, f"Missing required detail field: {field!r}"

    def test_evaluation_path_value(self, mock_boto3_session):
        """Spec §12: evaluation_path must be exactly 'unused-security-group-review-candidate'."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].details["evaluation_path"] == "unused-security-group-review-candidate"

    def test_attached_eni_count_is_zero(self, mock_boto3_session):
        """Spec §12: attached_eni_count must be 0 for emitted findings."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].details["attached_eni_count"] == 0

    def test_is_default_group_is_false(self, mock_boto3_session):
        """Spec §12: is_default_group must be False for emitted findings."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].details["is_default_group"] is False

    def test_region_scope_only_is_true(self, mock_boto3_session):
        """Spec §12: region_scope_only must be True for all emitted findings."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].details["region_scope_only"] is True

    def test_referenced_by_other_sg_always_present(self, mock_boto3_session):
        """Spec §12: referenced_by_other_sg must always be in details (not conditional)."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert "referenced_by_other_sg" in findings[0].details

    def test_referenced_by_other_sg_false_when_not_referenced(self, mock_boto3_session):
        """Spec §12: referenced_by_other_sg must be False (not absent) when not referenced."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].details["referenced_by_other_sg"] is False

    def test_referenced_by_other_sg_true_when_referenced(self, mock_boto3_session):
        """Spec §12: referenced_by_other_sg must be True when SG appears in another's rules."""
        sg_src = _make_sg(
            "sg-src",
            inbound=[{"IpProtocol": "tcp", "UserIdGroupPairs": [{"GroupId": "sg-tgt"}]}],
        )
        sg_tgt = _make_sg("sg-tgt")
        findings = _run(mock_boto3_session, [sg_src, sg_tgt], enis=[_make_eni(["sg-src"])])
        assert findings[0].details["referenced_by_other_sg"] is True

    def test_description_always_present_even_when_empty(self, mock_boto3_session):
        """Spec §12: description must always be in details (null if absent)."""
        sg = _make_sg("sg-1")
        del sg["Description"]
        findings = _run(mock_boto3_session, [sg])
        assert "description" in findings[0].details

    def test_signals_not_checked_covers_blind_spots(self, mock_boto3_session):
        """Spec §11: signals_not_checked must cover major blind spots."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        snc = findings[0].evidence.signals_not_checked
        assert isinstance(snc, list)
        assert len(snc) >= 5
        combined = " ".join(snc).lower()
        assert "launch template" in combined or "auto scaling" in combined
        assert "vpc association" in combined
        assert "eventual" in combined or "consistency" in combined

    def test_tags_in_details_when_present(self, mock_boto3_session):
        """Spec §12 optional: tags present in details when SG has tags."""
        sg = _make_sg("sg-tagged", tags=[{"Key": "env", "Value": "dev"}])
        findings = _run(mock_boto3_session, [sg])
        assert findings[0].details.get("tags") == {"env": "dev"}

    def test_heuristic_service_managed_hint_in_details(self, mock_boto3_session):
        """Spec §12 optional: heuristic_service_managed_hint present when name matches prefix."""
        findings = _run(mock_boto3_session, [_make_sg("sg-rds", "rds-my-db")])
        assert findings[0].details.get("heuristic_service_managed_hint") is True

    def test_heuristic_service_managed_hint_absent_for_plain_sg(self, mock_boto3_session):
        """Spec §12: heuristic_service_managed_hint absent when name does not match prefix."""
        findings = _run(mock_boto3_session, [_make_sg("sg-plain", "app-server")])
        assert "heuristic_service_managed_hint" not in findings[0].details


# ---------------------------------------------------------------------------
# §13 Title and reason contract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title(self, mock_boto3_session):
        """Spec §13: title must be 'Unused security group review candidate'."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].title == "Unused security group review candidate"

    def test_reason(self, mock_boto3_session):
        """Spec §13: reason must match canonical wording."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].reason == (
            "Security group has normalized attachment_eni_count == 0 "
            "and the default-group exclusion did not match"
        )

    def test_title_not_safe_to_delete(self, mock_boto3_session):
        """Spec §13: title must not imply delete-safe."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert "safe to delete" not in findings[0].title.lower()


# ---------------------------------------------------------------------------
# §9 Cost model
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_no_cost_estimate(self, mock_boto3_session):
        """Spec §9: SGs have no direct cost — estimated_monthly_cost_usd must be None."""
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# §6.1/§6.2 Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multi_page_sg_pagination(self, mock_boto3_session):
        """Spec §14: DescribeSecurityGroups must be fully paginated."""
        ec2 = mock_boto3_session._ec2
        sg_pag = MagicMock()
        sg_pag.paginate.return_value = [
            {"SecurityGroups": [_make_sg("sg-p1")]},
            {"SecurityGroups": [_make_sg("sg-p2")]},
        ]
        eni_pag = MagicMock()
        eni_pag.paginate.return_value = [{"NetworkInterfaces": []}]

        def _get_pag(name):
            if name == "describe_security_groups":
                return sg_pag
            return eni_pag

        ec2.get_paginator.side_effect = _get_pag
        ec2.describe_vpcs.return_value = {"Vpcs": []}
        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}
        assert ids == {"sg-p1", "sg-p2"}

    def test_multi_page_eni_pagination(self, mock_boto3_session):
        """Spec §14: DescribeNetworkInterfaces must be fully paginated."""
        ec2 = mock_boto3_session._ec2
        sg_pag = MagicMock()
        sg_pag.paginate.return_value = [
            {"SecurityGroups": [_make_sg("sg-used"), _make_sg("sg-free")]}
        ]
        eni_pag = MagicMock()
        eni_pag.paginate.return_value = [
            {"NetworkInterfaces": [_make_eni(["sg-used"], eni_id="eni-1")]},
            {"NetworkInterfaces": []},
        ]

        def _get_pag(name):
            if name == "describe_security_groups":
                return sg_pag
            return eni_pag

        ec2.get_paginator.side_effect = _get_pag
        ec2.describe_vpcs.return_value = {"Vpcs": []}
        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}
        assert "sg-used" not in ids
        assert "sg-free" in ids


# ---------------------------------------------------------------------------
# Optional VPC name enrichment
# ---------------------------------------------------------------------------


class TestVpcEnrichment:
    def test_vpc_name_in_details_and_signals(self, mock_boto3_session):
        """Spec §6 optional: vpc_name captured when VPC is tagged."""
        findings = _run(
            mock_boto3_session,
            [_make_sg("sg-1", "my-sg", vpc_id="vpc-abc")],
            vpc_names={"vpc-abc": "my-vpc"},
        )
        assert findings[0].details.get("vpc_name") == "my-vpc"
        assert any("my-vpc" in s for s in findings[0].evidence.signals_used)
        assert "my-vpc" in findings[0].summary

    def test_vpc_name_absent_when_describe_vpcs_fails(self, mock_boto3_session):
        """Spec §10: DescribeVpcs failure must not fail the rule."""
        ec2 = mock_boto3_session._ec2
        _setup_paginators(ec2, [_make_sg("sg-1", vpc_id="vpc-xyz")], [])
        ec2.describe_vpcs.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeVpcs",
        )
        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert len(findings) == 1
        assert "vpc_name" not in findings[0].details
        assert findings[0].details["vpc_id"] == "vpc-xyz"


# ---------------------------------------------------------------------------
# §2 Scope / provider metadata
# ---------------------------------------------------------------------------


class TestScope:
    def test_provider_is_aws(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].provider == "aws"

    def test_rule_id(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].rule_id == "aws.ec2.security_group.unused"

    def test_resource_type(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_make_sg("sg-1")])
        assert findings[0].resource_type == "aws.ec2.security_group"

    def test_region_propagated(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_paginators(ec2, [_make_sg("sg-1")], [])
        findings = find_unused_security_groups(mock_boto3_session, "eu-west-1")
        assert findings[0].region == "eu-west-1"

    def test_empty_account_returns_no_findings(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [])
        assert findings == []

    def test_all_default_returns_no_findings(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_make_sg("sg-d1", "default"), _make_sg("sg-d2", "default")],
        )
        assert findings == []
