from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ec2_sg_unused import find_unused_security_groups


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


def _make_eni(sg_ids: list) -> dict:
    return {
        "NetworkInterfaceId": f"eni-{''.join(sg_ids)}",
        "Groups": [{"GroupId": sg_id} for sg_id in sg_ids],
    }


def _setup_two_paginators(ec2, sgs: list, enis: list, vpc_names: dict | None = None) -> None:
    """Set up separate paginator mocks for describe_security_groups and describe_network_interfaces.

    vpc_names: optional dict of {vpc_id: name} to simulate describe_vpcs responses.
    """
    sg_paginator = MagicMock()
    eni_paginator = MagicMock()

    sg_paginator.paginate.return_value = [{"SecurityGroups": sgs}]
    eni_paginator.paginate.return_value = [{"NetworkInterfaces": enis}]

    def paginator_side_effect(name):
        if name == "describe_security_groups":
            return sg_paginator
        if name == "describe_network_interfaces":
            return eni_paginator
        raise ValueError(f"Unexpected paginator: {name}")

    ec2.get_paginator.side_effect = paginator_side_effect

    # describe_vpcs: return tagged VPCs or empty list
    if vpc_names:
        vpcs = [
            {
                "VpcId": vpc_id,
                "Tags": [{"Key": "Name", "Value": name}],
            }
            for vpc_id, name in vpc_names.items()
        ]
    else:
        vpcs = []
    ec2.describe_vpcs.return_value = {"Vpcs": vpcs}


class TestFindUnusedSecurityGroups:
    def test_unused_sg_flagged(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-unused", "my-sg")],
            enis=[],  # No ENIs using any SG
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "sg-unused"
        assert f.rule_id == "aws.ec2.security_group.unused"
        assert f.provider == "aws"
        assert f.resource_type == "aws.ec2.security_group"
        assert f.confidence == ConfidenceLevel.MEDIUM
        assert f.risk == RiskLevel.LOW

    def test_sg_in_use_not_flagged(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-inuse", "attached-sg")],
            enis=[_make_eni(["sg-inuse"])],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_default_sg_skipped(self, mock_boto3_session):
        """Default security groups cannot be deleted — flagging them is noise."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-default", "default")],
            enis=[],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_mix_of_used_unused_default(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[
                _make_sg("sg-1", "used-sg"),
                _make_sg("sg-2", "unused-sg"),
                _make_sg("sg-3", "default"),
                _make_sg("sg-4", "also-unused"),
            ],
            enis=[_make_eni(["sg-1"])],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        ids = {f.resource_id for f in findings}

        assert "sg-1" not in ids  # in use
        assert "sg-2" in ids  # unused, should be flagged
        assert "sg-3" not in ids  # default, skip
        assert "sg-4" in ids  # unused, should be flagged

    def test_sg_used_by_multiple_enis(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-shared", "shared-sg")],
            enis=[
                _make_eni(["sg-shared"]),
                _make_eni(["sg-shared"]),
            ],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_details_populated(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        inbound = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": []}]
        _setup_two_paginators(
            ec2,
            sgs=[
                _make_sg(
                    "sg-detail",
                    name="test-sg",
                    vpc_id="vpc-abc",
                    description="Test security group",
                    inbound=inbound,
                    tags=[{"Key": "env", "Value": "dev"}],
                )
            ],
            enis=[],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.details["sg_name"] == "test-sg"
        assert f.details["vpc_id"] == "vpc-abc"
        assert f.details["description"] == "Test security group"
        # 1 inbound + 1 default outbound = 2 rules
        assert f.details["rule_count"] == 2
        assert f.details["tags"] == {"env": "dev"}

    def test_no_cost_estimate(self, mock_boto3_session):
        """Security groups don't have a direct cost — cost field should be None."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(ec2, sgs=[_make_sg("sg-nocost")], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_empty_account(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(ec2, sgs=[], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_sg_with_no_enis_but_all_default(self, mock_boto3_session):
        """Account with only default SGs should produce no findings."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[
                _make_sg("sg-d1", "default"),
                _make_sg("sg-d2", "default"),
            ],
            enis=[],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")
        assert findings == []

    def test_permission_error_raised(self, mock_boto3_session):
        ec2 = mock_boto3_session._ec2
        error = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
            "DescribeSecurityGroups",
        )

        sg_paginator = MagicMock()
        sg_paginator.paginate.side_effect = error
        ec2.get_paginator.return_value = sg_paginator

        with pytest.raises(PermissionError, match="ec2:DescribeSecurityGroups"):
            find_unused_security_groups(mock_boto3_session, "us-east-1")

    def test_rule_count_signal_in_evidence(self, mock_boto3_session):
        """An unused SG with rules defined should note that in the evidence signals."""
        ec2 = mock_boto3_session._ec2
        inbound = [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": []}]
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-rules", "has-rules", inbound=inbound)],
            enis=[],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        signals = findings[0].evidence.signals_used
        assert any("rule" in s.lower() for s in signals)

    def test_vpc_name_in_details_and_signals(self, mock_boto3_session):
        """VPC name should appear in details and signals when the VPC is tagged."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-named", "my-sg", vpc_id="vpc-abc")],
            enis=[],
            vpc_names={"vpc-abc": "my-vpc"},
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.details.get("vpc_name") == "my-vpc"
        assert any("my-vpc" in s for s in f.evidence.signals_used)
        assert "my-vpc" in f.summary

    def test_vpc_name_absent_when_describe_vpcs_fails(self, mock_boto3_session):
        """If describe_vpcs raises ClientError the rule should still produce findings."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[_make_sg("sg-fallback", "fallback-sg", vpc_id="vpc-xyz")],
            enis=[],
        )
        ec2.describe_vpcs.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Denied"}},
            "DescribeVpcs",
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        # vpc_name absent, vpc_id still present
        assert "vpc_name" not in f.details
        assert f.details["vpc_id"] == "vpc-xyz"

    def test_high_confidence_when_no_rules_not_referenced_not_service_managed(
        self, mock_boto3_session
    ):
        """A ruleless, unreferenced, non-service-managed SG is a strong orphan signal -> HIGH."""
        ec2 = mock_boto3_session._ec2
        # Build a SG with no inbound and no outbound rules at all
        sg = _make_sg("sg-empty", "orphan-sg", outbound=[])
        _setup_two_paginators(ec2, sgs=[sg], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_medium_confidence_when_tagged(self, mock_boto3_session):
        """A tagged SG keeps MEDIUM confidence — tags suggest intent."""
        ec2 = mock_boto3_session._ec2
        sg = _make_sg("sg-tagged", "tagged-sg", outbound=[], tags=[{"Key": "env", "Value": "dev"}])
        _setup_two_paginators(ec2, sgs=[sg], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_medium_confidence_when_has_rules(self, mock_boto3_session):
        """SG with rules keeps MEDIUM confidence (rules suggest intentionality)."""
        ec2 = mock_boto3_session._ec2
        inbound = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": []}]
        _setup_two_paginators(ec2, sgs=[_make_sg("sg-ruled", "ruled-sg", inbound=inbound)], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_medium_confidence_when_service_managed(self, mock_boto3_session):
        """Service-managed SG keeps MEDIUM confidence even with no rules."""
        ec2 = mock_boto3_session._ec2
        sg = _make_sg("sg-eks", "eks-cluster-sg", outbound=[])
        _setup_two_paginators(ec2, sgs=[sg], enis=[])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_medium_confidence_when_referenced_by_other_sg(self, mock_boto3_session):
        """Referenced SG keeps MEDIUM confidence even with no rules."""
        ec2 = mock_boto3_session._ec2
        sg_source = _make_sg("sg-src", "source-sg", outbound=[])
        sg_ref = _make_sg(
            "sg-ref",
            "ref-sg",
            inbound=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [],
                    "UserIdGroupPairs": [{"GroupId": "sg-src", "UserId": "123456789012"}],
                }
            ],
        )
        _setup_two_paginators(ec2, sgs=[sg_source, sg_ref], enis=[_make_eni(["sg-ref"])])

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        assert findings[0].resource_id == "sg-src"
        assert findings[0].confidence == ConfidenceLevel.MEDIUM

    def test_sg_referenced_via_inbound_signals_and_details(self, mock_boto3_session):
        """SG referenced as inbound source by another SG should have a signal and detail flag."""
        ec2 = mock_boto3_session._ec2
        sg_source = _make_sg("sg-source", "source-sg")
        sg_consumer = _make_sg(
            "sg-consumer",
            "consumer-sg",
            inbound=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [],
                    "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "123456789012"}],
                }
            ],
        )
        _setup_two_paginators(
            ec2,
            sgs=[sg_source, sg_consumer],
            enis=[_make_eni(["sg-consumer"])],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "sg-source"
        assert f.details.get("referenced_by_other_sg") is True
        assert any(
            "Referenced by another security group in inbound or egress rules" in s
            for s in f.evidence.signals_used
        )
        assert any("may not indicate active usage" in s for s in f.evidence.signals_used)

    def test_sg_referenced_via_egress_signals_and_details(self, mock_boto3_session):
        """SG referenced in another SG's egress rule should also be flagged as referenced."""
        ec2 = mock_boto3_session._ec2
        sg_target = _make_sg("sg-target", "target-sg", outbound=[])
        sg_with_egress_ref = _make_sg(
            "sg-egress",
            "egress-sg",
            outbound=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [],
                    "UserIdGroupPairs": [{"GroupId": "sg-target", "UserId": "123456789012"}],
                }
            ],
        )
        _setup_two_paginators(
            ec2,
            sgs=[sg_target, sg_with_egress_ref],
            enis=[_make_eni(["sg-egress"])],  # egress-sg in use, target is not
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "sg-target"
        assert f.details.get("referenced_by_other_sg") is True

    def test_service_managed_prefix_adds_signal_and_detail(self, mock_boto3_session):
        """SGs with service-managed naming prefixes should have a heuristic signal."""
        ec2 = mock_boto3_session._ec2
        _setup_two_paginators(
            ec2,
            sgs=[
                _make_sg("sg-rds", "rds-my-database"),
                _make_sg("sg-eks", "eks-cluster-node"),
                _make_sg("sg-plain", "app-server"),
            ],
            enis=[],
        )

        findings = find_unused_security_groups(mock_boto3_session, "us-east-1")

        by_id = {f.resource_id: f for f in findings}
        assert len(findings) == 3

        for sg_id in ("sg-rds", "sg-eks"):
            f = by_id[sg_id]
            assert f.details.get("likely_service_managed") is True
            assert any("service-managed" in s.lower() for s in f.evidence.signals_used)

        assert "likely_service_managed" not in by_id["sg-plain"].details
