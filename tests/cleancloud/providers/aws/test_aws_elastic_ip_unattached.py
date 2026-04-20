import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.elastic_ip_unattached import find_unattached_elastic_ips

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"


def _eip(
    allocation_id: str | None = "eipalloc-001",
    public_ip: str | None = "203.0.113.1",
    domain: str | None = "vpc",
    association_id: str | None = None,
    instance_id: str | None = None,
    network_interface_id: str | None = None,
    private_ip_address: str | None = None,
    carrier_ip: str | None = None,
    tags: list | None = None,
    **extra,
) -> dict:
    raw: dict = {}
    if allocation_id is not None:
        raw["AllocationId"] = allocation_id
    if public_ip is not None:
        raw["PublicIp"] = public_ip
    if domain is not None:
        raw["Domain"] = domain
    if association_id is not None:
        raw["AssociationId"] = association_id
    if instance_id is not None:
        raw["InstanceId"] = instance_id
    if network_interface_id is not None:
        raw["NetworkInterfaceId"] = network_interface_id
    if private_ip_address is not None:
        raw["PrivateIpAddress"] = private_ip_address
    if carrier_ip is not None:
        raw["CarrierIp"] = carrier_ip
    if tags is not None:
        raw["Tags"] = tags
    raw.update(extra)
    return raw


def _run(mock_boto3_session, addresses: list) -> list:
    mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": addresses}
    return find_unattached_elastic_ips(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_vpc_eip_no_association_fields(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert len(findings) == 1
        f = findings[0]
        assert f.resource_id == "eipalloc-001"
        assert f.rule_id == "aws.ec2.elastic_ip.unattached"
        assert f.provider == "aws"
        assert f.resource_type == "aws.ec2.elastic_ip"
        assert f.region == _REGION

    def test_standard_domain_no_association_fields(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip="203.0.113.10", domain="standard")],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "203.0.113.10"

    def test_carrier_ip_only_as_resource_id(self, mock_boto3_session):
        """When only CarrierIp is present, it becomes the resource_id."""
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip=None, carrier_ip="203.0.113.20")],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "203.0.113.20"

    def test_byoip_and_service_managed_contextual_only(self, mock_boto3_session):
        """BYOIP / service_managed fields are contextual and must not suppress the finding."""
        findings = _run(
            mock_boto3_session,
            [
                _eip(
                    PublicIpv4Pool="ipv4pool-ec2-abc",
                    ServiceManaged=True,
                    CustomerOwnedIp="10.0.0.5",
                    CustomerOwnedIpv4Pool="coip-pool-001",
                )
            ],
        )
        assert len(findings) == 1

    def test_service_managed_false_still_emits(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(ServiceManaged=False)])
        assert len(findings) == 1

    def test_tags_present_still_emits(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(tags=[{"Key": "env", "Value": "prod"}])],
        )
        assert len(findings) == 1

    def test_multiple_unattached_all_emitted(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [
                _eip(allocation_id="eipalloc-a", public_ip="1.2.3.4"),
                _eip(allocation_id="eipalloc-b", public_ip="1.2.3.5"),
            ],
        )
        assert {f.resource_id for f in findings} == {"eipalloc-a", "eipalloc-b"}

    def test_empty_addresses_returns_empty(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [])
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_association_id_present(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(association_id="eipassoc-123")],
        )
        assert findings == []

    def test_instance_id_present_no_association_id(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(instance_id="i-abc")])
        assert findings == []

    def test_network_interface_id_present_no_association_id(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(network_interface_id="eni-abc")])
        assert findings == []

    def test_private_ip_address_present_no_association_id(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(private_ip_address="10.0.0.5")])
        assert findings == []

    def test_missing_all_identity_fields(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip=None, carrier_ip=None)],
        )
        assert findings == []

    def test_mixed_attached_and_unattached(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [
                _eip(allocation_id="eipalloc-attached", association_id="eipassoc-x"),
                _eip(allocation_id="eipalloc-free"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "eipalloc-free"

    def test_non_dict_item_skipped_not_raised(self, mock_boto3_session):
        """Non-dict items in Addresses must be skipped, not raise."""
        valid = _eip()
        for bad in (None, "string", 42, ["list"]):
            mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": [bad, valid]}
            findings = find_unattached_elastic_ips(mock_boto3_session, _REGION)
            assert len(findings) == 1, f"Expected 1 finding with bad item={bad!r}"

    def test_all_four_association_fields_each_independently_skip(self, mock_boto3_session):
        """Each of the four association fields independently triggers SKIP."""
        for field, value in [
            ("association_id", "eipassoc-1"),
            ("instance_id", "i-001"),
            ("network_interface_id", "eni-001"),
            ("private_ip_address", "10.0.0.1"),
        ]:
            findings = _run(mock_boto3_session, [_eip(**{field: value})])
            assert findings == [], f"Expected SKIP when {field} is present"


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_describe_addresses_unauthorized(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeAddresses",
        )
        with pytest.raises(PermissionError, match="ec2:DescribeAddresses"):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_describe_addresses_access_denied(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeAddresses",
        )
        with pytest.raises(PermissionError, match="ec2:DescribeAddresses"):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_describe_addresses_client_error_propagates(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.side_effect = ClientError(
            {"Error": {"Code": "RequestExpired", "Message": "expired"}},
            "DescribeAddresses",
        )
        with pytest.raises(ClientError):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_describe_addresses_botocore_error_propagates(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_addresses_key_absent_fails_rule(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.return_value = {}
        with pytest.raises(RuntimeError, match="Addresses"):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_addresses_not_a_list_fails_rule(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": "bad"}
        with pytest.raises(RuntimeError, match="Addresses"):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)

    def test_addresses_none_fails_rule(self, mock_boto3_session):
        mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": None}
        with pytest.raises(RuntimeError, match="Addresses"):
            find_unattached_elastic_ips(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_allocation_id_is_preferred_resource_id(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id="eipalloc-pref", public_ip="1.2.3.4")],
        )
        assert findings[0].resource_id == "eipalloc-pref"

    def test_public_ip_fallback_when_no_allocation_id(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip="5.6.7.8")],
        )
        assert findings[0].resource_id == "5.6.7.8"

    def test_carrier_ip_fallback_when_no_allocation_or_public(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip=None, carrier_ip="9.10.11.12")],
        )
        assert findings[0].resource_id == "9.10.11.12"

    def test_domain_absent_is_null_in_details(self, mock_boto3_session):
        raw = {"AllocationId": "eipalloc-nd", "PublicIp": "1.2.3.4"}
        _run(mock_boto3_session, [raw])
        mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": [raw]}
        findings = find_unattached_elastic_ips(mock_boto3_session, _REGION)
        assert findings[0].details["domain"] is None

    def test_empty_string_fields_treated_as_absent(self, mock_boto3_session):
        """Empty string AllocationId must not be used as resource_id."""
        raw = {"AllocationId": "", "PublicIp": "1.2.3.4"}
        mock_boto3_session._ec2.describe_addresses.return_value = {"Addresses": [raw]}
        findings = find_unattached_elastic_ips(mock_boto3_session, _REGION)
        assert findings[0].resource_id == "1.2.3.4"

    def test_optional_context_fields_captured(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [
                _eip(
                    NetworkBorderGroup="us-east-1-wl1-bos-wlz-1",
                    PublicIpv4Pool="ipv4pool-ec2-abc",
                    SubnetId="subnet-xyz",
                    NetworkInterfaceOwnerId="111122223333",
                    CustomerOwnedIp="10.0.0.5",
                    CustomerOwnedIpv4Pool="coip-001",
                )
            ],
        )
        d = findings[0].details
        assert d["network_border_group"] == "us-east-1-wl1-bos-wlz-1"
        assert d["public_ipv4_pool"] == "ipv4pool-ec2-abc"
        assert d["subnet_id"] == "subnet-xyz"
        assert d["network_interface_owner_id"] == "111122223333"
        assert d["customer_owned_ip"] == "10.0.0.5"
        assert d["customer_owned_ipv4_pool"] == "coip-001"

    def test_service_managed_string_enum_captured(self, mock_boto3_session):
        """ServiceManaged is a string enum — captured as string context."""
        for value in ("alb", "nlb", "rnat", "rds"):
            findings = _run(mock_boto3_session, [_eip(ServiceManaged=value)])
            assert findings[0].details["service_managed"] == value

    def test_service_managed_non_string_not_in_details(self, mock_boto3_session):
        """Non-string values (e.g. bool) must not be treated as valid string enum."""
        for bad in (True, False, 1, None):
            findings = _run(mock_boto3_session, [_eip(ServiceManaged=bad)])
            assert "service_managed" not in findings[0].details

    def test_service_managed_empty_string_not_in_details(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(ServiceManaged="")])
        assert "service_managed" not in findings[0].details

    def test_tags_normalized_to_dict(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(tags=[{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "ops"}])],
        )
        assert findings[0].details["tags"] == {"env": "prod", "team": "ops"}

    def test_empty_tags_not_in_details(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip(tags=[])])
        assert "tags" not in findings[0].details

    def test_allocation_id_null_in_details_when_absent(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip="1.2.3.4")],
        )
        assert findings[0].details["allocation_id"] is None

    def test_carrier_ip_null_in_details_when_absent(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].details["carrier_ip"] is None


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_always_high_confidence(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_standard_domain_also_high(self, mock_boto3_session):
        findings = _run(
            mock_boto3_session,
            [_eip(allocation_id=None, public_ip="1.2.3.4", domain="standard")],
        )
        assert findings[0].confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_low(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self, mock_boto3_session):
        """No hardcoded cost estimate allowed — must be None."""
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_all_required_fields_present(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        d = findings[0].details
        required = [
            "evaluation_path",
            "resource_id",
            "allocation_id",
            "public_ip",
            "carrier_ip",
            "domain",
            "currently_associated",
            "association_id",
            "instance_id",
            "network_interface_id",
            "private_ip_address",
        ]
        for field in required:
            assert field in d, f"Missing required field: {field}"

    def test_evaluation_path_exact(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].details["evaluation_path"] == "unattached-eip-review-candidate"

    def test_currently_associated_always_false(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].details["currently_associated"] is False

    def test_association_fields_always_null(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        d = findings[0].details
        assert d["association_id"] is None
        assert d["instance_id"] is None
        assert d["network_interface_id"] is None
        assert d["private_ip_address"] is None

    def test_signals_used_mention_not_associated(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        combined = " ".join(findings[0].evidence.signals_used).lower()
        assert "not associated" in combined or "currently not associated" in combined

    def test_signals_used_mention_allocated(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        combined = " ".join(findings[0].evidence.signals_used).lower()
        assert "allocated" in combined

    def test_signals_used_mention_aws_recommends(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        combined = " ".join(findings[0].evidence.signals_used).lower()
        assert "aws recommends" in combined or "recommends" in combined

    def test_signals_not_checked_include_blind_spots(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        snc = " ".join(findings[0].evidence.signals_not_checked).lower()
        assert "dns" in snc or "failover" in snc
        assert "application" in snc or "app" in snc
        assert "service-managed" in snc or "service managed" in snc

    def test_time_window_is_none(self, mock_boto3_session):
        """No temporal threshold — time_window must be None."""
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].evidence.time_window is None


# ---------------------------------------------------------------------------
# TestTitleAndReasonContract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].title == "Unattached Elastic IP review candidate"

    def test_reason(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert findings[0].reason == "Address has no current association per DescribeAddresses"

    def test_summary_contains_resource_id(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert "eipalloc-001" in findings[0].summary

    def test_title_does_not_claim_safe_to_release(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        combined = (findings[0].title + findings[0].summary + findings[0].reason).lower()
        assert "safe to release" not in combined

    def test_no_allocation_age_in_title_or_reason(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        combined = (findings[0].title + findings[0].summary + findings[0].reason).lower()
        assert "days ago" not in combined
        assert "allocated" not in combined or "no longer needed" in findings[0].summary.lower()

    def test_no_hardcoded_cost_in_summary(self, mock_boto3_session):
        findings = _run(mock_boto3_session, [_eip()])
        assert "$3.75" not in findings[0].summary
        assert "$3.75" not in findings[0].reason
