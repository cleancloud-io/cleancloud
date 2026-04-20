"""Tests for aws.ec2.eni.detached rule.

Covers all acceptance scenarios from docs/specs/aws/eni_detached.md §15 and
the normalization, evidence, confidence, cost, risk, title/reason, failure, and
pagination contracts from the same spec.
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis

_REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(ec2: MagicMock) -> MagicMock:
    session = MagicMock()
    session.client.return_value = ec2
    return session


def _setup_ec2(enis: list) -> MagicMock:
    """Return an ec2 client mock whose paginator yields one page of ENIs."""
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"NetworkInterfaces": enis}]
    return ec2


def _eni(
    eni_id: str = "eni-aabbccdd",
    status: str = "available",
    **extra,
) -> dict:
    """Build a minimal ENI dict with defaults that pass all exclusion rules."""
    base = {
        "NetworkInterfaceId": eni_id,
        "Status": status,
    }
    base.update(extra)
    return base


def _run(session: MagicMock) -> list:
    return find_detached_enis(session, _REGION)


def _client_error(code: str = "SomeError") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "DescribeNetworkInterfaces")


# ---------------------------------------------------------------------------
# §15 Must Emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_available_no_attachment_object(self):
        """Scenario 1: ENI available, no Attachment object → EMIT HIGH."""
        ec2 = _setup_ec2([_eni("eni-1", "available")])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-1"
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_available_attachment_detached(self):
        """Scenario 2: ENI available, Attachment.Status == 'detached' → EMIT HIGH."""
        eni = _eni(
            "eni-2", "available", Attachment={"Status": "detached", "AttachmentId": "eni-attach-01"}
        )
        ec2 = _setup_ec2([eni])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-2"
        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_requester_managed_available(self):
        """Scenario 3: Requester-managed ENI available → EMIT (no exclusion)."""
        eni = _eni("eni-3", "available", RequesterManaged=True)
        ec2 = _setup_ec2([eni])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-3"

    def test_operator_managed_available(self):
        """Scenario 4: Operator-managed ENI available → EMIT (no exclusion)."""
        eni = _eni("eni-4", "available", Operator={"Managed": True, "Principal": "some-service"})
        ec2 = _setup_ec2([eni])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-4"

    def test_any_interface_type_available(self):
        """Scenario 5: Any InterfaceType, Status available → EMIT (no type exclusion)."""
        for itype in ("interface", "load_balancer", "nat_gateway", "vpc_endpoint", "efa", "branch"):
            eni = _eni(f"eni-{itype}", "available", InterfaceType=itype)
            ec2 = _setup_ec2([eni])
            findings = _run(_make_session(ec2))
            assert len(findings) == 1, f"Expected emit for InterfaceType={itype!r}"
            assert findings[0].resource_id == f"eni-{itype}"


# ---------------------------------------------------------------------------
# §15 Must Skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_in_use_skipped(self):
        """Scenario 6: Status == 'in-use' → SKIP."""
        ec2 = _setup_ec2([_eni("eni-inuse", "in-use")])
        findings = _run(_make_session(ec2))
        assert findings == []

    def test_attaching_skipped(self):
        """Scenario 7a: Status == 'attaching' → SKIP."""
        ec2 = _setup_ec2([_eni("eni-attaching", "attaching")])
        assert _run(_make_session(ec2)) == []

    def test_detaching_skipped(self):
        """Scenario 7b: Status == 'detaching' → SKIP."""
        ec2 = _setup_ec2([_eni("eni-detaching", "detaching")])
        assert _run(_make_session(ec2)) == []

    def test_associated_skipped(self):
        """Scenario 7c: Status == 'associated' → SKIP."""
        ec2 = _setup_ec2([_eni("eni-associated", "associated")])
        assert _run(_make_session(ec2)) == []

    def test_available_attachment_attached_skipped(self):
        """Scenario 8: Status 'available' but Attachment.Status 'attached' → SKIP (inconsistency)."""
        eni = _eni("eni-conflict", "available", Attachment={"Status": "attached"})
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_available_attachment_attaching_skipped(self):
        """Structural inconsistency: 'available' + Attachment.Status 'attaching' → SKIP."""
        eni = _eni("eni-conflict2", "available", Attachment={"Status": "attaching"})
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_available_attachment_detaching_skipped(self):
        """Structural inconsistency: 'available' + Attachment.Status 'detaching' → SKIP."""
        eni = _eni("eni-conflict3", "available", Attachment={"Status": "detaching"})
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_missing_network_interface_id_skipped(self):
        """Scenario 9: Missing NetworkInterfaceId → SKIP."""
        eni = {"Status": "available"}
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_missing_status_skipped(self):
        """Scenario 10: Missing Status → SKIP."""
        eni = {"NetworkInterfaceId": "eni-nostatus"}
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []


# ---------------------------------------------------------------------------
# §15 Must Fail
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_client_error_raises(self):
        """Scenario 11: DescribeNetworkInterfaces request failure → FAIL RULE (re-raise)."""
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            _run(_make_session(ec2))

    def test_unauthorized_operation_raises_permission_error(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = _client_error("UnauthorizedOperation")
        with pytest.raises(PermissionError):
            _run(_make_session(ec2))

    def test_botocore_error_raises(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = BotoCoreError()
        with pytest.raises(BotoCoreError):
            _run(_make_session(ec2))


# ---------------------------------------------------------------------------
# §15 Must NOT Happen
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    def test_no_temporal_threshold_applied(self):
        """No temporal threshold — any available ENI regardless of creation age emits."""
        # Provide ENI with no CreateTime at all — must still emit.
        ec2 = _setup_ec2([_eni("eni-notime", "available")])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1

    def test_create_time_not_in_details(self):
        """CreateTime must not appear in details — no temporal claim from DescribeNetworkInterfaces."""
        ec2 = _setup_ec2([_eni("eni-ct", "available")])
        findings = _run(_make_session(ec2))
        assert "create_time" not in findings[0].details
        assert "age_days" not in findings[0].details

    def test_interface_type_not_exclusion(self):
        """No interface_type may be used as an exclusion gate."""
        excluded_types = [
            "load_balancer",
            "nat_gateway",
            "vpc_endpoint",
            "gateway_load_balancer",
            "gateway_load_balancer_endpoint",
        ]
        for itype in excluded_types:
            eni = _eni(f"eni-{itype}", "available", InterfaceType=itype)
            ec2 = _setup_ec2([eni])
            findings = _run(_make_session(ec2))
            assert len(findings) == 1, f"interface_type={itype!r} must not be excluded"

    def test_requester_managed_true_not_exclusion(self):
        """requester_managed == True must not exclude the ENI."""
        eni = _eni("eni-rm", "available", RequesterManaged=True)
        ec2 = _setup_ec2([eni])
        assert len(_run(_make_session(ec2))) == 1

    def test_cost_estimate_is_none(self):
        """estimated_monthly_cost_usd must always be None."""
        ec2 = _setup_ec2([_eni("eni-cost", "available")])
        findings = _run(_make_session(ec2))
        assert findings[0].estimated_monthly_cost_usd is None

    def test_confidence_never_medium_or_low(self):
        """HIGH confidence only; MEDIUM and LOW must not appear."""
        ec2 = _setup_ec2([_eni("eni-conf", "available")])
        f = _run(_make_session(ec2))[0]
        assert f.confidence not in (ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW)


# ---------------------------------------------------------------------------
# Normalization contract
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_non_dict_eni_skipped(self):
        """Non-dict item in NetworkInterfaces → SKIP (not FAIL RULE)."""
        ec2 = _setup_ec2(["not-a-dict", None, 42])
        assert _run(_make_session(ec2)) == []

    def test_empty_string_network_interface_id_skipped(self):
        """Empty string NetworkInterfaceId treated as absent → SKIP."""
        eni = {"NetworkInterfaceId": "", "Status": "available"}
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_empty_string_status_skipped(self):
        """Empty string Status treated as absent → SKIP."""
        eni = {"NetworkInterfaceId": "eni-x", "Status": ""}
        ec2 = _setup_ec2([eni])
        assert _run(_make_session(ec2)) == []

    def test_requester_managed_string_treated_as_null(self):
        """RequesterManaged as string → not a bool → normalized to null (not excluded)."""
        eni = _eni("eni-rmstr", "available", RequesterManaged="true")
        ec2 = _setup_ec2([eni])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].details["requester_managed"] is None

    def test_requester_managed_false_stored_correctly(self):
        eni = _eni("eni-rmf", "available", RequesterManaged=False)
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["requester_managed"] is False

    def test_requester_managed_true_stored_correctly(self):
        eni = _eni("eni-rmt", "available", RequesterManaged=True)
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["requester_managed"] is True

    def test_operator_managed_non_bool_treated_as_null(self):
        """Operator.Managed as string → null (not an exclusion)."""
        eni = _eni("eni-opstr", "available", Operator={"Managed": "yes"})
        ec2 = _setup_ec2([eni])
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].details["operator_managed"] is None

    def test_operator_managed_true_stored_and_not_excluded(self):
        eni = _eni("eni-opt", "available", Operator={"Managed": True, "Principal": "svc"})
        findings = _run(_make_session(_setup_ec2([eni])))
        assert len(findings) == 1
        assert findings[0].details["operator_managed"] is True
        assert findings[0].details["operator_principal"] == "svc"

    def test_operator_non_dict_yields_null_fields(self):
        eni = _eni("eni-opnd", "available", Operator="bad")
        findings = _run(_make_session(_setup_ec2([eni])))
        assert len(findings) == 1
        assert findings[0].details["operator_managed"] is None
        assert findings[0].details["operator_principal"] is None

    def test_tag_set_absent_yields_empty_list(self):
        eni = _eni("eni-notag", "available")
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["tag_set"] == []

    def test_tag_set_list_preserved(self):
        tags = [{"Key": "Name", "Value": "my-eni"}]
        eni = _eni("eni-tag", "available", TagSet=tags)
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["tag_set"] == tags

    def test_tag_set_non_list_yields_empty_list(self):
        eni = _eni("eni-badtag", "available", TagSet="not-a-list")
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["tag_set"] == []

    def test_public_ip_from_association(self):
        eni = _eni("eni-pub", "available", Association={"PublicIp": "1.2.3.4"})
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["public_ip"] == "1.2.3.4"

    def test_public_ip_absent_when_no_association(self):
        eni = _eni("eni-nopub", "available")
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["public_ip"] is None

    def test_association_non_dict_yields_null_public_ip(self):
        eni = _eni("eni-assocstr", "available", Association="bad")
        findings = _run(_make_session(_setup_ec2([eni])))
        assert findings[0].details["public_ip"] is None

    def test_empty_string_contextual_fields_yield_null(self):
        """Empty strings for contextual string fields must normalize to null."""
        eni = _eni(
            "eni-emptyctx",
            "available",
            InterfaceType="",
            AvailabilityZone="",
            SubnetId="",
            VpcId="",
            PrivateIpAddress="",
            Description="",
        )
        findings = _run(_make_session(_setup_ec2([eni])))
        d = findings[0].details
        assert d["interface_type"] is None
        assert d["availability_zone"] is None
        assert d["subnet_id"] is None
        assert d["vpc_id"] is None
        assert d["private_ip_address"] is None
        assert d["description"] is None

    def test_attachment_absent_yields_null_attachment_fields(self):
        eni = _eni("eni-noatt", "available")
        findings = _run(_make_session(_setup_ec2([eni])))
        d = findings[0].details
        assert d["attachment_status"] is None
        assert d["attachment_id"] is None
        assert d["attachment_instance_id"] is None
        assert d["attachment_instance_owner_id"] is None

    def test_attachment_fields_populated_from_object(self):
        att = {
            "Status": "detached",
            "AttachmentId": "eni-attach-01",
            "InstanceId": "i-abc123",
            "InstanceOwnerId": "123456789012",
        }
        eni = _eni("eni-att", "available", Attachment=att)
        findings = _run(_make_session(_setup_ec2([eni])))
        d = findings[0].details
        assert d["attachment_status"] == "detached"
        assert d["attachment_id"] == "eni-attach-01"
        assert d["attachment_instance_id"] == "i-abc123"
        assert d["attachment_instance_owner_id"] == "123456789012"

    def test_malformed_attachment_non_dict_yields_null_fields(self):
        eni = _eni("eni-badatt", "available", Attachment="not-a-dict")
        findings = _run(_make_session(_setup_ec2([eni])))
        d = findings[0].details
        assert d["attachment_status"] is None
        assert d["attachment_id"] is None


# ---------------------------------------------------------------------------
# Attachment consistency (structural inconsistency rule)
# ---------------------------------------------------------------------------


class TestAttachmentConsistency:
    def test_available_plus_detached_attachment_emits(self):
        """available + Attachment.Status 'detached' → consistent → EMIT."""
        eni = _eni("eni-detatt", "available", Attachment={"Status": "detached"})
        findings = _run(_make_session(_setup_ec2([eni])))
        assert len(findings) == 1

    def test_available_plus_null_attachment_status_emits(self):
        """available + Attachment object missing Status → null attachment_status → EMIT."""
        eni = _eni("eni-noastatus", "available", Attachment={"AttachmentId": "eni-attach-01"})
        findings = _run(_make_session(_setup_ec2([eni])))
        assert len(findings) == 1

    def test_available_plus_attached_skipped(self):
        eni = _eni("eni-inconsis1", "available", Attachment={"Status": "attached"})
        assert _run(_make_session(_setup_ec2([eni]))) == []

    def test_available_plus_attaching_skipped(self):
        eni = _eni("eni-inconsis2", "available", Attachment={"Status": "attaching"})
        assert _run(_make_session(_setup_ec2([eni]))) == []

    def test_available_plus_detaching_skipped(self):
        eni = _eni("eni-inconsis3", "available", Attachment={"Status": "detaching"})
        assert _run(_make_session(_setup_ec2([eni]))) == []

    def test_available_plus_unknown_attachment_status_skipped(self):
        """Unknown/malformed attachment_status (e.g. 'foo') → SKIP; only null/'detached' emits."""
        eni = _eni("eni-unknown-att", "available", Attachment={"Status": "foo"})
        assert _run(_make_session(_setup_ec2([eni]))) == []

    def test_available_plus_arbitrary_string_attachment_status_skipped(self):
        """Any non-null, non-'detached' attachment_status string → SKIP."""
        for bad_status in ("pending", "error", "unknown", "AVAILABLE", ""):
            eni_id = f"eni-bad-{bad_status or 'empty'}"
            # Empty string normalizes to None via _str(), so it should emit.
            # Non-empty unknown strings should skip.
            eni = _eni(eni_id, "available", Attachment={"Status": bad_status})
            findings = _run(_make_session(_setup_ec2([eni])))
            if bad_status == "":
                # Empty string → attachment_status normalizes to None → emit
                assert (
                    len(findings) == 1
                ), "Empty attachment Status should emit (normalized to null)"
            else:
                assert findings == [], f"attachment_status={bad_status!r} should skip"

    def test_attachment_status_does_not_override_top_level_status(self):
        """attachment_status is validation only; it must not independently produce eligibility."""
        eni = _eni("eni-auth", "in-use", Attachment={"Status": "detached"})
        assert _run(_make_session(_setup_ec2([eni]))) == []


# ---------------------------------------------------------------------------
# Signals used (§11.3)
# ---------------------------------------------------------------------------


class TestSignalsUsed:
    def test_top_level_status_signal_always_present(self):
        ec2 = _setup_ec2([_eni("eni-sig1", "available")])
        signals = _run(_make_session(ec2))[0].evidence.signals_used
        assert any("'available'" in s for s in signals)

    def test_requester_managed_true_adds_signal(self):
        eni = _eni("eni-rm-sig", "available", RequesterManaged=True)
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert any("requester-managed" in s.lower() for s in signals)

    def test_requester_managed_false_no_extra_signal(self):
        eni = _eni("eni-rmf-sig", "available", RequesterManaged=False)
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert not any("requester-managed" in s.lower() for s in signals)

    def test_requester_managed_null_no_extra_signal(self):
        eni = _eni("eni-rmn-sig", "available")
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert not any("requester-managed" in s.lower() for s in signals)

    def test_operator_managed_true_adds_signal(self):
        eni = _eni("eni-op-sig", "available", Operator={"Managed": True, "Principal": "svc-x"})
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert any("operator-managed" in s.lower() for s in signals)
        assert any("svc-x" in s for s in signals)

    def test_operator_managed_true_no_principal_uses_unknown(self):
        eni = _eni("eni-op-noprinc", "available", Operator={"Managed": True})
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert any("operator-managed" in s.lower() for s in signals)
        assert any("unknown" in s for s in signals)

    def test_operator_managed_false_no_extra_signal(self):
        eni = _eni("eni-opf-sig", "available", Operator={"Managed": False})
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert not any("operator-managed" in s.lower() for s in signals)

    def test_both_requester_and_operator_managed_both_signals_present(self):
        eni = _eni(
            "eni-both-sig",
            "available",
            RequesterManaged=True,
            Operator={"Managed": True, "Principal": "svc-y"},
        )
        signals = _run(_make_session(_setup_ec2([eni])))[0].evidence.signals_used
        assert any("requester-managed" in s.lower() for s in signals)
        assert any("operator-managed" in s.lower() for s in signals)


# ---------------------------------------------------------------------------
# Evidence contract (§11)
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_required_details_fields_present(self):
        """All required evidence/details fields must be present in every finding."""
        eni = _eni(
            "eni-evid",
            "available",
            InterfaceType="interface",
            RequesterManaged=True,
            Operator={"Managed": False, "Principal": "svc"},
            AvailabilityZone="us-east-1a",
            SubnetId="subnet-aaa",
            VpcId="vpc-bbb",
            PrivateIpAddress="10.0.0.5",
            Association={"PublicIp": "52.1.2.3"},
        )
        findings = _run(_make_session(_setup_ec2([eni])))
        d = findings[0].details

        required_fields = [
            "evaluation_path",
            "network_interface_id",
            "normalized_status",
            "attachment_status",
            "interface_type",
            "requester_managed",
            "operator_managed",
            "operator_principal",
            "availability_zone",
            "subnet_id",
            "vpc_id",
            "private_ip_address",
            "public_ip",
        ]
        for field in required_fields:
            assert field in d, f"Required field '{field}' missing from details"

    def test_evaluation_path_exact_value(self):
        ec2 = _setup_ec2([_eni("eni-ep", "available")])
        findings = _run(_make_session(ec2))
        assert findings[0].details["evaluation_path"] == "detached-eni-review-candidate"

    def test_normalized_status_always_available_in_details(self):
        ec2 = _setup_ec2([_eni("eni-ns", "available")])
        findings = _run(_make_session(ec2))
        assert findings[0].details["normalized_status"] == "available"

    def test_network_interface_id_in_details(self):
        ec2 = _setup_ec2([_eni("eni-id-check", "available")])
        findings = _run(_make_session(ec2))
        assert findings[0].details["network_interface_id"] == "eni-id-check"


# ---------------------------------------------------------------------------
# Confidence model (§12)
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_confidence_for_available_no_conflict(self):
        ec2 = _setup_ec2([_eni("eni-conf1", "available")])
        assert _run(_make_session(ec2))[0].confidence == ConfidenceLevel.HIGH

    def test_high_confidence_with_detached_attachment(self):
        eni = _eni("eni-conf2", "available", Attachment={"Status": "detached"})
        assert _run(_make_session(_setup_ec2([eni])))[0].confidence == ConfidenceLevel.HIGH

    def test_high_confidence_requester_managed(self):
        eni = _eni("eni-conf3", "available", RequesterManaged=True)
        assert _run(_make_session(_setup_ec2([eni])))[0].confidence == ConfidenceLevel.HIGH

    def test_high_confidence_operator_managed(self):
        eni = _eni("eni-conf4", "available", Operator={"Managed": True})
        assert _run(_make_session(_setup_ec2([eni])))[0].confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# Cost model (§11.2)
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self):
        ec2 = _setup_ec2([_eni("eni-cost1", "available")])
        assert _run(_make_session(ec2))[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# Risk model (§14)
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_is_low(self):
        ec2 = _setup_ec2([_eni("eni-risk", "available")])
        assert _run(_make_session(ec2))[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# Title and reason contract (§13)
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    def test_title_exact(self):
        ec2 = _setup_ec2([_eni("eni-title", "available")])
        assert _run(_make_session(ec2))[0].title == "ENI not currently attached review candidate"

    def test_reason_exact(self):
        ec2 = _setup_ec2([_eni("eni-reason", "available")])
        reason = _run(_make_session(ec2))[0].reason
        assert (
            reason
            == "ENI Status is 'available' — not currently attached per DescribeNetworkInterfaces"
        )

    def test_title_does_not_claim_safe_to_delete(self):
        ec2 = _setup_ec2([_eni("eni-safe", "available")])
        title = _run(_make_session(ec2))[0].title
        assert "delete" not in title.lower()
        assert "safe" not in title.lower()


# ---------------------------------------------------------------------------
# Pagination exhaustion
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_all_evaluated(self):
        """Pagination must be fully exhausted — all pages contribute findings."""
        ec2 = MagicMock()
        paginator = MagicMock()
        ec2.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NetworkInterfaces": [_eni("eni-p1", "available")]},
            {"NetworkInterfaces": [_eni("eni-p2", "available")]},
            {"NetworkInterfaces": [_eni("eni-p3", "in-use")]},
        ]
        findings = _run(_make_session(ec2))
        ids = {f.resource_id for f in findings}
        assert "eni-p1" in ids
        assert "eni-p2" in ids
        assert "eni-p3" not in ids
        assert len(findings) == 2

    def test_empty_page_yields_no_findings(self):
        ec2 = _setup_ec2([])
        assert _run(_make_session(ec2)) == []

    def test_paginator_called_with_correct_operation(self):
        ec2 = _setup_ec2([])
        _run(_make_session(ec2))
        ec2.get_paginator.assert_called_once_with("describe_network_interfaces")

    def test_mixed_valid_and_malformed_items(self):
        """Malformed items in a page are silently skipped; valid items emit."""
        ec2 = MagicMock()
        paginator = MagicMock()
        ec2.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "NetworkInterfaces": [
                    "not-a-dict",
                    None,
                    {"Status": "available"},  # missing NetworkInterfaceId
                    _eni("eni-valid", "available"),
                ]
            }
        ]
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-valid"


# ---------------------------------------------------------------------------
# Additional correctness checks
# ---------------------------------------------------------------------------


class TestCorrectness:
    def test_resource_id_matches_network_interface_id(self):
        ec2 = _setup_ec2([_eni("eni-rid", "available")])
        f = _run(_make_session(ec2))[0]
        assert f.resource_id == "eni-rid"
        assert f.details["network_interface_id"] == "eni-rid"

    def test_region_in_finding(self):
        ec2 = _setup_ec2([_eni("eni-reg", "available")])
        session = MagicMock()
        session.client.return_value = ec2
        findings = find_detached_enis(session, "eu-west-1")
        assert findings[0].region == "eu-west-1"

    def test_rule_id_correct(self):
        ec2 = _setup_ec2([_eni("eni-ruleid", "available")])
        assert _run(_make_session(ec2))[0].rule_id == "aws.ec2.eni.detached"

    def test_provider_is_aws(self):
        ec2 = _setup_ec2([_eni("eni-prov", "available")])
        assert _run(_make_session(ec2))[0].provider == "aws"

    def test_multiple_available_enis_all_emit(self):
        """All available ENIs in one page emit, regardless of other attributes."""
        enis = [
            _eni("eni-a1", "available"),
            _eni("eni-a2", "available", RequesterManaged=True),
            _eni("eni-a3", "available", InterfaceType="load_balancer"),
            _eni("eni-a4", "available", Operator={"Managed": True}),
            _eni("eni-a5", "available", Attachment={"Status": "detached"}),
        ]
        ec2 = _setup_ec2(enis)
        findings = _run(_make_session(ec2))
        ids = {f.resource_id for f in findings}
        assert ids == {"eni-a1", "eni-a2", "eni-a3", "eni-a4", "eni-a5"}

    def test_mixed_statuses_only_available_emits(self):
        enis = [
            _eni("eni-av", "available"),
            _eni("eni-iu", "in-use"),
            _eni("eni-at", "attaching"),
            _eni("eni-dt", "detaching"),
            _eni("eni-as", "associated"),
        ]
        ec2 = _setup_ec2(enis)
        findings = _run(_make_session(ec2))
        assert len(findings) == 1
        assert findings[0].resource_id == "eni-av"
