"""
Tests for azure.network.public_ip.unused — spec-aligned.

Covers: must-emit, must-skip, attachment contract (all 4 linkages),
        dynamic-placeholder contract, provisioning-state contract,
        finding shape, evidence contract, region filter, failure behavior,
        SDK-first / nested-fallback / ARM camelCase fallbacks.
"""

from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_ARM_ID = (
    "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip1"
)


def _ref(arm_id: str = "/some/resource/id"):
    """A SubResource-style reference with an id."""
    return SimpleNamespace(id=arm_id)


def _make_pip(
    name: str = "pip1",
    location: str = "eastus",
    provisioning_state: str = "Succeeded",
    ip_configuration=None,
    nat_gateway=None,
    service_public_ip_address=None,
    linked_public_ip_address=None,
    allocation_method: str = "Static",
    ip_address: str = "1.2.3.4",
    pip_id: str = _ARM_ID,
    tags=None,
    sku_name: str = "Standard",
    ip_version: str = "IPv4",
    ip_tags=None,
):
    return SimpleNamespace(
        id=pip_id,
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        ip_configuration=ip_configuration,
        nat_gateway=nat_gateway,
        service_public_ip_address=service_public_ip_address,
        linked_public_ip_address=linked_public_ip_address,
        public_ip_allocation_method=allocation_method,
        ip_address=ip_address,
        tags=tags,
        sku=SimpleNamespace(name=sku_name),
        public_ip_address_version=ip_version,
        ip_tags=ip_tags,
    )


def _run(pips):
    from unittest.mock import MagicMock

    client = MagicMock()
    client.public_ip_addresses.list_all.return_value = pips
    return find_unused_public_ips(subscription_id=_SUB, credential=None, client=client)


# ---------------------------------------------------------------------------
# Must Emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_static_with_ip_address_emits(self):
        """Static allocation, all linkages absent, ip_address present → emit."""
        assert len(_run([_make_pip()])) == 1

    def test_dynamic_with_ip_address_emits(self):
        """Dynamic allocation with assigned ip_address, all linkages absent → emit."""
        pip = _make_pip(allocation_method="Dynamic", ip_address="2.3.4.5")
        assert len(_run([pip])) == 1

    def test_only_unused_pip_in_mixed_list(self):
        """Only the unattached PIP emits from a list containing an attached one."""
        unused = _make_pip(pip_id="/id/pip-unused", name="pip-unused")
        used = _make_pip(pip_id="/id/pip-used", name="pip-used", ip_configuration=_ref())
        findings = _run([unused, used])
        assert len(findings) == 1
        assert findings[0].resource_id == "/id/pip-unused"


# ---------------------------------------------------------------------------
# Must Skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_if_id_absent(self):
        pip = _make_pip()
        pip.id = None
        assert _run([pip]) == []

    def test_skip_if_id_empty(self):
        pip = _make_pip()
        pip.id = ""
        assert _run([pip]) == []

    def test_skip_if_name_absent(self):
        pip = _make_pip()
        pip.name = None
        assert _run([pip]) == []

    def test_skip_if_name_empty(self):
        pip = _make_pip()
        pip.name = ""
        assert _run([pip]) == []

    def test_skip_if_provisioning_not_succeeded(self):
        assert _run([_make_pip(provisioning_state="Updating")]) == []

    def test_skip_if_provisioning_failed(self):
        assert _run([_make_pip(provisioning_state="Failed")]) == []

    def test_skip_dynamic_no_ip_address(self):
        """Unattached Dynamic PIP with no ip_address → dynamic-placeholder → skip."""
        pip = _make_pip(allocation_method="Dynamic", ip_address=None)
        assert _run([pip]) == []

    def test_skip_dynamic_empty_ip_address(self):
        pip = _make_pip(allocation_method="Dynamic", ip_address="")
        assert _run([pip]) == []


# ---------------------------------------------------------------------------
# Attachment Contract — all four linkage fields
# ---------------------------------------------------------------------------


class TestAttachmentContract:
    def test_ip_configuration_present_skips(self):
        assert _run([_make_pip(ip_configuration=_ref())]) == []

    def test_nat_gateway_present_skips(self):
        assert _run([_make_pip(nat_gateway=_ref())]) == []

    def test_service_public_ip_address_present_skips(self):
        assert _run([_make_pip(service_public_ip_address=_ref())]) == []

    def test_linked_public_ip_address_present_skips(self):
        assert _run([_make_pip(linked_public_ip_address=_ref())]) == []

    def test_ref_without_id_is_unresolvable_skips(self):
        """A reference object present but id absent → unresolvable linkage → skip."""
        pip = _make_pip(ip_configuration=SimpleNamespace(id=None))
        assert _run([pip]) == []

    def test_ref_with_empty_id_is_unresolvable_skips(self):
        """A reference object present but id empty → unresolvable linkage → skip."""
        pip = _make_pip(nat_gateway=SimpleNamespace(id=""))
        assert _run([pip]) == []

    def test_all_four_absent_emits(self):
        """All four linkages absent → emit."""
        assert len(_run([_make_pip()])) == 1


# ---------------------------------------------------------------------------
# Dynamic-Placeholder Contract
# ---------------------------------------------------------------------------


class TestDynamicPlaceholderContract:
    def test_static_no_ip_still_emits(self):
        """Static allocation with no ip_address is NOT a dynamic placeholder → emit."""
        pip = _make_pip(allocation_method="Static", ip_address=None)
        assert len(_run([pip])) == 1

    def test_dynamic_with_ip_emits(self):
        pip = _make_pip(allocation_method="Dynamic", ip_address="10.0.0.1")
        assert len(_run([pip])) == 1

    def test_dynamic_without_ip_skips(self):
        pip = _make_pip(allocation_method="Dynamic", ip_address=None)
        assert _run([pip]) == []

    def test_none_allocation_with_no_ip_still_emits(self):
        """allocation_method=None does not trigger the Dynamic check → emit."""
        pip = _make_pip(allocation_method=None, ip_address=None)
        assert len(_run([pip])) == 1


# ---------------------------------------------------------------------------
# Finding Shape
# ---------------------------------------------------------------------------


class TestFindingShape:
    def setup_method(self):
        self.finding = _run([_make_pip()])[0]

    def test_provider(self):
        assert self.finding.provider == "azure"

    def test_rule_id(self):
        assert self.finding.rule_id == "azure.network.public_ip.unused"

    def test_resource_type(self):
        assert self.finding.resource_type == "azure.network.public_ip"

    def test_resource_id_is_arm_id(self):
        assert self.finding.resource_id == _ARM_ID

    def test_region_is_normalized(self):
        pip = _make_pip(location="EastUS")
        f = _run([pip])[0]
        assert f.region == "eastus"

    def test_cost_is_none(self):
        assert self.finding.estimated_monthly_cost_usd is None

    def test_confidence_high(self):
        from cleancloud.core.confidence import ConfidenceLevel

        assert self.finding.confidence == ConfidenceLevel.HIGH

    def test_risk_low(self):
        from cleancloud.core.risk import RiskLevel

        assert self.finding.risk == RiskLevel.LOW

    def test_details_resource_name(self):
        assert self.finding.details["resource_name"] == "pip1"

    def test_details_subscription_id(self):
        assert self.finding.details["subscription_id"] == _SUB

    def test_details_allocation_method(self):
        assert self.finding.details["allocation_method"] == "Static"

    def test_details_ip_address(self):
        assert self.finding.details["ip_address"] == "1.2.3.4"

    def test_details_sku(self):
        assert self.finding.details["sku"] == "Standard"

    def test_details_ip_version(self):
        assert self.finding.details["ip_version"] == "IPv4"

    def test_details_attached_is_false(self):
        assert self.finding.details["attached"] is False

    def test_details_tags_none_becomes_empty_dict(self):
        pip = _make_pip(tags=None)
        f = _run([pip])[0]
        assert f.details["tags"] == {}

    def test_details_tags_preserved(self):
        pip = _make_pip(tags={"env": "prod"})
        f = _run([pip])[0]
        assert f.details["tags"] == {"env": "prod"}


# ---------------------------------------------------------------------------
# Evidence Contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def setup_method(self):
        self.ev = _run([_make_pip()])[0].evidence

    def test_signals_used_provisioning(self):
        assert "Provisioning state is Succeeded" in self.ev.signals_used

    def test_signals_used_attachment(self):
        assert any("ip_configuration" in s and "nat_gateway" in s for s in self.ev.signals_used)

    def test_signals_used_dynamic_placeholder(self):
        assert any("Dynamic-placeholder" in s for s in self.ev.signals_used)

    def test_signals_not_checked_planned(self):
        assert any("Planned future association" in s for s in self.ev.signals_not_checked)

    def test_signals_not_checked_dns(self):
        assert any("DNS" in s for s in self.ev.signals_not_checked)

    def test_signals_not_checked_traffic(self):
        assert any("traffic" in s for s in self.ev.signals_not_checked)

    def test_signals_not_checked_billing(self):
        assert any(
            "billing" in s.lower() or "Azure billing" in s for s in self.ev.signals_not_checked
        )

    def test_time_window_is_none(self):
        assert self.ev.time_window is None


# ---------------------------------------------------------------------------
# Region Filter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_exact_match_emits(self):
        assert len(_run([_make_pip(location="eastus")])) == 1

    def test_case_insensitive_filter(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.public_ip_addresses.list_all.return_value = [_make_pip(location="eastus")]
        findings = find_unused_public_ips(
            subscription_id=_SUB, credential=None, region_filter="EastUS", client=client
        )
        assert len(findings) == 1

    def test_region_mismatch_skips(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.public_ip_addresses.list_all.return_value = [_make_pip(location="westeurope")]
        findings = find_unused_public_ips(
            subscription_id=_SUB, credential=None, region_filter="eastus", client=client
        )
        assert findings == []

    def test_no_filter_includes_all(self):
        pips = [
            _make_pip(pip_id="/id/1", name="p1", location="eastus"),
            _make_pip(pip_id="/id/2", name="p2", location="westeurope"),
        ]
        assert len(_run(pips)) == 2

    def test_location_stored_lowercase(self):
        pip = _make_pip(location="WestEurope")
        f = _run([pip])[0]
        assert f.region == "westeurope"


# ---------------------------------------------------------------------------
# Failure Behavior
# ---------------------------------------------------------------------------


class TestFailureBehavior:
    def test_list_exception_propagates(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.public_ip_addresses.list_all.side_effect = RuntimeError("API error")
        with pytest.raises(RuntimeError):
            find_unused_public_ips(subscription_id=_SUB, credential=None, client=client)

    def test_malformed_pip_skipped(self):
        """PIP missing id is skipped; valid PIP still emits."""
        bad = SimpleNamespace(id=None, name="bad")
        good = _make_pip(pip_id="/id/good", name="good")
        findings = _run([bad, good])
        assert len(findings) == 1
        assert findings[0].resource_id == "/id/good"


# ---------------------------------------------------------------------------
# SDK Fallbacks — nested snake_case
# ---------------------------------------------------------------------------


class TestSDKFallbacks:
    def test_provisioning_state_from_nested_snake_case_emits(self):
        """pip.provisioning_state absent → pip.properties.provisioning_state used."""
        pip = _make_pip()
        pip.provisioning_state = None
        pip.properties = SimpleNamespace(provisioning_state="Succeeded", provisioningState=None)
        assert len(_run([pip])) == 1

    def test_provisioning_state_nested_not_succeeded_skips(self):
        pip = _make_pip()
        pip.provisioning_state = None
        pip.properties = SimpleNamespace(provisioning_state="Updating", provisioningState=None)
        assert _run([pip]) == []

    def test_provisioning_state_both_absent_skips(self):
        pip = _make_pip()
        pip.provisioning_state = None
        pip.properties = None
        assert _run([pip]) == []

    def test_ip_configuration_from_nested_snake_case_skips(self):
        """pip.ip_configuration absent → pip.properties.ipConfiguration used."""
        pip = _make_pip()
        pip.ip_configuration = None
        pip.properties = SimpleNamespace(
            ipConfiguration=_ref(),
            natGateway=None,
            servicePublicIPAddress=None,
            linkedPublicIPAddress=None,
        )
        assert _run([pip]) == []

    def test_nat_gateway_from_nested_arm_skips(self):
        pip = _make_pip()
        pip.nat_gateway = None
        pip.properties = SimpleNamespace(
            ipConfiguration=None,
            natGateway=_ref(),
            servicePublicIPAddress=None,
            linkedPublicIPAddress=None,
        )
        assert _run([pip]) == []

    def test_service_pip_from_nested_arm_skips(self):
        pip = _make_pip()
        pip.service_public_ip_address = None
        pip.properties = SimpleNamespace(
            ipConfiguration=None,
            natGateway=None,
            servicePublicIPAddress=_ref(),
            linkedPublicIPAddress=None,
        )
        assert _run([pip]) == []

    def test_linked_pip_from_nested_arm_skips(self):
        pip = _make_pip()
        pip.linked_public_ip_address = None
        pip.properties = SimpleNamespace(
            ipConfiguration=None,
            natGateway=None,
            servicePublicIPAddress=None,
            linkedPublicIPAddress=_ref(),
        )
        assert _run([pip]) == []

    def test_allocation_method_from_nested_snake_case(self):
        """pip.public_ip_allocation_method absent → nested snake_case used."""
        pip = _make_pip(allocation_method=None, ip_address=None)
        pip.public_ip_allocation_method = None
        pip.properties = SimpleNamespace(
            public_ip_allocation_method="Dynamic",
            publicIPAllocationMethod=None,
            ip_address=None,
            ipAddress=None,
        )
        # Dynamic + no ip_address → skip
        assert _run([pip]) == []

    def test_allocation_method_from_nested_camel_case(self):
        """Snake_case also absent → camelCase used."""
        pip = _make_pip(allocation_method=None, ip_address=None)
        pip.public_ip_allocation_method = None
        pip.properties = SimpleNamespace(
            public_ip_allocation_method=None,
            publicIPAllocationMethod="Dynamic",
            ip_address=None,
            ipAddress=None,
        )
        assert _run([pip]) == []

    def test_ip_address_from_nested_snake_case(self):
        """pip.ip_address absent → nested snake_case used."""
        pip = _make_pip(allocation_method="Dynamic", ip_address=None)
        pip.ip_address = None
        pip.properties = SimpleNamespace(
            ip_address="10.0.0.1",
            ipAddress=None,
            public_ip_allocation_method=None,
            publicIPAllocationMethod=None,
        )
        # Dynamic + ip_address from nested → emit
        assert len(_run([pip])) == 1

    def test_ip_address_from_nested_camel_case(self):
        pip = _make_pip(allocation_method="Dynamic", ip_address=None)
        pip.ip_address = None
        pip.properties = SimpleNamespace(
            ip_address=None,
            ipAddress="10.0.0.2",
            public_ip_allocation_method=None,
            publicIPAllocationMethod=None,
        )
        assert len(_run([pip])) == 1

    def test_provisioning_state_camel_case_emits(self):
        """All snake_case absent → pip.properties.provisioningState used."""
        pip = _make_pip()
        pip.provisioning_state = None
        pip.properties = SimpleNamespace(provisioning_state=None, provisioningState="Succeeded")
        assert len(_run([pip])) == 1

    def test_provisioning_state_camel_case_not_succeeded_skips(self):
        pip = _make_pip()
        pip.provisioning_state = None
        pip.properties = SimpleNamespace(provisioning_state=None, provisioningState="Deleting")
        assert _run([pip]) == []

    def test_nested_linkage_ref_with_no_id_is_unresolvable_skips(self):
        """SDK linkage absent but nested ARM attr has object with no id → unresolvable → skip."""
        pip = _make_pip()
        pip.ip_configuration = None
        pip.properties = SimpleNamespace(
            ipConfiguration=SimpleNamespace(id=None),
            natGateway=None,
            servicePublicIPAddress=None,
            linkedPublicIPAddress=None,
        )
        assert _run([pip]) == []
