"""
Tests for azure.vm.stopped_not_deallocated -- spec-aligned.

Covers: must-emit, must-skip, id/name guards, region filter,
        provisioning-state contract (SDK/nested/conflict),
        power-state contract (exact match, transitional, conflicting codes,
        no code, None statuses),
        instance_view failure behavior, finding shape,
        resolver unit tests (_resolve_provisioning_state, _resolve_power_state).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)

from cleancloud.providers.azure.rules.vm_stopped_not_deallocated import (
    _resolve_power_state,
    _resolve_provisioning_state,
    find_stopped_not_deallocated_vms,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_SUB = "sub-123"
_RG = "rg-test"
_VM_ID_TMPL = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    "/providers/Microsoft.Compute/virtualMachines/{name}"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_vm(
    name="my-vm",
    location="eastus",
    provisioning_state="Succeeded",
    vm_size="Standard_D2s_v3",
    os_type="Linux",
    tags=None,
    vm_id=None,
    properties=None,
) -> SimpleNamespace:
    """
    Build a fully qualifying VM SimpleNamespace.
    Includes provisioning_state="Succeeded" by default.
    """
    return SimpleNamespace(
        id=vm_id or _VM_ID_TMPL.format(name=name),
        name=name,
        location=location,
        provisioning_state=provisioning_state,
        hardware_profile=SimpleNamespace(vm_size=vm_size),
        storage_profile=SimpleNamespace(os_disk=SimpleNamespace(os_type=os_type)),
        tags=tags,
        properties=properties,
    )


def _make_iv(power_state_code, extra_codes=None) -> SimpleNamespace:
    """
    Build an instance_view SimpleNamespace with the given power state code.
    Optionally inject extra status codes (for conflict tests).
    """
    statuses = [SimpleNamespace(code="ProvisioningState/succeeded")]
    if power_state_code is not None:
        statuses.append(SimpleNamespace(code=power_state_code))
    for code in extra_codes or []:
        statuses.append(SimpleNamespace(code=code))
    return SimpleNamespace(statuses=statuses)


def _run(vms, iv_map=None, iv_default=None, region_filter=None):
    """
    Run find_stopped_not_deallocated_vms with an injected mock client.

    iv_map: dict of vm_name -> instance_view (for per-VM control)
    iv_default: single instance_view returned for all VMs
    """
    client = MagicMock()
    client.virtual_machines.list_all.return_value = vms

    if iv_map is not None:
        client.virtual_machines.instance_view.side_effect = (
            lambda resource_group_name, vm_name: iv_map[vm_name]
        )
    elif iv_default is not None:
        client.virtual_machines.instance_view.return_value = iv_default
    else:
        client.virtual_machines.instance_view.return_value = _make_iv("PowerState/stopped")

    return find_stopped_not_deallocated_vms(
        subscription_id=_SUB,
        credential=None,
        region_filter=region_filter,
        client=client,
    )


def _one(vms, **kwargs):
    results = _run(vms, **kwargs)
    assert len(results) == 1
    return results[0]


# ===========================================================================
# TestMustEmit
# ===========================================================================


class TestMustEmit:
    def test_qualifying_vm_emits(self):
        assert len(_run([_make_vm()])) == 1

    def test_multiple_stopped_vms_all_emit(self):
        vms = [_make_vm(name=f"vm-{i}") for i in range(3)]
        assert len(_run(vms)) == 3

    def test_emit_regardless_of_tags(self):
        assert len(_run([_make_vm(tags={"env": "prod"})])) == 1

    def test_emit_when_tags_none(self):
        assert len(_run([_make_vm(tags=None)])) == 1


# ===========================================================================
# TestMustSkip
# ===========================================================================


class TestMustSkip:
    def test_deallocated_skips(self):
        assert _run([_make_vm()], iv_default=_make_iv("PowerState/deallocated")) == []

    def test_running_skips(self):
        assert _run([_make_vm()], iv_default=_make_iv("PowerState/running")) == []

    def test_starting_skips(self):
        assert _run([_make_vm()], iv_default=_make_iv("PowerState/starting")) == []

    def test_stopping_skips(self):
        assert _run([_make_vm()], iv_default=_make_iv("PowerState/stopping")) == []

    def test_deallocating_skips(self):
        assert _run([_make_vm()], iv_default=_make_iv("PowerState/deallocating")) == []

    def test_provisioning_state_failed_skips(self):
        assert _run([_make_vm(provisioning_state="Failed")]) == []

    def test_provisioning_state_creating_skips(self):
        assert _run([_make_vm(provisioning_state="Creating")]) == []

    def test_provisioning_state_updating_skips(self):
        assert _run([_make_vm(provisioning_state="Updating")]) == []

    def test_provisioning_state_lowercase_skips(self):
        # Case-sensitive: only exact "Succeeded" qualifies
        assert _run([_make_vm(provisioning_state="succeeded")]) == []

    def test_no_power_state_code_skips(self):
        # Instance view has no PowerState/ code
        assert _run([_make_vm()], iv_default=_make_iv(None)) == []

    def test_conflicting_power_state_codes_skips(self):
        # Multiple different PowerState/ codes -> ambiguous -> skip
        iv = _make_iv("PowerState/stopped", extra_codes=["PowerState/running"])
        assert _run([_make_vm()], iv_default=iv) == []

    def test_mixed_vms_only_stopped_emits(self):
        vms = [
            _make_vm("vm-running"),
            _make_vm("vm-stopped"),
            _make_vm("vm-deallocated"),
        ]
        iv_map = {
            "vm-running": _make_iv("PowerState/running"),
            "vm-stopped": _make_iv("PowerState/stopped"),
            "vm-deallocated": _make_iv("PowerState/deallocated"),
        }
        results = _run(vms, iv_map=iv_map)
        assert len(results) == 1
        assert results[0].details["vm_name"] == "vm-stopped"


# ===========================================================================
# TestIdNameGuards -- spec 8.1, 8.2
# ===========================================================================


class TestIdNameGuards:
    def test_id_absent_skips(self):
        vm = _make_vm()
        del vm.id
        assert _run([vm]) == []

    def test_id_none_skips(self):
        vm = _make_vm()
        vm.id = None
        assert _run([vm]) == []

    def test_id_empty_skips(self):
        vm = _make_vm()
        vm.id = ""
        assert _run([vm]) == []

    def test_name_absent_skips(self):
        vm = _make_vm()
        del vm.name
        assert _run([vm]) == []

    def test_name_none_skips(self):
        vm = _make_vm()
        vm.name = None
        assert _run([vm]) == []

    def test_name_empty_skips(self):
        vm = _make_vm()
        vm.name = ""
        assert _run([vm]) == []


# ===========================================================================
# TestRegionFilter -- spec 8.3
# ===========================================================================


class TestRegionFilter:
    def test_matching_region_emits(self):
        results = _run([_make_vm(location="eastus")], region_filter="eastus")
        assert len(results) == 1

    def test_non_matching_region_skips(self):
        assert _run([_make_vm(location="westus")], region_filter="eastus") == []

    def test_region_filter_case_insensitive(self):
        assert len(_run([_make_vm(location="eastus")], region_filter="EastUS")) == 1

    def test_no_region_filter_emits_all(self):
        vms = [
            _make_vm(name="vm-east", location="eastus"),
            _make_vm(name="vm-west", location="westus"),
        ]
        assert len(_run(vms)) == 2

    def test_region_filter_only_eastus(self):
        vms = [
            _make_vm(name="vm-east", location="eastus"),
            _make_vm(name="vm-west", location="westus"),
        ]
        results = _run(vms, region_filter="eastus")
        assert len(results) == 1
        assert results[0].details["vm_name"] == "vm-east"


# ===========================================================================
# TestProvisioningStateContract -- spec 9.1
# ===========================================================================


class TestProvisioningStateContract:
    def test_sdk_succeeded_emits(self):
        assert len(_run([_make_vm(provisioning_state="Succeeded")])) == 1

    def test_nested_snake_case_used(self):
        vm = _make_vm(provisioning_state=None)
        vm.properties = SimpleNamespace(provisioning_state="Succeeded", provisioningState=None)
        assert len(_run([vm])) == 1

    def test_nested_camel_case_used(self):
        vm = _make_vm(provisioning_state=None)
        vm.properties = SimpleNamespace(provisioning_state=None, provisioningState="Succeeded")
        assert len(_run([vm])) == 1

    def test_sdk_nested_conflict_skips(self):
        vm = _make_vm(provisioning_state="Succeeded")
        vm.properties = SimpleNamespace(provisioning_state="Failed", provisioningState=None)
        assert _run([vm]) == []

    def test_both_absent_skips(self):
        vm = _make_vm(provisioning_state=None)
        vm.properties = None
        assert _run([vm]) == []

    def test_sdk_and_nested_agree_emits(self):
        vm = _make_vm(provisioning_state="Succeeded")
        vm.properties = SimpleNamespace(provisioning_state="Succeeded", provisioningState=None)
        assert len(_run([vm])) == 1


# ===========================================================================
# TestPowerStateContract -- spec 9.2
# ===========================================================================


class TestPowerStateContract:
    def test_exact_stopped_emits(self):
        assert len(_run([_make_vm()], iv_default=_make_iv("PowerState/stopped"))) == 1

    def test_all_non_stopped_codes_skip(self):
        non_stopped = [
            "PowerState/running",
            "PowerState/starting",
            "PowerState/stopping",
            "PowerState/deallocating",
            "PowerState/deallocated",
        ]
        for code in non_stopped:
            assert _run([_make_vm()], iv_default=_make_iv(code)) == [], f"Expected skip for {code}"

    def test_no_power_state_code_skips(self):
        # statuses has only ProvisioningState/ -- no PowerState/
        assert _run([_make_vm()], iv_default=_make_iv(None)) == []

    def test_duplicate_same_code_emits(self):
        # Two identical PowerState/stopped codes -> not conflicting -> emit
        iv = _make_iv("PowerState/stopped", extra_codes=["PowerState/stopped"])
        assert len(_run([_make_vm()], iv_default=iv)) == 1

    def test_conflicting_power_state_codes_skip(self):
        iv = _make_iv("PowerState/stopped", extra_codes=["PowerState/running"])
        assert _run([_make_vm()], iv_default=iv) == []

    def test_statuses_none_skips(self):
        iv = SimpleNamespace(statuses=None)
        assert _run([_make_vm()], iv_default=iv) == []

    def test_statuses_empty_skips(self):
        iv = SimpleNamespace(statuses=[])
        assert _run([_make_vm()], iv_default=iv) == []

    def test_statuses_code_none_skips(self):
        # Status entry with code=None should be ignored; no PowerState/ -> skip
        iv = SimpleNamespace(statuses=[SimpleNamespace(code=None)])
        assert _run([_make_vm()], iv_default=iv) == []


# ===========================================================================
# TestInstanceViewFailure -- spec 12
# ===========================================================================


class TestInstanceViewFailure:
    def test_instance_view_http_error_skips_vm(self):
        # HttpResponseError (404, 403, 429, 5xx) -> skip that VM
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.side_effect = HttpResponseError(message="Not Found")
        assert (
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)
            == []
        )

    def test_instance_view_service_request_error_skips_vm(self):
        # ServiceRequestError (connection reset, DNS, network timeout) -> skip that VM
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.side_effect = ServiceRequestError(
            message="Connection reset"
        )
        assert (
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)
            == []
        )

    def test_instance_view_service_response_error_skips_vm(self):
        # ServiceResponseError (incomplete read, stream closed) -> skip that VM
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.side_effect = ServiceResponseError(
            message="Incomplete read"
        )
        assert (
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)
            == []
        )

    def test_instance_view_azure_base_error_propagates(self):
        # AzureError (root base class, e.g. serialization bug) is NOT caught
        from azure.core.exceptions import AzureError

        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.side_effect = AzureError("internal SDK error")
        with pytest.raises(AzureError):
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)

    def test_instance_view_unrelated_error_propagates(self):
        # Non-Azure errors (coding bugs) must NOT be swallowed
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.side_effect = RuntimeError("bug")
        with pytest.raises(RuntimeError):
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)

    def test_instance_view_fails_one_emits_other(self):
        vm_ok = _make_vm(name="vm-ok")
        vm_bad = _make_vm(name="vm-bad")

        client = MagicMock()
        client.virtual_machines.list_all.return_value = [vm_bad, vm_ok]

        def _iv(resource_group_name, vm_name):
            if vm_name == "vm-bad":
                raise ServiceRequestError(message="timeout")
            return _make_iv("PowerState/stopped")

        client.virtual_machines.instance_view.side_effect = _iv
        results = find_stopped_not_deallocated_vms(
            subscription_id=_SUB, credential=None, client=client
        )
        assert len(results) == 1
        assert results[0].details["vm_name"] == "vm-ok"

    def test_list_all_exception_propagates(self):
        client = MagicMock()
        client.virtual_machines.list_all.side_effect = RuntimeError("subscription error")
        with pytest.raises(RuntimeError):
            find_stopped_not_deallocated_vms(subscription_id=_SUB, credential=None, client=client)

    def test_malformed_id_skips_vm(self):
        # ID with no resourceGroups segment -> _extract_resource_group raises -> skip
        vm = _make_vm(vm_id="/malformed/id")
        assert _run([vm]) == []

    def test_inject_client_used(self):
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [_make_vm()]
        client.virtual_machines.instance_view.return_value = _make_iv("PowerState/stopped")
        results = find_stopped_not_deallocated_vms(
            subscription_id=_SUB, credential=None, client=client
        )
        client.virtual_machines.list_all.assert_called_once()
        assert len(results) == 1


# ===========================================================================
# TestFindingShape -- spec 11
# ===========================================================================


class TestFindingShape:
    def test_required_fields(self):
        f = _one([_make_vm()])
        assert f.provider == "azure"
        assert f.rule_id == "azure.vm.stopped_not_deallocated"
        assert f.resource_type == "azure.virtual_machine"
        assert f.resource_id == _VM_ID_TMPL.format(name="my-vm")
        assert f.region == "eastus"
        assert f.risk.value == "high"
        assert f.confidence.value == "high"
        assert f.estimated_monthly_cost_usd is None

    def test_required_detail_keys(self):
        f = _one([_make_vm(vm_size="Standard_D4s_v3", os_type="Windows")])
        d = f.details
        assert d["vm_name"] == "my-vm"
        assert d["subscription_id"] == _SUB
        assert d["power_state"] == "PowerState/stopped"
        assert d["provisioning_state"] == "Succeeded"
        assert d["vm_size"] == "Standard_D4s_v3"
        assert d["os_type"] == "Windows"
        assert isinstance(d["tags"], dict)

    def test_tags_normalized_to_empty_dict_when_none(self):
        f = _one([_make_vm(tags=None)])
        assert f.details["tags"] == {}

    def test_tags_preserved_when_set(self):
        f = _one([_make_vm(tags={"env": "prod", "team": "infra"})])
        assert f.details["tags"] == {"env": "prod", "team": "infra"}

    def test_evidence_signals_used(self):
        f = _one([_make_vm()])
        used = " ".join(f.evidence.signals_used)
        assert "Succeeded" in used
        assert "PowerState/stopped" in used
        assert "compute" in used.lower()

    def test_evidence_signals_not_checked(self):
        f = _one([_make_vm()])
        combined = " ".join(f.evidence.signals_not_checked).lower()
        assert "intentional" in combined or "accidental" in combined
        assert "reservation" in combined or "licensing" in combined

    def test_estimated_cost_always_none(self):
        f = _one([_make_vm()])
        assert f.estimated_monthly_cost_usd is None


# ===========================================================================
# TestResolveProvisioningState -- unit tests
# ===========================================================================


class TestResolveProvisioningState:
    def _ns(self, sdk=None, props=None):
        return SimpleNamespace(provisioning_state=sdk, properties=props)

    def test_sdk_value_returned(self):
        assert _resolve_provisioning_state(self._ns(sdk="Succeeded")) == "Succeeded"

    def test_nested_snake_used(self):
        obj = self._ns(
            sdk=None,
            props=SimpleNamespace(provisioning_state="Succeeded", provisioningState=None),
        )
        assert _resolve_provisioning_state(obj) == "Succeeded"

    def test_nested_camel_used(self):
        obj = self._ns(
            sdk=None,
            props=SimpleNamespace(provisioning_state=None, provisioningState="Succeeded"),
        )
        assert _resolve_provisioning_state(obj) == "Succeeded"

    def test_conflict_returns_none(self):
        obj = self._ns(
            sdk="Succeeded",
            props=SimpleNamespace(provisioning_state="Failed", provisioningState=None),
        )
        assert _resolve_provisioning_state(obj) is None

    def test_both_absent_returns_none(self):
        assert _resolve_provisioning_state(self._ns()) is None

    def test_no_props_attribute_uses_sdk(self):
        obj = SimpleNamespace(provisioning_state="Succeeded")
        assert _resolve_provisioning_state(obj) == "Succeeded"


# ===========================================================================
# TestResolvePowerState -- unit tests
# ===========================================================================


class TestResolvePowerState:
    def _iv(self, codes):
        return SimpleNamespace(statuses=[SimpleNamespace(code=c) for c in codes])

    def test_single_stopped_code(self):
        assert _resolve_power_state(self._iv(["PowerState/stopped"])) == "PowerState/stopped"

    def test_single_running_code(self):
        assert _resolve_power_state(self._iv(["PowerState/running"])) == "PowerState/running"

    def test_provisioning_code_ignored(self):
        # ProvisioningState/ is not a PowerState/ code
        assert (
            _resolve_power_state(self._iv(["ProvisioningState/succeeded", "PowerState/stopped"]))
            == "PowerState/stopped"
        )

    def test_no_power_state_code_returns_none(self):
        assert _resolve_power_state(self._iv(["ProvisioningState/succeeded"])) is None

    def test_empty_statuses_returns_none(self):
        assert _resolve_power_state(self._iv([])) is None

    def test_statuses_none_returns_none(self):
        iv = SimpleNamespace(statuses=None)
        assert _resolve_power_state(iv) is None

    def test_conflicting_codes_returns_none(self):
        assert _resolve_power_state(self._iv(["PowerState/stopped", "PowerState/running"])) is None

    def test_duplicate_same_code_returns_code(self):
        # Two identical codes -> not conflicting
        assert (
            _resolve_power_state(self._iv(["PowerState/stopped", "PowerState/stopped"]))
            == "PowerState/stopped"
        )

    def test_code_none_entry_ignored(self):
        iv = SimpleNamespace(
            statuses=[SimpleNamespace(code=None), SimpleNamespace(code="PowerState/stopped")]
        )
        assert _resolve_power_state(iv) == "PowerState/stopped"

    def test_no_statuses_attribute_returns_none(self):
        iv = SimpleNamespace()
        assert _resolve_power_state(iv) is None
