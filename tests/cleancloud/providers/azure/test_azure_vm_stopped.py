from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.vm_stopped_not_deallocated import (
    find_stopped_not_deallocated_vms,
)


def _make_vm(name, location="eastus", vm_size="Standard_D2s_v3", os_type="Linux", tags=None):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/{name}",
        name=name,
        location=location,
        hardware_profile=SimpleNamespace(vm_size=vm_size),
        storage_profile=SimpleNamespace(os_disk=SimpleNamespace(os_type=os_type)),
        tags=tags,
    )


def _make_instance_view(power_state_code):
    return SimpleNamespace(
        statuses=[
            SimpleNamespace(code="ProvisioningState/succeeded"),
            SimpleNamespace(code=power_state_code),
        ],
    )


@pytest.fixture
def mock_compute_client(mocker):
    client = mocker.MagicMock()
    return client


def test_stopped_vm_detected(mock_compute_client):
    """PowerState/stopped should be flagged."""
    vm = _make_vm("vm-stopped")
    mock_compute_client.virtual_machines.list_all.return_value = [vm]
    mock_compute_client.virtual_machines.instance_view.return_value = _make_instance_view(
        "PowerState/stopped"
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "azure"
    assert finding.rule_id == "azure.vm.stopped_not_deallocated"
    assert finding.resource_type == "azure.virtual_machine"
    assert finding.confidence.value == "high"
    assert finding.risk.value == "high"
    assert finding.details["vm_name"] == "vm-stopped"
    assert finding.details["power_state"] == "PowerState/stopped"
    assert finding.details["vm_size"] == "Standard_D2s_v3"


def test_deallocated_vm_skipped(mock_compute_client):
    """PowerState/deallocated should NOT be flagged."""
    vm = _make_vm("vm-deallocated")
    mock_compute_client.virtual_machines.list_all.return_value = [vm]
    mock_compute_client.virtual_machines.instance_view.return_value = _make_instance_view(
        "PowerState/deallocated"
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert len(findings) == 0


def test_running_vm_skipped(mock_compute_client):
    """PowerState/running should NOT be flagged."""
    vm = _make_vm("vm-running")
    mock_compute_client.virtual_machines.list_all.return_value = [vm]
    mock_compute_client.virtual_machines.instance_view.return_value = _make_instance_view(
        "PowerState/running"
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert len(findings) == 0


def test_transitional_states_skipped(mock_compute_client):
    """Transitional power states (starting, stopping, deallocating) should NOT be flagged."""
    vms = [
        _make_vm("vm-starting"),
        _make_vm("vm-stopping"),
        _make_vm("vm-deallocating"),
    ]
    mock_compute_client.virtual_machines.list_all.return_value = vms

    instance_views = {
        "vm-starting": _make_instance_view("PowerState/starting"),
        "vm-stopping": _make_instance_view("PowerState/stopping"),
        "vm-deallocating": _make_instance_view("PowerState/deallocating"),
    }
    mock_compute_client.virtual_machines.instance_view.side_effect = (
        lambda resource_group_name, vm_name: instance_views[vm_name]
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert len(findings) == 0


def test_region_filter(mock_compute_client):
    """Only VMs in the filtered region should be checked."""
    vms = [
        _make_vm("vm-east", location="eastus"),
        _make_vm("vm-west", location="westus"),
    ]
    mock_compute_client.virtual_machines.list_all.return_value = vms
    mock_compute_client.virtual_machines.instance_view.return_value = _make_instance_view(
        "PowerState/stopped"
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_compute_client,
    )

    assert len(findings) == 1
    assert findings[0].details["vm_name"] == "vm-east"


def test_mixed_vms(mock_compute_client):
    """Only stopped (not deallocated) VMs should be flagged from a mix."""
    vms = [
        _make_vm("vm-running"),
        _make_vm("vm-stopped"),
        _make_vm("vm-deallocated"),
    ]
    mock_compute_client.virtual_machines.list_all.return_value = vms

    instance_views = {
        "vm-running": _make_instance_view("PowerState/running"),
        "vm-stopped": _make_instance_view("PowerState/stopped"),
        "vm-deallocated": _make_instance_view("PowerState/deallocated"),
    }
    mock_compute_client.virtual_machines.instance_view.side_effect = (
        lambda resource_group_name, vm_name: instance_views[vm_name]
    )

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert len(findings) == 1
    assert findings[0].details["vm_name"] == "vm-stopped"


def test_empty_subscription(mock_compute_client):
    """No VMs should return empty findings."""
    mock_compute_client.virtual_machines.list_all.return_value = []

    findings = find_stopped_not_deallocated_vms(
        subscription_id="sub-123",
        credential=None,
        client=mock_compute_client,
    )

    assert findings == []
