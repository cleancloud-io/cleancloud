from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def _extract_resource_group(vm_id: str) -> str:
    """Extract resource group name from a VM resource ID."""
    parts = vm_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Cannot extract resource group from VM ID: {vm_id}")


def _get_power_state(instance_view) -> Optional[str]:
    """Extract power state from instance view statuses."""
    for status in instance_view.statuses or []:
        if status.code and status.code.startswith("PowerState/"):
            return status.code
    return None


def find_stopped_not_deallocated_vms(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure VMs that are stopped but not deallocated.

    VMs in 'Stopped' state (OS-level shutdown) still incur full compute charges.
    Only 'Deallocated' VMs stop incurring compute costs. This is a common Azure
    cost trap where users think their VM is off but are paying full price.

    IAM permissions:
    - Microsoft.Compute/virtualMachines/read
    """
    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for vm in compute_client.virtual_machines.list_all():
        if region_filter and (vm.location or "").lower() != region_filter.lower():
            continue

        try:
            resource_group = _extract_resource_group(vm.id)
            instance_view = compute_client.virtual_machines.instance_view(
                resource_group_name=resource_group,
                vm_name=vm.name,
            )
        except Exception:
            continue

        power_state = _get_power_state(instance_view)

        if power_state != "PowerState/stopped":
            continue

        evidence = Evidence(
            signals_used=[
                "VM power state is 'Stopped' (not 'Deallocated')",
                "Stopped VMs incur full compute charges",
            ],
            signals_not_checked=[
                "Whether stop was intentional or accidental",
                "Planned future usage",
                "IaC-managed intent",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.vm.stopped_not_deallocated",
                resource_type="azure.virtual_machine",
                resource_id=vm.id,
                region=vm.location,
                title="Azure VM Stopped but Not Deallocated",
                summary=(
                    f"VM '{vm.name}' is stopped but not deallocated — "
                    "still incurring full compute charges"
                ),
                reason="VM power state is 'Stopped' (not 'Deallocated')",
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "vm_name": vm.name,
                    "vm_size": (
                        getattr(vm.hardware_profile, "vm_size", None)
                        if vm.hardware_profile
                        else None
                    ),
                    "os_type": (
                        getattr(vm.storage_profile.os_disk, "os_type", None)
                        if vm.storage_profile and vm.storage_profile.os_disk
                        else None
                    ),
                    "location": vm.location,
                    "power_state": power_state,
                    "subscription_id": subscription_id,
                    "tags": vm.tags,
                },
            )
        )

    return findings
