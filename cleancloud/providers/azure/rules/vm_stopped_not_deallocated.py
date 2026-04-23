"""
Rule: azure.vm.stopped_not_deallocated

Intent:
    Detect Azure virtual machines in the billed stopped-allocated state
    (PowerState/stopped) that continue to incur compute charges even though
    they appear off.

    This is a review-candidate rule only. It does not prove the stop was
    accidental, that the VM should be deleted, or that a specific monthly
    saving exists.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to exactly "Succeeded"
    - per-VM instance_view retrieval fails (skip that VM)
    - runtime power state unresolvable, absent, or not exactly PowerState/stopped

Detection:
    - provisioning state is "Succeeded" (SDK-first with nested fallback)
    - runtime power state resolves to exactly "PowerState/stopped" from
      instance_view statuses (one unambiguous code)

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    The rule may state that compute charges continue, but must not emit a
    numeric estimate without a SKU-aware pricing model.

APIs:
    - Microsoft.Compute/virtualMachines/read (virtual_machines.list_all)
    - Microsoft.Compute/virtualMachines/instanceView/action
      (virtual_machines.instance_view per VM)
"""

from datetime import datetime, timezone
from typing import List, Optional

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.vm.stopped_not_deallocated"
_RESOURCE_TYPE = "azure.virtual_machine"
_TARGET_POWER_STATE = "PowerState/stopped"


def _norm_location(s: str) -> str:
    """Lowercase only -- exact lowercase match per spec 7."""
    return s.lower() if s else ""


def _extract_resource_group(vm_id: str) -> str:
    """Extract resource group name from a VM ARM resource ID."""
    parts = vm_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Cannot extract resource group from VM ID: {vm_id}")


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(vm) -> Optional[str]:
    """
    Resolve provisioning state from the VM model/control-plane payload per spec 9.1.

    Priority:
    1. SDK projection: vm.provisioning_state
    2. nested/raw properties: vm.properties.provisioningState

    Returns None (skip) on conflict or when both absent.
    Only "Succeeded" is eligible; caller skips on anything else.
    """
    sdk_val = getattr(vm, "provisioning_state", None)

    props = getattr(vm, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "provisioning_state", None)
        if nested_val is None:
            nested_val = getattr(props, "provisioningState", None)

    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip

    return sdk_val or nested_val


def _resolve_power_state(instance_view) -> Optional[str]:
    """
    Extract the runtime power state from instance view statuses per spec 9.2.

    Required behavior:
    - Collect all codes starting with "PowerState/"
    - Zero codes -> unknown -> return None (skip)
    - Exactly one unique code -> return it
    - Multiple conflicting codes -> ambiguous -> return None (skip)

    Caller skips unless the returned value is exactly "PowerState/stopped".
    """
    statuses = getattr(instance_view, "statuses", None) or []
    ps_codes = [
        s.code for s in statuses if getattr(s, "code", None) and s.code.startswith("PowerState/")
    ]

    if not ps_codes:
        return None  # no power state present -> unknown -> skip

    unique = set(ps_codes)
    if len(unique) > 1:
        return None  # conflicting codes -> ambiguous -> skip

    return ps_codes[0]


def find_stopped_not_deallocated_vms(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure VMs that are stopped but not deallocated (PowerState/stopped).

    VMs in the stopped-allocated state still incur full compute charges.
    Only deallocated VMs stop incurring compute costs.

    IAM permissions:
    - Microsoft.Compute/virtualMachines/read
    - Microsoft.Compute/virtualMachines/instanceView/action
    """
    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for vm in compute_client.virtual_machines.list_all():
        # spec 8.1: id must be present and non-empty
        vm_id = getattr(vm, "id", None)
        if not vm_id:
            continue

        # spec 8.2: name must be present and non-empty
        vm_name = getattr(vm, "name", None)
        if not vm_name:
            continue

        # spec 8.3: region filter -- exact lowercase match
        location = _norm_location(getattr(vm, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.4 / 9.1: provisioning state must resolve to exactly "Succeeded"
        # Avoids transient Stopped observations during VM creation / start
        if _resolve_provisioning_state(vm) != "Succeeded":
            continue

        # spec 8.5 / 9.2: per-VM instance_view to get authoritative runtime power state.
        # Expected per-VM retrieval failures -> skip this VM (spec 12).
        # ValueError:            malformed ARM id from _extract_resource_group.
        # HttpResponseError:     HTTP-level failure (404, 403, 429, 5xx).
        # ServiceRequestError:   transport failure before a response (connection reset,
        #                        DNS, network timeout).
        # ServiceResponseError:  transport failure while reading the response
        #                        (incomplete read, stream closed).
        # SerializationError, DeserializationError, and all other exceptions propagate.
        try:
            resource_group = _extract_resource_group(vm_id)
            instance_view = compute_client.virtual_machines.instance_view(
                resource_group_name=resource_group,
                vm_name=vm_name,
            )
        except (ValueError, HttpResponseError, ServiceRequestError, ServiceResponseError):
            continue

        # spec 8.5 / 9.2: resolve power state; None = unknown -> skip
        power_state = _resolve_power_state(instance_view)
        if power_state is None:
            continue

        # spec 8.6: emit only for exact PowerState/stopped
        if power_state != _TARGET_POWER_STATE:
            continue

        # --- Context fields (best-effort; never gate emission) ---
        hw = getattr(vm, "hardware_profile", None)
        vm_size = getattr(hw, "vm_size", None) if hw else None

        sp = getattr(vm, "storage_profile", None)
        os_disk = getattr(sp, "os_disk", None) if sp else None
        os_type = getattr(os_disk, "os_type", None) if os_disk else None

        tags = getattr(vm, "tags", None) or {}  # spec 7: never None in output

        # --- EMIT ---
        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=vm_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title="Azure VM Stopped but Not Deallocated",
                summary=(
                    f"VM '{vm_name}' is stopped but not deallocated — " "compute charges continue"
                ),
                reason=(
                    "Runtime power state is 'PowerState/stopped'; "
                    "stopped-allocated VMs continue to incur compute charges"
                ),
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Provisioning state is 'Succeeded'",
                        f"Runtime power state is exact '{_TARGET_POWER_STATE}' "
                        "from instance_view statuses",
                        "Stopped-allocated VMs continue to incur compute charges; "
                        "only 'Deallocated' stops compute billing",
                    ],
                    signals_not_checked=[
                        "Whether the stop was intentional or accidental",
                        "Planned restart or future usage",
                        "IaC-managed or schedule-managed intent",
                        "Reservation, savings plan, or licensing context",
                        "Attached disk, networking, or license costs",
                    ],
                    time_window=None,
                ),
                details={
                    "vm_name": vm_name,
                    "subscription_id": subscription_id,
                    "power_state": power_state,
                    "provisioning_state": "Succeeded",
                    "vm_size": vm_size,
                    "os_type": os_type,
                    "tags": tags,
                },
            )
        )

    return findings
