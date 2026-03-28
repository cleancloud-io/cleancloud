from datetime import datetime, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# GCP charges for static IPs that are reserved but not attached to a running resource.
# PREMIUM network tier (default): $0.010/hour = ~$7.20/month per unused IP.
# STANDARD network tier: lower cost — verify current rate at
# https://cloud.google.com/vpc/network-pricing#ipaddress
# Global external IPs are always PREMIUM. Only regional IPs can be STANDARD.
# We use the PREMIUM rate as the conservative estimate for all tiers; when a
# regional IP is STANDARD, we note it in the finding so users can verify actual cost.
_UNUSED_IP_COST_USD_MONTH = 7.20  # PREMIUM tier reference


def find_unused_static_ips(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
) -> List[Finding]:
    """
    Find reserved external IP addresses not attached to any resource.

    GCP bills ~$7.20/month for each static IP in RESERVED status (allocated but
    not in use). These accumulate when VMs, load balancers, or NAT gateways are
    deleted without releasing their reserved IPs.

    Covers both regional and global external IPs.

    Detection logic:
    - Regional IP: status == RESERVED (not IN_USE)
    - Global IP: status == RESERVED (not IN_USE)

    IAM permissions required:
    - compute.addresses.list (included in roles/compute.viewer)
    - compute.globalAddresses.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # --- Regional IPs ---
    # aggregated_list() returns a lazy pager — PermissionDenied fires during
    # iteration (not at call time), so the try/except must wrap the full loop.
    addresses_client = compute_v1.AddressesClient(credentials=credentials)
    try:
        for region_scope, region_addresses in addresses_client.aggregated_list(project=project_id):
            if not region_addresses.addresses:
                continue

            # region_scope is like "regions/us-central1"
            region_name = region_scope.split("/")[-1]

            if region_filter and region_name != region_filter:
                continue

            for address in region_addresses.addresses:
                if address.status != "RESERVED":
                    continue  # IN_USE — attached to a resource
                # Only EXTERNAL IPs incur the static IP reservation charge.
                # INTERNAL addresses use VPC subnet allocation and are not billed this way.
                if address.address_type and address.address_type != "EXTERNAL":
                    continue

                labels = dict(address.labels) if address.labels else {}
                network_tier = address.network_tier or "PREMIUM"

                regional_signals_not_checked = [
                    "IP held for imminent re-attachment",
                    "Compliance or security requirement to hold specific IP",
                ]
                if network_tier == "STANDARD":
                    regional_signals_not_checked.append(
                        "STANDARD tier IPs cost less than PREMIUM — cost shown is the "
                        "PREMIUM reference rate; verify actual rate at "
                        "cloud.google.com/vpc/network-pricing#ipaddress"
                    )

                findings.append(
                    Finding(
                        provider="gcp",
                        rule_id="gcp.compute.ip.unused",
                        resource_type="gcp.compute.address",
                        resource_id=f"projects/{project_id}/regions/{region_name}/addresses/{address.name}",
                        region=region_name,
                        title="Unused Reserved External IP",
                        summary=(
                            f"Regional static IP '{address.name}' ({address.address}) in "
                            f"'{region_name}' is reserved but not attached to any resource, "
                            f"billing ~${_UNUSED_IP_COST_USD_MONTH}/month (estimated)."
                        ),
                        reason="IP address status is RESERVED — not attached to any VM, LB, or NAT gateway",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        detected_at=now,
                        evidence=Evidence(
                            signals_used=[
                                "Address status: RESERVED (not IN_USE)",
                                f"Address type: {address.address_type or 'EXTERNAL'}",
                                f"Network tier: {network_tier}",
                                f"IP: {address.address}",
                                f"~${_UNUSED_IP_COST_USD_MONTH}/month (PREMIUM tier reference, estimated)",
                            ],
                            signals_not_checked=regional_signals_not_checked,
                            time_window=None,
                        ),
                        details={
                            "address_name": address.name,
                            "ip_address": address.address,
                            "address_type": address.address_type or "EXTERNAL",
                            "purpose": address.purpose or None,
                            "region": region_name,
                            "scope": "regional",
                            "is_regional": True,
                            "network_tier": network_tier,
                            "creation_timestamp": address.creation_timestamp or None,
                            "labels": labels,
                        },
                        estimated_monthly_cost_usd=_UNUSED_IP_COST_USD_MONTH,
                    )
                )

    except (PermissionDenied, Forbidden) as e:
        raise PermissionError(
            f"compute.addresses.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        # Compute Engine API not enabled for this project — return empty
        return findings

    # --- Global IPs ---
    # Graceful degradation: if global IP permission is denied, return regional findings
    # rather than failing the entire rule. Global IPs are less common and the caller
    # already has actionable regional results.
    if region_filter:
        # Global IPs have no region — skip when region filter is active
        return findings

    global_addresses_client = compute_v1.GlobalAddressesClient(credentials=credentials)
    try:
        for address in global_addresses_client.list(project=project_id):
            if address.status != "RESERVED":
                continue  # IN_USE

            labels = dict(address.labels) if address.labels else {}
            # Global IPs are always PREMIUM tier (regional-only IPs can be STANDARD)

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.compute.ip.unused",
                    resource_type="gcp.compute.global_address",
                    resource_id=f"projects/{project_id}/global/addresses/{address.name}",
                    region="global",
                    title="Unused Reserved Global IP",
                    summary=(
                        f"Global static IP '{address.name}' ({address.address}) is reserved "
                        f"but not attached to any resource, billing ~${_UNUSED_IP_COST_USD_MONTH}/month "
                        f"(estimated)."
                    ),
                    reason="Global IP address status is RESERVED — not attached to any load balancer",
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=[
                            "Address status: RESERVED (not IN_USE)",
                            "Scope: global",
                            "Network tier: PREMIUM (global IPs are always PREMIUM)",
                            f"IP: {address.address}",
                            f"~${_UNUSED_IP_COST_USD_MONTH}/month (PREMIUM tier reference, estimated)",
                        ],
                        signals_not_checked=[
                            "IP held for imminent load balancer creation",
                            "Compliance or security requirement to hold specific IP",
                        ],
                        time_window=None,
                    ),
                    details={
                        "address_name": address.name,
                        "ip_address": address.address,
                        "address_type": address.address_type or "EXTERNAL",
                        "purpose": address.purpose or None,
                        "scope": "global",
                        "is_regional": False,
                        "network_tier": "PREMIUM",
                        "creation_timestamp": address.creation_timestamp or None,
                        "labels": labels,
                    },
                    estimated_monthly_cost_usd=_UNUSED_IP_COST_USD_MONTH,
                )
            )

    except (PermissionDenied, Forbidden, NotFound):
        # Partial degradation: return regional findings even if global IPs are inaccessible
        pass

    return findings


find_unused_static_ips.RULE_ID = "gcp.compute.ip.unused"
