"""
Rule: gcp.compute.ip.unused

    (spec — docs/specs/gcp/ip_unused.md)

Intent:
    Detect static external IPv4 address reservations currently in RESERVED state
    so they can be reviewed as conservative cleanup candidates.

Exclusions:
    - address record malformed or name absent/empty (spec 8.1)
    - regional aggregated scope key unsupported or malformed (spec 8.2)
    - region filter set and normalized regional scope does not match (spec 8.3)
    - address is global and a region filter is set (spec 8.4)
    - status not exactly "RESERVED" (spec 8.5)
    - addressType absent, unknown, or not exactly "EXTERNAL" (spec 8.6)
    - ipVersion absent, unknown, or not exactly "IPV4" (spec 8.7)
    - purpose == "NAT_AUTO" (spec 8.8)
    - users[] resolves to one or more entries (spec 8.9)

Detection:
    - status == "RESERVED"
    - addressType == "EXTERNAL"
    - ipVersion == "IPV4"
    - purpose != "NAT_AUTO"
    - users[] empty or absent
    - covers regional (regions/REGION) and global addresses

Confidence (spec 10.1):
    - HIGH for all findings

Risk (spec 10.2):
    - LOW for all findings

Cost model (spec 9.7):
    - estimated_monthly_cost_usd = 7.30
    - Derived from Google's documented $0.01/hour for unused static external IPv4
      × 730-hour normalized month.

APIs:
    - compute.addresses.list (via addresses.aggregatedList)
    - compute.globalAddresses.list
"""

import warnings
from datetime import datetime, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# spec 9.7: $0.01/hour × 730-hour normalized month = $7.30/month
_UNUSED_IP_COST_USD_MONTH = 7.30


def find_unused_static_ips(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
) -> List[Finding]:
    """
    Find reserved external IPv4 addresses not in use.

    GCP bills $7.30/month (estimated) for each static external IPv4 address in
    RESERVED status. These accumulate when VMs, load balancers, or NAT gateways
    are deleted without releasing their reserved IPs.

    Covers both regional and global external IPv4 addresses.

    IAM permissions required:
    - compute.addresses.list (included in roles/compute.viewer)
    - compute.globalAddresses.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # --- Regional IPs (addresses.aggregatedList) ---
    # aggregated_list() returns a lazy pager — PermissionDenied fires during
    # iteration (not at call time), so the try/except must wrap the full loop.
    # return_partial_success=True allows partial results when some scopes are
    # unreachable rather than failing the entire call (spec 9.1.2).
    # Response scope keys for addresses: "regions/REGION".
    # See: https://cloud.google.com/compute/docs/reference/rest/v1/addresses/aggregatedList
    addresses_client = compute_v1.AddressesClient(credentials=credentials)
    try:
        pager = addresses_client.aggregated_list(
            request={"project": project_id, "return_partial_success": True}
        )
        for page in pager.pages:
            # spec 9.1.6-7: surface top-level page warning — callers must not treat
            # zero findings as proof of full clean coverage.
            _page_warning = getattr(page, "warning", None)
            if _page_warning and getattr(_page_warning, "code", ""):
                warnings.warn(
                    f"gcp.compute.ip.unused: aggregated inventory returned a top-level warning "
                    f"(code: {_page_warning.code}) — regional address coverage may be incomplete",
                    UserWarning,
                    stacklevel=2,
                )

            # spec 9.1.6-7: surface unreachable scopes
            for unreachable_scope in getattr(page, "unreachables", None) or []:
                warnings.warn(
                    f"gcp.compute.ip.unused: aggregated inventory could not reach scope "
                    f"'{unreachable_scope}' — findings from this scope are unavailable",
                    UserWarning,
                    stacklevel=2,
                )

            for scope_key, scope_addresses in (getattr(page, "items", None) or {}).items():
                # spec 9.1.6-7: surface scope-level warning
                _scope_warning = getattr(scope_addresses, "warning", None)
                if _scope_warning and getattr(_scope_warning, "code", ""):
                    warnings.warn(
                        f"gcp.compute.ip.unused: aggregated inventory returned partial "
                        f"coverage for scope '{scope_key}' "
                        f"(code: {_scope_warning.code}) — findings from this scope may be incomplete",
                        UserWarning,
                        stacklevel=2,
                    )

                if not scope_addresses.addresses:
                    continue

                # spec 8.2 / 7: supported form is exactly "regions/REGION"
                scope_parts = scope_key.split("/")
                if len(scope_parts) != 2 or scope_parts[0] != "regions":
                    continue  # skip "global" and any other unexpected scope types

                region_name = scope_parts[1]

                # spec 8.3
                if region_filter and region_name != region_filter:
                    continue

                for address in scope_addresses.addresses:
                    # spec 8.1: skip malformed records with absent / empty name
                    if not address.name:
                        continue

                    # spec 8.5: only RESERVED addresses are eligible
                    if address.status != "RESERVED":
                        continue

                    # spec 8.6: addressType absent, unknown, or not exactly "EXTERNAL" → skip
                    if address.address_type != "EXTERNAL":
                        continue

                    # spec 8.7: ipVersion absent, unknown, or not exactly "IPV4" → skip
                    if address.ip_version != "IPV4":
                        continue

                    # spec 8.8: NAT_AUTO addresses are Cloud NAT automatic allocations,
                    # not customer-held unused reservations
                    if address.purpose == "NAT_AUTO":
                        continue

                    # spec 8.9: non-empty users[] is contradictory current-use evidence
                    if address.users:
                        continue

                    labels = dict(address.labels) if address.labels else {}
                    # spec 7: preserve exact documented value; do not guess if absent
                    network_tier = address.network_tier or None

                    signals_not_checked = [
                        "IP held for imminent re-attachment or manual failover",
                        "DNS, firewall allowlist, or customer integration dependencies",
                        "Operational reserve, cutover, or HA intent",
                        "Contract-specific or non-USD billing differences",
                    ]
                    if network_tier == "STANDARD":
                        signals_not_checked.append(
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
                                f"Regional static IPv4 address '{address.name}' ({address.address}) in "
                                f"'{region_name}' is reserved but not attached to any resource, "
                                f"billing ~${_UNUSED_IP_COST_USD_MONTH}/month (estimated, "
                                f"public USD list pricing at $0.01/hr)."
                            ),
                            reason="Address status is RESERVED and no contradictory current-use evidence was found",
                            risk=RiskLevel.LOW,
                            confidence=ConfidenceLevel.HIGH,
                            detected_at=now,
                            evidence=Evidence(
                                signals_used=[
                                    "Address status: RESERVED (not IN_USE)",
                                    "Address type: EXTERNAL",
                                    "IP version: IPv4",
                                    "Scope: regional",
                                    f"Network tier: {network_tier or 'unknown'}",
                                    f"IP: {address.address}",
                                    f"~${_UNUSED_IP_COST_USD_MONTH}/month (estimated public USD list price at $0.01/hr × 730h)",
                                ],
                                signals_not_checked=signals_not_checked,
                                time_window=None,
                            ),
                            details={
                                "address_name": address.name,
                                "ip_address": address.address or None,
                                "scope": "regional",
                                "is_regional": True,
                                "address_type": address.address_type,
                                "ip_version": address.ip_version,
                                "purpose": address.purpose or None,
                                "network_tier": network_tier,
                                "region": region_name,
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

    # spec 8.4 / 9.6: global addresses have no regional scope — skip when region filter active
    if region_filter:
        return findings

    # --- Global IPs (globalAddresses.list) ---
    global_addresses_client = compute_v1.GlobalAddressesClient(credentials=credentials)
    try:
        for address in global_addresses_client.list(project=project_id):
            # spec 8.1
            if not address.name:
                continue

            # spec 8.5
            if address.status != "RESERVED":
                continue

            # spec 8.6
            if address.address_type != "EXTERNAL":
                continue

            # spec 8.7
            if address.ip_version != "IPV4":
                continue

            # spec 8.8
            if address.purpose == "NAT_AUTO":
                continue

            # spec 8.9
            if address.users:
                continue

            labels = dict(address.labels) if address.labels else {}
            # spec 7: preserve exact documented value; do not guess if absent.
            # GCP documents global IPs are always PREMIUM — the API normally returns
            # "PREMIUM", but store None rather than fabricating a value when absent.
            network_tier = address.network_tier or None

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.compute.ip.unused",
                    resource_type="gcp.compute.global_address",
                    resource_id=f"projects/{project_id}/global/addresses/{address.name}",
                    region="global",
                    title="Unused Reserved Global IP",
                    summary=(
                        f"Global static IPv4 address '{address.name}' ({address.address}) is reserved "
                        f"but not attached to any resource, billing ~${_UNUSED_IP_COST_USD_MONTH}/month "
                        f"(estimated, public USD list pricing at $0.01/hr)."
                    ),
                    reason="Global address status is RESERVED and no contradictory current-use evidence was found",
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=[
                            "Address status: RESERVED (not IN_USE)",
                            "Address type: EXTERNAL",
                            "IP version: IPv4",
                            "Scope: global",
                            f"Network tier: {network_tier or 'unknown'} (global IPs are documented as always PREMIUM by GCP)",
                            f"IP: {address.address}",
                            f"~${_UNUSED_IP_COST_USD_MONTH}/month (estimated public USD list price at $0.01/hr × 730h)",
                        ],
                        signals_not_checked=[
                            "IP held for imminent re-attachment or manual failover",
                            "DNS, firewall allowlist, or customer integration dependencies",
                            "Operational reserve, cutover, or HA intent",
                            "Contract-specific or non-USD billing differences",
                        ],
                        time_window=None,
                    ),
                    details={
                        "address_name": address.name,
                        "ip_address": address.address or None,
                        "scope": "global",
                        "is_regional": False,
                        "address_type": address.address_type,
                        "ip_version": address.ip_version,
                        "purpose": address.purpose or None,
                        "network_tier": network_tier,
                        "creation_timestamp": address.creation_timestamp or None,
                        "labels": labels,
                    },
                    estimated_monthly_cost_usd=_UNUSED_IP_COST_USD_MONTH,
                )
            )

    except (PermissionDenied, Forbidden) as e:
        # spec 9.8.2: global permission failures must surface as a permission error
        # during full-scope scans; silent degradation to regional-only is not acceptable.
        raise PermissionError(
            f"compute.globalAddresses.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        pass

    return findings


find_unused_static_ips.RULE_ID = "gcp.compute.ip.unused"
