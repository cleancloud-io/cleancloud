"""
Rule: gcp.compute.vm.stopped

    (spec — docs/specs/gcp/vm_stopped.md)

Intent:
    Detect Compute Engine VM instances in the documented stopped lifecycle state
    that have remained stopped for at least the configured threshold and therefore
    represent conservative review candidates for cleanup of lingering
    attached-cost surfaces.

    This is a conservative review-candidate rule only. It is not proof that
    the VM is abandoned, not proof that attached resources should be deleted,
    and not proof of a specific monthly saving.

Exclusions:
    - instance record malformed or name absent / empty (spec 8.1)
    - aggregated scope key does not resolve to exact zones/ZONE (spec 8.2)
    - region filter set and normalized region is unknown or does not match (spec 8.3)
    - instance is proven to have active MIG membership (spec 8.4)
    - normalized lifecycle state not STOPPED_VM (spec 8.5)
    - lastStopTimestamp absent or unparsable (spec 8.6)
    - stop age < max_age_days (spec 8.7)

Detection:
    - normalized status is STOPPED_VM (TERMINATED or STOPPED)
    - lastStopTimestamp parsable and stop_age_days >= max_age_days

Cost model (spec 9.6):
    estimated_monthly_cost_usd = None
    Attached resources continue billing by their own pricing surface;
    no flat rate estimate is appropriate.

APIs:
    - compute.googleapis.com: instances.aggregatedList with returnPartialSuccess=true
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

# spec 2.1: canonical stopped lifecycle states
_STOPPED_STATUSES = frozenset({"TERMINATED", "STOPPED"})


def _whole_utc_days_since(ts: datetime, now: datetime) -> int:
    """Return the number of whole UTC calendar days between ts and now."""
    return (now.astimezone(timezone.utc).date() - ts.astimezone(timezone.utc).date()).days


def _parse_gcp_timestamp(ts: str) -> Optional[datetime]:
    """Parse a GCP RFC3339 timestamp to a UTC-aware datetime, or return None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_zone(zone_scope: str) -> Optional[str]:
    """
    Return zone name from an exact 'zones/ZONE' aggregated scope key.

    Returns None for any other scope form, including keys with extra path
    segments such as 'zones/us-central1-a/extra' (spec 9.2.1).
    """
    if not zone_scope.startswith("zones/"):
        return None
    zone = zone_scope[len("zones/") :]
    # Reject empty suffix or any additional path segments
    if not zone or "/" in zone:
        return None
    return zone


def _derive_region(zone: str) -> str:
    """
    Derive region from a zone string by dropping the trailing zone letter.

    Returns 'unknown' when the zone string is not parseable as a standard
    GCP zone (spec 9.2.4).  Standard form: '{area}-{sub}-{letter}'.
    """
    parts = zone.rsplit("-", 1)
    if len(parts) == 2 and "-" in parts[0]:
        return parts[0]
    return "unknown"


def _is_mig_member(instance) -> bool:
    """
    Return True only when first-party proof of active MIG membership is available.

    Spec 9.4.3 allows two proof-source categories:

    a) Direct managed-instance-group membership surfaces — e.g., the result of
       calling instanceGroupManagers.listManagedInstances for each MIG and
       checking whether the instance self-link appears.  Doing so requires
       additional API calls that are out of scope for a rule using only
       instances.aggregatedList; this path is not exercised here.

    b) Current instance metadata — the 'created-by' key set by GCP at
       instance creation time referencing 'instanceGroupManagers/...'.
       This is the only first-party proof available from the aggregated
       list response and is checked below.

    No name patterns, user labels, or other weak heuristics are used (spec 9.4.4).
    """
    # Proof source b: GCP-set 'created-by' instance metadata
    metadata = getattr(instance, "metadata", None)
    if not metadata:
        return False
    for item in getattr(metadata, "items", None) or []:
        if getattr(item, "key", None) == "created-by":
            val = getattr(item, "value", "") or ""
            if "instanceGroupManagers/" in val:
                return True
    return False


def _has_external_nat_ip(instance) -> bool:
    """True when any network interface has a NAT IP (spec 7 / 10.2.9)."""
    for nic in getattr(instance, "network_interfaces", None) or []:
        for ac in getattr(nic, "access_configs", None) or []:
            if getattr(ac, "nat_ip", None):
                return True
    return False


def find_stopped_vms(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    max_age_days: int = 30,
) -> List[Finding]:
    """
    Find Compute Engine VMs in STOPPED_VM state for max_age_days+ days.

    Detection requires lastStopTimestamp to be present and parseable.
    Instances with no usable stop timestamp are skipped rather than guessed.
    Instances with proven active MIG membership are excluded.

    IAM permissions required:
    - compute.instances.list (roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    instances_client = compute_v1.InstancesClient(credentials=credentials)

    # spec 9.1: aggregated inventory with returnPartialSuccess — PermissionDenied
    # and NotFound fire during iteration, so the try/except wraps the full loop.
    try:
        for zone_scope, zone_instances in instances_client.aggregated_list(
            project=project_id,
            return_partial_success=True,
        ):
            # spec 9.1.4: surface partial-coverage warnings
            _warn = getattr(zone_instances, "warning", None)
            if _warn and getattr(_warn, "code", None):
                warnings.warn(
                    f"gcp.compute.vm.stopped: aggregated inventory returned partial "
                    f"coverage for scope '{zone_scope}' (code: {_warn.code}) — "
                    f"findings from this scope may be incomplete",
                    UserWarning,
                    stacklevel=2,
                )

            if not getattr(zone_instances, "instances", None):
                continue

            # spec 9.2.1: accept only exact zones/ZONE scope keys
            zone_name = _extract_zone(zone_scope)
            if zone_name is None:
                continue

            # spec 9.2.3–9.2.4: derive region; 'unknown' when not parseable
            region = _derive_region(zone_name)

            # spec 9.2.6: region filter with unknown region → skip (with warning)
            if region_filter:
                if region == "unknown":
                    warnings.warn(
                        f"gcp.compute.vm.stopped: skipped zone scope '{zone_name}' "
                        f"because region could not be derived "
                        f"(region_filter={region_filter!r})",
                        UserWarning,
                        stacklevel=2,
                    )
                    continue
                if region != region_filter:
                    continue

            for instance in zone_instances.instances:
                try:
                    # spec 8.1: name must be present and non-empty
                    if not getattr(instance, "name", ""):
                        continue

                    # spec 8.4: skip proven MIG members
                    if _is_mig_member(instance):
                        continue

                    # spec 8.5: only STOPPED_VM lifecycle states are eligible
                    raw_status = instance.status or ""
                    if raw_status not in _STOPPED_STATUSES:
                        continue

                    # spec 8.6 / 9.5: lastStopTimestamp must be present and parseable
                    stop_time = _parse_gcp_timestamp(instance.last_stop_timestamp or "")
                    if stop_time is None:
                        continue  # skip rather than guess (spec 9.5.4)

                    # spec 8.7 / 9.5.3: stop age must meet the threshold
                    stop_age_days = _whole_utc_days_since(stop_time, now)
                    if stop_age_days < max_age_days:
                        continue

                    # --- All exclusions passed: build finding ---

                    # Disk analysis (spec 7)
                    disks = list(getattr(instance, "disks", None) or [])
                    persistent_disks = [d for d in disks if getattr(d, "type_", "") == "PERSISTENT"]
                    persistent_disk_count = len(persistent_disks)
                    persistent_disk_total_gb = sum(
                        max(0, int(getattr(d, "disk_size_gb", 0) or 0)) for d in persistent_disks
                    )
                    boot_disk_count = sum(1 for d in disks if getattr(d, "boot", False))
                    disk_kinds_present = sorted(
                        {getattr(d, "type_", "") for d in disks if getattr(d, "type_", "")}
                    )

                    # Machine type (spec 7)
                    machine_type_raw = instance.machine_type or ""
                    machine_type = (
                        machine_type_raw.split("/")[-1] if machine_type_raw else "unknown"
                    )

                    # Network and GPU context (spec 7)
                    external_nat_ip_present = _has_external_nat_ip(instance)
                    gpu_attached = bool(getattr(instance, "guest_accelerators", None))

                    # Scheduling context (spec 7)
                    scheduling = getattr(instance, "scheduling", None)
                    automatic_restart = (
                        getattr(scheduling, "automatic_restart", None) if scheduling else None
                    )

                    # Labels and timestamps
                    labels = dict(instance.labels) if instance.labels else {}
                    last_stop_timestamp_str = stop_time.isoformat()
                    last_start_ts = instance.last_start_timestamp or ""

                    # spec 9.7: confidence is age-led
                    confidence = (
                        ConfidenceLevel.HIGH if stop_age_days >= 90 else ConfidenceLevel.MEDIUM
                    )

                    # spec 10.2: signals_used
                    signals_used = [
                        f"Instance lifecycle state: {raw_status} (STOPPED_VM)",
                        f"Stopped for {stop_age_days} days (threshold: {max_age_days} days)",
                        (
                            f"Persistent disks: {persistent_disk_count} disk(s), "
                            f"{persistent_disk_total_gb} GB total — "
                            f"attached resources continue billing"
                        ),
                        f"Machine type: {machine_type}",
                    ]
                    if boot_disk_count > 0:
                        signals_used.append(f"Boot disk present: {boot_disk_count} boot disk(s)")
                    if disk_kinds_present:
                        signals_used.append(f"Attached disk kinds: {', '.join(disk_kinds_present)}")
                    if external_nat_ip_present:
                        signals_used.append(
                            "External NAT IP present — may indicate active connectivity dependency"
                        )
                    if gpu_attached:
                        signals_used.append("GPU attached — higher-cost resource context")
                    if automatic_restart is not None:
                        signals_used.append(f"automaticRestart: {automatic_restart}")

                    # spec 10.3: required details
                    details: dict = {
                        "instance_name": instance.name,
                        "machine_type": machine_type,
                        "zone": zone_name,
                        "raw_status": raw_status,
                        "stop_age_days": stop_age_days,
                        "max_age_days_threshold": max_age_days,
                        "last_stop_timestamp": last_stop_timestamp_str,
                        "mig_membership": False,  # proven non-MIG (MIG members were excluded)
                        "persistent_disk_count": persistent_disk_count,
                        "persistent_disk_total_gb": persistent_disk_total_gb,
                        "disk_kinds_present": disk_kinds_present,
                        "boot_disk_count": boot_disk_count,
                        "external_nat_ip_present": external_nat_ip_present,
                        "gpu_attached": gpu_attached,
                        "labels": labels,
                    }
                    # conditional details (spec 10.3: when present)
                    if last_start_ts:
                        details["last_start_timestamp"] = last_start_ts
                    if automatic_restart is not None:
                        details["automatic_restart"] = automatic_restart

                    # spec 10.2: signals_not_checked — region_unparseable is a
                    # diagnostic code only relevant when region derivation failed
                    # for this finding (spec 9.2 / 10.2).
                    signals_not_checked = [
                        "Planned seasonal or scheduled shutdown intent",
                        "Rollback, forensics, or future restart intent",
                        "Exact resource-specific monthly pricing for disks and IPs "
                        "was not estimated",
                        "Static external IP usage and billing state were not fully " "resolved",
                        "missing_last_stop_timestamp: older or atypical VMs with no "
                        "usable stop timestamp are intentionally skipped",
                    ]
                    if region == "unknown":
                        signals_not_checked.append(
                            "region_unparseable: region could not be derived from zone — "
                            "regional context is unavailable for this instance"
                        )

                    findings.append(
                        Finding(
                            provider="gcp",
                            rule_id="gcp.compute.vm.stopped",
                            resource_type="gcp.compute.instance",
                            resource_id=(
                                f"projects/{project_id}/zones/{zone_name}"
                                f"/instances/{instance.name}"
                            ),
                            region=region,
                            title=f"Stopped VM ({stop_age_days}+ Days)",
                            summary=(
                                f"VM '{instance.name}' ({machine_type}) in zone '{zone_name}' "
                                f"has been stopped for {stop_age_days} days. "
                                f"Attached disks ({persistent_disk_count} disk(s), "
                                f"{persistent_disk_total_gb} GB) continue billing."
                            ),
                            reason=(
                                f"Instance has been in {raw_status} state for {stop_age_days} days "
                                f"(>= {max_age_days}-day threshold)"
                            ),
                            risk=RiskLevel.MEDIUM,
                            confidence=confidence,
                            detected_at=now,
                            evidence=Evidence(
                                signals_used=signals_used,
                                signals_not_checked=signals_not_checked,
                                time_window=f"{max_age_days} days",
                            ),
                            details=details,
                            # spec 9.6: always None — attached resources bill by their own pricing
                            estimated_monthly_cost_usd=None,
                        )
                    )
                except (AttributeError, TypeError, ValueError) as e:
                    # spec 9.9.3: malformed instance records are skipped item-by-item
                    warnings.warn(
                        f"gcp.compute.vm.stopped: skipped malformed instance "
                        f"{getattr(instance, 'name', '<unknown>')}: {e}",
                        UserWarning,
                        stacklevel=2,
                    )
                    continue

    except (PermissionDenied, Forbidden) as e:
        raise PermissionError(
            f"compute.instances.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        # Compute Engine API not enabled for this project — return empty
        return findings

    return findings


find_stopped_vms.RULE_ID = "gcp.compute.vm.stopped"
