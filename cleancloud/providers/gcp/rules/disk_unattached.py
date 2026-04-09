from datetime import datetime, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# GCP Persistent Disk pricing ($/GB/month, us-central1 reference).
# Source: https://cloud.google.com/compute/disks-image-pricing
#
# Notes:
# - pd-extreme also bills for provisioned IOPS separately (not estimable from listing).
# - Hyperdisk types bill for capacity + provisioned IOPS and/or throughput separately.
#   Only the capacity component can be estimated here; actual cost is typically higher.
#   hyperdisk-balanced: 3,000 IOPS and 140 MiB/s free baseline, additional usage billed.
#   hyperdisk-extreme: all provisioned IOPS billable, no free baseline.
#   hyperdisk-throughput: all provisioned throughput billable.
#   Using pd-standard rate as conservative capacity-only floor for all hyperdisk types.
_DISK_TYPE_COST_PER_GB: dict = {
    "pd-standard": 0.04,
    "pd-balanced": 0.10,
    "pd-ssd": 0.17,
    "pd-extreme": 0.125,  # capacity only; provisioned IOPS billed separately
    "hyperdisk-balanced": 0.04,  # capacity only; IOPS + throughput billed separately
    "hyperdisk-extreme": 0.04,  # capacity only; all IOPS billed separately
    "hyperdisk-throughput": 0.04,  # capacity only; throughput billed separately
}
_DEFAULT_COST_PER_GB = 0.04  # pd-standard as conservative fallback

_HYPERDISK_TYPES = frozenset({"hyperdisk-balanced", "hyperdisk-extreme", "hyperdisk-throughput"})


def find_unattached_disks(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
) -> List[Finding]:
    """
    Find Compute Engine persistent disks not attached to any VM.

    Persistent disks bill regardless of attachment status. Orphaned disks are
    commonly left behind after VM deletion — a high-volume, zero-utility cost source.

    Detection logic:
    - Disk status == READY (exists, not being created or deleted)
    - Disk users list is empty (not attached to any instance)
    - Covers both zonal disks (zones/ZONE) and regional disks (regions/REGION)

    Confidence:
    - Zonal disk, unattached, detached > 7 days ago (or never detached): HIGH
    - Zonal disk, detached 24h–7d ago: MEDIUM — may still be in a deletion pipeline
    - Either type detached < 24h ago: LOW — very likely mid-pipeline
    - Regional disk, unattached: MEDIUM — may be intentionally kept for HA failover

    IAM permissions required:
    - compute.disks.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    disks_client = compute_v1.DisksClient(credentials=credentials)

    # aggregated_list() returns a lazy pager — PermissionDenied fires during
    # iteration (not at call time), so the try/except must wrap the full loop.
    # Response scope keys: "zones/ZONE" (zonal) or "regions/REGION" (regional).
    # See: https://cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList
    try:
        for scope_key, scope_disks in disks_client.aggregated_list(project=project_id):
            if not scope_disks.disks:
                continue

            # scope_key is "zones/us-central1-a" or "regions/us-central1"
            scope_parts = scope_key.split("/")
            scope_type = scope_parts[0]  # "zones" or "regions"
            location = scope_parts[1]  # zone name or region name

            if scope_type == "zones":
                zone_name = location
                region = zone_name.rsplit("-", 1)[0]  # "us-central1-a" -> "us-central1"
                is_regional = False
            elif scope_type == "regions":
                zone_name = None
                region = location
                is_regional = True
            else:
                continue  # skip unknown scope types (e.g. "global")

            if region_filter and region != region_filter:
                continue

            for disk in scope_disks.disks:
                if disk.status != "READY":
                    continue
                if disk.users:  # non-empty = attached to one or more VMs
                    continue

                # Extract short disk type from full resource URL
                # e.g. "zones/us-central1-a/diskTypes/pd-ssd" -> "pd-ssd"
                disk_type_url = disk.type_ or ""
                disk_type = disk_type_url.split("/")[-1] if disk_type_url else "pd-standard"

                size_gb = int(disk.size_gb) if disk.size_gb is not None else 0
                cost_per_gb = _DISK_TYPE_COST_PER_GB.get(disk_type, _DEFAULT_COST_PER_GB)
                monthly_cost = round(size_gb * cost_per_gb, 2)

                labels = dict(disk.labels) if disk.labels else {}

                # Regional disks use a different resource path than zonal disks.
                # lastAttachTimestamp / lastDetachTimestamp are [Output Only] fields
                # confirmed in GCP Disk API:
                # https://cloud.google.com/compute/docs/reference/rest/v1/disks
                if is_regional:
                    resource_id = f"projects/{project_id}/regions/{region}/disks/{disk.name}"
                    report_location = region
                else:
                    resource_id = f"projects/{project_id}/zones/{zone_name}/disks/{disk.name}"
                    report_location = zone_name

                # Confidence: regional disks are often intentionally provisioned for HA
                # (replicated across two zones); an unattached regional disk is more
                # ambiguous than an unattached zonal disk.
                confidence = ConfidenceLevel.MEDIUM if is_regional else ConfidenceLevel.HIGH

                # Modulate confidence by time since last detach.
                # A disk detached < 24h ago may be mid-pipeline (VM deleted, disk
                # deletion pending). After 7 days the disk is almost certainly orphaned.
                last_detach_str = disk.last_detach_timestamp or ""
                hours_since_detach: Optional[float] = None
                if last_detach_str:
                    try:
                        # GCP uses RFC3339; handle both "+HH:MM" and "Z" offsets
                        ts = last_detach_str.replace("Z", "+00:00")
                        last_detach = datetime.fromisoformat(ts)
                        if last_detach.tzinfo is None:
                            last_detach = last_detach.replace(tzinfo=timezone.utc)
                        hours_since_detach = (now - last_detach).total_seconds() / 3600
                        if hours_since_detach < 24:
                            confidence = ConfidenceLevel.LOW
                        elif hours_since_detach < 7 * 24 and not is_regional:
                            # Zonal disk detached 24h–7d ago: still plausibly in a pipeline.
                            # Regional disks stay at their MEDIUM base regardless.
                            confidence = ConfidenceLevel.MEDIUM
                    except ValueError:
                        pass

                signals_used = [
                    "Disk status: READY",
                    "No VM users (users list empty)",
                    f"Disk type: {disk_type} (~${cost_per_gb}/GB/month storage)",
                    f"Size: {size_gb} GB -> ~${monthly_cost}/month (estimated, region-dependent)",
                ]
                if is_regional:
                    signals_used.append(
                        "Regional disk (replicated across 2 zones — often provisioned for HA)"
                    )
                if hours_since_detach is not None:
                    signals_used.append(f"Last detached: {hours_since_detach:.0f}h ago")

                signals_not_checked = [
                    "Disk reserved for imminent VM recreation",
                    "Snapshot-only workflow (intentional detachment)",
                    "Cross-project disk sharing",
                ]
                if disk_type in _HYPERDISK_TYPES:
                    signals_not_checked.append(
                        f"Hyperdisk IOPS and throughput charges are billed separately from "
                        f"capacity — actual monthly cost is likely higher than ~${monthly_cost}"
                    )
                if disk_type == "pd-extreme":
                    signals_not_checked.append(
                        "pd-extreme provisioned IOPS are billed separately from capacity"
                    )

                details: dict = {
                    "disk_name": disk.name,
                    "disk_type": disk_type,
                    "size_gb": size_gb,
                    "location": report_location,
                    "is_regional": is_regional,
                    "labels": labels,
                    "creation_timestamp": disk.creation_timestamp or None,
                }
                if last_detach_str:
                    details["last_detach_timestamp"] = last_detach_str
                if disk.last_attach_timestamp:
                    details["last_attach_timestamp"] = disk.last_attach_timestamp

                findings.append(
                    Finding(
                        provider="gcp",
                        rule_id="gcp.compute.disk.unattached",
                        resource_type="gcp.compute.disk",
                        resource_id=resource_id,
                        region=report_location,
                        title="Unattached Persistent Disk",
                        summary=(
                            f"Persistent disk '{disk.name}' ({size_gb} GB, {disk_type}) "
                            f"in {'region' if is_regional else 'zone'} '{report_location}' "
                            f"is not attached to any VM but continues to incur storage "
                            f"charges (~${monthly_cost}/month, estimated, region-dependent)."
                        ),
                        reason="Disk has no attached VM (users list is empty)",
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=Evidence(
                            signals_used=signals_used,
                            signals_not_checked=signals_not_checked,
                            time_window=None,
                        ),
                        details=details,
                        estimated_monthly_cost_usd=monthly_cost if monthly_cost > 0 else None,
                    )
                )

    except (PermissionDenied, Forbidden) as e:
        raise PermissionError(
            f"compute.disks.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        # Compute Engine API not enabled for this project — return empty
        return findings

    return findings


find_unattached_disks.RULE_ID = "gcp.compute.disk.unattached"
