"""
Rule: gcp.compute.disk.unattached

    (spec — docs/specs/gcp/disk_unattached.md)

Intent:
    Detect Compute Engine persistent disks that are currently unattached to
    any VM and still bill for storage so they can be reviewed as conservative
    cleanup candidates.

Exclusions:
    - disk record malformed or name absent/empty (spec 8.1)
    - aggregated scope key unsupported or unresolvable (spec 8.2)
    - disk status not exactly "READY" (spec 8.4)
    - disk users field unresolvable / not an explicit empty list (spec 8.5)
    - disk users non-empty (spec 8.6)

Detection:
    - disk status == "READY"
    - users[] is explicitly an empty list (no current VM attachment)
    - covers zonal (zones/ZONE) and regional (regions/REGION) scopes

Confidence (spec 9.4):
    - Zonal, detached < 24h: LOW
    - Zonal, detached 24h–7d: MEDIUM
    - Zonal, detached >= 7d (or never): HIGH
    - Regional, detached < 24h: LOW
    - Regional, otherwise: MEDIUM

Cost model (spec 9.5):
    - estimated_monthly_cost_usd = None
    - No flat region-reference price table; pricing varies by type, region, and currency.
    - State only that unattached disks continue to incur storage charges.

APIs:
    - compute.disks.list (via disks.aggregatedList)
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
            # spec 9.6 / 9.1.8-9: surface partial-success warnings so callers know
            # that zero findings cannot be interpreted as a clean project.
            _scope_warning = getattr(scope_disks, "warning", None)
            if _scope_warning and getattr(_scope_warning, "code", ""):
                warnings.warn(
                    f"gcp.compute.disk.unattached: aggregated inventory returned partial "
                    f"coverage for scope '{scope_key}' "
                    f"(code: {_scope_warning.code}) — findings from this scope may be incomplete",
                    UserWarning,
                    stacklevel=2,
                )

            if not scope_disks.disks:
                continue

            # --- spec 8.2: scope key must be exactly "zones/ZONE" or "regions/REGION" ---
            scope_parts = scope_key.split("/")
            if len(scope_parts) != 2:
                continue  # too few or too many segments — skip

            scope_type = scope_parts[0]  # "zones" or "regions"
            location = scope_parts[1]  # zone name or region name

            if scope_type == "zones":
                zone_name = location
                # spec 7 / 9.1.5: derive region by stripping the trailing zone letter.
                # GCP zone names always end in a single alphabetic letter (e.g. "-a").
                # A scope like zones/us-central1 (no zone letter) must skip — rsplit
                # alone would silently derive "us" from "us-central1", which is wrong.
                zone_parts = zone_name.rsplit("-", 1)
                if len(zone_parts) < 2 or len(zone_parts[1]) != 1 or not zone_parts[1].isalpha():
                    continue  # spec 8.2 / 7: zone lacks a single-letter suffix → skip
                region = zone_parts[0]
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
                # spec 8.1: skip malformed records with absent / empty name
                if not disk.name:
                    continue

                # spec 8.4: only READY disks are eligible
                if disk.status != "READY":
                    continue

                # spec 8.5: users must be an explicit list — any other type
                # (None, str, dict, tuple, …) means attachment state is unresolvable.
                # An empty list is the only value that safely means "unattached".
                if not isinstance(disk.users, list):
                    continue
                # spec 8.6: any current user entry means attached → skip
                if disk.users:
                    continue

                # Extract short disk type from full resource URL.
                # e.g. "zones/us-central1-a/diskTypes/pd-ssd" -> "pd-ssd"
                # spec 7: fallback to "unknown" (not a guessed default type)
                disk_type_url = disk.type_ or ""
                disk_type = disk_type_url.split("/")[-1] if disk_type_url else "unknown"

                # spec 7: parse size as non-negative int; use 0 on malformed values
                try:
                    size_gb = int(disk.size_gb) if disk.size_gb is not None else 0
                except (ValueError, TypeError):
                    size_gb = 0

                labels = dict(disk.labels) if disk.labels else {}

                # Regional disks use a different resource path than zonal disks.
                if is_regional:
                    resource_id = f"projects/{project_id}/regions/{region}/disks/{disk.name}"
                    report_location = region
                else:
                    resource_id = f"projects/{project_id}/zones/{zone_name}/disks/{disk.name}"
                    report_location = zone_name

                # spec 9.4: confidence baseline
                confidence = ConfidenceLevel.MEDIUM if is_regional else ConfidenceLevel.HIGH

                # Modulate confidence by time since last detach.
                # spec 7: treat non-string timestamps as unknown rather than crashing.
                raw_ts = disk.last_detach_timestamp
                last_detach_str = raw_ts if isinstance(raw_ts, str) else ""
                hours_since_detach: Optional[float] = None
                if last_detach_str:
                    try:
                        ts = last_detach_str.replace("Z", "+00:00")
                        last_detach = datetime.fromisoformat(ts)
                        if last_detach.tzinfo is None:
                            last_detach = last_detach.replace(tzinfo=timezone.utc)
                        hours_since_detach = (now - last_detach).total_seconds() / 3600
                        if hours_since_detach < 24:
                            confidence = ConfidenceLevel.LOW
                        elif hours_since_detach < 7 * 24 and not is_regional:
                            # Zonal disk detached 24h–7d: plausibly still mid-pipeline.
                            # Regional disks remain at MEDIUM baseline.
                            confidence = ConfidenceLevel.MEDIUM
                    except (ValueError, AttributeError):
                        pass  # unparseable timestamp — keep baseline confidence

                signals_used = [
                    "Disk status: READY",
                    "No VM users (users list empty)",
                    f"Disk type: {disk_type}",
                    f"Size: {size_gb} GB",
                ]
                if is_regional:
                    signals_used.append(
                        "Regional disk (replicated across 2 zones — often provisioned for HA)"
                    )
                if hours_since_detach is not None:
                    signals_used.append(f"Last detached: {hours_since_detach:.0f}h ago")

                # spec 9.5 / 10.2: never claim a specific dollar cost — pricing varies
                signals_not_checked = [
                    "Exact monthly cost (varies by disk type, region, currency, and provisioned performance — see GCP billing)",
                    "Disk reserved for imminent VM recreation",
                    "Snapshot, image, or template restore dependency (disk may be intentionally detached)",
                    "Cross-project disk sharing",
                ]
                if disk_type in _HYPERDISK_TYPES:
                    signals_not_checked.append(
                        "Hyperdisk IOPS and throughput charges are billed separately from capacity cost"
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
                            f"is not attached to any VM but continues to incur storage charges."
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
                        # spec 9.5.1: cost model is None — pricing varies by type/region/currency
                        estimated_monthly_cost_usd=None,
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
