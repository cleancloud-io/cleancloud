"""
Rule: gcp.compute.snapshot.old

    (spec — docs/specs/gcp/snapshot_old.md)

Intent:
    Detect old standard snapshot resources that are conservative cleanup review
    candidates after excluding stronger Google-documented signals that the
    snapshot is part of an intentional automated backup workflow.

Exclusions:
    - snapshot record malformed or name absent/empty (spec 8.1)
    - status not exactly "READY" (spec 8.2)
    - creationTimestamp absent or unparsable (spec 8.3)
    - age_days < max_age_days (spec 8.4)
    - snapshotType == "ARCHIVE" (spec 8.5)
    - sourceSnapshotSchedulePolicy or sourceSnapshotSchedulePolicyId present
      and non-empty (spec 8.6)
    - autoCreated == True (spec 8.7)

Detection:
    - status == "READY"
    - creationTimestamp parsable
    - age_days >= max_age_days
    - not archive, not schedule-created, not auto-created

Confidence (spec 9.8):
    - LOW for all findings

Risk (spec 9.9):
    - LOW for all findings

Cost model (spec 9.7):
    - estimated_monthly_cost_usd = None
    - No flat per-GB rate; pricing varies by snapshot type and storage location.

APIs:
    - compute.snapshots.list
"""

import re
from datetime import datetime, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_BYTES_PER_GB = 1024**3


def _parse_gcp_timestamp(ts: str) -> Optional[datetime]:
    """Parse a GCP RFC3339 timestamp like '2024-01-15T10:30:00.000-07:00'."""
    if not ts:
        return None
    try:
        cleaned = re.sub(r"\.\d+", "", ts)
        cleaned = cleaned.replace("Z", "+00:00")
        return datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        return None


def find_old_snapshots(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    max_age_days: int = 90,
) -> List[Finding]:
    """
    Find disk snapshots older than max_age_days that are not part of automated
    backup workflows.

    Old snapshots accumulate silently after VM deletion, manual one-off backups,
    or abandoned snapshot schedules. This rule excludes archive, schedule-created,
    and auto-created snapshots as stronger signals of intentional backup workflows.

    Snapshots are global resources — region_filter is ignored (spec 9.1.3).

    IAM permissions required:
    - compute.snapshots.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    snapshots_client = compute_v1.SnapshotsClient(credentials=credentials)

    # list() returns a lazy pager — PermissionDenied fires during iteration
    # (not at call time), so the try/except must wrap the full loop.
    try:
        for snapshot in snapshots_client.list(project=project_id):
            # spec 8.1: skip malformed records with absent / empty name
            if not snapshot.name:
                continue

            # spec 8.2 / 9.2: only READY snapshots are stably evaluable
            if snapshot.status != "READY":
                continue

            # spec 8.3 / 9.3: creationTimestamp must be parsable; skip if absent or malformed
            created_at = _parse_gcp_timestamp(snapshot.creation_timestamp or "")
            if created_at is None:
                continue

            # spec 8.4 / 9.3: emit only when age_days >= max_age_days
            age_days = (now - created_at).days
            if age_days < max_age_days:
                continue

            # spec 8.5 / 9.5: archive snapshots are a low-cost long-retention class — skip
            if snapshot.snapshot_type == "ARCHIVE":
                continue

            # spec 8.6 / 9.4: schedule-created snapshots are intentional recurring backups
            # not in (None, "") is more explicit than truthiness: empty string is "not present"
            if snapshot.source_snapshot_schedule_policy not in (None, ""):
                continue
            if snapshot.source_snapshot_schedule_policy_id not in (None, ""):
                continue

            # spec 8.7 / 9.4: auto-created snapshots are intentional backups
            if getattr(snapshot, "auto_created", None):
                continue

            # Normalize storage fields for context only (spec 9.7 / 7)
            # spec 7: non-negative integer; negative values normalize to 0
            try:
                disk_size_gb = max(0, int(snapshot.disk_size_gb)) if snapshot.disk_size_gb else 0
            except (ValueError, TypeError):
                disk_size_gb = 0

            try:
                storage_bytes = max(0, int(snapshot.storage_bytes)) if snapshot.storage_bytes else 0
            except (ValueError, TypeError):
                storage_bytes = 0

            # spec 7: preserve exact documented values; None when absent
            storage_bytes_status = snapshot.storage_bytes_status or None
            snapshot_type = snapshot.snapshot_type or None
            # getattr preserves explicit None/unknown on malformed or minimal mock objects
            auto_created = getattr(snapshot, "auto_created", None)
            # resolve chain_name: prefer SDK snake_case; camelCase as fallback for raw objects
            chain_name = (
                getattr(snapshot, "chain_name", None) or getattr(snapshot, "chainName", None) or ""
            )

            # spec 9.10: malformed context fields must not fail the whole rule
            try:
                labels = dict(snapshot.labels) if snapshot.labels else {}
            except Exception:
                labels = {}

            try:
                storage_locations = (
                    list(snapshot.storage_locations) if snapshot.storage_locations else []
                )
            except Exception:
                storage_locations = []

            # spec 10.2: signals_used must disclose status, age, threshold, storage context
            signals_used = [
                "Status: READY",
                f"Snapshot age: {age_days} days (threshold: {max_age_days} days)",
                f"Created: {created_at.date().isoformat()}",
            ]
            if snapshot_type:
                signals_used.append(f"Snapshot type: {snapshot_type}")
            # spec 3.3 / 9.7: diskSizeGb is source disk size, not billed snapshot size
            signals_used.append(
                f"Source disk size: {disk_size_gb} GB (not the billed snapshot storage size)"
            )
            # spec 9.7: storageBytes as context only, including when very small or zero
            storage_gb = storage_bytes / _BYTES_PER_GB
            status_note = f" ({storage_bytes_status})" if storage_bytes_status else ""
            signals_used.append(
                f"Billed storage (storageBytes): {storage_gb:.1f} GB{status_note} — context only; "
                f"deleting may not reclaim full amount due to incremental sharing"
            )
            if chain_name:
                signals_used.append(f"Snapshot is part of a named incremental chain: {chain_name}")

            # spec 10.3: required details fields
            details: dict = {
                "snapshot_name": snapshot.name,
                "created_at": created_at.isoformat(),
                "age_days": age_days,
                "max_age_days_threshold": max_age_days,
                "disk_size_gb": disk_size_gb,
                "storage_bytes": storage_bytes,
                "storage_bytes_status": storage_bytes_status,
                "storage_locations": storage_locations,
                "snapshot_type": snapshot_type,
                "auto_created": auto_created,
                "labels": labels,
            }
            # Conditionally include optional fields when present (spec 10.3)
            if snapshot.source_snapshot_schedule_policy not in (None, ""):
                details["source_snapshot_schedule_policy"] = (
                    snapshot.source_snapshot_schedule_policy
                )
            if snapshot.source_snapshot_schedule_policy_id not in (None, ""):
                details["source_snapshot_schedule_policy_id"] = (
                    snapshot.source_snapshot_schedule_policy_id
                )
            if snapshot.source_disk:
                details["source_disk"] = snapshot.source_disk
            if snapshot.source_disk_id:
                details["source_disk_id"] = snapshot.source_disk_id
            if chain_name:
                details["chain_name"] = chain_name

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.compute.snapshot.old",
                    resource_type="gcp.compute.snapshot",
                    resource_id=f"projects/{project_id}/global/snapshots/{snapshot.name}",
                    region="global",
                    title=f"Old Disk Snapshot ({age_days} Days)",
                    summary=(
                        f"Snapshot '{snapshot.name}' is {age_days} days old "
                        f"and has not been identified as part of an automated backup workflow."
                    ),
                    reason=(
                        f"Snapshot is {age_days} days old (threshold: {max_age_days} days) "
                        f"and no schedule-created or auto-created evidence was found"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.LOW,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=[
                            "Business or application retention intent",
                            "DR, audit, or compliance requirements",
                            "Snapshot restore frequency or operational usage was not evaluated",
                            "Whether deleting this snapshot would materially reduce billed "
                            "storage (snapshots are incremental — adjacent snapshots may "
                            "share data blocks)",
                            "Exact monthly pricing from current storage location and snapshot type",
                        ],
                        time_window=f"{max_age_days} days",
                    ),
                    details=details,
                    # spec 9.7: no flat per-GB estimate; pricing varies by type and location
                    estimated_monthly_cost_usd=None,
                )
            )

    except (PermissionDenied, Forbidden) as e:
        raise PermissionError(
            f"compute.snapshots.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        # Compute Engine API not enabled for this project — return empty
        return findings

    return findings


find_old_snapshots.RULE_ID = "gcp.compute.snapshot.old"
