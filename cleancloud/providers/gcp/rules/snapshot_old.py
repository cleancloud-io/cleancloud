import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# GCP snapshot storage pricing: ~$0.026/GB/month (multi-regional standard)
# Source: https://cloud.google.com/compute/disks-image-pricing#disk_snapshots
_SNAPSHOT_COST_PER_GB_MONTH = 0.026

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
    Find disk snapshots older than 90 days.

    GCP snapshots are stored in Cloud Storage and billed at ~$0.026/GB/month.
    Snapshots accumulate silently — automated snapshot policies are frequently
    removed while their snapshots are left behind, and one-off manual snapshots
    are rarely cleaned up. 90 days is a reliable threshold that avoids flagging
    routine backup cycles while catching chronic waste.

    Confidence is HIGH when the source disk no longer exists (clear orphan),
    MEDIUM when the source disk is still present (might be intentional long-term
    backup or DR snapshot).

    Snapshots are global resources — region_filter is not applied (they have no
    region; source disk zone is an unreliable proxy for filtering intent).

    Detection logic:
    - Snapshot creation timestamp older than `max_age_days` days
    - Snapshot status == READY

    IAM permissions required:
    - compute.snapshots.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)

    snapshots_client = compute_v1.SnapshotsClient(credentials=credentials)

    # list() returns a lazy pager — PermissionDenied fires during iteration
    # (not at call time), so the try/except must wrap the full loop.
    try:
        for snapshot in snapshots_client.list(project=project_id):
            if snapshot.status != "READY":
                continue

            created_at = _parse_gcp_timestamp(snapshot.creation_timestamp or "")
            if created_at is None or created_at > cutoff:
                continue

            max_age_days_actual = (now - created_at).days

            # Empty source_disk means the source disk has been deleted — clear orphan
            source_disk = snapshot.source_disk or ""
            source_disk_deleted = not bool(source_disk)

            # Higher confidence when source disk is gone (orphaned snapshot)
            confidence = ConfidenceLevel.HIGH if source_disk_deleted else ConfidenceLevel.MEDIUM

            # Use actual compressed storage bytes if available; fall back to disk size
            storage_bytes = int(snapshot.storage_bytes or 0)
            disk_size_gb = int(snapshot.disk_size_gb or 0)
            billable_gb = (storage_bytes / _BYTES_PER_GB) if storage_bytes > 0 else disk_size_gb
            monthly_cost = round(billable_gb * _SNAPSHOT_COST_PER_GB_MONTH, 2)

            labels = dict(snapshot.labels) if snapshot.labels else {}

            signals = [
                f"Snapshot age: {max_age_days_actual} days (created {created_at.date().isoformat()})",
                "Status: READY",
                f"Disk size: {disk_size_gb} GB",
            ]
            if storage_bytes > 0:
                signals.append(
                    f"Actual stored size: {billable_gb:.1f} GB -> ~${monthly_cost}/month"
                )
            else:
                signals.append(f"Estimated cost: ~${monthly_cost}/month (disk size used as proxy)")
            if source_disk_deleted:
                signals.append(
                    "Source disk reference missing — likely orphaned snapshot "
                    "(GCP clears sourceDisk when the backing disk is deleted)"
                )
            else:
                signals.append(f"Source disk: {source_disk.split('/')[-1]}")

            details = {
                "snapshot_name": snapshot.name,
                "disk_size_gb": disk_size_gb,
                "storage_bytes": storage_bytes,
                "max_age_days": max_age_days_actual,
                "max_age_days_threshold": max_age_days,
                "created_at": created_at.isoformat(),
                "source_disk_deleted": source_disk_deleted,
                # storage_locations: ["us-central1"] = regional, ["us"] = multi-regional.
                # Affects pricing — multi-regional ($0.026/GB) costs more than regional.
                "storage_locations": (
                    list(snapshot.storage_locations) if snapshot.storage_locations else []
                ),
                "labels": labels,
            }
            if not source_disk_deleted:
                details["source_disk"] = source_disk.split("/")[-1]
                details["source_disk_url"] = source_disk  # full URL for cross-project lookup
            if snapshot.source_disk_id:
                details["source_disk_id"] = snapshot.source_disk_id  # stable numeric ID
            if snapshot.chain_name:
                details["chain_name"] = snapshot.chain_name  # non-empty only when explicitly set

            findings.append(
                Finding(
                    provider="gcp",
                    rule_id="gcp.compute.snapshot.old",
                    resource_type="gcp.compute.snapshot",
                    resource_id=f"projects/{project_id}/global/snapshots/{snapshot.name}",
                    region="global",
                    title=f"Old Disk Snapshot ({max_age_days_actual} Days)",
                    summary=(
                        f"Snapshot '{snapshot.name}' ({disk_size_gb} GB) is {max_age_days_actual} days old"
                        + (" and its source disk no longer exists." if source_disk_deleted else ".")
                        + f" Estimated storage cost: ~${monthly_cost}/month."
                    ),
                    reason=f"Snapshot is {max_age_days_actual} days old (threshold: {max_age_days} days)",
                    risk=RiskLevel.LOW,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals,
                        signals_not_checked=[
                            "Compliance or regulatory data retention requirements",
                            "Disaster recovery snapshot policy",
                            "Part of an active backup rotation",
                            "Snapshot storage is incremental — deleting this snapshot may not "
                            "fully reclaim its estimated cost if adjacent snapshots share blocks",
                            "Snapshot storage location (regional vs multi-regional) may affect "
                            "pricing (rule uses multi-regional rate of $0.026/GB/month)",
                        ],
                        time_window=f"{max_age_days} days",
                    ),
                    details=details,
                    estimated_monthly_cost_usd=monthly_cost if monthly_cost > 0 else None,
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
