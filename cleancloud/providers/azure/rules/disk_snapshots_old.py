"""
Rule: azure.compute.snapshot.old

Intent:
    Detect Azure managed snapshots that are old enough to be cleanup review
    candidates. Age alone does not prove a snapshot is unused, orphaned, or
    safe to delete. This is a conservative review-candidate rule only.

Exclusions:
    - id absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning_state != "Succeeded"
    - timeCreated absent or unparsable
    - completionPercent present and < 100
    - age_days < 30 (review_age_days)

Detection:
    - provisioning_state == "Succeeded"
    - timeCreated parseable and age_days >= 30

Confidence model (spec 8):
    LOW    — 30 <= age_days < max_age_days
    MEDIUM — age_days >= max_age_days
    HIGH is never used; age alone cannot establish HIGH confidence

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Azure bills snapshots on used size, not diskSizeGB — no per-snapshot
    cost estimate is possible without that data.

APIs:
    - Microsoft.Compute/snapshots/read (snapshots.list)
"""

from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.compute.snapshot.old"
_RESOURCE_TYPE = "azure.compute.snapshot"

# Minimum age for a snapshot to become a review candidate (spec: review_age_days = 30).
_REVIEW_AGE_DAYS = 30


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec section 4."""
    return s.lower() if s else ""


def _parse_time_created(snapshot) -> Optional[datetime]:
    """
    Return a UTC-aware datetime for the snapshot creation timestamp, or None.

    Accepts datetime objects (aware or naive) and ISO-format strings.
    Naive datetimes are treated as UTC. Unparseable values return None.
    """
    tc = getattr(snapshot, "time_created", None)
    if tc is None:
        return None
    if isinstance(tc, datetime):
        return tc if tc.tzinfo is not None else tc.replace(tzinfo=timezone.utc)
    if isinstance(tc, str):
        try:
            dt = datetime.fromisoformat(tc.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            return None
    return None


def find_old_snapshots(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
    max_age_days: int = 90,
) -> List[Finding]:
    """
    Find Azure managed snapshots that are review candidates based on age.

    Does not infer unused, orphaned, or safe-to-delete from age alone.
    Confidence is LOW for [review_age_days, max_age_days) and MEDIUM for
    >= max_age_days. estimated_monthly_cost_usd is always None.

    IAM permissions:
    - Microsoft.Compute/snapshots/read
    """
    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for snapshot in compute_client.snapshots.list():
        # spec 6A: id must be present and non-empty
        snap_id = getattr(snapshot, "id", None)
        if not snap_id:
            continue

        # resource_name is required (spec 12.3); skip malformed records without a name
        snap_name = getattr(snapshot, "name", None)
        if not snap_name:
            continue

        # spec 6A: region filter — exact lowercase match
        location = _norm_location(getattr(snapshot, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 6A: provisioning_state must be exactly "Succeeded"
        if getattr(snapshot, "provisioning_state", None) != "Succeeded":
            continue

        # spec 6A: timeCreated must be parseable
        time_created = _parse_time_created(snapshot)
        if time_created is None:
            continue

        # spec 6A: completionPercent — skip if present and < 100.
        # A non-numeric value is treated as malformed and causes a conservative skip.
        completion_percent = getattr(snapshot, "completion_percent", None)
        if completion_percent is not None:
            try:
                if completion_percent < 100:
                    continue
            except TypeError:
                continue  # non-numeric completionPercent → skip conservatively

        # spec 4: compute age in whole UTC days; skip if below review threshold
        age_days = (now - time_created).days
        if age_days < _REVIEW_AGE_DAYS:
            continue

        # spec 8: confidence — LOW for lower band, MEDIUM for higher, never HIGH
        confidence = ConfidenceLevel.MEDIUM if age_days >= max_age_days else ConfidenceLevel.LOW

        # spec 12.2: required signals
        signals_used = [
            f"Snapshot age is {age_days} days",
            "Snapshot provisioning state is Succeeded",
        ]
        if completion_percent is not None:
            # completionPercent was present and used as a best-effort gate
            signals_used.append(f"Snapshot completionPercent is {completion_percent}")

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Business or application restore intent",
                "Azure Backup or external backup ownership",
                "Disaster recovery retention intent",
                "Whether deleting the snapshot reduces billed used size",
            ],
            time_window=None,
        )

        # spec 12.3: source_resource_id from creation_data if present
        creation_data = getattr(snapshot, "creation_data", None)
        source_resource_id = (
            getattr(creation_data, "source_resource_id", None)
            if creation_data is not None
            else None
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=snap_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title=f"Old managed snapshot ({age_days} days)",
                summary=(
                    f"Snapshot '{snap_name}' has existed for {age_days} days "
                    f"and is a cleanup review candidate"
                ),
                reason=(
                    f"Snapshot age is {age_days} days, which meets the "
                    f"{_REVIEW_AGE_DAYS}-day review threshold"
                ),
                risk=RiskLevel.LOW,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                details={
                    "resource_name": snap_name,
                    "subscription_id": subscription_id,
                    "age_days": age_days,
                    "time_created": time_created.isoformat(),
                    "disk_size_gb": getattr(snapshot, "disk_size_gb", None),
                    "sku": (
                        getattr(snapshot.sku, "name", None)
                        if getattr(snapshot, "sku", None) is not None
                        else None
                    ),
                    "incremental": getattr(snapshot, "incremental", None),
                    "source_resource_id": source_resource_id,
                    "tags": getattr(snapshot, "tags", None) or {},
                },
            )
        )

    return findings
