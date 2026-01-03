from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

MIN_SNAPSHOT_AGE_DAYS = 7


def _age_in_days(created_at: datetime) -> int:
    return (datetime.now(timezone.utc) - created_at).days


def find_untagged_resources(
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find untagged Azure resources (disks, snapshots).

    Conservative rule (review-only):
    - Only checks presence of tags
    - Does NOT infer intended usage or IaC ownership

    IAM permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    """

    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    # ======================
    # Managed Disks
    # ======================
    for disk in compute_client.disks.list():
        if region_filter and disk.location != region_filter:
            continue

        if disk.tags:
            continue

        confidence_value = (
            ConfidenceLevel.MEDIUM if disk.managed_by is None else ConfidenceLevel.LOW
        )

        evidence = Evidence(
            signals_used=["No tags found on disk"],
            signals_not_checked=[
                "Planned VM attachment",
                "IaC-managed intent",
                "Application-level usage",
                "Disaster recovery or backup planning",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.untagged_resource",
                resource_type="azure.managed_disk",
                resource_id=disk.id,
                region=disk.location,
                title="Untagged Azure managed disk",
                summary="Disk has no tags",
                reason="No tags found on resource",
                risk=RiskLevel.LOW,
                confidence=confidence_value,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": disk.name,
                    "subscription_id": subscription_id,
                    "tags_present": False,
                    "managed_by": disk.managed_by,
                },
            )
        )

    # ======================
    # Snapshots
    # ======================
    for snap in compute_client.snapshots.list():
        if region_filter and snap.location != region_filter:
            continue

        if snap.tags:
            continue

        if not snap.time_created:
            continue

        age_days = _age_in_days(snap.time_created)
        if age_days < MIN_SNAPSHOT_AGE_DAYS:
            continue

        evidence = Evidence(
            signals_used=[f"No tags found on snapshot, age {age_days} days"],
            signals_not_checked=[
                "Disk usage by applications",
                "IaC-managed ownership",
                "Disaster recovery or backup planning",
                "Future planned usage",
            ],
            time_window=f">={MIN_SNAPSHOT_AGE_DAYS} days",
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.untagged_resource",
                resource_type="azure.snapshot",
                resource_id=snap.id,
                region=snap.location,
                title="Untagged Azure snapshot",
                summary="Snapshot has no tags",
                reason="No tags found on resource",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.LOW,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": snap.name,
                    "subscription_id": subscription_id,
                    "tags_present": False,
                    "age_days": age_days,
                },
            )
        )

    return findings
