from datetime import datetime, timezone
from typing import List

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

MIN_AGE_DAYS_HIGH = 14
MIN_AGE_DAYS_MEDIUM = 7


def _age_in_days(created_at: datetime) -> int:
    now = datetime.now(timezone.utc)
    return (now - created_at).days


def find_unattached_managed_disks(
    subscription_id: str,
    credential,
    region_filter: str = None,
) -> List[Finding]:
    """
    Find unattached Azure managed disks that are likely orphaned.

    Conservative rule (review-only):
    - Disk is not attached to any VM
    - Age exceeds threshold
    - Does NOT infer intended usage

    IAM permissions:
    - Microsoft.Compute/disks/read
    """

    findings: List[Finding] = []

    compute_client = ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for disk in compute_client.disks.list():
        if region_filter and disk.location != region_filter:
            continue

        # Primary signal: attachment state
        if disk.managed_by is not None:
            continue

        # Secondary signal: age
        if not disk.time_created:
            continue

        disk_age_days = _age_in_days(disk.time_created)

        if disk_age_days >= MIN_AGE_DAYS_MEDIUM:
            confidence_value = ConfidenceLevel.MEDIUM  # conservative for all ages
        else:
            continue  # too new

        evidence = Evidence(
            signals_used=[
                "Disk.managed_by is None (not attached to any VM)",
                f"Disk age = {disk_age_days} days",
            ],
            signals_not_checked=[
                "Planned future VM attachment",
                "IaC-managed intent",
                "Application-level usage",
                "Disaster recovery or backup planning",
            ],
            time_window=f"{MIN_AGE_DAYS_MEDIUM}-{MIN_AGE_DAYS_HIGH}+ days",
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.unattached_managed_disk",
                resource_type="azure.managed_disk",
                resource_id=disk.id,
                region=disk.location,
                title="Unattached Azure managed disk",
                summary=f"Disk not attached to any VM for {disk_age_days} days",
                reason="Disk has no VM attachment and exceeds age threshold",
                risk=RiskLevel.LOW,
                confidence=confidence_value,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": disk.name,
                    "subscription_id": subscription_id,
                    "managed_by": None,
                    "age_days": disk_age_days,
                    "sku": disk.sku.name if disk.sku else None,
                    "size_gb": disk.disk_size_gb,
                    "tags": disk.tags,
                },
            )
        )

    return findings
