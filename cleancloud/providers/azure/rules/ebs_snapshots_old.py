from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

MIN_AGE_DAYS_MEDIUM = 30
MIN_AGE_DAYS_HIGH = 90


def _age_in_days(created_at: datetime) -> int:
    now = datetime.now(timezone.utc)
    return (now - created_at).days


def find_old_snapshots(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find old Azure managed snapshots that may be orphaned.

    Conservative rule (review-only):
    - Snapshot age checked
    - Other usage/ownership not inferred

    IAM permissions:
    - Microsoft.Compute/snapshots/read
    """

    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    for snapshot in compute_client.snapshots.list():
        if region_filter and snapshot.location != region_filter:
            continue

        if not snapshot.time_created:
            continue

        age_days = _age_in_days(snapshot.time_created)

        if age_days >= MIN_AGE_DAYS_HIGH:
            confidence_value = ConfidenceLevel.MEDIUM  # conservative
        elif age_days >= MIN_AGE_DAYS_MEDIUM:
            confidence_value = ConfidenceLevel.MEDIUM
        else:
            continue  # too new, ignore

        evidence = Evidence(
            signals_used=[f"Snapshot age is {age_days} days"],
            signals_not_checked=[
                "Disk usage by applications",
                "IaC-managed ownership",
                "Disaster recovery or backup intent",
                "Future planned usage",
            ],
            time_window=f"{MIN_AGE_DAYS_MEDIUM}-{MIN_AGE_DAYS_HIGH} days",
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id="azure.old_snapshot",
                resource_type="azure.snapshot",
                resource_id=snapshot.id,
                region=snapshot.location,
                title="Old Azure managed snapshot",
                summary=f"Snapshot has existed for {age_days} days",
                reason="Snapshot age exceeds configured threshold",
                risk=RiskLevel.LOW,
                confidence=confidence_value,
                detected_at=datetime.now(timezone.utc),
                evidence=evidence,
                details={
                    "resource_name": snapshot.name,
                    "subscription_id": subscription_id,
                    "age_days": age_days,
                    "disk_size_gb": snapshot.disk_size_gb,
                    "sku": snapshot.sku.name if snapshot.sku else None,
                    "tags": snapshot.tags,
                },
            )
        )

    return findings
