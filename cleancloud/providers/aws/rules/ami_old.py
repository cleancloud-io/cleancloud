from datetime import datetime, timezone
from typing import List

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_old_amis(
    session: boto3.Session,
    region: str,
    days_old: int = 180,
) -> List[Finding]:
    """
    Find AMIs (Amazon Machine Images) older than `days_old`.

    Conservative rule (review-only):
    - Only checks owned AMIs (not public/shared)
    - Uses configurable age threshold (default 180 days) (AMIs can be long-lived golden images)
    - Does NOT check if AMI is actively used for launching instances
    - Confidence MEDIUM (age is moderate signal; may be golden image)

    IAM permissions:
    - ec2:DescribeImages
    """
    ec2 = session.client("ec2", region_name=region)

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # Get all AMIs owned by this account (paginated for large accounts)
    paginator = ec2.get_paginator("describe_images")

    for page in paginator.paginate(Owners=["self"]):
        for ami in page.get("Images", []):
            # Parse creation date
            creation_date_str = ami.get("CreationDate")
            if not creation_date_str:
                continue

            try:
                creation_date = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            age_days = (now - creation_date).days

            if age_days < days_old:
                continue

            ami_id = ami.get("ImageId")
            ami_name = ami.get("Name", "unnamed")
            ami_state = ami.get("State", "unknown")

            # Skip AMIs that are not available
            if ami_state != "available":
                continue

            # Determine image type info
            platform = ami.get("PlatformDetails", "Linux/UNIX")
            architecture = ami.get("Architecture", "x86_64")
            root_device_type = ami.get("RootDeviceType", "ebs")

            signals = [
                f"AMI age is {age_days} days (exceeds {days_old}-day threshold)",
                f"AMI state is '{ami_state}'",
            ]

            # Check for snapshot storage (EBS-backed AMIs have associated snapshots)
            block_devices = ami.get("BlockDeviceMappings", [])
            snapshot_ids = []
            total_size_gb = 0
            for bd in block_devices:
                ebs = bd.get("Ebs", {})
                if ebs.get("SnapshotId"):
                    snapshot_ids.append(ebs["SnapshotId"])
                    size = ebs.get("VolumeSize")
                    if isinstance(size, (int, float)):
                        total_size_gb += size

            if snapshot_ids:
                signals.append(
                    f"AMI has {len(snapshot_ids)} EBS snapshot(s) totaling ~{total_size_gb} GB"
                )

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=[
                    "Active EC2 instances launched from this AMI",
                    "Launch template references",
                    "Auto Scaling group references",
                    "Golden image / baseline usage",
                    "Disaster recovery intent",
                    "Compliance retention requirements",
                ],
                time_window=f"{days_old} days",
            )

            # Estimate monthly storage cost (~$0.05/GB-month for EBS snapshots)
            estimated_monthly_cost = None
            cost_usd = None
            if total_size_gb > 0:
                cost_usd = round(total_size_gb * 0.05, 2)
                estimated_monthly_cost = f"~${total_size_gb * 0.05:.2f}/month (snapshot storage)"

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.ami.old",
                    resource_type="aws.ec2.ami",
                    resource_id=ami_id,
                    region=region,
                    estimated_monthly_cost_usd=cost_usd,
                    title=f"AMI Older Than {days_old} Days",
                    summary=(
                        f"AMI '{ami_name}' is {age_days} days old and may be "
                        f"incurring snapshot storage costs."
                    ),
                    reason=f"AMI exceeds {days_old}-day age threshold",
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.MEDIUM,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "ami_name": ami_name,
                        "creation_date": creation_date.isoformat(),
                        "age_days": age_days,
                        "state": ami_state,
                        "platform": platform,
                        "architecture": architecture,
                        "root_device_type": root_device_type,
                        "snapshot_ids": snapshot_ids,
                        "total_size_gb": total_size_gb,
                        "estimated_monthly_cost": estimated_monthly_cost,
                        "tags": ami.get("Tags", []),
                    },
                )
            )

    return findings
