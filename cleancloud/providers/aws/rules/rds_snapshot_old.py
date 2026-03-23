from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# ~$0.095/GB-month for RDS automated/manual snapshots (us-east-1)
_SNAPSHOT_COST_PER_GB = 0.095


def find_old_rds_snapshots(
    session: boto3.Session,
    region: str,
    days_old: int = 90,
) -> List[Finding]:
    """
    Find manual RDS snapshots older than `days_old` days.

    Manual RDS snapshots are retained indefinitely until explicitly deleted and
    accrue storage charges at ~$0.095/GB-month. Snapshots older than 90 days
    are rarely needed for active recovery and are a common source of forgotten
    spend.

    Only manual snapshots are flagged — automated snapshots are managed by
    the RDS retention policy and delete themselves automatically.

    IAM permissions:
    - rds:DescribeDBSnapshots
    """
    rds = session.client("rds", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page.get("DBSnapshots", []):
                # Only consider available snapshots
                if snap.get("Status") != "available":
                    continue

                create_time = snap.get("SnapshotCreateTime")
                if not create_time:
                    continue

                age_days = int((now - create_time).total_seconds() // 86400)
                if age_days < days_old:
                    continue

                snapshot_id = snap["DBSnapshotIdentifier"]
                db_instance_id = snap.get("DBInstanceIdentifier", "unknown")
                size_gb = snap.get("AllocatedStorage", 0)
                engine = snap.get("Engine", "unknown")
                tags = {t["Key"]: t["Value"] for t in snap.get("TagList", [])}

                cost_usd = round(size_gb * _SNAPSHOT_COST_PER_GB, 2) if size_gb else None

                signals = [
                    f"Manual RDS snapshot is {age_days} days old (threshold: {days_old} days)",
                    f"Created at: {create_time.strftime('%Y-%m-%d')}",
                    f"Source DB instance: {db_instance_id}",
                    f"Engine: {engine}",
                    f"Size: {size_gb} GB",
                ]
                if cost_usd is not None:
                    signals.append(
                        f"Accruing ~${cost_usd}/month in snapshot storage " f"(~$0.095/GB-month)"
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Compliance or audit retention requirements",
                        "Disaster recovery intent",
                        "Referenced by application or runbook",
                        "Cross-region restore dependency",
                    ],
                    time_window=f"{age_days} days",
                )

                details = {
                    "db_instance_id": db_instance_id,
                    "engine": engine,
                    "size_gb": size_gb,
                    "age_days": age_days,
                    "age_threshold_days": days_old,
                    "create_time": create_time.isoformat(),
                }
                if tags:
                    details["tags"] = tags

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.rds.snapshot.old",
                        resource_type="aws.rds.snapshot",
                        resource_id=snapshot_id,
                        region=region,
                        title=f"Old Manual RDS Snapshot ({age_days} Days)",
                        summary=(
                            f"Manual RDS snapshot '{snapshot_id}' of '{db_instance_id}' "
                            f"is {age_days} days old and accruing storage charges."
                        ),
                        reason=f"Manual RDS snapshot exceeds {days_old}-day retention threshold",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        detected_at=now,
                        evidence=evidence,
                        details=details,
                        estimated_monthly_cost_usd=cost_usd,
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError("Missing required IAM permission: rds:DescribeDBSnapshots") from e
        raise

    return findings
