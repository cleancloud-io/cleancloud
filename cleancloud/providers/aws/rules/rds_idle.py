from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_idle_rds_instances(
    session: boto3.Session,
    region: str,
    days_idle: int = 14,
) -> List[Finding]:
    """
    Find RDS instances with zero database connections for `days_idle` days.

    RDS instances incur significant hourly charges depending on instance class.
    Idle instances with no connections are a clear cost optimization signal.

    Detection logic:
    - Instance status is 'available'
    - Instance is older than `days_idle` days
    - CloudWatch DatabaseConnections metric sum is 0 over `days_idle` period
    - Not a read replica (ReadReplicaSourceDBInstanceIdentifier is empty)
    - Not an Aurora cluster member (DBClusterIdentifier is empty)

    IAM permissions:
    - rds:DescribeDBInstances
    - cloudwatch:GetMetricStatistics
    """
    rds = session.client("rds", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                # Only check available instances
                status = instance.get("DBInstanceStatus")
                if status != "available":
                    continue

                db_instance_id = instance["DBInstanceIdentifier"]

                # Skip read replicas
                if instance.get("ReadReplicaSourceDBInstanceIdentifier"):
                    continue

                # Skip Aurora cluster members — Aurora instances are managed at
                # the cluster level and may show zero connections on individual
                # reader/writer nodes even when the cluster is active.
                if instance.get("DBClusterIdentifier"):
                    continue

                tags = instance.get("TagList", [])

                # Calculate age
                create_time = instance.get("InstanceCreateTime")
                age_days = 0
                if create_time:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        pass

                # Skip if instance is younger than the idle threshold
                if age_days < days_idle:
                    continue

                # Check CloudWatch metrics for connections
                total_connections = _get_metric_sum(
                    cloudwatch,
                    "AWS/RDS",
                    "DatabaseConnections",
                    "DBInstanceIdentifier",
                    db_instance_id,
                    now - timedelta(days=days_idle),
                    now,
                )

                if total_connections > 0:
                    continue

                # Gather instance details
                engine = instance.get("Engine", "unknown")
                engine_version = instance.get("EngineVersion", "unknown")
                instance_class = instance.get("DBInstanceClass", "unknown")
                multi_az = instance.get("MultiAZ", False)
                storage_gb = instance.get("AllocatedStorage", 0)
                signals_not_checked = [
                    "Planned future usage",
                    "Disaster recovery intent",
                    "Seasonal traffic patterns",
                    "Application deployment cycles",
                ]

                signals = [
                    f"Zero database connections for {days_idle} days (CloudWatch metrics)",
                    f"DatabaseConnections sum: {total_connections}",
                    f"Instance status is '{status}'",
                    f"Engine: {engine} {engine_version}",
                    f"Instance class: {instance_class}",
                ]

                if age_days > 0:
                    signals.append(f"Instance is {age_days} days old")

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{days_idle} days",
                )

                estimated_monthly_cost = _estimate_monthly_cost(instance_class, multi_az)
                cost_usd = _estimate_monthly_cost_usd(instance_class, multi_az)

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.rds.instance.idle",
                        resource_type="aws.rds.instance",
                        resource_id=db_instance_id,
                        region=region,
                        estimated_monthly_cost_usd=cost_usd,
                        title=f"Idle RDS Instance (No Connections for {days_idle}+ Days)",
                        summary=(
                            f"RDS instance '{db_instance_id}' ({engine}, {instance_class}) "
                            f"has had zero database connections for {days_idle}+ days."
                        ),
                        reason=f"RDS instance has zero connections for {days_idle}+ days",
                        risk=RiskLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "engine": f"{engine} {engine_version}",
                            "instance_class": instance_class,
                            "connections_14d": total_connections,
                            "estimated_monthly_cost": estimated_monthly_cost,
                            "multi_az": multi_az,
                            "allocated_storage_gb": storage_gb,
                            "age_days": age_days,
                            "idle_days_threshold": days_idle,
                            **({"tags": {t["Key"]: t["Value"] for t in tags}} if tags else {}),
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "rds:DescribeDBInstances, cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _get_metric_sum(
    cloudwatch,
    namespace: str,
    metric_name: str,
    dimension_name: str,
    dimension_value: str,
    start_time: datetime,
    end_time: datetime,
) -> int:
    """Get sum of a CloudWatch metric over the time period."""
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[
                {
                    "Name": dimension_name,
                    "Value": dimension_value,
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 1 day in seconds
            Statistics=["Sum"],
        )

        datapoints = response.get("Datapoints", [])
        # Use any() instead of sum() — missing datapoints are omitted by
        # CloudWatch (not returned as 0), so summing could mask gaps.
        # any() is safer: if any single day had connections, it's not idle.
        if any(dp.get("Sum", 0) > 0 for dp in datapoints):
            return 1
        return 0

    except ClientError:
        # If we can't get metrics, assume there might be connections
        # to avoid false positives
        return 1  # Non-zero to indicate possible connections


def _estimate_monthly_cost(instance_class: str, multi_az: bool) -> str:
    """Rough monthly cost estimate based on instance class."""
    # Approximate on-demand pricing (us-east-1, varies by region/engine)
    cost_map = {
        "db.t3.micro": 12,
        "db.t3.small": 24,
        "db.t3.medium": 49,
        "db.t3.large": 97,
        "db.t4g.micro": 11,
        "db.t4g.small": 22,
        "db.t4g.medium": 44,
        "db.t4g.large": 88,
        "db.r5.large": 172,
        "db.r5.xlarge": 344,
        "db.r5.2xlarge": 688,
        "db.r6g.large": 155,
        "db.r6g.xlarge": 310,
        "db.m5.large": 125,
        "db.m5.xlarge": 250,
        "db.m6g.large": 113,
        "db.m6g.xlarge": 225,
    }

    base_cost = cost_map.get(instance_class)
    if base_cost:
        total = base_cost * 2 if multi_az else base_cost
        return f"~${total}/month (region dependent)"
    return "Cost varies by instance class (region dependent)"


def _estimate_monthly_cost_usd(instance_class: str, multi_az: bool) -> float | None:
    """Numeric monthly cost estimate for aggregation."""
    cost_map = {
        "db.t3.micro": 12,
        "db.t3.small": 24,
        "db.t3.medium": 49,
        "db.t3.large": 97,
        "db.t4g.micro": 11,
        "db.t4g.small": 22,
        "db.t4g.medium": 44,
        "db.t4g.large": 88,
        "db.r5.large": 172,
        "db.r5.xlarge": 344,
        "db.r5.2xlarge": 688,
        "db.r6g.large": 155,
        "db.r6g.xlarge": 310,
        "db.m5.large": 125,
        "db.m5.xlarge": 250,
        "db.m6g.large": 113,
        "db.m6g.xlarge": 225,
    }
    base_cost = cost_map.get(instance_class)
    if base_cost:
        return float(base_cost * 2 if multi_az else base_cost)
    return None
