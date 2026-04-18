from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_idle_rds_instances(
    session: boto3.Session,
    region: str,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find RDS instances with zero database connections for `idle_days` days.

    RDS instances incur significant hourly charges depending on instance class
    and engine. Cost estimates in this rule are based on MySQL/PostgreSQL us-east-1
    on-demand pricing — Oracle, SQL Server, and other engines have different rates.

    Detection logic:
    - Instance status is 'available'
    - Instance is older than `idle_days` days
    - CloudWatch DatabaseConnections metric sum is 0 over `idle_days` period
    - Not a read replica (ReadReplicaSourceDBInstanceIdentifier is empty)
    - Not an Aurora cluster member (DBClusterIdentifier is empty)

    Confidence tiers:
    - MEDIUM: Zero connections + low peak CPU + low storage I/O (three-signal agreement)
    - LOW:    Zero connections only, or CPU/IO data unavailable

    Risk tiers:
    - HIGH:   MEDIUM confidence (multiple corroborating signals)
    - MEDIUM: LOW confidence (connections only, or metrics partially unavailable)

    Notes on accuracy:
    - DatabaseConnections == 0 does not guarantee no activity. Connection poolers
      (RDS Proxy, PgBouncer, application-level pools) may route queries without
      maintaining persistent connections visible to CloudWatch. Always verify
      application-level usage before acting on this finding.
    - CloudWatch publishes DatabaseConnections as a daily Sum. Zero datapoints
      (not zero values) means metric visibility is absent — this rule surfaces
      those as LOW-confidence "metrics unavailable" findings rather than skipping,
      so operators know the instance was not verified.
    - Storage cost estimate uses gp2/gp3 at ~$0.115/GB-month (us-east-1). io1/io2
      volumes are more expensive (~$0.125/GB + IOPS charge). Multi-AZ doubling is
      approximate: actual billing includes standby compute + storage nuances.
    - Automated backups and snapshots may justify retaining an otherwise idle instance.

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
                if age_days < idle_days:
                    continue

                start_time = now - timedelta(days=idle_days)

                # Check CloudWatch metrics for connections
                total_connections, conn_datapoints = _get_metric_sum(
                    cloudwatch,
                    "AWS/RDS",
                    "DatabaseConnections",
                    "DBInstanceIdentifier",
                    db_instance_id,
                    start_time,
                    now,
                )

                if total_connections > 0:
                    continue

                # Gather instance details (needed for both finding paths below)
                engine = instance.get("Engine", "unknown")
                engine_version = instance.get("EngineVersion", "unknown")
                instance_class = instance.get("DBInstanceClass", "unknown")
                multi_az = instance.get("MultiAZ", False)
                storage_gb = instance.get("AllocatedStorage", 0)
                compute_cost = _estimate_monthly_cost(instance_class, multi_az)
                compute_cost_usd = _estimate_monthly_cost_usd(instance_class, multi_az)
                storage_cost_usd = round(storage_gb * 0.115, 2) if storage_gb else 0.0
                storage_cost_usd = storage_cost_usd * 2 if multi_az else storage_cost_usd
                total_cost_usd = (
                    (compute_cost_usd + storage_cost_usd) if compute_cost_usd is not None else None
                )

                if conn_datapoints == 0:
                    # Zero datapoints means CloudWatch has no visibility — we cannot
                    # distinguish "truly idle" from "metrics not published". Surface a
                    # LOW-confidence finding so the operator knows to verify manually.
                    findings.append(
                        Finding(
                            provider="aws",
                            rule_id="aws.rds.instance.idle",
                            resource_type="aws.rds.instance",
                            resource_id=db_instance_id,
                            region=region,
                            estimated_monthly_cost_usd=total_cost_usd,
                            title="RDS Instance Requires Connection Verification",
                            summary=(
                                f"RDS instance '{db_instance_id}' ({engine}, {instance_class}) "
                                f"has no CloudWatch connection data — idle status is unconfirmed."
                            ),
                            reason=(
                                "DatabaseConnections metric returned zero datapoints; "
                                "idle status cannot be confirmed"
                            ),
                            risk=RiskLevel.MEDIUM,
                            confidence=ConfidenceLevel.LOW,
                            detected_at=now,
                            evidence=Evidence(
                                signals_used=[
                                    f"Instance status is '{status}'",
                                    f"Engine: {engine} {engine_version}",
                                    f"Instance class: {instance_class}",
                                    f"Instance is {age_days} days old",
                                ],
                                signals_not_checked=[
                                    "DatabaseConnections — CloudWatch returned zero datapoints; "
                                    "metric may not be published for this instance",
                                    "CPU utilisation",
                                    "Storage I/O (ReadIOPS / WriteIOPS)",
                                    "Planned future usage",
                                    "Disaster recovery intent",
                                    "Automated backups or snapshots that may justify retention",
                                ],
                                time_window=f"{idle_days} days",
                            ),
                            details={
                                "engine": f"{engine} {engine_version}",
                                "instance_class": instance_class,
                                f"connections_{idle_days}d": None,
                                "connections_datapoints": 0,
                                "metrics_note": (
                                    "DatabaseConnections returned zero datapoints — "
                                    "metric visibility absent; idle status unconfirmed"
                                ),
                                "estimated_compute_cost": compute_cost,
                                "estimated_storage_cost": (
                                    f"~${storage_cost_usd:.2f}/month "
                                    "(gp2/gp3 approx ~$0.115/GB; io1/io2 higher)"
                                ),
                                "multi_az": multi_az,
                                "allocated_storage_gb": storage_gb,
                                "age_days": age_days,
                                "idle_days_threshold": idle_days,
                                **({"tags": {t["Key"]: t["Value"] for t in tags}} if tags else {}),
                            },
                        )
                    )
                    continue

                # Corroborating signal 1: peak CPU utilisation.
                # Use Maximum (not Average) to catch bursty workloads — a single
                # high-CPU day within the window means the instance was active.
                peak_cpu, cpu_datapoints = _get_peak_cpu(
                    cloudwatch, db_instance_id, start_time, now
                )

                if peak_cpu is not None and peak_cpu >= 5.0:
                    # CPU active despite zero connections — unusual but skip to avoid FP
                    continue

                # Corroborating signal 2: storage I/O (ReadIOPS + WriteIOPS).
                # If connections == 0 but IOPS > 0, a background process or connection
                # pooler may be active. If IOPS == 0, it corroborates idle.
                has_io, read_iops, write_iops, io_datapoints = _get_storage_io(
                    cloudwatch, db_instance_id, start_time, now
                )

                if has_io:
                    # Storage I/O active despite zero connections — skip to avoid FP
                    continue

                signals_not_checked = [
                    "Planned future usage",
                    "Disaster recovery intent",
                    "Seasonal traffic patterns",
                    "Application deployment cycles",
                    (
                        "Connection poolers or proxies (RDS Proxy, PgBouncer) — "
                        "may route queries without visible persistent connections"
                    ),
                    "External readers or indirect usage patterns",
                    "Automated backups or snapshots that may justify retention",
                ]

                signals = [
                    f"Zero database connections for {idle_days} days "
                    f"({conn_datapoints} of up to {idle_days} daily datapoints)",
                    f"DatabaseConnections sum: {total_connections}",
                    f"Instance status is '{status}'",
                    f"Engine: {engine} {engine_version}",
                    f"Instance class: {instance_class}",
                ]

                cpu_confirmed = False
                if peak_cpu is not None:
                    signals.append(
                        f"Peak daily CPU utilisation: {peak_cpu:.1f}% "
                        f"(threshold: 5%) — corroborating idle signal"
                    )
                    cpu_confirmed = True
                else:
                    signals_not_checked.append("CPU utilisation (metric unavailable)")

                io_confirmed = False
                if io_datapoints > 0:
                    signals.append(
                        f"Storage I/O: ReadIOPS={read_iops}, WriteIOPS={write_iops} "
                        f"— corroborating idle signal"
                    )
                    io_confirmed = True
                else:
                    signals_not_checked.append("Storage I/O (ReadIOPS / WriteIOPS — no data)")

                if age_days > 0:
                    signals.append(f"Instance is {age_days} days old")

                # MEDIUM confidence only when all three signals agree: zero connections,
                # low peak CPU, and low storage I/O. Any missing or inconclusive
                # corroborating signal leaves confidence at LOW.
                # Risk mirrors confidence: HIGH for MEDIUM confidence, MEDIUM for LOW.
                if cpu_confirmed and io_confirmed:
                    confidence = ConfidenceLevel.MEDIUM
                    risk = RiskLevel.HIGH
                else:
                    confidence = ConfidenceLevel.LOW
                    risk = RiskLevel.MEDIUM

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.rds.instance.idle",
                        resource_type="aws.rds.instance",
                        resource_id=db_instance_id,
                        region=region,
                        estimated_monthly_cost_usd=total_cost_usd,
                        title=f"Idle RDS Instance (No Connections for {idle_days}+ Days)",
                        summary=(
                            f"RDS instance '{db_instance_id}' ({engine}, {instance_class}) "
                            f"has had zero database connections for {idle_days}+ days."
                        ),
                        reason=f"RDS instance has zero connections for {idle_days}+ days",
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "engine": f"{engine} {engine_version}",
                            "instance_class": instance_class,
                            f"connections_{idle_days}d": total_connections,
                            "connections_datapoints": conn_datapoints,
                            "peak_cpu_pct": round(peak_cpu, 2) if peak_cpu is not None else None,
                            "read_iops": read_iops,
                            "write_iops": write_iops,
                            "estimated_compute_cost": (
                                compute_cost
                                + " (MySQL/PostgreSQL us-east-1 rate; engine-dependent)"
                                if compute_cost and "varies" not in compute_cost
                                else compute_cost
                            ),
                            "estimated_storage_cost": (
                                f"~${storage_cost_usd:.2f}/month "
                                "(gp2/gp3 approx ~$0.115/GB; io1/io2 higher; Multi-AZ doubling approximate)"
                            ),
                            "multi_az": multi_az,
                            "allocated_storage_gb": storage_gb,
                            "age_days": age_days,
                            "idle_days_threshold": idle_days,
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
) -> tuple:
    """Get sum of a CloudWatch metric over the time period.

    Returns (value, datapoint_count):
    - value: 1 if any datapoint has Sum > 0, else 0
    - datapoint_count: number of datapoints returned (0 = no metric visibility)

    Zero datapoints is distinct from all-zero datapoints — the caller should
    handle datapoint_count == 0 as "unknown" rather than "confirmed idle".
    """
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
        count = len(datapoints)
        # Use any() instead of sum() — missing datapoints are omitted by
        # CloudWatch (not returned as 0), so summing could mask gaps.
        # any() is safer: if any single day had connections, it's not idle.
        if any(dp.get("Sum", 0) > 0 for dp in datapoints):
            return 1, count
        return 0, count

    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permissions: cloudwatch:GetMetricStatistics"
            ) from e
        # Other errors (throttle, transient): assume connections to avoid false positives
        return 1, -1


def _get_peak_cpu(
    cloudwatch, db_instance_id: str, start_time: datetime, end_time: datetime
) -> tuple:
    """Return (peak_cpu_pct, datapoint_count) for the RDS instance over the window.

    Uses Maximum statistic (not Average) to catch bursty workloads — a single
    high-CPU day means the instance was active during that window.

    Returns (None, 0) on error — caller treats None as CPU signal unavailable.
    """
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=["Maximum"],
        )
        datapoints = response.get("Datapoints", [])
        if not datapoints:
            return None, 0
        peak = max(dp["Maximum"] for dp in datapoints)
        return peak, len(datapoints)
    except ClientError:
        return None, 0


def _get_storage_io(
    cloudwatch, db_instance_id: str, start_time: datetime, end_time: datetime
) -> tuple:
    """Return (has_io, read_iops_sum, write_iops_sum, datapoint_count).

    Checks ReadIOPS and WriteIOPS over the window. Any non-zero IOPS means
    the storage was active, which is a strong signal of actual database usage
    even if DatabaseConnections appears zero (e.g. via connection poolers).

    datapoint_count is the combined count from both metrics; 0 means no data.
    """
    try:

        def _fetch(metric_name: str) -> tuple:
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName=metric_name,
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_instance_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=["Sum"],
            )
            datapoints = response.get("Datapoints", [])
            total = sum(dp.get("Sum", 0) for dp in datapoints)
            return int(total), len(datapoints)

        read_iops, read_count = _fetch("ReadIOPS")
        write_iops, write_count = _fetch("WriteIOPS")
        has_io = (read_iops > 0) or (write_iops > 0)
        return has_io, read_iops, write_iops, read_count + write_count

    except ClientError:
        # On error, assume no IO (don't skip the finding) but return 0 datapoints
        # so the caller knows IO was not verified.
        return False, 0, 0, 0


def _estimate_monthly_cost(instance_class: str, multi_az: bool) -> str:
    """Rough monthly cost estimate based on instance class.

    Rates are approximate MySQL/PostgreSQL us-east-1 on-demand pricing.
    Oracle, SQL Server, and other engines have different (often higher) costs.
    """
    cost_map = {
        "db.t3.micro": 12,
        "db.t3.small": 24,
        "db.t3.medium": 49,
        "db.t3.large": 97,
        "db.t3.xlarge": 194,
        "db.t4g.micro": 11,
        "db.t4g.small": 22,
        "db.t4g.medium": 44,
        "db.t4g.large": 88,
        "db.t4g.xlarge": 175,
        "db.r5.large": 172,
        "db.r5.xlarge": 344,
        "db.r5.2xlarge": 688,
        "db.r6g.large": 155,
        "db.r6g.xlarge": 310,
        "db.r6i.large": 184,
        "db.r6i.xlarge": 368,
        "db.r6i.2xlarge": 736,
        "db.r7g.large": 175,
        "db.r7g.xlarge": 350,
        "db.r7g.2xlarge": 700,
        "db.m5.large": 125,
        "db.m5.xlarge": 250,
        "db.m6g.large": 113,
        "db.m6g.xlarge": 225,
        "db.m6i.large": 139,
        "db.m6i.xlarge": 277,
        "db.m6i.2xlarge": 554,
        "db.m7g.large": 130,
        "db.m7g.xlarge": 260,
        "db.m7g.2xlarge": 520,
    }

    base_cost = cost_map.get(instance_class)
    if base_cost:
        total = base_cost * 2 if multi_az else base_cost
        return f"~${total}/month (region dependent)"
    return "Cost varies by instance class (region dependent)"


def _estimate_monthly_cost_usd(instance_class: str, multi_az: bool) -> Optional[float]:
    """Numeric monthly cost estimate for aggregation."""
    cost_map = {
        "db.t3.micro": 12,
        "db.t3.small": 24,
        "db.t3.medium": 49,
        "db.t3.large": 97,
        "db.t3.xlarge": 194,
        "db.t4g.micro": 11,
        "db.t4g.small": 22,
        "db.t4g.medium": 44,
        "db.t4g.large": 88,
        "db.t4g.xlarge": 175,
        "db.r5.large": 172,
        "db.r5.xlarge": 344,
        "db.r5.2xlarge": 688,
        "db.r6g.large": 155,
        "db.r6g.xlarge": 310,
        "db.r6i.large": 184,
        "db.r6i.xlarge": 368,
        "db.r6i.2xlarge": 736,
        "db.r7g.large": 175,
        "db.r7g.xlarge": 350,
        "db.r7g.2xlarge": 700,
        "db.m5.large": 125,
        "db.m5.xlarge": 250,
        "db.m6g.large": 113,
        "db.m6g.xlarge": 225,
        "db.m6i.large": 139,
        "db.m6i.xlarge": 277,
        "db.m6i.2xlarge": 554,
        "db.m7g.large": 130,
        "db.m7g.xlarge": 260,
        "db.m7g.2xlarge": 520,
    }
    base_cost = cost_map.get(instance_class)
    if base_cost:
        return float(base_cost * 2 if multi_az else base_cost)
    return None
