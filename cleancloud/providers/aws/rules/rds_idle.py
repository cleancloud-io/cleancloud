"""
Rule: aws.rds.instance.idle

    (spec — docs/specs/aws/rds_idle.md)

Intent:
    Detect provisioned standalone DB instances that are currently available, old
    enough to evaluate, and show no trusted CloudWatch client-connection activity
    for the configured observation window, so they can be reviewed as possible
    cleanup candidates.

Exclusions:
    - db_instance_id absent (malformed identity)
    - normalized_status absent (missing current-state signal)
    - normalized_status != "available"
    - db_cluster_identifier present (cluster member)
    - read_replica_source_db_instance_identifier present (read replica)
    - read_replica_source_db_cluster_identifier present (cross-cluster read replica)
    - instance_create_time_utc absent, naive, or in the future
    - age_days < idle_days_threshold (too new to evaluate)
    - DatabaseConnections returns no datapoints (insufficient evidence)
    - any DatabaseConnections Maximum > 0

Detection:
    - db_instance_id present, normalized_status == "available"
    - standalone (not a cluster member or read replica)
    - age_days >= idle_days_threshold
    - DatabaseConnections Maximum returns datapoints and all are zero

Key rules:
    - DatabaseConnections Maximum is the sole required activity metric.
    - Missing CloudWatch datapoints → SKIP ITEM (not zero).
    - CloudWatch API failure → FAIL RULE (not LOW-confidence finding).
    - No CPU or I/O thresholds — not required for baseline eligibility.
    - estimated_monthly_cost_usd = None.
    - Confidence: MEDIUM always.
    - Risk: MEDIUM always.

Blind spots:
    - Sessions without network connections that the database hasn't cleaned up
    - Sessions created by the database engine for its own purposes
    - Sessions created by parallel execution capabilities or job schedulers
    - Amazon RDS connections
    - RDS Proxy, PgBouncer, and application connection pools that can hide real
      usage while keeping observed client connection counts low or zero
    - Planned future usage or disaster recovery intent
    - Exact region-specific pricing impact

APIs:
    - rds:DescribeDBInstances
    - cloudwatch:GetMetricStatistics
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATUS = "available"
_CW_NAMESPACE = "AWS/RDS"
_CW_DIM = "DBInstanceIdentifier"

_FINDING_TITLE = "Idle RDS instance review candidate"

_SIGNALS_NOT_CHECKED = (
    "Sessions without network connections that the database hasn't cleaned up",
    "Sessions created by the database engine for its own purposes",
    "Sessions created by parallel execution capabilities",
    "Sessions created by the database engine job scheduler",
    "Amazon RDS connections",
    "RDS Proxy, PgBouncer, and application connection pools that can hide real "
    "usage while keeping observed client connection counts low or zero",
    "Planned future usage or disaster recovery intent",
    "Exact region-specific pricing impact",
)


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _choose_period(idle_days: int) -> int:
    """Return a deterministic Period compliant with CloudWatch retention rules.

    idle_days * 86400 is a multiple of 60, 300, and 3600, satisfying all three
    CloudWatch retention constraints for the chosen lookback window.
    """
    return idle_days * 86400


def _normalize_db_instance(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeDBInstances item to the canonical field shape.

    Returns None when required identity/state/age fields are absent or invalid —
    the caller must skip the item. All rule logic must operate only on the
    returned normalized dict.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity fields (required; absent → skip) ---
    db_instance_id = _str(item.get("DBInstanceIdentifier"))
    if db_instance_id is None:
        return None

    # --- State fields (required; absent → skip) ---
    normalized_status = _str(item.get("DBInstanceStatus"))
    if normalized_status is None:
        return None

    # --- InstanceCreateTime (required; absent, naive, or future → skip) ---
    raw_ct = item.get("InstanceCreateTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        # Naive datetime — cannot safely compare to UTC; treat as absent → skip.
        return None
    instance_create_time_utc = raw_ct.astimezone(timezone.utc)
    if instance_create_time_utc > now_utc:
        # Future InstanceCreateTime is invalid → skip.
        return None
    age_days = int((now_utc - instance_create_time_utc).total_seconds() // 86400)

    # --- Scope fields (optional → null) ---
    db_cluster_identifier = _str(item.get("DBClusterIdentifier"))
    read_replica_source_db_instance_identifier = _str(
        item.get("ReadReplicaSourceDBInstanceIdentifier")
    )
    read_replica_source_db_cluster_identifier = _str(
        item.get("ReadReplicaSourceDBClusterIdentifier")
    )

    # --- Core context fields (optional → null / []) ---
    engine = _str(item.get("Engine"))
    engine_version = _str(item.get("EngineVersion"))
    db_instance_class = _str(item.get("DBInstanceClass"))
    storage_type = _str(item.get("StorageType"))
    dbi_resource_id = _str(item.get("DbiResourceId"))
    db_instance_arn = _str(item.get("DBInstanceArn"))

    raw_multi_az = item.get("MultiAZ")
    multi_az = raw_multi_az if isinstance(raw_multi_az, bool) else None

    raw_storage = item.get("AllocatedStorage")
    allocated_storage_gib = raw_storage if isinstance(raw_storage, int) else None

    raw_tags = item.get("TagList")
    tag_set: list = raw_tags if isinstance(raw_tags, list) else []

    return {
        "resource_id": db_instance_id,
        "db_instance_id": db_instance_id,
        "normalized_status": normalized_status,
        "instance_create_time_utc": instance_create_time_utc,
        "age_days": age_days,
        "db_cluster_identifier": db_cluster_identifier,
        "read_replica_source_db_instance_identifier": read_replica_source_db_instance_identifier,
        "read_replica_source_db_cluster_identifier": read_replica_source_db_cluster_identifier,
        "engine": engine,
        "engine_version": engine_version,
        "db_instance_class": db_instance_class,
        "multi_az": multi_az,
        "allocated_storage_gib": allocated_storage_gib,
        "storage_type": storage_type,
        "dbi_resource_id": dbi_resource_id,
        "db_instance_arn": db_instance_arn,
        "tag_set": tag_set,
    }


def _get_database_connections_max(
    cloudwatch,
    db_instance_id: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[float]:
    """Fetch DatabaseConnections Maximum over the observation window.

    Returns None if no datapoints (insufficient evidence → caller must SKIP ITEM).
    Returns the maximum value (>= 0.0) if datapoints are present.
    Raises ClientError / BotoCoreError / PermissionError on API failure (caller → FAIL RULE).
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName="DatabaseConnections",
            Dimensions=[{"Name": _CW_DIM, "Value": db_instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=["Maximum"],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        raise
    except BotoCoreError:
        raise

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None  # No datapoints → insufficient evidence → SKIP ITEM

    return max(dp.get("Maximum", 0.0) for dp in datapoints)


def find_idle_rds_instances(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    rds = session.client("rds", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    try:
        paginator = rds.get_paginator("describe_db_instances")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: rds:DescribeDBInstances"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    period = _choose_period(idle_days_threshold)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("DBInstances", []):
            # --- Step 1: Normalize ---
            n = _normalize_db_instance(raw_item, now)
            if n is None:
                continue

            # --- Step 2: EXCLUSION RULES ---

            # EXCLUSION: status must be available
            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            # EXCLUSION: not standalone — cluster member or any form of read replica
            if n["db_cluster_identifier"] is not None:
                continue
            if n["read_replica_source_db_instance_identifier"] is not None:
                continue
            if n["read_replica_source_db_cluster_identifier"] is not None:
                continue

            # EXCLUSION: too young to evaluate
            if n["age_days"] < idle_days_threshold:
                continue

            # --- Step 3: CloudWatch (FAIL RULE on error; SKIP ITEM if no data) ---
            db_connections_max = _get_database_connections_max(
                cloudwatch,
                n["db_instance_id"],
                window_start,
                now,
                period,
            )

            if db_connections_max is None:
                # No datapoints → insufficient trusted evidence → SKIP ITEM
                continue

            # EXCLUSION: observed client connections
            if db_connections_max > 0:
                continue

            # --- Step 4: EMIT ---
            signals_used = [
                f"DB instance Status is '{_ELIGIBLE_STATUS}' (able to accept connections)",
                "DB instance is standalone — not a DB cluster member or read replica",
                f"Age is {n['age_days']} days, meeting the {idle_days_threshold}-day threshold",
                f"DatabaseConnections Maximum was zero across all datapoints in the "
                f"{idle_days_threshold}-day observation window "
                "(CleanCloud-derived idle heuristic based on observed client network connections)",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.rds.instance.idle",
                    resource_type="aws.rds.instance",
                    resource_id=n["db_instance_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"RDS instance {n['db_instance_id']} has no observed client "
                        f"connection activity in the last {idle_days_threshold} days"
                    ),
                    reason=(
                        f"DB instance has no observed client connection activity "
                        f"via DatabaseConnections Maximum in the last {idle_days_threshold} days"
                    ),
                    risk=RiskLevel.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-rds-instance-review-candidate",
                        "db_instance_id": n["db_instance_id"],
                        "normalized_status": n["normalized_status"],
                        "instance_create_time": n["instance_create_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "engine": n["engine"],
                        "engine_version": n["engine_version"],
                        "db_instance_class": n["db_instance_class"],
                        "database_connections_max": db_connections_max,
                        "db_cluster_identifier": n["db_cluster_identifier"],
                        "read_replica_source_db_instance_identifier": n[
                            "read_replica_source_db_instance_identifier"
                        ],
                        "read_replica_source_db_cluster_identifier": n[
                            "read_replica_source_db_cluster_identifier"
                        ],
                        "multi_az": n["multi_az"],
                        "allocated_storage_gib": n["allocated_storage_gib"],
                        "storage_type": n["storage_type"],
                        "dbi_resource_id": n["dbi_resource_id"],
                        "db_instance_arn": n["db_instance_arn"],
                        "tag_set": n["tag_set"],
                    },
                )
            )

    return findings
