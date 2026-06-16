"""
Rule: aws.redshift.cluster.idle

    (spec — docs/specs/aws/redshift_cluster_idle.md)

Intent:
    Detect provisioned Redshift clusters that are in 'available' status but have
    had zero observed database connections over the configured idle window, so
    they can be reviewed as candidates for pausing or deletion.

    This is a CleanCloud-derived idle heuristic based on Redshift cluster
    metadata and CloudWatch activity metrics. It is a read-only
    review-candidate rule — not a stop-safe or delete-safe rule.

Exclusions:
    - cluster_identifier absent (malformed inventory item)
    - cluster_status absent or not "available"
    - cluster_availability_status is Unavailable, Maintenance, or Failed
    - ClusterCreateTime absent, naive, or future beyond clock_skew_tolerance
    - cluster younger than idle_days_threshold
    - CloudWatch returned no datapoints for DatabaseConnections
    - DatabaseConnections Sum > 0

Detection:
    - ClusterStatus == "available"
    - cluster_age_days >= idle_days_threshold
    - DatabaseConnections Sum == 0 over the full evaluation window

Key rules:
    - DatabaseConnections Sum is the sole required activity metric.
    - Missing CloudWatch datapoints → SKIP ITEM (not zero).
    - CloudWatch API failure → FAIL RULE.
    - ReadIOPS / WriteIOPS are best-effort secondary signals for confidence.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH when connections + IOPS all zero; MEDIUM otherwise.
    - Risk: HIGH when number_of_nodes >= 4; MEDIUM otherwise.
    - Paused clusters are excluded (already cost-optimized).
    - Redshift Serverless is out of scope (separate API).
    - clock_skew_tolerance_seconds = 300.

Blind spots:
    - Business value or planned future use
    - Whether pausing or deleting is safe
    - Disaster recovery or compliance retention purpose
    - Exact price impact or savings impact

APIs:
    - redshift:DescribeClusters
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
from cleancloud.providers.aws.errors import is_permission_error

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATUS = "available"
_CLOCK_SKEW_TOLERANCE_SECONDS = 300
_CW_NAMESPACE = "AWS/Redshift"
_CW_DIM = "ClusterIdentifier"

_UNAVAILABLE_AVAILABILITY_STATUSES = frozenset({"Unavailable", "Maintenance", "Failed"})

_FINDING_TITLE = "Idle Redshift cluster review candidate"
_FINDING_REASON = (
    "Available Redshift cluster has had zero database connections "
    "over the configured idle window"
)

_SIGNALS_NOT_CHECKED = (
    "Business value or planned future use",
    "Whether pausing or deleting is safe",
    "Disaster recovery or compliance retention purpose",
    "Exact price impact or savings impact",
)

RULE_METADATA = {
    "id": "aws.redshift.cluster.idle",
    "category": "hygiene",
    "service": "redshift",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _choose_period(idle_days: int) -> int:
    """Return a single full-window period in seconds."""
    return idle_days * 86400


def _normalize_cluster(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeClusters item to canonical fields.

    Returns None when required fields are absent or invalid — caller must skip.
    """
    if not isinstance(item, dict):
        return None

    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)

    # --- Identity (required) ---
    cluster_identifier = _str(item.get("ClusterIdentifier"))
    if cluster_identifier is None:
        return None

    # --- Status (required) ---
    cluster_status = _str(item.get("ClusterStatus"))
    if cluster_status is None:
        return None

    # --- ClusterAvailabilityStatus (optional) ---
    cluster_availability_status = _str(item.get("ClusterAvailabilityStatus"))

    # --- ClusterCreateTime (required) ---
    raw_ct = item.get("ClusterCreateTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    cluster_create_time_utc = raw_ct.astimezone(timezone.utc)
    if cluster_create_time_utc > now_utc + skew_tol:
        return None

    cluster_age_days = max(0, int((now_utc - cluster_create_time_utc).total_seconds() // 86400))

    # --- Optional fields ---
    node_type = _str(item.get("NodeType"))

    raw_num_nodes = item.get("NumberOfNodes")
    number_of_nodes = (
        raw_num_nodes
        if isinstance(raw_num_nodes, int)
        and not isinstance(raw_num_nodes, bool)
        and raw_num_nodes > 0
        else None
    )

    cluster_namespace_arn = _str(item.get("ClusterNamespaceArn"))

    endpoint = item.get("Endpoint")
    if isinstance(endpoint, dict):
        cluster_endpoint_address = _str(endpoint.get("Address"))
        raw_port = endpoint.get("Port")
        cluster_endpoint_port = (
            raw_port if isinstance(raw_port, int) and not isinstance(raw_port, bool) else None
        )
    else:
        cluster_endpoint_address = None
        cluster_endpoint_port = None

    raw_storage = item.get("TotalStorageCapacityInMegaBytes")
    total_storage_capacity_mb = (
        raw_storage
        if isinstance(raw_storage, (int, float)) and not isinstance(raw_storage, bool)
        else None
    )

    resource_id = cluster_namespace_arn or cluster_identifier

    return {
        "cluster_identifier": cluster_identifier,
        "cluster_status": cluster_status,
        "cluster_availability_status": cluster_availability_status,
        "cluster_create_time_utc": cluster_create_time_utc,
        "cluster_age_days": cluster_age_days,
        "node_type": node_type,
        "number_of_nodes": number_of_nodes,
        "cluster_namespace_arn": cluster_namespace_arn,
        "cluster_endpoint_address": cluster_endpoint_address,
        "cluster_endpoint_port": cluster_endpoint_port,
        "total_storage_capacity_mb": total_storage_capacity_mb,
        "resource_id": resource_id,
    }


def _get_cw_sum(
    cloudwatch,
    metric_name: str,
    cluster_identifier: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[float]:
    """Fetch a CloudWatch metric Sum over the observation window.

    Returns None if no datapoints (insufficient evidence → caller must SKIP ITEM).
    Returns the Sum value (>= 0.0) if datapoints are present.
    Raises on API failure (caller → FAIL RULE).
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[{"Name": _CW_DIM, "Value": cluster_identifier}],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=["Sum"],
        )
    except ClientError as exc:
        if is_permission_error(exc):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        raise
    except BotoCoreError:
        raise

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None

    return sum(dp.get("Sum", 0.0) for dp in datapoints)


def _get_secondary_sum(
    cloudwatch,
    metric_name: str,
    cluster_identifier: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[float]:
    """Best-effort fetch of a secondary CloudWatch metric. Returns None on any failure."""
    try:
        return _get_cw_sum(
            cloudwatch, metric_name, cluster_identifier, start_time, end_time, period
        )
    except Exception:
        return None


def find_idle_redshift_clusters(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    redshift = session.client("redshift", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    # Spec 8: paginate DescribeClusters.
    try:
        paginator = redshift.get_paginator("describe_clusters")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if is_permission_error(exc):
            raise PermissionError(
                "Missing required IAM permission: redshift:DescribeClusters"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    period = _choose_period(idle_days_threshold)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("Clusters", []):
            # --- Step 1: Normalize ---
            n = _normalize_cluster(raw_item, now)
            if n is None:
                continue

            # --- Step 2: Exclusion rules ---

            # Status must be "available"
            if n["cluster_status"] != _ELIGIBLE_STATUS:
                continue

            # Exclude transient availability states
            if (
                n["cluster_availability_status"] is not None
                and n["cluster_availability_status"] in _UNAVAILABLE_AVAILABILITY_STATUSES
            ):
                continue

            # Too young to evaluate
            if n["cluster_age_days"] < idle_days_threshold:
                continue

            # --- Step 3: Primary CloudWatch signal (FAIL RULE on error) ---
            database_connections_sum = _get_cw_sum(
                cloudwatch,
                "DatabaseConnections",
                n["cluster_identifier"],
                window_start,
                now,
                period,
            )

            # No datapoints → insufficient evidence → SKIP ITEM
            if database_connections_sum is None:
                continue

            # Any connections → not idle
            if database_connections_sum > 0:
                continue

            # --- Step 4: Secondary signals (best-effort) ---
            read_iops_sum = _get_secondary_sum(
                cloudwatch, "ReadIOPS", n["cluster_identifier"], window_start, now, period
            )
            write_iops_sum = _get_secondary_sum(
                cloudwatch, "WriteIOPS", n["cluster_identifier"], window_start, now, period
            )

            # --- Step 5: Confidence and Risk ---
            all_secondary_present = read_iops_sum is not None and write_iops_sum is not None
            all_secondary_zero = (
                all_secondary_present and read_iops_sum == 0 and write_iops_sum == 0
            )
            confidence = ConfidenceLevel.HIGH if all_secondary_zero else ConfidenceLevel.MEDIUM

            risk = (
                RiskLevel.HIGH
                if n["number_of_nodes"] is not None and n["number_of_nodes"] >= 4
                else RiskLevel.MEDIUM
            )

            # --- Step 6: Emit ---
            signals_used = [
                f"Cluster status is '{_ELIGIBLE_STATUS}'",
                f"Cluster age is {n['cluster_age_days']} days, meeting the "
                f"{idle_days_threshold}-day threshold",
                f"DatabaseConnections Sum was 0 over the {idle_days_threshold}-day "
                "evaluation window",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.redshift.cluster.idle",
                    resource_type="aws.redshift.cluster",
                    resource_id=n["resource_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"Redshift cluster '{n['cluster_identifier']}' has had zero "
                        f"database connections for {idle_days_threshold} days"
                    ),
                    reason=_FINDING_REASON,
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        # Required fields
                        "evaluation_path": "idle-redshift-cluster-review-candidate",
                        "cluster_identifier": n["cluster_identifier"],
                        "resource_id": n["resource_id"],
                        "cluster_status": _ELIGIBLE_STATUS,
                        "cluster_create_time": n["cluster_create_time_utc"].isoformat(),
                        "cluster_age_days": n["cluster_age_days"],
                        "node_type": n["node_type"],
                        "number_of_nodes": n["number_of_nodes"],
                        "idle_days_threshold": idle_days_threshold,
                        "evaluation_window_start": window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "database_connections_sum": database_connections_sum,
                        "is_idle": True,
                        # Optional context
                        "cluster_availability_status": n["cluster_availability_status"],
                        "cluster_endpoint_address": n["cluster_endpoint_address"],
                        "cluster_endpoint_port": n["cluster_endpoint_port"],
                        "read_iops_sum": read_iops_sum,
                        "write_iops_sum": write_iops_sum,
                        "total_storage_capacity_mb": n["total_storage_capacity_mb"],
                    },
                )
            )

    return findings
