from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Approximate Cloud SQL monthly cost by machine tier (us-central1, HA disabled)
# Source: https://cloud.google.com/sql/pricing
_CLOUD_SQL_COST_USD: dict = {
    "db-f1-micro": 7.67,
    "db-g1-small": 25.22,
    "db-n1-standard-1": 46.55,
    "db-n1-standard-2": 93.10,
    "db-n1-standard-4": 186.19,
    "db-n1-standard-8": 372.39,
    "db-n1-standard-16": 744.78,
    "db-n1-highmem-2": 113.45,
    "db-n1-highmem-4": 226.90,
    "db-n1-highmem-8": 453.80,
    "db-n1-highmem-16": 907.60,
    "db-custom-1-3840": 53.52,
    "db-custom-2-7680": 107.04,
    "db-custom-4-15360": 214.08,
}

_DAYS_IDLE = 7


def _list_sql_instances(project_id: str, credentials) -> list:
    """
    List all Cloud SQL instances using the Cloud SQL Admin REST API.

    Uses AuthorizedSession (google-auth) — automatically handles token refresh
    and avoids requiring google-api-python-client as an additional dependency.

    Raises PermissionError on 403 so the caller can gracefully skip this rule.
    Returns [] on 404 (Cloud SQL API not enabled for the project).
    """
    session = AuthorizedSession(credentials)
    resp = session.get(
        f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/instances"
    )
    if resp.status_code == 403:
        raise PermissionError("cloudsql.instances.list permission required (roles/cloudsql.viewer)")
    if resp.status_code == 404:
        return []  # Cloud SQL API not enabled for this project
    resp.raise_for_status()
    return resp.json().get("items", [])


def _has_connections(
    monitoring_client: monitoring_v3.MetricServiceClient,
    project_id: str,
    instance_name: str,
) -> bool:
    """
    Query Cloud Monitoring for database connections over the last 7 days.

    Returns True if any connections detected (active instance).
    Returns True on any error — conservative fallback avoids false positives.
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=_DAYS_IDLE)

        end_ts = timestamp_pb2.Timestamp()
        end_ts.FromDatetime(now)
        start_ts = timestamp_pb2.Timestamp()
        start_ts.FromDatetime(start)

        interval = monitoring_v3.TimeInterval(start_time=start_ts, end_time=end_ts)

        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": (
                    'metric.type="cloudsql.googleapis.com/database/network/connections"'
                    f' AND resource.labels.database_id="{project_id}:{instance_name}"'
                ),
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        for series in results:
            for point in series.points:
                val = point.value.int64_value or int(point.value.double_value or 0)
                if val > 0:
                    return True

        return False  # No connections detected over the window

    except Exception:
        # Monitoring unavailable or permission denied — conservative: assume active
        return True


def find_idle_sql_instances(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
) -> List[Finding]:
    """
    Find Cloud SQL instances with zero database connections for 7 days.

    Cloud SQL bills continuously regardless of query load — an idle db-n1-standard-2
    costs ~$93/month with zero queries. Dev and staging databases are frequently
    left running after feature branches merge or projects wind down.

    Only RUNNABLE instances are evaluated. Read replicas are excluded (no
    independent billing — master instance cost is what matters). Instances in
    SUSPENDED, FAILED, or MAINTENANCE states are skipped.

    Monitoring errors are treated conservatively: if Cloud Monitoring is
    unavailable or permission-denied, the instance is assumed active (not flagged).

    Detection logic:
    - Instance state == RUNNABLE
    - Not a read replica (instanceType != READ_REPLICA_INSTANCE)
    - Cloud Monitoring: max connections == 0 over last 7 days

    IAM permissions required:
    - cloudsql.instances.list (roles/cloudsql.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # PermissionError propagates to scan.py which records it as a skipped rule
    instances = _list_sql_instances(project_id, credentials)

    if not instances:
        return findings

    # If Cloud Monitoring client cannot be created, skip rather than false-positive
    try:
        monitoring_client = monitoring_v3.MetricServiceClient(credentials=credentials)
    except Exception:
        return findings

    for instance in instances:
        state = instance.get("state", "")
        if state != "RUNNABLE":
            continue

        # Exclude read replicas — no independent cost basis
        if instance.get("instanceType") == "READ_REPLICA_INSTANCE":
            continue

        instance_name = instance.get("name", "")
        region = instance.get("region", "")
        database_version = instance.get("databaseVersion", "")
        tier = (instance.get("settings") or {}).get("tier", "")

        if region_filter and region != region_filter:
            continue

        # Skip instances created within the last 24 hours — zero connections on a
        # brand-new instance is not a signal of waste. createTime is ISO 8601 UTC.
        create_time_str = instance.get("createTime", "")
        if create_time_str:
            try:
                created_at = datetime.fromisoformat(create_time_str.replace("Z", "+00:00"))
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                if (now - created_at).total_seconds() < 86400:
                    continue
            except ValueError:
                pass

        # Conservative: if monitoring check fails, assume active — don't flag
        if _has_connections(monitoring_client, project_id, instance_name):
            continue

        settings = instance.get("settings") or {}

        monthly_cost = _CLOUD_SQL_COST_USD.get(tier)
        cost_signal = (
            f"Tier '{tier}' costs ~${monthly_cost}/month (compute only, no HA)"
            if monthly_cost
            else f"Tier: {tier or 'unknown'} (cost estimate unavailable)"
        )

        # Confidence scales with cost impact: a $7/month dev DB at zero connections
        # is ambiguous; a $90+/month instance idle for 7 days is a clear signal.
        confidence = (
            ConfidenceLevel.HIGH if monthly_cost and monthly_cost > 50 else ConfidenceLevel.MEDIUM
        )

        labels = settings.get("userLabels", {})

        # HA doubles compute cost. availabilityType: "REGIONAL" = HA, "ZONAL" = no HA.
        ha_enabled = settings.get("availabilityType") == "REGIONAL"

        # Storage size and type — billed separately from compute.
        # Cloud SQL pricing: PD_SSD ~$0.17/GB/month, PD_HDD ~$0.09/GB/month.
        data_disk_size_gb = settings.get("dataDiskSizeGb")
        data_disk_type = settings.get("dataDiskType", "")

        # Backup retention — additional storage cost for retained backups.
        backup_cfg = settings.get("backupConfiguration") or {}
        backup_retention = (backup_cfg.get("backupRetentionSettings") or {}).get("retainedBackups")

        # Parse CPU and memory from custom tier names (format: db-custom-{cpu}-{memory_mb}).
        cpu_count: Optional[int] = None
        memory_gb: Optional[float] = None
        if tier.startswith("db-custom-"):
            parts = tier.split("-")
            if len(parts) == 4:
                try:
                    cpu_count = int(parts[2])
                    memory_gb = round(int(parts[3]) / 1024, 1)
                except ValueError:
                    pass

        signals_used = [
            "Instance state: RUNNABLE",
            f"Zero TCP connections observed via Cloud Monitoring over "
            f"{_DAYS_IDLE} days "
            f"(metric: cloudsql.googleapis.com/database/network/connections; "
            f"may not capture short-lived or non-TCP workloads)",
            f"Database version: {database_version}",
            cost_signal,
        ]
        if ha_enabled:
            signals_used.append(
                "HA enabled (availabilityType: REGIONAL) — actual compute cost is ~2x the estimate"
            )
        if data_disk_size_gb:
            signals_used.append(
                f"Storage: {data_disk_size_gb} GB ({data_disk_type or 'unknown type'}) — "
                f"billed separately from compute"
            )

        details = {
            "instance_name": instance_name,
            "database_version": database_version,
            "tier": tier,
            "region": region,
            "ha_enabled": ha_enabled,
            "days_idle_threshold": _DAYS_IDLE,
            "estimated_monthly_cost_usd": monthly_cost,
            "labels": labels,
        }
        if data_disk_size_gb is not None:
            details["data_disk_size_gb"] = data_disk_size_gb
        if data_disk_type:
            details["data_disk_type"] = data_disk_type
        if backup_retention is not None:
            details["backup_retained_count"] = backup_retention
        if cpu_count is not None:
            details["cpu_count"] = cpu_count
            details["memory_gb"] = memory_gb

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.sql.instance.idle",
                resource_type="gcp.sql.instance",
                resource_id=f"projects/{project_id}/instances/{instance_name}",
                region=region,
                title=f"Idle Cloud SQL Instance ({_DAYS_IDLE}+ Days)",
                summary=(
                    f"Cloud SQL instance '{instance_name}' ({database_version}, {tier}) "
                    f"in region '{region}' has had no observed database connections via "
                    f"Cloud Monitoring over {_DAYS_IDLE}+ days but continues to incur "
                    f"compute charges."
                ),
                reason=f"Zero database connections detected over the last {_DAYS_IDLE} days",
                risk=RiskLevel.HIGH,
                confidence=confidence,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals_used,
                    signals_not_checked=[
                        "Short-lived or batch connections (cron jobs, ETL) not visible in Cloud Monitoring connection metrics over the 7-day window",
                        "Non-TCP workloads or Unix socket connections via Cloud SQL Proxy",
                        "Scheduled maintenance window",
                        "Planned reactivation for upcoming sprint",
                        "Read replicas (excluded from this rule)",
                        "Storage, backups, HA configuration, and network egress not included "
                        "in cost estimate — actual cost is often 2–5x higher",
                    ],
                    time_window=f"{_DAYS_IDLE} days",
                ),
                details=details,
                estimated_monthly_cost_usd=monthly_cost,
            )
        )

    return findings


find_idle_sql_instances.RULE_ID = "gcp.sql.instance.idle"
