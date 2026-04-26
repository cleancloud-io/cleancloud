"""
Rule: gcp.sql.instance.idle

    (spec — docs/specs/gcp/sql_instance_idle.md)

Intent:
    Detect primary Cloud SQL instances that show no observed active database
    connections for the full configured idle window and therefore represent
    conservative review candidates for cleanup, stop/start reconsideration,
    or rightsizing.

    This is a conservative review-candidate rule only. It is not proof that
    the instance is safe to delete, not proof that no business continuity
    purpose exists, and not proof of a specific monthly saving.

Exclusions:
    - instance record malformed or name absent / empty (spec 8.1)
    - region absent / empty (spec 8.2)
    - region filter set and region does not match (spec 8.3)
    - state absent, unknown, or not exactly "RUNNABLE" (spec 8.4)
    - instanceType absent, unknown, or not exactly "CLOUD_SQL_INSTANCE" (spec 8.5)
    - replica exclusion contract triggered (masterInstanceName present) (spec 8.6)
    - createTime absent or unparsable (spec 8.7)
    - instance newer than window_start (spec 8.8)
    - active_connections metric cannot be resolved reliably (spec 8.9)
    - active_connections_max > 0 anywhere in the window (spec 8.10)

Detection:
    - state == "RUNNABLE"
    - instanceType == "CLOUD_SQL_INSTANCE"
    - masterInstanceName absent / empty
    - createTime parsable and instance older than window_start
    - active_connections_max == 0 for the full window

Cost model (spec 9.10):
    estimated_monthly_cost_usd = None
    Pricing varies by edition, region, compute shape, HA, storage, and
    commitment model; no flat tier estimate is appropriate.

APIs:
    - sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances
    - monitoring.googleapis.com: cloudsql.googleapis.com/database/active_connections
      on cloudsql_database monitored resource
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, PermissionDenied
from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# spec 6.3 / 9.5: Cloud SQL metrics are sampled every 60s and can be delayed
# up to 165s. A 5-minute buffer conservatively covers documented visibility lag.
_MONITORING_LAG_BUFFER = timedelta(minutes=5)

# spec 9.6.9: coverage quality thresholds.
# Maximum tolerated consecutive gap between observed data points.  Accounts for
# the documented 60 s sampling period + up to 165 s visibility lag, plus a
# conservative buffer for occasional missed samples.
_MAX_COVERAGE_GAP = timedelta(minutes=10)
# Tolerated offset between window boundary and first/last observed point.
# Accounts for sampling alignment and in-flight visibility lag at window edges.
_COVERAGE_EDGE_TOLERANCE = timedelta(minutes=10)


def _parse_create_time(ts: str) -> Optional[datetime]:
    """Parse an RFC3339 createTime string to a UTC-aware datetime, or return None."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _list_sql_instances(project_id: str, credentials) -> list:
    """
    List all Cloud SQL instances using the Cloud SQL Admin REST API.

    Raises PermissionError on 403 (spec 9.13.1).
    Returns [] on 404 (Cloud SQL API not enabled — spec 9.13.3).
    """
    session = AuthorizedSession(credentials)
    resp = session.get(
        f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/instances"
    )
    if resp.status_code == 403:
        raise PermissionError("cloudsql.instances.list permission required (roles/cloudsql.viewer)")
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return resp.json().get("items", [])


def _query_active_connections(
    monitoring_client: monitoring_v3.MetricServiceClient,
    project_id: str,
    instance_name: str,
    instance_region: str,
    window_start: datetime,
    window_end: datetime,
) -> Optional[float]:
    """
    Query cloudsql.googleapis.com/database/active_connections for one instance.

    Matches by exact documented cloudsql_database monitored-resource identity
    labels (project_id, location, resource_id).  Aggregates across all matched
    series to handle the database label dimension (spec 9.6–9.7).

    Also evaluates coverage quality (spec 9.6.8–9.6.9): the observed timestamps
    must span the full window within _COVERAGE_EDGE_TOLERANCE, and no consecutive
    gap between observed points may exceed _MAX_COVERAGE_GAP.

    Returns:
        float >= 0.0  — active_connections_max; 0.0 means confirmed idle
        None          — unresolved coverage (no series / no points / partial
                        window / large gap / unreadable timestamps / failure);
                        caller must skip (spec 8.9)

    Raises:
        PermissionError — monitoring.timeSeries.list permission denied (spec 9.13.2)
    """
    try:
        end_ts = timestamp_pb2.Timestamp()
        end_ts.FromDatetime(window_end)
        start_ts = timestamp_pb2.Timestamp()
        start_ts.FromDatetime(window_start)

        interval = monitoring_v3.TimeInterval(start_time=start_ts, end_time=end_ts)

        # spec 9.6.3: exact label matching — project_id, location, resource_id
        filter_str = (
            'metric.type="cloudsql.googleapis.com/database/active_connections"'
            ' AND resource.type="cloudsql_database"'
            f' AND resource.labels.project_id="{project_id}"'
            f' AND resource.labels.location="{instance_region}"'
            f' AND resource.labels.resource_id="{instance_name}"'
        )

        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )

        # spec 9.7: aggregate across all matched series (all database label variants)
        has_series = False
        has_points = False
        max_val = 0.0
        all_timestamps: list = []

        for series in results:
            has_series = True
            for point in series.points:
                has_points = True
                which = point.value.WhichOneof("value")
                if which == "int64_value":
                    val = float(point.value.int64_value)
                elif which == "double_value":
                    val = float(point.value.double_value)
                else:
                    # Unrecognised or unset value type → unresolved coverage → skip
                    return None
                if val > max_val:
                    max_val = val
                # Collect timestamp for coverage quality evaluation (spec 9.6.8–9.6.9).
                # Any parse failure means coverage cannot be verified → unresolved.
                try:
                    ts = point.interval.end_time
                    all_timestamps.append(
                        datetime.fromtimestamp(ts.seconds + ts.nanos / 1e9, tz=timezone.utc)
                    )
                except Exception:
                    # spec 9.6.8: parse failure → unresolved coverage → skip
                    return None

        if not has_series:
            # spec 9.6.7: no time series → unresolved coverage → skip
            return None
        if not has_points:
            # spec 9.6.8: series present but no data points → unusable → skip
            return None
        if not all_timestamps:
            # no readable timestamps → cannot verify coverage → skip
            return None

        # spec 9.6.9: coverage quality — partial-window or materially sparse → skip
        # Deduplicate before the gap check so identical timestamps from multiple
        # series don't produce spurious zero-length intervals.
        all_timestamps = sorted(set(all_timestamps))
        if all_timestamps[0] > window_start + _COVERAGE_EDGE_TOLERANCE:
            # data starts too late — partial window coverage
            return None
        if all_timestamps[-1] < window_end - _COVERAGE_EDGE_TOLERANCE:
            # data ends too early — partial window coverage
            return None
        for i in range(1, len(all_timestamps)):
            if all_timestamps[i] - all_timestamps[i - 1] > _MAX_COVERAGE_GAP:
                # large missing chunk in the middle of the window
                return None

        return max_val

    except (PermissionDenied, Forbidden) as e:
        # spec 9.13.2: monitoring permission failures must surface as permission error
        raise PermissionError(
            f"monitoring.timeSeries.list permission required (roles/monitoring.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except Exception:
        # all other failures → unresolved coverage → skip (spec 9.13.5)
        return None


def find_idle_sql_instances(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Cloud SQL instances with zero active connections for idle_days days.

    Detection requires active_connections_max == 0 for the full observation
    window on cloudsql.googleapis.com/database/active_connections matched by
    exact cloudsql_database identity labels.  Unresolved metric coverage causes
    the instance to be skipped rather than flagged.

    IAM permissions required:
    - cloudsql.instances.list (roles/cloudsql.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # spec 6.3: window_end with lag buffer; window_start = window_end - idle_days
    window_end = now - _MONITORING_LAG_BUFFER
    window_start = window_end - timedelta(days=idle_days)

    # PermissionError propagates (spec 9.13.1)
    instances = _list_sql_instances(project_id, credentials)

    if not instances:
        return findings

    # If monitoring client cannot be created, skip rather than false-positive (spec 9.13.4)
    try:
        monitoring_client = monitoring_v3.MetricServiceClient(credentials=credentials)
    except Exception:
        return findings

    for instance in instances:
        # spec 8.1: name must be present and non-empty
        instance_name = instance.get("name", "")
        if not instance_name:
            continue

        # spec 8.2: region must be present and non-empty
        region = instance.get("region", "")
        if not region:
            continue

        # spec 8.3: region filter — exact string equality
        if region_filter and region != region_filter:
            continue

        # spec 8.4: only RUNNABLE is eligible
        if instance.get("state") != "RUNNABLE":
            continue

        # spec 8.5: only primary CLOUD_SQL_INSTANCE is eligible
        instance_type = instance.get("instanceType", "")
        if instance_type != "CLOUD_SQL_INSTANCE":
            continue

        # spec 8.6 / 9.4: replica exclusion — masterInstanceName present and non-empty
        master_instance_name = instance.get("masterInstanceName", "")
        if master_instance_name:
            continue

        # spec 8.7 / 9.5: createTime must be parsable
        created_at = _parse_create_time(instance.get("createTime", ""))
        if created_at is None:
            continue  # absent or unparsable → skip

        # spec 8.8 / 9.5: instance must be old enough for the full observation window
        if created_at > window_start:
            continue

        # spec 8.9–8.10 / 9.6–9.7: query documented active_connections metric
        # PermissionError propagates (spec 9.13.2)
        active_connections_max = _query_active_connections(
            monitoring_client,
            project_id,
            instance_name,
            region,
            window_start,
            window_end,
        )

        if active_connections_max is None:
            continue  # unresolved coverage → skip (spec 8.9)

        if active_connections_max > 0:
            continue  # active → skip (spec 8.10)

        # --- All exclusions passed: build finding ---
        settings = instance.get("settings") or {}
        database_version = instance.get("databaseVersion", "")
        tier = settings.get("tier", "")
        availability_type = settings.get("availabilityType", "")
        ha_enabled = availability_type == "REGIONAL"
        data_disk_size_gb = settings.get("dataDiskSizeGb")
        data_disk_type = settings.get("dataDiskType", "")
        backup_cfg = settings.get("backupConfiguration") or {}
        backup_retention = (backup_cfg.get("backupRetentionSettings") or {}).get("retainedBackups")
        labels = settings.get("userLabels") or {}

        # spec 10.2: signals_used must disclose state, type, metric coverage, connections,
        # version, tier, HA context, and storage/backup context when present
        signals_used = [
            "Instance state: RUNNABLE",
            "Instance type: CLOUD_SQL_INSTANCE (primary)",
            (
                f"Metric coverage: FULL for {idle_days}-day window "
                f"(cloudsql.googleapis.com/database/active_connections "
                f"on cloudsql_database)"
            ),
            f"active_connections_max = {active_connections_max:.0f} over {idle_days}-day window",
            f"Database version: {database_version or 'unknown'}",
            f"Tier: {tier or 'unknown'}",
        ]
        if ha_enabled:
            signals_used.append(
                "HA enabled (availabilityType: REGIONAL) — regional instance "
                "with primary and standby"
            )
        if data_disk_size_gb is not None:
            signals_used.append(
                f"Storage: {data_disk_size_gb} GB "
                f"({data_disk_type or 'unknown type'}) — "
                f"billed separately from compute"
            )
        if backup_retention is not None:
            signals_used.append(f"Backup retention: {backup_retention} retained backups")

        # spec 10.3: required details fields
        details: dict = {
            "instance_name": instance_name,
            "instance_type": instance_type,
            "database_version": database_version,
            "tier": tier,
            "region": region,
            "created_at": created_at.isoformat(),
            "idle_days_threshold": idle_days,
            "metric_coverage": "FULL",
            "active_connections_max": active_connections_max,
            "ha_enabled": ha_enabled,
            "availability_type": availability_type or None,
            "labels": labels,
        }
        # conditional details (spec 10.3: when present)
        if master_instance_name:
            details["master_instance_name"] = master_instance_name
        if data_disk_size_gb is not None:
            details["data_disk_size_gb"] = data_disk_size_gb
        if data_disk_type:
            details["data_disk_type"] = data_disk_type
        if backup_retention is not None:
            details["backup_retained_count"] = backup_retention

        # Custom tier CPU/memory parsing — context only
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
                title=f"Idle Cloud SQL Instance ({idle_days}+ Days)",
                summary=(
                    f"Cloud SQL instance '{instance_name}' "
                    f"({database_version or 'unknown'}, {tier or 'unknown'}) "
                    f"in region '{region}' shows no observed active connections over "
                    f"{idle_days}+ days."
                ),
                reason=(
                    f"active_connections_max == 0 over the {idle_days}-day observation window "
                    f"(cloudsql.googleapis.com/database/active_connections)"
                ),
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals_used,
                    signals_not_checked=[
                        "Short-lived workload bursts between metric samples were not evaluated",
                        "Business or application retention intent",
                        "Migration, failback, or future reactivation intent",
                        "Storage, backup, and network savings were not estimated",
                        "Engine-specific internal work not represented by active client "
                        "connections alone",
                    ],
                    time_window=f"{idle_days} days",
                ),
                details=details,
                # spec 9.10: always None — pricing varies by edition, region, compute shape,
                # HA, storage, and commitment model; no flat estimate is appropriate
                estimated_monthly_cost_usd=None,
            )
        )

    return findings


find_idle_sql_instances.RULE_ID = "gcp.sql.instance.idle"
