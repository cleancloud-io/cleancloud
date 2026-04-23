"""
Rule: azure.sql.database.idle

Intent:
    Detect dedicated Azure SQL Database single-database resources that show
    no observable user workload activity over the configured idle window and
    therefore represent conservative cleanup or rightsizing review candidates.

    This is a conservative review-candidate rule only. It is not proof that a
    database is delete-safe, not proof that no business continuity purpose
    exists, and not proof of a specific monthly saving.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - status does not resolve to "Online"
    - name == "master" (system database)
    - database age unknown or less than idle_days
    - database is in an elastic pool (no per-database billing)
    - database is replica / secondary-shaped
    - database is currently paused (serverless paused — compute cost is zero)
    - any required metric cannot be resolved reliably (series absent or empty)
    - any required metric is non-zero over the idle window

Detection:
    - status is Online
    - database age >= idle_days
    - not pooled, not replica / secondary-shaped, not paused
    - all five required metrics zero over the idle window:
      connection_successful (Total), sessions_count (Maximum),
      cpu_percent (Maximum), physical_data_read_percent (Maximum),
      log_write_percent (Maximum)

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Azure SQL pricing varies by purchasing model, tier, compute shape,
    storage, backup, and serverless behavior; no flat estimate is appropriate.

APIs:
    - Microsoft.Sql/servers/read (servers.list)
    - Microsoft.Sql/servers/databases/read (databases.list_by_server)
    - Microsoft.Insights/metrics/read (monitor metrics for connection_successful,
      sessions_count, cpu_percent, physical_data_read_percent, log_write_percent)
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.sql import SqlManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.sql.database.idle"
_RESOURCE_TYPE = "azure.sql.database"

# Required activity metrics: (REST metric name, aggregation type, datapoint attribute)
_REQUIRED_METRICS = [
    ("connection_successful", "Total", "total"),
    ("sessions_count", "Maximum", "maximum"),
    ("cpu_percent", "Maximum", "maximum"),
    ("physical_data_read_percent", "Maximum", "maximum"),
    ("log_write_percent", "Maximum", "maximum"),
]


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec section 7."""
    return s.lower() if s else ""


# ---------------------------------------------------------------------------
# SDK-first / nested-fallback resolvers (spec 9.1–9.5)
# ---------------------------------------------------------------------------


def _resolve_status(db) -> Optional[str]:
    """
    Resolve database status per spec 9.1:
    1. SDK projection (db.status)
    2. Nested snake_case (db.properties.status)
    Otherwise None (unknown → caller must skip).
    """
    v = getattr(db, "status", None)
    if v is not None:
        return str(v)
    props = getattr(db, "properties", None)
    if props is not None:
        v = getattr(props, "status", None)
        if v is not None:
            return str(v)
    return None


def _resolve_str_field(db, sdk_attr: str, arm_attr: str) -> Optional[str]:
    """
    Resolve a string field with SDK-first / nested fallback:
    1. SDK projection (db.<sdk_attr>)
    2. Nested snake_case (db.properties.<sdk_attr>)
    3. Nested ARM camelCase (db.properties.<arm_attr>)
    Returns the first non-empty value found, or None.
    """
    v = getattr(db, sdk_attr, None)
    if v:
        return str(v)
    props = getattr(db, "properties", None)
    if props is not None:
        v = getattr(props, sdk_attr, None)
        if v:
            return str(v)
        v = getattr(props, arm_attr, None)
        if v:
            return str(v)
    return None


def _resolve_creation_date(db) -> Optional[datetime]:
    """
    Resolve creation_date per spec 9.2:
    1. SDK projection (db.creation_date)
    2. Nested snake_case (db.properties.creation_date)
    3. Nested ARM camelCase (db.properties.creationDate)
    Returns a UTC-aware datetime or None.
    """
    v = getattr(db, "creation_date", None)
    if v is None:
        props = getattr(db, "properties", None)
        if props is not None:
            v = getattr(props, "creation_date", None)
            if v is None:
                v = getattr(props, "creationDate", None)
    return _coerce_datetime(v)


def _resolve_date_field(db, sdk_attr: str, arm_attr: str) -> Optional[datetime]:
    """
    Resolve a date field with SDK-first / nested fallback.
    Returns a UTC-aware datetime or None.
    """
    v = getattr(db, sdk_attr, None)
    if v is None:
        props = getattr(db, "properties", None)
        if props is not None:
            v = getattr(props, sdk_attr, None)
            if v is None:
                v = getattr(props, arm_attr, None)
    return _coerce_datetime(v)


def _coerce_datetime(v) -> Optional[datetime]:
    """Convert datetime / ISO string to UTC-aware datetime, or return None."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            return None
    return None


def _is_replica_secondary(db) -> bool:
    """
    Replica / secondary exclusion contract per spec 9.4.
    Returns True when the database is replica / secondary-shaped.

    Signals checked (SDK-first / nested fallback):
    - secondary_type (non-empty → explicit replica indicator; standalone skip)
    - source_database_id alone is NOT sufficient; it must be paired with
      secondary/replica-shaped control-plane context (spec 9.4). Since
      secondary_type is the canonical pairing signal and is already caught
      above, source_database_id is only relevant when combined with it.
    """
    if _resolve_str_field(db, "secondary_type", "secondaryType"):
        return True
    return False


def _is_paused(db) -> bool:
    """
    Current paused-state contract per spec 9.5.
    Returns True when the database is currently paused.

    Signals checked:
    1. status == "Paused"
    2. paused_date present with no evidence of a later resumed_date
    """
    if _resolve_status(db) == "Paused":
        return True
    paused_date = _resolve_date_field(db, "paused_date", "pausedDate")
    if paused_date is None:
        return False
    resumed_date = _resolve_date_field(db, "resumed_date", "resumedDate")
    if resumed_date is None:
        return True  # paused with no resume evidence
    return paused_date > resumed_date


# ---------------------------------------------------------------------------
# Metric query (spec 9.6)
# ---------------------------------------------------------------------------


def _query_metric(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    aggregation: str,
    dp_attr: str,
    window_start: datetime,
    window_end: datetime,
) -> Optional[float]:
    """
    Query a single Azure Monitor metric for the given timespan.

    Returns:
      float >= 0  — metric resolved; 0.0 means confirmed zero for the window
      None        — metric unknown / query failed / series absent or empty
                    → caller must skip the database (spec 9.6, rules 3 & 4)

    Per spec 9.6:
    - If the metric query raises     → None (unknown)
    - If the metric is absent from response   → None (unknown)
    - If the series is empty or unusable      → None (unknown)
    - If all datapoints are 0 or None and series is usable → 0.0 (confirmed zero)
    - If any datapoint > 0           → that positive value (database is active)
    """
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        timespan = f"{window_start.strftime(fmt)}/{window_end.strftime(fmt)}"
        response = monitor_client.metrics.list(
            resource_uri,
            metricnames=metric_name,
            timespan=timespan,
            interval="P1D",
            aggregation=aggregation,
        )

        # Locate the metric in the response (name may be LocalizableString or str)
        matched = None
        for m in response.value or []:
            m_name = m.name
            if hasattr(m_name, "value"):
                name_val = m_name.value
            else:
                name_val = str(m_name) if m_name is not None else None
            if name_val and name_val.lower() == metric_name.lower():
                matched = m
                break

        if matched is None:
            return None  # metric absent from response → unknown

        # Collect aggregated datapoints.
        # Distinguish "no data items at all" (series unusable → unknown) from
        # "data items present but all None" (series usable, all zero → 0.0).
        # Spec 9.6 rule 2: usable series where all datapoints are 0 or None
        # counts as zero for the window, not unknown.
        has_data_items = False
        values = []
        for ts in matched.timeseries or []:
            for dp in ts.data or []:
                has_data_items = True
                val = getattr(dp, dp_attr, None)
                if val is not None:
                    values.append(val)

        if not has_data_items:
            return None  # series has no data items → unusable → unknown

        if not values:
            return 0.0  # all datapoints None → usable series, confirmed zero

        return max(values)

    except Exception:
        return None  # query failure → unknown


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_resource_group(resource_id: str) -> str:
    """Extract resource group name from an Azure resource ID."""
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    raise ValueError(f"Cannot extract resource group from resource ID: {resource_id}")


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------


def find_idle_sql_databases(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[SqlManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Azure SQL databases with no observable user workload activity over idle_days.

    Detection requires all five required activity metrics (connection_successful,
    sessions_count, cpu_percent, physical_data_read_percent, log_write_percent)
    to be zero for the full observation window. Single-metric silence is not enough.

    IAM permissions:
    - Microsoft.Sql/servers/read
    - Microsoft.Sql/servers/databases/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    sql_client = client or SqlManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=idle_days)

    for server in sql_client.servers.list():
        # Server-level region pre-filter (optimization — database location == server location in Azure SQL)
        server_location = _norm_location(getattr(server, "location", "") or "")
        if region_filter and server_location != _norm_location(region_filter):
            continue

        server_id = getattr(server, "id", None)
        if not server_id:
            continue

        try:
            resource_group = _extract_resource_group(server_id)
        except ValueError:
            continue

        server_name = getattr(server, "name", None) or ""

        try:
            db_list = list(sql_client.databases.list_by_server(resource_group, server_name))
        except Exception:
            continue  # spec 12: skip server on listing failure

        for db in db_list:
            # spec 8.1: id must be present and non-empty
            db_id = getattr(db, "id", None)
            if not db_id:
                continue

            # spec 8.2: name must be present and non-empty
            db_name = getattr(db, "name", None)
            if not db_name:
                continue

            # spec 8.3: region filter — exact lowercase match on database location
            db_location = _norm_location(getattr(db, "location", "") or "")
            if region_filter and db_location != _norm_location(region_filter):
                continue

            # spec 8.4 / 9.1: status must resolve to exactly "Online"
            if _resolve_status(db) != "Online":
                continue

            # spec 8.5: skip master system database
            if db_name == "master":
                continue

            # spec 8.6 / 9.2: age must be known and >= idle_days
            creation_date = _resolve_creation_date(db)
            if creation_date is None:
                continue  # age unknown → skip
            age_days = (now - creation_date).days
            if age_days < idle_days:
                continue

            # spec 8.7 / 9.3: skip elastic pool databases (billing is at pool level)
            elastic_pool_id = _resolve_str_field(db, "elastic_pool_id", "elasticPoolId")
            if elastic_pool_id:
                continue

            # spec 8.8 / 9.4: skip replica / secondary-shaped databases
            if _is_replica_secondary(db):
                continue

            # spec 8.9 / 9.5: skip currently paused databases (compute cost is already zero)
            if _is_paused(db):
                continue

            # spec 8.10–8.11 / 9.6: query all five required metrics
            metric_values: dict = {}
            skip_db = False
            for metric_name, aggregation, dp_attr in _REQUIRED_METRICS:
                val = _query_metric(
                    mon_client,
                    db_id,
                    metric_name,
                    aggregation,
                    dp_attr,
                    window_start,
                    now,
                )
                if val is None:
                    skip_db = True  # metric unknown → skip (spec 9.6 rule 3/4)
                    break
                metric_values[metric_name] = val

            if skip_db:
                continue

            if any(v > 0 for v in metric_values.values()):
                continue  # at least one metric non-zero → database is active

            # --- context-only details (spec 9.8) ---
            sku = getattr(db, "sku", None)
            sku_tier = getattr(sku, "tier", None) if sku else None
            current_slo = getattr(db, "current_service_objective_name", None)
            auto_pause_delay = getattr(db, "auto_pause_delay", None)
            if auto_pause_delay is None:
                props = getattr(db, "properties", None)
                if props is not None:
                    auto_pause_delay = getattr(props, "auto_pause_delay", None)
                    if auto_pause_delay is None:
                        auto_pause_delay = getattr(props, "autoPauseDelay", None)
            paused_date_raw = getattr(db, "paused_date", None)
            tags = getattr(db, "tags", None) or {}

            findings.append(
                Finding(
                    provider="azure",
                    rule_id=_RULE_ID,
                    resource_type=_RESOURCE_TYPE,
                    resource_id=db_id,
                    region=db_location,
                    estimated_monthly_cost_usd=None,  # spec 10: always None
                    title="Idle Azure SQL Database",
                    summary=(
                        f"SQL database '{db_name}' on server '{server_name}' "
                        f"shows no observable activity for {idle_days}+ days"
                    ),
                    reason=(
                        f"All five required activity metrics are zero over {idle_days} days: "
                        "connection_successful, sessions_count, cpu_percent, "
                        "physical_data_read_percent, log_write_percent"
                    ),
                    risk=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=[
                            "Database status is Online",
                            f"Database age is at least {idle_days} days",
                            "Database is not in an elastic pool",
                            "Replica / secondary exclusion contract is not triggered",
                            "Paused-state contract is not triggered",
                            f"Zero connection_successful over {idle_days}-day window",
                            f"Zero sessions_count over {idle_days}-day window",
                            f"Zero cpu_percent over {idle_days}-day window",
                            f"Zero physical_data_read_percent over {idle_days}-day window",
                            f"Zero log_write_percent over {idle_days}-day window",
                        ],
                        signals_not_checked=[
                            "Planned future cutover or deployment intent",
                            "Undeclared business continuity requirements",
                            "Workload activity outside documented rule signals",
                            "Exact Azure billing amount for this database",
                        ],
                        time_window=f"{idle_days} days",
                    ),
                    details={
                        "database_name": db_name,
                        "server_name": server_name,
                        "status": _resolve_status(db),
                        "current_service_objective_name": current_slo,
                        "sku_tier": sku_tier,
                        "elastic_pool_id": elastic_pool_id,
                        "auto_pause_delay": auto_pause_delay,
                        "paused_date": (
                            str(paused_date_raw) if paused_date_raw is not None else None
                        ),
                        "creation_date": str(creation_date),
                        "idle_days": idle_days,
                        "connection_successful": metric_values.get("connection_successful"),
                        "sessions_count": metric_values.get("sessions_count"),
                        "cpu_percent": metric_values.get("cpu_percent"),
                        "physical_data_read_percent": metric_values.get(
                            "physical_data_read_percent"
                        ),
                        "log_write_percent": metric_values.get("log_write_percent"),
                        "tags": tags,
                    },
                )
            )

    return findings
