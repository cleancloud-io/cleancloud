"""
Rule: azure.ai_search.idle

Intent:
    Detect Azure AI Search services that are structurally empty and
    operationally inactive over a fixed 90-day observation window, making
    them conservative review candidates for deletion or rightsizing.

    This rule intentionally requires BOTH documented activity silence AND
    confirmed structural emptiness before emitting. Either condition alone
    is not sufficient.

    Review-candidate rule only. Does not prove deletion is safe, that no
    future go-live depends on the service, or that a specific monthly saving
    exists.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning_state does not resolve to exactly "succeeded" (SDK+nested, conflict -> skip)
    - status does not resolve to exactly "running" (SDK+nested, conflict -> skip)
    - sku.name not in supported dedicated billable tiers
      (basic / standard / standard2 / standard3 / storage_optimized_l1 / storage_optimized_l2)
    - created_at absent, invalid, in the future, or service age < 90 days
    - replica_count or partition_count not a known positive integer (SDK+nested, conflict -> skip)
    - data-plane client factory returns None (package unavailable -> skip)
    - any required object surface (indexes, indexers, data_sources, skillsets, synonym_maps)
      fails, is unavailable, or is non-empty
    - any optional object surface (aliases, knowledge_sources, agents) that could be fully
      enumerated and is non-empty
    - any required activity metric cannot be resolved reliably (< 95% daily-bucket coverage)
    - any required activity metric is non-zero over 90 days
    - per-service SDK retrieval raises an expected error

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Risk = MEDIUM (always)
    Confidence = HIGH (always, when all conditions met)

APIs:
    - Microsoft.Search/searchServices/read  (services.list_by_subscription)
    - Microsoft.Insights/metrics/read
    - Azure AI Search data-plane object list APIs (RBAC keyless auth, no admin keys)
"""

import math
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, List, Optional, Tuple

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.search import SearchManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.ai_search.idle"
_RESOURCE_TYPE = "azure.ai.search_service"
_IDLE_WINDOW_DAYS = 90  # fixed per spec 6.3
_MIN_AGE_DAYS = 90  # spec 8.7
_MIN_COVERAGE = 0.95  # spec 9.5

# Supported dedicated billable tiers (spec 9.2)
_SUPPORTED_SKUS = frozenset(
    {
        "basic",
        "standard",
        "standard2",
        "standard3",
        "storage_optimized_l1",
        "storage_optimized_l2",
    }
)

# Required object surfaces (spec 9.3): (surface_key, data_plane_method_name)
_REQUIRED_SURFACES: Tuple[Tuple[str, str], ...] = (
    ("indexes", "list_indexes"),
    ("indexers", "list_indexers"),
    ("data_sources", "list_data_source_connections"),
    ("skillsets", "list_skillsets"),
    ("synonym_maps", "list_synonym_maps"),
)

# Optional reinforcing surfaces (spec 9.3.5-9.3.7): enumerated when supported;
# if non-empty, the service still must skip (spec 9.3.7).
_OPTIONAL_SURFACES: Tuple[Tuple[str, str], ...] = (
    ("aliases", "list_aliases"),
    ("knowledge_sources", "list_knowledge_sources"),
    ("agents", "list_agents"),
)

# Required activity metrics (spec 9.5): (metric_name, aggregation_type)
_REQUIRED_METRICS: Tuple[Tuple[str, str], ...] = (
    ("SearchQueriesPerSecond", "Average"),
    ("DocumentsProcessedCount", "Total"),
    ("SkillExecutionCount", "Total"),
)

# SKU alias table: stripped-lowercase SDK variant -> canonical _SUPPORTED_SKUS key
_SKU_ALIASES = {
    "storageoptimizedl1": "storage_optimized_l1",
    "storageoptimizedl2": "storage_optimized_l2",
}

_SENTINEL = object()

RULE_METADATA = {
    "id": _RULE_ID,
    "category": "ai",
    "service": "search",
    "cost_impact": "high",
}


class _MetricResult(Enum):
    ACTIVE = "ACTIVE"
    ZERO = "ZERO"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _normalize_sku(raw: str) -> str:
    """
    Normalize an Azure Search SKU name to the canonical _SUPPORTED_SKUS key.

    Spec 7: lowercase only — no character stripping beyond case folding.
    Known SDK camelCase variants (e.g. "StorageOptimizedL1") are then resolved
    via _SKU_ALIASES to their canonical underscore form.

    Anything not in _SKU_ALIASES is returned as-is after lowercasing; the caller
    checks membership in _SUPPORTED_SKUS and skips on no match.
    """
    lowered = (raw or "").lower()
    return _SKU_ALIASES.get(lowered, lowered)


def _norm_location(s: str) -> str:
    """Lowercase only -- exact lowercase match per spec 7."""
    return s.lower() if s else ""


def _extract_resource_group(resource_id: str) -> Optional[str]:
    """Extract resource group name from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


# ---------------------------------------------------------------------------
# State resolvers (spec 9.1)
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(svc) -> Optional[str]:
    """
    SDK-first / nested fallback. Returns None on conflict or both absent.
    Only exact "succeeded" is eligible; caller skips on anything else.
    """
    sdk_val = getattr(svc, "provisioning_state", None)
    props = getattr(svc, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "provisioning_state", None)
        if nested_val is None:
            nested_val = getattr(props, "provisioningState", None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip
    return sdk_val or nested_val


def _resolve_status(svc) -> Optional[str]:
    """
    SDK-first / nested fallback. Returns None on conflict or both absent.
    Only exact "running" is eligible; caller skips on anything else.
    """
    sdk_val = getattr(svc, "status", None)
    props = getattr(svc, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "status", None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip
    return sdk_val or nested_val


def _resolve_capacity(svc, sdk_attr: str, nested_snake: str, nested_camel: str) -> Optional[int]:
    """
    Resolve replica_count or partition_count. SDK-first / nested fallback.
    Returns a known positive integer, or None (conflict, absent, zero, invalid).
    """
    sdk_val = getattr(svc, sdk_attr, None)
    props = getattr(svc, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, nested_snake, None)
        if nested_val is None:
            nested_val = getattr(props, nested_camel, None)
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip
    val = sdk_val if sdk_val is not None else nested_val
    if val is None:
        return None
    try:
        n = int(val)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def _resolve_created_at(svc) -> Optional[datetime]:
    """
    Resolve creation timestamp from systemData.createdAt.
    Returns a UTC-aware datetime, or None if absent, invalid, or in the future.
    """
    system_data = getattr(svc, "system_data", None)
    if system_data is None:
        return None
    raw = getattr(system_data, "created_at", None)
    if raw is None:
        return None

    if isinstance(raw, datetime):
        ts = raw if raw.tzinfo is not None else raw.replace(tzinfo=timezone.utc)
    elif isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    else:
        return None

    if ts > datetime.now(timezone.utc):
        return None  # future timestamp -> invalid -> skip
    return ts


# ---------------------------------------------------------------------------
# Structural-emptiness contract (spec 9.3)
# ---------------------------------------------------------------------------


def _check_object_surfaces(dp_client) -> Optional[dict]:
    """
    Enumerate all required and optional object surfaces per spec 9.3.

    Returns a dict of {surface_key: count} for successfully enumerated surfaces,
    or None if any required surface fails, is unavailable, or is non-empty
    (required or optional).

    Sensitive content (credentials, keys, connection strings) must never be
    captured; only counts are recorded (spec 9.4).
    """
    object_counts: dict = {}

    for surface_key, method_name in _REQUIRED_SURFACES:
        fn = getattr(dp_client, method_name, None)
        if fn is None:
            return None  # required surface unavailable -> skip service
        try:
            count = sum(1 for _ in fn())
        except Exception:
            return None  # required surface failed -> skip service
        if count > 0:
            return None  # non-empty required surface -> skip service (spec 9.3.3)
        object_counts[surface_key] = 0

    for surface_key, method_name in _OPTIONAL_SURFACES:
        fn = getattr(dp_client, method_name, None)
        if fn is None:
            continue  # optional surface not supported -> omit from counts
        try:
            count = sum(1 for _ in fn())
        except Exception:
            continue  # optional surface failed -> omit from counts (spec 9.3.6)
        if count > 0:
            return None  # non-empty optional surface -> skip service (spec 9.3.7)
        object_counts[surface_key] = 0

    return object_counts


# ---------------------------------------------------------------------------
# Activity-metric contract (spec 9.5)
# ---------------------------------------------------------------------------


def _evaluate_metric(
    monitor_client,
    resource_id: str,
    metric_name: str,
    aggregation: str,
    window_start: datetime,
    window_end: datetime,
) -> _MetricResult:
    """
    Evaluate a single Azure Monitor metric over the 90-day window per spec 9.5.

    Queries Azure Monitor without a fixed interval so it auto-selects the finest
    available granularity for the timespan. Activity is evaluated at each returned
    source bucket before any UTC-day normalization, which prevents short-lived
    spikes from being diluted into a daily average (spec 9.5.2).

    Coverage is measured in UTC-aligned daily buckets (spec 9.5 definitions).
    >= 95% coverage is required.  Returns ACTIVE, ZERO, or UNKNOWN.

    Fail-closed on unusable response shapes (spec 9.5.6):
    - absent or non-datetime timestamp -> UNKNOWN (entire metric)
    - non-numeric aggregation value    -> UNKNOWN (entire metric)
    - malformed series element         -> UNKNOWN (entire metric)

    Datapoints with no populated aggregation value reduce bucket coverage toward
    the threshold, driving toward UNKNOWN via the coverage check (not fail-close).

    Datapoints outside the requested window are filtered out (not fail-closed).
    """
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start.strftime(fmt)}/{window_end.strftime(fmt)}"

    first_bucket = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    expected_buckets = math.ceil((window_end - first_bucket).total_seconds() / 86400)
    if expected_buckets == 0:
        return _MetricResult.UNKNOWN

    try:
        response = monitor_client.metrics.list(
            resource_id,
            metricnames=metric_name,
            timespan=timespan,
            # No interval= parameter: Azure Monitor auto-selects the finest available
            # granularity for this timespan. This preserves source-bucket granularity
            # so short-lived activity is not diluted away (spec 9.5.2).
            aggregation=aggregation,
        )
    except Exception:
        return _MetricResult.UNKNOWN

    if not hasattr(response, "value") or response.value is None:
        return _MetricResult.UNKNOWN

    agg_attr = aggregation.lower()  # "average" or "total"

    # Per-bucket maximum across all timeseries and dimension slices.
    # Activity evaluated at source-bucket level (spec 9.5.2); timestamps normalized
    # to UTC day only for coverage calculation (spec 9.5.3).
    bucket_max: dict = {}

    try:
        for metric in response.value:
            for ts in getattr(metric, "timeseries", None) or []:
                for data in getattr(ts, "data", None) or []:
                    if data.timestamp is None:
                        return _MetricResult.UNKNOWN  # unparseable -> fail-closed

                    ts_dt = data.timestamp
                    if not isinstance(ts_dt, datetime):
                        return _MetricResult.UNKNOWN  # unparseable timestamp type -> fail-closed

                    val = getattr(data, agg_attr, None)
                    if val is None:
                        continue  # sparse/missing aggregation -> reduces coverage, not fail-close
                    if not isinstance(val, (int, float)):
                        return _MetricResult.UNKNOWN  # non-numeric aggregation -> fail-closed

                    ts_utc = (
                        ts_dt if ts_dt.tzinfo is not None else ts_dt.replace(tzinfo=timezone.utc)
                    )
                    if not (window_start <= ts_utc < window_end):
                        continue  # outside window -> filter

                    key = ts_utc.strftime("%Y-%m-%dT00:00:00Z")
                    existing = bucket_max.get(key)
                    bucket_max[key] = max(existing, val) if existing is not None else val
    except (AttributeError, TypeError, ValueError):
        return _MetricResult.UNKNOWN  # malformed response shape -> fail-closed

    observed = len(bucket_max)
    if observed == 0:
        return _MetricResult.UNKNOWN
    if observed / expected_buckets < _MIN_COVERAGE:
        return _MetricResult.UNKNOWN

    signal = sum(bucket_max.values())
    return _MetricResult.ACTIVE if signal > 0 else _MetricResult.ZERO


# ---------------------------------------------------------------------------
# Default data-plane factory
# ---------------------------------------------------------------------------


def _make_default_data_plane_factory(credential) -> Callable[[str], Optional[object]]:
    """
    Returns a factory that creates Azure Search data-plane clients via RBAC credentials.

    Requires the azure-search-documents package. If unavailable or construction fails,
    the factory returns None for every endpoint; the caller skips that service (spec 9.3.4).

    The implementation must not retrieve admin keys (spec 6.2).
    """

    def factory(endpoint: str) -> Optional[object]:
        try:
            from azure.search.documents.indexes import (  # noqa: PLC0415
                SearchIndexClient,
                SearchIndexerClient,
            )

            return _DataPlaneClients(
                SearchIndexClient(endpoint, credential),
                SearchIndexerClient(endpoint, credential),
            )
        except (ImportError, Exception):
            return None

    return factory


class _DataPlaneClients:
    """
    Thin adapter over SearchIndexClient and SearchIndexerClient.
    Exposes only name-listing methods to keep enumeration lightweight
    and avoid capturing sensitive object definitions (spec 9.4).
    """

    def __init__(self, index_client, indexer_client):
        self._ic = index_client
        self._ixer = indexer_client

    def list_indexes(self):
        return self._ic.list_index_names()

    def list_synonym_maps(self):
        return self._ic.list_synonym_map_names()

    def list_indexers(self):
        return self._ixer.list_indexer_names()

    def list_data_source_connections(self):
        return self._ixer.list_data_source_connection_names()

    def list_skillsets(self):
        return self._ixer.list_skillset_names()


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_ai_search_services(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client=None,
    monitor_client=None,
    data_plane_factory: Optional[Callable[[str], Optional[object]]] = None,
) -> List[Finding]:
    """
    Find Azure AI Search services that are structurally empty and have no
    documented query, indexing, or skill activity for 90 days.

    IAM permissions:
    - Microsoft.Search/searchServices/read
    - Microsoft.Insights/metrics/read
    - Azure AI Search data-plane RBAC (Search Service Contributor or equivalent)

    data_plane_factory: callable(endpoint: str) -> data-plane client or None.
        If the callable returns None for an endpoint, that service is skipped.
        The returned client must expose at minimum:
            list_indexes(), list_indexers(), list_data_source_connections(),
            list_skillsets(), list_synonym_maps().
        Optionally: list_aliases(), list_knowledge_sources(), list_agents().
        Defaults to _make_default_data_plane_factory(credential) which requires
        the azure-search-documents package.
    """
    findings: List[Finding] = []

    search_client = client or SearchManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    if data_plane_factory is None:
        data_plane_factory = _make_default_data_plane_factory(credential)

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=_IDLE_WINDOW_DAYS)

    # Subscription-wide service inventory (spec 12: propagate if this fails)
    for svc in search_client.services.list_by_subscription():
        # spec 8.1: id guard
        svc_id = getattr(svc, "id", None)
        if not svc_id:
            continue

        # spec 8.2: name guard
        svc_name = getattr(svc, "name", None)
        if not svc_name:
            continue

        # Per-service: resolve state, enumerate objects, evaluate metrics.
        # Expected SDK retrieval failures -> skip this service (spec 12).
        # HttpResponseError: HTTP-level failure (404, 403, 429, 5xx).
        # ServiceRequestError: transport failure before a response.
        # ServiceResponseError: transport failure while reading the response.
        try:
            # spec 8.3: region filter -- exact lowercase match
            location = _norm_location(getattr(svc, "location", "") or "")
            if region_filter and location != _norm_location(region_filter):
                continue

            # spec 8.4 / 9.1: provisioning_state must resolve to exactly "succeeded"
            if _resolve_provisioning_state(svc) != "succeeded":
                continue

            # spec 8.5 / 9.1: status must resolve to exactly "running"
            if _resolve_status(svc) != "running":
                continue

            # spec 8.6 / 9.2: SKU must be a supported dedicated billable tier
            sku_obj = getattr(svc, "sku", None)
            sku_raw = getattr(sku_obj, "name", None) if sku_obj else None
            if isinstance(sku_obj, dict):
                sku_raw = sku_obj.get("name")
            sku_name = _normalize_sku(sku_raw)
            if sku_name not in _SUPPORTED_SKUS:
                continue

            # spec 8.7: created_at must be present, valid, and service age >= 90 days
            created_at = _resolve_created_at(svc)
            if created_at is None:
                continue  # absent or invalid -> skip
            age_days = (now - created_at).days
            if age_days < _MIN_AGE_DAYS:
                continue

            # spec 8.8: replica_count and partition_count must be known positive integers
            replica_count = _resolve_capacity(svc, "replica_count", "replica_count", "replicaCount")
            if replica_count is None:
                continue

            partition_count = _resolve_capacity(
                svc, "partition_count", "partition_count", "partitionCount"
            )
            if partition_count is None:
                continue

            resource_group = _extract_resource_group(svc_id)

            # spec 8.9-8.10 / 9.3: data-plane structural emptiness
            endpoint = f"https://{svc_name}.search.windows.net"
            dp_client = data_plane_factory(endpoint)
            if dp_client is None:
                continue  # data-plane unavailable -> skip (spec 9.3.4)

            object_counts = _check_object_surfaces(dp_client)
            if object_counts is None:
                continue  # required surface failed or non-empty -> skip

            # spec 8.11-8.12 / 9.5: all three required activity metrics must be ZERO
            metric_outcomes: dict = {}
            all_zero = True
            for metric_name, aggregation in _REQUIRED_METRICS:
                result = _evaluate_metric(
                    mon_client, svc_id, metric_name, aggregation, window_start, now
                )
                metric_outcomes[metric_name] = result
                if result != _MetricResult.ZERO:
                    all_zero = False
                    break

            if not all_zero:
                continue

            # --- Context fields (best-effort; never gate emission) ---
            hosting_mode = getattr(svc, "hosting_mode", None)
            tags = getattr(svc, "tags", None) or {}  # never None in output

            # --- EMIT ---
            signals_used = [
                "Provisioning state is 'succeeded'",
                "Service status is 'running'",
                f"Supported dedicated billable SKU confirmed: '{sku_name}'",
                f"Service age is {age_days} days (>= {_MIN_AGE_DAYS} days)",
                f"replica_count={replica_count}, partition_count={partition_count} confirmed",
                (
                    f"All required object surfaces confirmed empty with full pagination exhaustion "
                    f"({', '.join(k for k, _ in _REQUIRED_SURFACES)})"
                ),
                (
                    f"All required activity metrics resolved to zero over {_IDLE_WINDOW_DAYS} days "
                    f"with >= {int(_MIN_COVERAGE * 100)}% daily-bucket coverage "
                    f"({', '.join(m for m, _ in _REQUIRED_METRICS)})"
                ),
            ]

            findings.append(
                Finding(
                    provider="azure",
                    rule_id=_RULE_ID,
                    resource_type=_RESOURCE_TYPE,
                    resource_id=svc_id,
                    region=location,
                    estimated_monthly_cost_usd=None,  # spec 10: always None
                    title=f"Idle Azure AI Search Service: {svc_name}",
                    summary=(
                        f"Azure AI Search service '{svc_name}' ({sku_name}) is structurally "
                        f"empty and has no documented activity over {_IDLE_WINDOW_DAYS} days"
                    ),
                    reason=(
                        f"No configured search objects and no query, indexing, or skill activity "
                        f"over {_IDLE_WINDOW_DAYS} days; dedicated service continues to incur cost"
                    ),
                    risk=RiskLevel.MEDIUM,  # spec 11.1: always MEDIUM
                    confidence=ConfidenceLevel.HIGH,  # spec 11.1: always HIGH
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=[
                            "Future go-live or migration intent",
                            "Business-owner intent not visible in Azure control plane",
                            "Premium-feature billing not inferable from baseline surfaces",
                        ],
                        time_window=f"{_IDLE_WINDOW_DAYS} days",
                    ),
                    details={
                        "service_name": svc_name,
                        "resource_group": resource_group,
                        "subscription_id": subscription_id,
                        "sku_name": sku_name,
                        "replica_count": replica_count,
                        "partition_count": partition_count,
                        "hosting_mode": hosting_mode,
                        "status": "running",
                        "provisioning_state": "succeeded",
                        "created_at": created_at.isoformat(),
                        "idle_window_days": _IDLE_WINDOW_DAYS,
                        "object_counts": object_counts,
                        "metrics_used": [m for m, _ in _REQUIRED_METRICS],
                        "tags": tags,
                    },
                )
            )

        except (HttpResponseError, ServiceRequestError, ServiceResponseError):
            continue  # per-service retrieval failure -> skip (spec 12)

    return findings
