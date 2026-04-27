"""
Rule: gcp.vertex.featurestore.idle

    (spec — docs/specs/gcp/ai/featurestore_idle.md)

Intent:
    Detect Vertex AI feature serving stores with documented, provisioned
    online-serving capacity that show no documented online-serving
    request-count telemetry over a conservative review window.

    This is a conservative review-candidate rule only. It is not proof that
    a store is safe to delete, not proof that offline feature workflows are
    unused, and not proof of a specific monthly saving.

Covered resource families:
    - Vertex AI Feature Store (Legacy) Featurestore (spec 9.1)
    - Vertex AI Feature Online Store with Bigtable online serving (spec 9.2)

Exclusions:
    - resource name malformed or store ID / region absent (spec 7)
    - region filter set and region does not exactly match (spec 4.4)
    - state not exactly STABLE (spec 9.1.2, 9.2.2)
    - reference_time absent, unparsable, or in the future (spec 7)
    - store younger than full observation window (spec 4.7)
    - legacy: fixedNodeCount == 0 and no valid scaling.minNodeCount (spec 9.3)
    - legacy: both fixedNodeCount and scaling.minNodeCount materially present — invalid mode (spec 7)
    - FeatureOnlineStore: storage type not exactly Bigtable (spec 9.2.5, 9.3)
    - FeatureOnlineStore: bigtable.autoScaling absent, unusable, or maxNodeCount < minNodeCount (spec 7)
    - metric coverage unresolved — not exactly idle_days aligned daily buckets (spec 8.4)
    - aggregate request count > 0 (spec 9.1.7, 9.2.8)

Detection (legacy Featurestore):
    - state == "STABLE"
    - legacy_online_serving_mode is "fixed" or "autoscaled"
    - reference_time_utc <= evaluation_window_start_utc
    - metric_coverage_state == "full_window" and telemetry_state == "confirmed_zero"

Detection (Bigtable-backed FeatureOnlineStore):
    - state == "STABLE"
    - storage type is Bigtable (bigtable key present, optimized key absent)
    - bigtable_min_node_count >= 1 and bigtable_max_node_count >= bigtable_min_node_count
    - reference_time_utc <= evaluation_window_start_utc
    - metric_coverage_state == "full_window" and telemetry_state == "confirmed_zero"

Cost model (spec 3.5, 10.1):
    estimated_monthly_cost_usd = None
    Pricing varies by backing, region, node count, and commitment model;
    no flat estimate is appropriate.

APIs:
    - aiplatform.googleapis.com/v1: projects/{project}/locations/{loc}/featurestores
    - aiplatform.googleapis.com/v1: projects/{project}/locations/{loc}/featureOnlineStores
    - monitoring.googleapis.com: aiplatform.googleapis.com/featurestore/online_serving/request_count
    - monitoring.googleapis.com: aiplatform.googleapis.com/featureonlinestore/online_serving/request_count
"""

import warnings
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.api import metric_pb2
from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import duration_pb2, timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Integer sentinel for DELTA metric kind (google.api.metric_pb2.MetricDescriptor.MetricKind.DELTA)
_METRIC_KIND_DELTA: int = int(metric_pb2.MetricDescriptor.MetricKind.DELTA)

RULE_METADATA = {
    "id": "gcp.vertex.featurestore.idle",
    "category": "ai",
    "service": "aiplatform",
    "cost_impact": "high",
}

# Default idle window (spec 6.3)
_DEFAULT_IDLE_DAYS = 30

# Canonical alignment period: one full UTC day (spec 8.3)
_ALIGNMENT_PERIOD_SECONDS = 86400

# Monitoring metric types (spec 8.1)
_LEGACY_METRIC = "aiplatform.googleapis.com/featurestore/online_serving/request_count"
_NEW_METRIC = "aiplatform.googleapis.com/featureonlinestore/online_serving/request_count"

# Monitored resource types (spec 8.1)
_LEGACY_RESOURCE_TYPE = "aiplatform.googleapis.com/Featurestore"
_NEW_RESOURCE_TYPE = "aiplatform.googleapis.com/FeatureOnlineStore"

# Resource ID labels on the monitored resource (spec 8.1)
_LEGACY_ID_LABEL = "featurestore_id"
_NEW_ID_LABEL = "feature_online_store_id"

# Known Vertex AI Feature Store locations. Used as fallback when the locations/-
# wildcard returns 400 (Feature Store APIs do not support the wildcard in all projects).
_FEATURESTORE_LOCATIONS = [
    "global",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west4",
    "northamerica-northeast1",
    "southamerica-east1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-north1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast3",
    "asia-south1",
    "asia-southeast1",
    "australia-southeast1",
    "me-west1",
]


def _parse_location(name: str) -> Optional[str]:
    """Extract region from resource name: projects/.../locations/{region}/..."""
    parts = name.split("/")
    try:
        return parts[parts.index("locations") + 1]
    except (ValueError, IndexError):
        return None


def _parse_resource_id(name: str) -> str:
    """Extract the last segment from a resource name."""
    return name.rsplit("/", 1)[-1] if name else ""


def _parse_rfc3339(ts: str) -> Optional[datetime]:
    """Parse an RFC3339 timestamp, normalize to UTC-aware datetime, or return None."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        # spec 7: all timestamps must be normalized to timezone-aware UTC before comparison
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def _resolve_reference_time(create_str: str, update_str: str, now: datetime) -> Optional[datetime]:
    """
    Resolve reference_time_utc = max(createTime, updateTime) (spec 7).

    Future timestamps are discarded before the max. Returns None when neither
    timestamp is parseable or both resolve to future values.
    """
    create_time = _parse_rfc3339(create_str)
    update_time = _parse_rfc3339(update_str)

    if create_time and create_time > now:
        create_time = None
    if update_time and update_time > now:
        update_time = None

    if create_time and update_time:
        return max(create_time, update_time)
    return create_time or update_time


def _query_store_activity(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    store_id: str,
    region: str,
    metric_type: str,
    resource_type: str,
    id_label: str,
    window_start: datetime,
    window_end: datetime,
    idle_days: int,
) -> str:
    """
    Query the canonical request-count metric for a single store over the full window.

    Applies the exact filter required by spec 8.2: metric.type, resource.type,
    resource.labels.location, and the family-specific store ID label.

    Validates coverage per spec 8.4:
    - exactly one reduced series must remain
    - exactly idle_days aligned daily datapoints
    - each datapoint has a valid numeric value and no future timestamp
    - no gap between adjacent datapoints exceeds the alignment period

    Returns:
        "confirmed_zero"    — full window, exactly idle_days buckets, total == 0
        "positive_activity" — full coverage and aggregate total > 0
        "unresolved"        — any coverage constraint violated

    Raises:
        Any exception from the Monitoring RPC layer (network, permission, etc.)
        propagates to the caller so it can surface family-level visibility (spec 11.4).
    """
    start_ts = timestamp_pb2.Timestamp()
    start_ts.FromDatetime(window_start)
    end_ts = timestamp_pb2.Timestamp()
    end_ts.FromDatetime(window_end)

    interval = monitoring_v3.TimeInterval(start_time=start_ts, end_time=end_ts)

    # spec 8.2: exact filter on all four required dimensions
    filter_str = (
        f'metric.type="{metric_type}"'
        f' AND resource.type="{resource_type}"'
        f' AND resource.labels.location="{region}"'
        f' AND resource.labels.{id_label}="{store_id}"'
    )

    results = list(
        client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": monitoring_v3.Aggregation(
                    alignment_period=duration_pb2.Duration(seconds=_ALIGNMENT_PERIOD_SECONDS),
                    per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
                    cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
                    group_by_fields=[f"resource.labels.{id_label}"],
                ),
            }
        )
    )

    # spec 8.4 point 1: exactly 1 reduced series
    if len(results) != 1:
        return "unresolved"

    # spec 8.3 point 5: metric kind must resolve to DELTA
    if results[0].metric_kind != _METRIC_KIND_DELTA:
        return "unresolved"

    points = list(results[0].points)

    # spec 8.4 point 2: exactly idle_days aligned datapoints
    if len(points) != idle_days:
        return "unresolved"

    # spec 8.4 point 3: pre-compute expected daily bucket end times as whole-second Unix
    # timestamps. Cloud Monitoring returns ts.seconds with nanos=0; comparing against
    # datetime objects derived from a sub-second-precise window_start would cause spurious
    # mismatches. Integer-second comparison is both correct and tolerant of tiny variance.
    _ws_secs = int(window_start.timestamp())
    expected_bucket_end_seconds: frozenset = frozenset(
        _ws_secs + n * _ALIGNMENT_PERIOD_SECONDS for n in range(1, idle_days + 1)
    )

    total = 0.0
    timestamps = []
    seen_bucket_seconds: set = set()

    for point in points:
        # spec 8.4 point 3/4: each point must map to exactly one documented bucket end
        try:
            ts = point.interval.end_time
            point_dt = datetime.fromtimestamp(ts.seconds + ts.nanos / 1e9, tz=timezone.utc)
            # whole-second membership check; duplicate seconds → same bucket twice
            if ts.seconds not in expected_bucket_end_seconds or ts.seconds in seen_bucket_seconds:
                return "unresolved"
            seen_bucket_seconds.add(ts.seconds)
            timestamps.append(point_dt)
        except Exception:
            return "unresolved"

        # spec 8.4 point 5: valid numeric value — WhichOneof dispatch (0 is falsy)
        which = point.value.WhichOneof("value")
        if which == "int64_value":
            val = float(point.value.int64_value)
        elif which == "double_value":
            val = float(point.value.double_value)
        else:
            return "unresolved"

        total += val

    # spec 8.4 point 6: no gap between adjacent points exceeds alignment period
    timestamps.sort()
    for i in range(1, len(timestamps)):
        if (timestamps[i] - timestamps[i - 1]).total_seconds() > _ALIGNMENT_PERIOD_SECONDS:
            return "unresolved"

    return "confirmed_zero" if total == 0.0 else "positive_activity"


def _list_featurestores(session: AuthorizedSession, project_id: str) -> list:
    """
    List legacy Vertex AI featurestores across all locations.

    Returns all stores (filtering by online-serving capacity happens in the caller).
    Returns [] if the API is not enabled (404). Raises PermissionError on 403.

    Tries the locations/- wildcard first; falls back to per-location queries
    when the wildcard returns 400 (not supported by all projects).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate_location(location: str) -> Optional[list]:
        results = []
        params: dict = {"pageSize": 100}
        while True:
            resp = session.get(f"{base_url}/{location}/featurestores", params=params)
            if resp.status_code == 403:
                raise PermissionError(
                    f"aiplatform.featurestores.list permission denied for project {project_id}. "
                    "Grant roles/aiplatform.viewer to the scanning identity."
                )
            if resp.status_code == 404:
                return []
            if resp.status_code == 400:
                return None  # wildcard unsupported — signal caller to try per-location
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("featurestores", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
            params["pageToken"] = page_token
        return results

    result = _paginate_location("-")
    if result is not None:
        return result

    stores: list = []
    seen: set = set()
    for location in _FEATURESTORE_LOCATIONS:
        loc_result = _paginate_location(location)
        if loc_result is None:
            continue
        for store in loc_result:
            name = store.get("name", "")
            if name and name not in seen:
                seen.add(name)
                stores.append(store)
    return stores


def _list_feature_online_stores(session: AuthorizedSession, project_id: str) -> list:
    """
    List Vertex AI Feature Online Stores across all locations.

    Returns all stores (filtering by storage type happens in the caller).
    Returns [] if the API returns 404 (not enabled or no stores).
    Raises PermissionError on 403.

    Tries the locations/- wildcard first; falls back to per-location queries
    when the wildcard returns 400.
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate_location(location: str) -> Optional[list]:
        results = []
        params: dict = {"pageSize": 100}
        while True:
            resp = session.get(f"{base_url}/{location}/featureOnlineStores", params=params)
            if resp.status_code == 403:
                raise PermissionError(
                    f"aiplatform.featureOnlineStores.list permission denied for project {project_id}. "
                    "Grant roles/aiplatform.viewer to the scanning identity."
                )
            if resp.status_code == 404:
                return []
            if resp.status_code == 400:
                return None  # wildcard unsupported — signal caller to try per-location
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("featureOnlineStores", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
            params["pageToken"] = page_token
        return results

    result = _paginate_location("-")
    if result is not None:
        return result

    stores: list = []
    seen: set = set()
    for location in _FEATURESTORE_LOCATIONS:
        loc_result = _paginate_location(location)
        if loc_result is None:
            continue
        for store in loc_result:
            name = store.get("name", "")
            if name and name not in seen:
                seen.add(name)
                stores.append(store)
    return stores


def find_idle_featurestores(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Vertex AI feature stores with zero online-serving requests for idle_days days.

    Emits findings only when documented provisioned online-serving capacity is present
    and the canonical request-count metric confirms exactly zero activity for the full
    aligned observation window (exactly idle_days daily aligned buckets, spec 8.4).

    No age-only or monitoring-absent fallback is used (spec 8.5).

    IAM permissions required:
    - aiplatform.featurestores.list (roles/aiplatform.viewer)
    - aiplatform.featureOnlineStores.list (roles/aiplatform.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer)
    """
    idle_days = max(1, idle_days)
    session = AuthorizedSession(credentials)
    # Truncate to whole seconds so window boundaries are exact UTC instants with no
    # sub-second component. This ensures int(window_start.timestamp()) is lossless and
    # bucket boundaries in _query_store_activity match the spec's exact definition.
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # spec 6.3 / 2.1: evaluation window
    window_end = now
    window_start = window_end - timedelta(seconds=idle_days * _ALIGNMENT_PERIOD_SECONDS)

    findings: List[Finding] = []

    # Create monitoring client once; skip all per-store queries if creation fails.
    # Emit a warning so the failure is operationally visible (spec 11.4).
    try:
        monitoring_client: Optional[monitoring_v3.MetricServiceClient] = (
            monitoring_v3.MetricServiceClient(credentials=credentials)
        )
    except Exception as e:
        warnings.warn(
            f"gcp.vertex.featurestore.idle: monitoring client creation failed "
            f"({type(e).__name__}: {e}) — all stores will be skipped (no age-only fallback)",
            UserWarning,
            stacklevel=2,
        )
        monitoring_client = None

    # -------------------------------------------------------------------------
    # Legacy featurestores (spec 9.1)
    # -------------------------------------------------------------------------
    legacy_stores: list = []
    try:
        legacy_stores = _list_featurestores(session, project_id)
    except PermissionError:
        raise
    except Exception as e:
        warnings.warn(
            f"gcp.vertex.featurestore.idle: featurestores listing failed "
            f"({type(e).__name__}: {e}) — legacy stores may be incomplete",
            stacklevel=2,
        )

    for store in legacy_stores:
        # spec 7: resource name and store ID must be present
        name = store.get("name", "")
        if not name:
            continue
        store_id = _parse_resource_id(name)
        if not store_id:
            continue

        # spec 7: region must be parseable from the resource name
        region = _parse_location(name)
        if not region:
            continue

        # spec 4.4: exact region filter match
        if region_filter and region != region_filter:
            continue

        # spec 9.1.2: only STABLE state
        if store.get("state") != "STABLE":
            continue

        # spec 7: reference_time = max(createTime, updateTime)
        reference_time = _resolve_reference_time(
            store.get("createTime", ""), store.get("updateTime", ""), now
        )
        if reference_time is None:
            continue

        # spec 4.7: full observation window must be coverable
        if reference_time > window_start:
            continue

        # spec 7: resolve legacy_online_serving_mode — malformed config skips (spec 11.3)
        try:
            config = store.get("onlineServingConfig") or {}
            fixed_nodes = int(config.get("fixedNodeCount") or 0)
            scaling = config.get("scaling") or {}
            scaling_min = int(scaling.get("minNodeCount") or 0)
        except (TypeError, ValueError, AttributeError):
            continue

        if fixed_nodes > 0 and scaling_min > 0:
            # spec 7: invalid mode — both materially present
            continue
        elif fixed_nodes > 0:
            serving_mode = "fixed"
            provisioned_nodes = fixed_nodes
        elif scaling_min > 0:
            serving_mode = "autoscaled"
            provisioned_nodes = scaling_min
        else:
            # no provisioned online-serving capacity
            continue

        # spec 8.5: no age-only or monitoring-absent fallback
        if monitoring_client is None:
            continue

        # spec 8.2–8.4: per-store monitoring query with full coverage validation.
        # RPC/network failures propagate as a warning and skip the store (spec 11.4).
        try:
            telemetry = _query_store_activity(
                monitoring_client,
                project_id,
                store_id,
                region,
                _LEGACY_METRIC,
                _LEGACY_RESOURCE_TYPE,
                _LEGACY_ID_LABEL,
                window_start,
                window_end,
                idle_days,
            )
        except Exception as e:
            warnings.warn(
                f"gcp.vertex.featurestore.idle: monitoring query failed for "
                f"legacy store '{store_id}' ({type(e).__name__}: {e})",
                UserWarning,
                stacklevel=2,
            )
            continue

        if telemetry != "confirmed_zero":
            continue  # positive_activity or unresolved — neither emits

        # --- All conditions met: emit finding ---

        signals_used = [
            "Resource family: Vertex AI Feature Store (Legacy)",
            "State: STABLE",
            f"Region: {region}",
            f"Reference time (max(createTime, updateTime)): {reference_time.isoformat()}",
            f"Idle window: {idle_days} days (full window, exactly {idle_days} aligned daily buckets confirmed)",
            f"Serving mode: {serving_mode}, provisioned node floor: {provisioned_nodes}",
            f"Metric: {_LEGACY_METRIC}",
            "Aggregate request count over full window: 0",
        ]

        signals_not_checked = [
            "Periodic or low-frequency batch workflows with access frequency below the idle window",
            "Feature stores accessed by scheduled pipelines (e.g. weekly jobs)",
            "Offline feature generation, sync, or BigQuery-backed workflows",
            "Stores intentionally kept warm for latency-sensitive cold-start mitigation",
        ]

        details: dict = {
            "store_name": name,
            "store_id": store_id,
            "store_family": "legacy_featurestore",
            "state": "STABLE",
            "region": region,
            "reference_time": reference_time.isoformat(),
            "idle_days_threshold": idle_days,
            "legacy_serving_mode": serving_mode,
            "provisioned_node_floor": provisioned_nodes,
            "metric_type": _LEGACY_METRIC,
            "metric_coverage_state": "full_window",
            "telemetry_state": "confirmed_zero",
            "request_count_total": 0,
        }
        if serving_mode == "fixed":
            details["fixed_node_count"] = fixed_nodes
        else:
            details["scaling_min_node_count"] = scaling_min

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.featurestore.idle",
                resource_type="gcp.vertex.featurestore",
                resource_id=name,
                region=region,
                title=(
                    f"Idle Vertex AI Feature Store (Legacy, "
                    f"{provisioned_nodes} node{'s' if provisioned_nodes != 1 else ''})"
                ),
                summary=(
                    f"Legacy Vertex AI Feature Store '{store_id}' ({serving_mode}, "
                    f"{provisioned_nodes} node{'s' if provisioned_nodes != 1 else ''}) "
                    f"in region '{region}' shows zero online-serving requests "
                    f"over {idle_days} days."
                ),
                reason=(
                    f"Aggregate online-serving request count == 0 over the {idle_days}-day "
                    f"observation window ({_LEGACY_METRIC})"
                ),
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals_used,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                ),
                details=details,
                # spec 10.1: always None — pricing varies by backing, region, and commitment
                estimated_monthly_cost_usd=None,
            )
        )

    # -------------------------------------------------------------------------
    # Bigtable-backed FeatureOnlineStores (spec 9.2)
    # -------------------------------------------------------------------------
    new_stores: list = []
    try:
        new_stores = _list_feature_online_stores(session, project_id)
    except PermissionError:
        raise
    except Exception as e:
        warnings.warn(
            f"gcp.vertex.featurestore.idle: featureOnlineStores listing failed "
            f"({type(e).__name__}: {e}) — new stores may be incomplete",
            stacklevel=2,
        )

    for store in new_stores:
        # spec 7: resource name and store ID must be present
        name = store.get("name", "")
        if not name:
            continue
        store_id = _parse_resource_id(name)
        if not store_id:
            continue

        # spec 7: region must be parseable from the resource name
        region = _parse_location(name)
        if not region:
            continue

        # spec 4.4: exact region filter match
        if region_filter and region != region_filter:
            continue

        # spec 9.2.2: only STABLE state
        if store.get("state") != "STABLE":
            continue

        # spec 7: reference_time = max(createTime, updateTime)
        reference_time = _resolve_reference_time(
            store.get("createTime", ""), store.get("updateTime", ""), now
        )
        if reference_time is None:
            continue

        # spec 4.7: full observation window must be coverable
        if reference_time > window_start:
            continue

        # spec 9.2.5, 9.3: storage type must be exactly Bigtable; optimized is out of scope
        has_bigtable = "bigtable" in store
        has_optimized = "optimized" in store

        if not has_bigtable or has_optimized:
            # neither-present or both-present → unusable union; optimized → out of scope
            continue

        # spec 7: bigtable.autoScaling must be present and structurally usable (spec 11.3)
        try:
            bigtable_config = store.get("bigtable") or {}
            autoscaling = bigtable_config.get("autoScaling")
            if not autoscaling:
                continue
            min_nodes = int(autoscaling.get("minNodeCount") or 0)
            max_nodes = int(autoscaling.get("maxNodeCount") or 0)
        except (TypeError, ValueError, AttributeError):
            continue

        # spec 7: min >= 1 and max >= min
        if min_nodes < 1 or max_nodes < min_nodes:
            continue

        # spec 8.5: no age-only or monitoring-absent fallback
        if monitoring_client is None:
            continue

        # spec 8.2–8.4: per-store monitoring query with full coverage validation.
        # RPC/network failures propagate as a warning and skip the store (spec 11.4).
        try:
            telemetry = _query_store_activity(
                monitoring_client,
                project_id,
                store_id,
                region,
                _NEW_METRIC,
                _NEW_RESOURCE_TYPE,
                _NEW_ID_LABEL,
                window_start,
                window_end,
                idle_days,
            )
        except Exception as e:
            warnings.warn(
                f"gcp.vertex.featurestore.idle: monitoring query failed for "
                f"feature online store '{store_id}' ({type(e).__name__}: {e})",
                UserWarning,
                stacklevel=2,
            )
            continue

        if telemetry != "confirmed_zero":
            continue  # positive_activity or unresolved — neither emits

        # --- All conditions met: emit finding ---

        signals_used = [
            "Resource family: Vertex AI Feature Online Store (Bigtable-backed)",
            "State: STABLE",
            f"Region: {region}",
            f"Reference time (max(createTime, updateTime)): {reference_time.isoformat()}",
            f"Idle window: {idle_days} days (full window, exactly {idle_days} aligned daily buckets confirmed)",
            f"Bigtable autoscaling: minNodeCount={min_nodes}, maxNodeCount={max_nodes}",
            f"Metric: {_NEW_METRIC}",
            "Aggregate request count over full window: 0",
        ]

        signals_not_checked = [
            "Periodic or low-frequency batch workflows with access frequency below the idle window",
            "Feature stores accessed by scheduled pipelines (e.g. weekly jobs)",
            "Offline feature generation, sync, or BigQuery-backed workflows",
            "Stores intentionally kept warm for latency-sensitive cold-start mitigation",
        ]

        details: dict = {
            "store_name": name,
            "store_id": store_id,
            "store_family": "feature_online_store",
            "state": "STABLE",
            "region": region,
            "reference_time": reference_time.isoformat(),
            "idle_days_threshold": idle_days,
            "storage_type": "bigtable",
            "bigtable_min_node_count": min_nodes,
            "bigtable_max_node_count": max_nodes,
            "metric_type": _NEW_METRIC,
            "metric_coverage_state": "full_window",
            "telemetry_state": "confirmed_zero",
            "request_count_total": 0,
        }

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.featurestore.idle",
                resource_type="gcp.vertex.feature_online_store",
                resource_id=name,
                region=region,
                title=(
                    f"Idle Vertex AI Feature Online Store "
                    f"(Bigtable, min {min_nodes} node{'s' if min_nodes != 1 else ''})"
                ),
                summary=(
                    f"Vertex AI Feature Online Store '{store_id}' "
                    f"(Bigtable, min {min_nodes} node{'s' if min_nodes != 1 else ''}) "
                    f"in region '{region}' shows zero online-serving requests "
                    f"over {idle_days} days."
                ),
                reason=(
                    f"Aggregate online-serving request count == 0 over the {idle_days}-day "
                    f"observation window ({_NEW_METRIC})"
                ),
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals_used,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                ),
                details=details,
                # spec 10.1: always None — pricing varies by backing, region, and commitment
                estimated_monthly_cost_usd=None,
            )
        )

    return findings


find_idle_featurestores.RULE_ID = "gcp.vertex.featurestore.idle"
