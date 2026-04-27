import warnings
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.auth.transport.requests import AuthorizedSession
from google.cloud import monitoring_v3
from google.protobuf import duration_pb2, timestamp_pb2

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "gcp.vertex.featurestore.idle",
    "category": "ai",
    "service": "aiplatform",
    "cost_impact": "high",
}

# Default idle window — 30 days without any online serving requests = confidently idle.
# Longer than other rules because feature stores are sometimes used in periodic batch
# workflows with sparse online inference (e.g., weekly recommendation refreshes).
_DEFAULT_IDLE_DAYS = 30

# Legacy featurestore: cost per Bigtable node (us-central1, on-demand, SSD-backed).
# A fixedNodeCount=1 store bills at $0.27/hr continuously.
_BIGTABLE_NODE_HOURLY_COST = 0.27  # published GCP rate

# New featureOnlineStore (Optimized / BigQuery-backed): no per-node billing;
# costs arise from storage and query compute — conservative flat estimate.
_OPTIMIZED_STORE_MONTHLY_COST = 100.0  # [est] conservative — actual varies by storage/queries

_HOURS_PER_MONTH = 730.0

# Monitoring metric names
_LEGACY_REQUEST_COUNT_METRIC = "aiplatform.googleapis.com/featurestore/online_serving/request_count"
_NEW_REQUEST_COUNT_METRIC = (
    "aiplatform.googleapis.com/featureonlinestore/online_serving/request_count"
)

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

# Feature Store states that indicate the store is active and incurring charges.
# STABLE is the normal operating state for both legacy featurestores and Feature
# Online Stores. UPDATING is excluded — in-flight updates don't indicate idleness.
_ACTIVE_STATES = {"STABLE"}


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


def _age_days(create_str: str, now: datetime) -> Optional[float]:
    """Parse createTime ISO string and return age in days. Returns None on failure."""
    if not create_str:
        return None
    try:
        dt = datetime.fromisoformat(create_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds() / 86400
    except (ValueError, AttributeError):
        return None


def _list_featurestores(session: AuthorizedSession, project_id: str) -> list:
    """List legacy Vertex AI featurestores across all locations.

    Returns only stores with online serving configured (fixedNodeCount > 0 or
    scaling.minNodeCount > 0). Returns [] if the API is not enabled (404).
    Raises PermissionError on 403.

    Tries the locations/- wildcard first; falls back to per-location queries
    when the wildcard returns 400 (not supported by all projects).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate_location(location: str) -> Optional[list]:
        """Paginate one location. Returns None on 400 (unsupported), [] on 404."""
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
            for store in data.get("featurestores", []):
                config = store.get("onlineServingConfig") or {}
                fixed = config.get("fixedNodeCount", 0)
                scaling_min = (config.get("scaling") or {}).get("minNodeCount", 0)
                if fixed > 0 or scaling_min > 0:
                    results.append(store)
            page_token = data.get("nextPageToken")
            if not page_token:
                break
            params["pageToken"] = page_token
        return results

    # Fast path: wildcard covers all regions in one call sequence
    result = _paginate_location("-")
    if result is not None:
        return result

    # Fallback: per-location queries
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
    """List new-generation Vertex AI Feature Online Stores across all locations.

    Returns [] if the API returns 404 (not enabled or no stores). Raises PermissionError on 403.

    Tries the locations/- wildcard first; falls back to per-location queries
    when the wildcard returns 400 (not supported by all projects).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate_location(location: str) -> Optional[list]:
        """Paginate one location. Returns None on 400 (unsupported), [] on 404."""
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

    # Fast path: wildcard covers all regions in one call sequence
    result = _paginate_location("-")
    if result is not None:
        return result

    # Fallback: per-location queries
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


def _fetch_request_counts(
    credentials,
    project_id: str,
    idle_days: int,
    metric: str,
    id_label: str,
) -> dict[str, int]:
    """Fetch total online serving request counts per store over the past idle_days days.

    Returns store_id → total_request_count. Returns {} on any error (monitoring optional).
    """
    try:
        client = monitoring_v3.MetricServiceClient(credentials=credentials)
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=idle_days)
        interval = monitoring_v3.TimeInterval(
            start_time=timestamp_pb2.Timestamp(seconds=int(start.timestamp())),
            end_time=timestamp_pb2.Timestamp(seconds=int(now.timestamp())),
        )
        results = client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": f'metric.type="{metric}"',
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": monitoring_v3.Aggregation(
                    alignment_period=duration_pb2.Duration(seconds=86400),  # 1-day buckets
                    per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
                    cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
                    group_by_fields=[f"resource.labels.{id_label}"],
                ),
            }
        )
        counts: dict[str, int] = {}
        for ts in results:
            store_id = ts.resource.labels.get(id_label, "")
            if not store_id:
                continue
            if not ts.points:
                # No data points — metric exists but no observations in window.
                # Skip rather than treating as zero to avoid HIGH-confidence
                # false positives when telemetry is absent.
                continue
            total = sum(int(p.value.int64_value) for p in ts.points)
            counts[store_id] = counts.get(store_id, 0) + total
        return counts
    except Exception as e:
        warnings.warn(
            f"gcp.vertex.featurestore.idle: monitoring query failed for {metric} "
            f"({type(e).__name__}: {e}) — falling back to age-based detection",
            stacklevel=2,
        )
        return {}


def find_idle_featurestores(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Vertex AI Feature Store online stores with no serving activity for an extended period.

    Legacy featurestores and Bigtable-backed Feature Online Stores incur Bigtable compute
    charges continuously while in STABLE state, regardless of whether any ReadFeatureValues
    requests are made. A single-node legacy store costs ~$197/month; a 3-node HA store
    costs ~$591/month. Optimized (BigQuery-backed) Feature Online Stores incur storage and
    query compute charges instead of per-node billing (~$100+/month estimated).
    These stores are often left running after a project winds down or a model is retired.

    Detection logic:
    - Lists legacy Vertex AI featurestores with online serving configured (fixedNodeCount > 0
      or scaling.minNodeCount > 0) and new-generation Feature Online Stores via the Vertex AI
      REST API (wildcard location with per-region fallback)
    - Queries Cloud Monitoring for total online_serving/request_count over idle_days days
    - Stores with zero requests are flagged as idle (HIGH confidence)
    - If monitoring data is unavailable, stores older than idle_days are flagged
      based on age alone (LOW confidence — heuristic: existence duration only)

    IAM permissions required:
    - aiplatform.featurestores.list (roles/aiplatform.viewer)
    - aiplatform.featureOnlineStores.list (roles/aiplatform.viewer)
    - monitoring.timeSeries.list (roles/monitoring.viewer) — optional; fallback to age
    """
    idle_days = max(1, idle_days)
    session = AuthorizedSession(credentials)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # --- Legacy featurestores ---
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

    legacy_counts = _fetch_request_counts(
        credentials,
        project_id,
        idle_days,
        _LEGACY_REQUEST_COUNT_METRIC,
        "featurestore_id",
    )

    for store in legacy_stores:
        name = store.get("name", "")
        store_id = _parse_resource_id(name)
        region = _parse_location(name) or "unknown"

        if region_filter and not region.startswith(region_filter):
            continue

        state = store.get("state", "")
        if state not in _ACTIVE_STATES:
            continue

        config = store.get("onlineServingConfig") or {}
        fixed_nodes = config.get("fixedNodeCount", 0)
        scaling_min = (config.get("scaling") or {}).get("minNodeCount", 0)
        node_count = fixed_nodes if fixed_nodes > 0 else scaling_min
        is_autoscaled = fixed_nodes == 0 and scaling_min > 0
        hourly = _BIGTABLE_NODE_HOURLY_COST * node_count
        monthly = hourly * _HOURS_PER_MONTH

        create_str = store.get("createTime", "")
        age = _age_days(create_str, now)

        request_count = legacy_counts.get(store_id)

        if request_count is not None:
            if request_count > 0:
                continue  # Active — skip
            confidence = ConfidenceLevel.HIGH
            idle_signal = f"0 ReadFeatureValues requests over {idle_days}d (monitoring confirmed)"
        elif age is not None and age >= idle_days:
            confidence = ConfidenceLevel.LOW
            idle_signal = (
                f"no monitoring data; store has been STABLE for {age:.0f}d "
                f"(heuristic: age only — request activity unknown)"
            )
        else:
            continue

        risk = RiskLevel.HIGH if confidence == ConfidenceLevel.HIGH else RiskLevel.MEDIUM

        display_name = (store.get("displayName") or "").strip() or store_id
        age_str = f"{age:.1f}d" if age is not None else "unknown"

        node_label = (
            f"{node_count} Bigtable node{'s' if node_count != 1 else ''} (autoscaled min)"
            if is_autoscaled
            else f"{node_count} Bigtable node{'s' if node_count != 1 else ''} (fixed)"
        )
        signals = [
            f"Store state: STABLE (billable) — age: {age_str}",
            f"Idle signal: {idle_signal}",
            f"Online serving config: {node_label}",
            f"Burn rate: ~${hourly:.2f}/hr (~${monthly:,.0f}/mo, {node_count} node{'s' if node_count != 1 else ''} × ${_BIGTABLE_NODE_HOURLY_COST}/hr)",
        ]

        not_checked = [
            "Periodic or low-frequency batch workflows that query less often than the idle window",
            "Feature stores accessed by pipelines running on a schedule (e.g. weekly)",
            "Committed use discounts — actual cost may be lower",
            "Stores intentionally kept warm for latency-sensitive cold-start mitigation",
        ]

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=not_checked,
            time_window=f"{idle_days}d",
        )

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.featurestore.idle",
                resource_type="gcp.vertex.featurestore",
                resource_id=name or store_id,
                region=region,
                title=f"Idle Vertex AI Feature Store ({node_count} node{'s' if node_count != 1 else ''})",
                summary=(
                    f"Vertex AI Feature Store '{display_name}' has had no online serving "
                    f"requests for at least {idle_days} days while maintaining "
                    f"{node_count} Bigtable node{'s' if node_count != 1 else ''}, "
                    f"costing ~${hourly:.2f}/hr (~${monthly:,.0f}/mo)."
                ),
                reason=(
                    (
                        f"Feature Store in STABLE state with zero ReadFeatureValues requests "
                        f"for ≥{idle_days} days"
                    )
                    if request_count is not None
                    else (
                        f"Feature Store in STABLE state for ≥{idle_days} days "
                        f"(heuristic: age only — no request data available)"
                    )
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                estimated_monthly_cost_usd=round(monthly, 2),
                details={
                    "store_name": name,
                    "store_id": store_id,
                    "store_type": "legacy_featurestore",
                    "region": region,
                    "bigtable_node_count": node_count,
                    "bigtable_scaling": "autoscaled" if is_autoscaled else "fixed",
                    "age_days": round(age, 1) if age is not None else None,
                    "request_count": request_count,
                    "idle_days_threshold": idle_days,
                    "hourly_cost_usd": round(hourly, 4),
                    "pricing_confidence": "published",
                    "pricing_scope": "us_central1_reference",
                },
            )
        )

    # --- New featureOnlineStores ---
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

    new_counts = _fetch_request_counts(
        credentials,
        project_id,
        idle_days,
        _NEW_REQUEST_COUNT_METRIC,
        "feature_online_store_id",
    )

    for store in new_stores:
        name = store.get("name", "")
        store_id = _parse_resource_id(name)
        region = _parse_location(name) or "unknown"

        if region_filter and not region.startswith(region_filter):
            continue

        state = store.get("state", "")
        if state not in _ACTIVE_STATES:
            continue

        # Determine backing type and cost
        bigtable_config = store.get("bigtable") or {}
        is_optimized = store.get("optimized") is not None
        autoscaling = bigtable_config.get("autoScaling") or {}
        min_nodes = autoscaling.get("minNodeCount", 0)

        if is_optimized:
            # Optimized (BigQuery-backed) — flat estimate; no Bigtable node charges
            hourly = _OPTIMIZED_STORE_MONTHLY_COST / _HOURS_PER_MONTH
            monthly = _OPTIMIZED_STORE_MONTHLY_COST
            backing_label = "Optimized (BigQuery-backed)"
            pricing_confidence = "estimated"
        elif min_nodes > 0:
            hourly = _BIGTABLE_NODE_HOURLY_COST * min_nodes
            monthly = hourly * _HOURS_PER_MONTH
            backing_label = f"{min_nodes} Bigtable node{'s' if min_nodes != 1 else ''} (min)"
            pricing_confidence = "published"
        else:
            # Unknown backing — still STABLE but can't estimate cost accurately
            hourly = _BIGTABLE_NODE_HOURLY_COST  # conservative single-node floor
            monthly = hourly * _HOURS_PER_MONTH
            backing_label = "unknown backing"
            pricing_confidence = "estimated"

        create_str = store.get("createTime", "")
        age = _age_days(create_str, now)

        request_count = new_counts.get(store_id)

        if request_count is not None:
            if request_count > 0:
                continue
            confidence = ConfidenceLevel.HIGH
            idle_signal = f"0 serving requests over {idle_days}d (monitoring confirmed)"
        elif age is not None and age >= idle_days:
            confidence = ConfidenceLevel.LOW
            idle_signal = (
                f"no monitoring data; store has been STABLE for {age:.0f}d "
                f"(heuristic: age only — request activity unknown)"
            )
        else:
            continue

        risk = RiskLevel.HIGH if confidence == ConfidenceLevel.HIGH else RiskLevel.MEDIUM

        display_name = (store.get("displayName") or "").strip() or store_id
        age_str = f"{age:.1f}d" if age is not None else "unknown"

        signals = [
            f"Store state: STABLE (billable) — age: {age_str}",
            f"Idle signal: {idle_signal}",
            f"Backing: {backing_label}",
            f"Burn rate: ~${hourly:.2f}/hr (~${monthly:,.0f}/mo)",
        ]

        not_checked = [
            "Periodic or low-frequency batch workflows that query less often than the idle window",
            "Feature stores accessed by pipelines running on a schedule (e.g. weekly)",
            "Optimized stores — cost estimate is conservative; actual cost depends on storage size and query volume",
            "Committed use discounts — actual cost may be lower",
        ]

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=not_checked,
            time_window=f"{idle_days}d",
        )

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.featurestore.idle",
                resource_type="gcp.vertex.feature_online_store",
                resource_id=name or store_id,
                region=region,
                title=f"Idle Vertex AI Feature Online Store ({backing_label})",
                summary=(
                    f"Vertex AI Feature Online Store '{display_name}' ({backing_label}) "
                    f"has had no serving requests for at least {idle_days} days, "
                    f"costing ~${hourly:.2f}/hr (~${monthly:,.0f}/mo)."
                ),
                reason=(
                    (
                        f"Feature Online Store in STABLE state with zero serving requests "
                        f"for ≥{idle_days} days"
                    )
                    if request_count is not None
                    else (
                        f"Feature Online Store in STABLE state for ≥{idle_days} days "
                        f"(heuristic: age only — no request data available)"
                    )
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                estimated_monthly_cost_usd=round(monthly, 2),
                details={
                    "store_name": name,
                    "store_id": store_id,
                    "store_type": "feature_online_store",
                    "backing": "optimized" if is_optimized else "bigtable",
                    "region": region,
                    "bigtable_min_nodes": min_nodes if not is_optimized else None,
                    "age_days": round(age, 1) if age is not None else None,
                    "request_count": request_count,
                    "idle_days_threshold": idle_days,
                    "hourly_cost_usd": round(hourly, 4),
                    "pricing_confidence": pricing_confidence,
                    "pricing_scope": "us_central1_reference",
                },
            )
        )

    return findings
