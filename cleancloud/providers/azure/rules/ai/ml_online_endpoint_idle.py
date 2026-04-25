"""
Rule: azure.ml.online_endpoint.idle

Intent:
    Detect Azure Machine Learning managed online endpoints that retain billable
    deployment baseline instances while RequestsPerMinute stays at zero over a
    documented observation window.

    This rule is deliberately precision-first. It is not a generic "quiet workspace"
    rule, not proof that deleting an endpoint is safe, and not proof of a specific
    monthly saving. It is a conservative review-candidate rule for managed online
    endpoints that appear to be continuously provisioned but unused.

Exclusions (spec 8):
    - endpoint.id absent or empty
    - endpoint.name absent or empty
    - workspace.name absent or empty
    - region filter set and normalized endpoint location does not match
    - managed scope not established per spec 9.1
    - provisioning_state != "Succeeded" (exact case-sensitive)
    - created_at absent, invalid, in the future, or age < effective idle_days
    - deployment inventory cannot be resolved (listing fails)
    - no stable deployment with a known positive baseline instance count
    - RequestsPerMinute metric result is not ZERO per spec 9.5

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)

APIs:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read
    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read
    - Microsoft.Insights/metrics/read
"""

from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

from azure.core.exceptions import HttpResponseError
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.ml.online_endpoint.idle"
_RESOURCE_TYPE = "azure.ml.online_endpoint"
_DEFAULT_IDLE_DAYS = 7

RULE_METADATA = {
    "id": _RULE_ID,
    "category": "ai",
    "service": "machinelearningservices",
    "cost_impact": "high",
}

# GPU VM size prefixes — uppercase-normalized exact prefix matching (spec 7, 9.4)
_GPU_VM_PREFIXES = ("STANDARD_NC", "STANDARD_ND", "STANDARD_NV")

_METRIC_NAME = "RequestsPerMinute"
_METRIC_AGGREGATION = "Average"
_METRIC_INTERVAL = "PT1M"

_COVERAGE_ACCEPTABLE = 0.80  # minimum coverage for acceptable ZERO result
_COVERAGE_HIGH = 0.95  # coverage threshold for HIGH confidence


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec 7 (spaces and hyphens preserved)."""
    return s.lower() if s else ""


def _extract_resource_group(resource_id: Optional[str]) -> Optional[str]:
    """Extract resource group name from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


def _parse_utc_timestamp(raw) -> Optional[datetime]:
    """
    Parse raw timestamp to UTC-normalized datetime.
    Naive datetimes are treated as UTC; aware non-UTC datetimes are converted to UTC.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.rstrip("Z"))
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _is_gpu(instance_type: Optional[str]) -> bool:
    """GPU classification: uppercase-normalized exact prefix matching (spec 7, 9.4)."""
    if not instance_type:
        return False
    return any(instance_type.upper().startswith(p) for p in _GPU_VM_PREFIXES)


# ---------------------------------------------------------------------------
# Managed scope resolution (spec 9.1)
# ---------------------------------------------------------------------------


def _endpoint_scope_signal(endpoint) -> str:
    """
    Resolve endpoint-level managed/kubernetes scope signal from documented
    endpoint class name or kind attribute (spec 9.1.1).
    Returns: "managed", "kubernetes", or "unknown".
    """
    cls_name = type(endpoint).__name__
    if cls_name == "ManagedOnlineEndpoint":
        return "managed"
    if cls_name == "KubernetesOnlineEndpoint":
        return "kubernetes"

    kind = getattr(endpoint, "kind", None)
    if isinstance(kind, str):
        k = kind.lower()
        if k == "managed":
            return "managed"
        if k == "kubernetes":
            return "kubernetes"

    return "unknown"


def _deployment_scope_signal(deployment) -> str:
    """
    Resolve deployment-level managed/kubernetes scope hint from documented
    deployment class name (spec 9.1.2).
    Returns: "managed", "kubernetes", or "unknown".
    """
    cls_name = type(deployment).__name__
    if cls_name == "ManagedOnlineDeployment":
        return "managed"
    if cls_name == "KubernetesOnlineDeployment":
        return "kubernetes"
    return "unknown"


def _resolve_managed_scope(endpoint, stable_deployments: List) -> Tuple[bool, str]:
    """
    Resolve managed scope per spec 9.1 strict priority rules.
    Returns (is_managed: bool, managed_scope_source: str).
    managed_scope_source: "endpoint", "deployment", or "none".
    """
    ep_signal = _endpoint_scope_signal(endpoint)

    # Priority 1: endpoint-level explicit Kubernetes -> out of scope (spec 9.1.5.i)
    if ep_signal == "kubernetes":
        return (False, "none")

    # Collect deployment-level scope hints from stable deployments
    dep_signals = [_deployment_scope_signal(d) for d in stable_deployments]
    dep_has_managed = any(s == "managed" for s in dep_signals)
    dep_has_kubernetes = any(s == "kubernetes" for s in dep_signals)

    # Priority 2: endpoint-level explicit managed (spec 9.1.5.ii)
    if ep_signal == "managed":
        # If any stable deployment explicitly identifies Kubernetes -> conflict -> skip (spec 9.1.6)
        if dep_has_kubernetes:
            return (False, "none")
        return (True, "endpoint")

    # Priority 3: no endpoint-level signal; stable-deployment explicit managed (spec 9.1.5.iii)
    if dep_has_managed and not dep_has_kubernetes:
        return (True, "deployment")

    # Priority 4: out of scope (spec 9.1.5.iv)
    return (False, "none")


# ---------------------------------------------------------------------------
# Traffic metric (spec 9.5)
# ---------------------------------------------------------------------------


def _query_requests_per_minute(
    monitor_client: Any,
    endpoint_id: str,
    effective_idle_days: int,
) -> Tuple[str, Optional[float]]:
    """
    Query RequestsPerMinute on the endpoint ARM resource id (spec 9.5).

    Returns:
      ("ZERO", coverage_ratio)  when coverage >= 80% and every usable bucket Average == 0
      ("ACTIVE", None)          when any usable bucket has Average > 0
      ("UNKNOWN", None)         on query failure, no usable data, or coverage < 80%
    """
    now_utc = datetime.now(timezone.utc)
    # floor_to_minute(now_utc - 5 minutes) per spec 9.5
    raw_end = now_utc - timedelta(minutes=5)
    metric_end_utc = raw_end.replace(second=0, microsecond=0)
    window_start_utc = metric_end_utc - timedelta(days=effective_idle_days)

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start_utc.strftime(fmt)}/{metric_end_utc.strftime(fmt)}"

    # Expected complete minute buckets in [window_start_utc, metric_end_utc)
    expected_buckets = int((metric_end_utc - window_start_utc).total_seconds() // 60)
    if expected_buckets <= 0:
        return ("UNKNOWN", None)

    try:
        response = monitor_client.metrics.list(
            endpoint_id,
            metricnames=_METRIC_NAME,
            timespan=timespan,
            interval=_METRIC_INTERVAL,
            aggregation=_METRIC_AGGREGATION,
        )
    except PermissionError:
        raise
    except HttpResponseError as exc:
        if exc.status_code in (401, 403):
            raise PermissionError(
                "Missing required permissions: Microsoft.Insights/metrics/read"
            ) from exc
        return ("UNKNOWN", None)
    except Exception:
        return ("UNKNOWN", None)

    # Count unique complete minute buckets inside [window_start_utc, metric_end_utc).
    # A usable datapoint must have a parseable UTC timestamp within the window (spec 9.5).
    # Deduplication by bucket prevents duplicate or overlapping series from overstating coverage.
    usable_buckets: set = set()

    for metric in response.value or []:
        for ts in getattr(metric, "timeseries", None) or []:
            for point in getattr(ts, "data", None) or []:
                avg = getattr(point, "average", None)
                if avg is None:
                    continue

                # Resolve and parse the datapoint timestamp
                raw_ts = getattr(point, "time_stamp", None)
                if raw_ts is None:
                    raw_ts = getattr(point, "timestamp", None)
                pt_utc = _parse_utc_timestamp(raw_ts)
                if pt_utc is None:
                    continue  # unparseable timestamp -> not a usable datapoint (spec 9.5)

                # Floor to the minute to identify the complete minute bucket
                bucket = pt_utc.replace(second=0, microsecond=0)

                # Must be within [window_start_utc, metric_end_utc) (spec 9.5.3)
                if bucket < window_start_utc or bucket >= metric_end_utc:
                    continue  # out-of-window -> skip

                usable_buckets.add(bucket)
                if avg > 0:
                    return ("ACTIVE", None)

    coverage_ratio = len(usable_buckets) / expected_buckets
    if coverage_ratio < _COVERAGE_ACCEPTABLE:
        return ("UNKNOWN", None)

    return ("ZERO", coverage_ratio)


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_ml_online_endpoints(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Azure ML managed online endpoints with zero RequestsPerMinute while
    retaining positive deployment baseline instances.

    Detection logic (spec 4, 8, 9):
    - Managed scope established from documented endpoint/deployment surfaces
    - Endpoint provisioning_state exactly "Succeeded"
    - Endpoint created_at resolves to a known UTC timestamp; age >= effective idle_days
    - At least one stable deployment with a known positive baseline instance count
    - RequestsPerMinute == 0 across the rolling UTC window defined in spec 9.5

    IAM permissions:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read
    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    effective_idle_days = max(idle_days, 1)  # spec 6.3: minimum effective 1

    arm_client = client or AzureMachineLearningWorkspaces(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    def _ws_client(rg: str, ws_name: str) -> Any:
        # Tests inject a single mock client that covers all operations.
        # Production creates a workspace-scoped MLClient for endpoint/deployment ops.
        if client is not None:
            return client
        from azure.ai.ml import MLClient  # noqa: PLC0415

        return MLClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=rg,
            workspace_name=ws_name,
        )

    region_filter_norm = _norm_location(region_filter) if region_filter else None

    # Subscription-wide workspace inventory: propagate if this fails (spec 12)
    for ws in arm_client.workspaces.list_by_subscription():
        # spec 8.3: workspace name guard
        ws_name = getattr(ws, "name", None)
        if not ws_name:
            continue

        # Resolve resource group from workspace
        rg = getattr(ws, "resource_group", None)
        if not rg:
            rg = _extract_resource_group(getattr(ws, "id", None))
        if not rg:
            continue

        try:
            ep_client = _ws_client(rg, ws_name)

            for ep in ep_client.online_endpoints.list():
                try:
                    # spec 8.1: endpoint.id guard
                    ep_id = getattr(ep, "id", None)
                    if not ep_id:
                        continue

                    # spec 8.2: endpoint.name guard
                    ep_name = getattr(ep, "name", None)
                    if not ep_name:
                        continue

                    # Endpoint location (spec 7, 9.2.1: use endpoint resource location, not workspace)
                    location_raw = getattr(ep, "location", None) or ""
                    location_norm = _norm_location(location_raw)
                    if not location_norm:
                        continue  # spec 7: unresolved location -> skip

                    # spec 8.4: region filter — exact lowercase equality
                    if region_filter_norm and location_norm != region_filter_norm:
                        continue

                    # spec 8.6: provisioning_state must be exactly "Succeeded" (case-sensitive)
                    prov_state = getattr(ep, "provisioning_state", None)
                    if prov_state != "Succeeded":
                        continue

                    # spec 8.7 / 9.2: created_at from systemData.createdAt
                    created_at: Optional[datetime] = None
                    sys_data = getattr(ep, "system_data", None) or getattr(ep, "systemData", None)
                    if sys_data is not None:
                        raw_created = getattr(sys_data, "created_at", None)
                        if raw_created is None:
                            raw_created = getattr(sys_data, "createdAt", None)
                        created_at = _parse_utc_timestamp(raw_created)

                    if created_at is None:
                        continue  # spec 8.7: required
                    if created_at > now:
                        continue  # spec 9.2.3: future created_at -> skip
                    age_days = (now - created_at).days
                    if age_days < effective_idle_days:
                        continue  # spec 8.7 / 9.2.4: age gate

                    # spec 8.8: deployment inventory must resolve successfully
                    all_deployments: List = []
                    try:
                        for dep in ep_client.online_deployments.list(ep_name):
                            all_deployments.append(dep)
                    except Exception:
                        continue  # spec 8.8: listing failure -> skip endpoint

                    # Stable deployments: exact provisioning_state == "Succeeded" (spec 9.3.2)
                    stable_deployments = [
                        d
                        for d in all_deployments
                        if getattr(d, "provisioning_state", None) == "Succeeded"
                    ]

                    # spec 8.5: managed scope per spec 9.1
                    is_managed, managed_scope_source = _resolve_managed_scope(
                        ep, stable_deployments
                    )
                    if not is_managed:
                        continue

                    # spec 8.9 / 9.3: billing-relevant deployments
                    billing_relevant_count = 0
                    total_baseline_instances = 0
                    first_instance_type: Optional[str] = None
                    any_gpu = False

                    for dep in stable_deployments:
                        # Baseline instance count resolution order (spec 9.3.4):
                        # scale_settings.min_instances -> instance_count -> unknown
                        scale = getattr(dep, "scale_settings", None)
                        cnt = None
                        if scale is not None:
                            cnt = getattr(scale, "min_instances", None)
                        if cnt is None:
                            cnt = getattr(dep, "instance_count", None)

                        if cnt is None:
                            continue  # unknown -> not billing-relevant (spec 9.3.4-5)
                        try:
                            cnt_int = int(cnt)
                        except (TypeError, ValueError):
                            continue
                        if cnt_int <= 0:
                            continue  # not billing-relevant (spec 9.3.5)

                        billing_relevant_count += 1
                        total_baseline_instances += cnt_int

                        it = getattr(dep, "instance_type", None)
                        if it and first_instance_type is None:
                            first_instance_type = it
                        if it and _is_gpu(it):
                            any_gpu = True

                    if billing_relevant_count == 0:
                        continue  # spec 8.9 / 9.3.6: no billing-relevant deployment

                    # spec 8.10: traffic metric must resolve to ZERO per spec 9.5
                    metric_result, coverage_ratio = _query_requests_per_minute(
                        mon_client, ep_id, effective_idle_days
                    )
                    if metric_result != "ZERO":
                        continue  # ACTIVE or UNKNOWN -> skip (spec 8.10)

                    # spec 9.6: confidence from metric coverage
                    if coverage_ratio >= _COVERAGE_HIGH:
                        confidence = ConfidenceLevel.HIGH
                    else:
                        confidence = ConfidenceLevel.MEDIUM

                    # spec 9.6: risk from GPU presence
                    risk = RiskLevel.HIGH if any_gpu else RiskLevel.MEDIUM

                    # spec 9.5: idle_since_days = effective idle window (not observational estimate)
                    idle_since_days = effective_idle_days

                    # Endpoint kind for details; tags never None in output (spec 7)
                    ep_kind = getattr(ep, "kind", None)
                    tags = getattr(ep, "tags", None) or {}

                    # spec 11.2: signals_used
                    signals_used = [
                        f"Managed scope established from {managed_scope_source} surfaces",
                        "Endpoint provisioning state is 'Succeeded'",
                        (
                            f"Endpoint age is {age_days} days "
                            f"(>= configured idle window of {effective_idle_days} days)"
                        ),
                        (
                            f"{billing_relevant_count} deployment(s) retain positive configured "
                            f"baseline instance count (total: {total_baseline_instances})"
                        ),
                        (
                            f"{_METRIC_NAME} metric result is ZERO with "
                            f">={_COVERAGE_ACCEPTABLE:.0%} coverage "
                            f"across a {effective_idle_days}-day rolling UTC window "
                            f"(coverage: {coverage_ratio:.1%}, aggregation: {_METRIC_AGGREGATION})"
                        ),
                    ]

                    details = {
                        "endpoint_name": ep_name,
                        "workspace_name": ws_name,
                        "resource_group": rg,
                        "subscription_id": subscription_id,
                        "location": location_norm,
                        "endpoint_kind": ep_kind,
                        "managed_scope_source": managed_scope_source,
                        "endpoint_provisioning_state": "Succeeded",
                        "created_at": created_at.isoformat(),
                        "billing_relevant_deployment_count": billing_relevant_count,
                        "deployment_count": len(all_deployments),
                        "stable_deployment_count": len(stable_deployments),
                        "instance_type": first_instance_type,
                        "is_gpu": any_gpu,
                        "baseline_instance_count_total": total_baseline_instances,
                        "idle_days_threshold": effective_idle_days,
                        "idle_since_days": idle_since_days,
                        "metric_name": _METRIC_NAME,
                        "metric_aggregation": _METRIC_AGGREGATION,
                        "metric_coverage_ratio": coverage_ratio,
                        "tags": tags,
                    }

                    title = f"Idle Azure ML Managed Online Endpoint: {ep_name}"
                    summary = (
                        f"Azure ML managed online endpoint '{ep_name}' in workspace '{ws_name}' "
                        f"has received no scoring requests (RequestsPerMinute == 0) for "
                        f"{effective_idle_days} days while retaining "
                        f"{total_baseline_instances} positive baseline deployment instance(s), "
                        f"continuing to incur compute cost."
                    )
                    reason = (
                        f"RequestsPerMinute is zero across a {effective_idle_days}-day rolling "
                        f"window while {billing_relevant_count} deployment(s) retain positive "
                        f"baseline instances"
                    )

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id=_RULE_ID,
                            resource_type=_RESOURCE_TYPE,
                            resource_id=ep_id,
                            region=location_norm,
                            title=title,
                            summary=summary,
                            reason=reason,
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            estimated_monthly_cost_usd=None,  # spec 10: always None
                            evidence=Evidence(
                                signals_used=signals_used,
                                signals_not_checked=[
                                    "Future traffic intent or standby usage",
                                    "Autoscale policies or live instance state not visible from deployment configuration",
                                    "Exact endpoint cost after discounts, reservations, or special commercial terms",
                                    "Business-owner intent or rollout plans",
                                ],
                                time_window=f"{effective_idle_days} days",
                            ),
                            details=details,
                        )
                    )

                except PermissionError:
                    raise
                except Exception:
                    continue  # spec 12: malformed or failed per-endpoint record -> skip

        except PermissionError:
            raise
        except Exception:
            continue  # spec 12: per-workspace failure -> skip; preserve findings so far

    return findings
