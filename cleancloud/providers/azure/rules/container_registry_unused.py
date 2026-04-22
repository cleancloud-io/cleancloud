"""
Rule: azure.container_registry.unused

Intent:
    Detect Azure Container Registries with no successful image pull or push
    activity over the configured inactivity window.

Exclusions:
    - registry.id absent or empty
    - outside region filter (lowercase match; no space or hyphen removal)
    - provisioning state does not resolve to exactly "Succeeded"
    - properties.creationDate absent, unparsable, or after window_start
    - SuccessfulPullCount or SuccessfulPushCount evaluates to UNKNOWN
      (query failure after retries, no valid metric series, or coverage < 0.80)
    - either metric evaluates to ACTIVE (aggregate total > 0)

Detection:
    - provisioning state resolves to "Succeeded"
    - properties.creationDate <= window_start
    - SuccessfulPullCount evaluates to ZERO
    - SuccessfulPushCount evaluates to ZERO

Metric evaluation contract (spec 9.2):
    interval:         PT1H
    retries:          up to 3 total attempts; exponential backoff 1s then 2s
    expected_buckets: ceil((window_end - floor_hour(window_start)) / 1h)
    observed_buckets: unique hour-aligned UTC timestamps with a numeric total
    coverage_ratio:   observed_buckets / expected_buckets
    ZERO:     valid metric series, coverage_ratio >= 0.80, aggregate total == 0
    ACTIVE:   valid metric series, coverage_ratio >= 0.80, aggregate total > 0
    UNKNOWN:  query failure after retries | no valid series | coverage_ratio < 0.80

Cost model:
    estimated_monthly_cost_usd = _SKU_COST_USD[sku_name.lower()]
    None when SKU absent or unrecognized (base fee only; excludes storage)

APIs:
    - Microsoft.ContainerRegistry/registries/read  (registries.list)
    - Microsoft.Insights/metrics/read              (metrics.list)
"""

import math
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.container_registry.unused"
_RESOURCE_TYPE = "azure.container_registry"

# Base monthly registry fee by normalized SKU (lowercase key). Does not include storage.
_SKU_COST_USD = {
    "basic": 5.0,
    "standard": 20.0,
    "premium": 50.0,
}

# Exponential backoff delays between retry attempts (seconds)
_RETRY_DELAYS = (1.0, 2.0)


class _MetricResult(Enum):
    ACTIVE = "ACTIVE"
    ZERO = "ZERO"
    UNKNOWN = "UNKNOWN"


def _norm_location(s: str) -> str:
    """Lowercase only. Do not remove spaces, hyphens, or digits (spec 7)."""
    return s.lower() if s else ""


def _resolve_provisioning_state(registry) -> Optional[str]:
    """
    Resolve registry provisioning state per spec 9.1:
    1. properties.provisioning_state (SDK projection of properties.provisioningState)
    2. SDK fallback: registry.provisioning_state
    3. otherwise None
    """
    props = getattr(registry, "properties", None)
    if props is not None:
        state = getattr(props, "provisioning_state", None)
        if state is not None:
            return state
    return getattr(registry, "provisioning_state", None)


def _parse_creation_date(registry) -> Optional[datetime]:
    """
    Parse registry creation date from SDK attributes.
    Returns a timezone-aware UTC datetime, or None if absent or unparsable.

    The Python SDK flattens properties.creationDate to registry.creation_date;
    both the nested and flat forms are checked for compatibility.
    """
    candidates = []

    props = getattr(registry, "properties", None)
    if props is not None:
        candidates.append(getattr(props, "creation_date", None))

    candidates.append(getattr(registry, "creation_date", None))

    for created in candidates:
        if created is None:
            continue
        if isinstance(created, datetime):
            if created.tzinfo is None:
                return created.replace(tzinfo=timezone.utc)
            return created
        try:
            dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            return dt
        except (ValueError, AttributeError):
            continue

    return None


def _evaluate_metric(
    monitor_client: MonitorManagementClient,
    resource_uri: str,
    metric_name: str,
    window_start: datetime,
    window_end: datetime,
) -> _MetricResult:
    """
    Evaluate a single Azure Monitor metric per spec 9.2.

    All UNKNOWN-producing conditions (exception, unusable response shape, no valid
    series, insufficient coverage) consume a retry attempt. Only a definitive
    ZERO or ACTIVE result exits the loop early.

    Returns ACTIVE, ZERO, or UNKNOWN.
    """
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start.strftime(fmt)}/{window_end.strftime(fmt)}"
    # Spec: expected_buckets is the count of UTC-aligned hourly buckets overlapping
    # [window_start, window_end). The first overlapping bucket starts at
    # floor_hour(window_start); ceil((window_end - first_bucket) / 1h) gives the
    # exact count regardless of whether window_start is hour-aligned.
    first_bucket_h = window_start.replace(minute=0, second=0, microsecond=0)
    expected_buckets = math.ceil((window_end - first_bucket_h).total_seconds() / 3600)

    for attempt in range(3):
        if attempt > 0:
            time.sleep(_RETRY_DELAYS[attempt - 1])

        try:
            response = monitor_client.metrics.list(
                resource_uri,
                metricnames=metric_name,
                timespan=timespan,
                interval="PT1H",
                aggregation="Total",
            )
        except Exception:
            continue  # exception → retry

        if not hasattr(response, "value") or response.value is None:
            continue  # unusable response shape → retry

        # Collect hour-aligned bucket totals, summing across all timeseries and
        # dimension slices. Only usable datapoints — numeric total, parseable UTC
        # timestamp inside the requested window — contribute to coverage.
        bucket_totals: dict = {}
        for metric in response.value:
            for ts in metric.timeseries or []:
                for data in ts.data or []:
                    if data.timestamp is None or data.total is None:
                        continue
                    ts_dt = data.timestamp
                    if not isinstance(ts_dt, datetime):
                        continue  # unparseable timestamp → skip datapoint
                    ts_utc = (
                        ts_dt if ts_dt.tzinfo is not None else ts_dt.replace(tzinfo=timezone.utc)
                    )
                    # Spec: usable datapoint must be inside the requested window
                    if not (window_start <= ts_utc < window_end):
                        continue
                    key = ts_utc.strftime("%Y-%m-%dT%H:00:00Z")
                    bucket_totals[key] = bucket_totals.get(key, 0.0) + data.total

        observed_buckets = len(bucket_totals)
        if observed_buckets == 0:
            continue  # no valid metric series → retry

        if observed_buckets / expected_buckets < 0.80:
            continue  # insufficient coverage → retry

        # Coverage is acceptable — result is definitive, no further retries needed.
        aggregate_total = sum(bucket_totals.values())
        return _MetricResult.ACTIVE if aggregate_total > 0 else _MetricResult.ZERO

    return _MetricResult.UNKNOWN  # all attempts exhausted


def find_unused_container_registries(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ContainerRegistryManagementClient] = None,
    monitor_client: Optional[MonitorManagementClient] = None,
    days_unused: int = 90,
) -> List[Finding]:
    """
    Find Azure Container Registries with no successful pull or push activity
    for `days_unused` days.

    Detection requires:
    - provisioningState resolves to "Succeeded"
    - properties.creationDate <= window_start
    - SuccessfulPullCount evaluates to ZERO
    - SuccessfulPushCount evaluates to ZERO

    IAM permissions:
    - Microsoft.ContainerRegistry/registries/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []

    acr_client = client or ContainerRegistryManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days_unused)

    for registry in acr_client.registries.list():
        # spec 8.1: id must be present and non-empty
        registry_id = getattr(registry, "id", None)
        if not registry_id:
            continue

        # spec 8.2: region filter (lowercase only; no space or hyphen removal)
        location = _norm_location(getattr(registry, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.3: provisioning state must resolve to exactly "Succeeded"
        if _resolve_provisioning_state(registry) != "Succeeded":
            continue

        # spec 8.4 + 8.5: creation date must be known and <= window_start
        created_at = _parse_creation_date(registry)
        if created_at is None:
            continue
        if created_at > window_start:
            continue

        resource_uri = registry_id.rstrip("/")

        # spec 8.6: pull metric must evaluate to ZERO
        pull_result = _evaluate_metric(
            mon_client,
            resource_uri,
            "SuccessfulPullCount",
            window_start,
            now,
        )
        if pull_result is not _MetricResult.ZERO:
            continue

        # spec 8.7: push metric must evaluate to ZERO
        push_result = _evaluate_metric(
            mon_client,
            resource_uri,
            "SuccessfulPushCount",
            window_start,
            now,
        )
        if push_result is not _MetricResult.ZERO:
            continue

        # --- EMIT ---
        sku = getattr(registry, "sku", None)
        sku_name = getattr(sku, "name", None) if sku else None
        tags = getattr(registry, "tags", None) or {}

        cost_usd = _SKU_COST_USD.get(sku_name.lower()) if sku_name else None

        signals_used = [
            "Registry creation date satisfies properties.creationDate <= window_start",
            f"SuccessfulPullCount and SuccessfulPushCount both evaluated to ZERO for the {days_unused}-day window",
            f"Registry SKU: {sku_name}",
        ]
        if cost_usd is not None:
            signals_used.append(f"ACR {sku_name} tier costs ~${cost_usd:.0f}/month plus storage")

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Planned reactivation or migration intent",
                "Images referenced by stopped or undeployed workloads",
                "Failed pull or login attempts not treated as active use",
                "Storage charges not included in estimated base monthly cost",
            ],
            time_window=f"{days_unused} days",
        )

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=registry_id,
                region=location,
                title=f"Unused Container Registry ({days_unused}+ days no pulls or pushes)",
                summary=(
                    f"Container Registry '{registry.name}' ({sku_name or 'unknown SKU'}) "
                    f"has had no successful pulls or pushes for {days_unused}+ days"
                ),
                reason=(
                    f"SuccessfulPullCount and SuccessfulPushCount both evaluated to ZERO "
                    f"over a {days_unused}-day window"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details={
                    "registry_name": registry.name,
                    "sku": sku_name,
                    "location": location,
                    "created_at": created_at.isoformat(),
                    "days_unused_threshold": days_unused,
                    "tags": tags,
                },
                estimated_monthly_cost_usd=cost_usd,
            )
        )

    return findings
