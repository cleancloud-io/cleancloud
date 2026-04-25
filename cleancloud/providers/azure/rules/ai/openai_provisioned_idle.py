"""
Rule: azure.openai.provisioned_deployment.idle

Intent:
    Detect Azure OpenAI provisioned deployments that retain billable PTU capacity
    while showing no observed Azure OpenAI request traffic over a conservative
    documented observation window.

    This rule is deliberately precision-first. It is not proof that deleting a
    deployment is safe, not proof that a reservation can be canceled without
    consequence, and not proof of an exact monthly saving. It is a conservative
    review-candidate rule for provisioned Azure OpenAI deployments that appear to
    be continuously billed but unused.

Exclusions (spec 8):
    - account.id absent, None, or empty
    - account.name absent, None, or empty
    - deployment.id absent, None, or empty
    - deployment.name absent, None, or empty
    - account location unresolved
    - region filter set and normalized account location does not match
    - account provisioning_state != "Succeeded" (exact case-sensitive)
    - deployment provisioning_state != "Succeeded" (exact case-sensitive)
    - deployment model_format != "OpenAI" (exact case-sensitive)
    - deployment sku_name not in documented provisioned-managed set
    - ptu_capacity absent, invalid, zero, or negative
    - created_at absent, invalid, in the future, or age < effective idle_days
    - AzureOpenAIRequests metric result not ZERO per spec 9.3

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)

APIs:
    - Microsoft.CognitiveServices/accounts/read
    - Microsoft.CognitiveServices/accounts/deployments/read
    - Microsoft.Insights/metrics/read
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from azure.core.exceptions import HttpResponseError
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.openai.provisioned_deployment.idle"
_RESOURCE_TYPE = "azure.openai.provisioned_deployment"
_DEFAULT_IDLE_DAYS = 7

RULE_METADATA = {
    "id": _RULE_ID,
    "category": "ai",
    "service": "cognitiveservices",
    "cost_impact": "high",
}

# Provisioned SKU names that bill by PTU (spec 3.2, 9.1.5)
_PROVISIONED_SKUS = frozenset(
    {
        "ProvisionedManaged",
        "GlobalProvisionedManaged",
        "DataZoneProvisionedManaged",
    }
)

_METRIC_NAME = "AzureOpenAIRequests"
_METRIC_AGGREGATION = "Total"
_METRIC_INTERVAL = "PT1M"

_COVERAGE_ACCEPTABLE = 0.80  # minimum coverage for acceptable ZERO result
_COVERAGE_HIGH = 0.95  # coverage threshold for HIGH confidence
_MAX_IDLE_DAYS = 30  # soft upper bound; avoids multi-month metric queries


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


def _escape_odata_string(value: str) -> str:
    """
    Escape a string literal for use in an Azure Monitor OData filter expression.

    Rules applied:
    - Single quotes are escaped to '' (OData spec 4.5.2 string literals).
    - ASCII control characters (< 0x20, excluding tab 0x09) are stripped because
      they cannot appear in a well-formed OData string and can confuse filter parsing.
    """
    # Strip ASCII control chars before building the OData filter string.
    # Azure Monitor rejects filter expressions that contain raw control chars
    # (NUL, CR, LF, ESC, etc.); tab (0x09) is kept as it can appear in valid names.
    sanitized = "".join(ch for ch in value if ch == "\t" or ord(ch) >= 0x20)
    return sanitized.replace("'", "''")


# ---------------------------------------------------------------------------
# Traffic metric (spec 9.3)
# ---------------------------------------------------------------------------


def _query_openai_requests(
    monitor_client: Any,
    account_id: str,
    deployment_name: str,
    effective_idle_days: int,
) -> Tuple[
    str, Optional[float], Optional[int], Optional[int], Optional[datetime], Optional[datetime]
]:
    """
    Query AzureOpenAIRequests on the parent account ARM resource id (spec 9.3).

    After applying the ModelDeploymentName deployment scoping filter, sums Total
    across all remaining dimension series into per-minute bucket_totals. Any
    bucket_total > 0 is activity; coverage is based on unique usable minute buckets
    after that aggregation (spec 9.3.6–9.3.8).

    Returns a 6-tuple: (result_code, coverage_ratio, expected_buckets, observed_count,
                        window_start_utc, metric_end_utc)

    result_code values:
      "ZERO"                   coverage >= 80% and every bucket_total == 0
      "ACTIVE"                 any bucket_total > 0
      "UNKNOWN_QUERY_FAILURE"  exception during query or invalid window (expected_buckets <= 0)
      "UNKNOWN_NO_DATA"        query succeeded but no usable datapoints inside the window
      "UNKNOWN_LOW_COVERAGE"   had usable data but coverage fell below 80% threshold

    Window timestamps are returned for every non-failure case to let callers record
    the exact evaluation window in finding details.
    """
    now_utc = datetime.now(timezone.utc)
    # floor_to_minute(now_utc - 5 minutes) per spec 9.3
    raw_end = now_utc - timedelta(minutes=5)
    metric_end_utc = raw_end.replace(second=0, microsecond=0)
    window_start_utc = metric_end_utc - timedelta(days=effective_idle_days)

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{window_start_utc.strftime(fmt)}/{metric_end_utc.strftime(fmt)}"

    # Expected complete minute buckets in [window_start_utc, metric_end_utc)
    expected_buckets = int((metric_end_utc - window_start_utc).total_seconds() // 60)
    if expected_buckets <= 0:
        return ("UNKNOWN_QUERY_FAILURE", None, None, None, None, None)

    try:
        response = monitor_client.metrics.list(
            account_id,
            metricnames=_METRIC_NAME,
            timespan=timespan,
            interval=_METRIC_INTERVAL,
            aggregation=_METRIC_AGGREGATION,
            filter=f"ModelDeploymentName eq '{_escape_odata_string(deployment_name)}'",
        )
    except PermissionError:
        raise
    except HttpResponseError as exc:
        if exc.status_code in (401, 403):
            raise PermissionError(
                "Missing required permissions: Microsoft.Insights/metrics/read"
            ) from exc
        return ("UNKNOWN_QUERY_FAILURE", None, None, None, None, None)
    except Exception:
        return ("UNKNOWN_QUERY_FAILURE", None, None, None, None, None)

    # Per-minute bucket totals: sum Total across all remaining dimension series (spec 9.3.6.v).
    # Keyed by floored-to-minute UTC datetime so duplicate timestamps or multiple series
    # do not overstate coverage (spec 9.3.8).
    usable_bucket_totals: Dict[datetime, float] = {}

    for metric in response.value or []:
        for ts in getattr(metric, "timeseries", None) or []:
            for point in getattr(ts, "data", None) or []:
                total = getattr(point, "total", None)
                if total is None:
                    continue

                # Resolve and parse the datapoint timestamp
                raw_ts = getattr(point, "time_stamp", None)
                if raw_ts is None:
                    raw_ts = getattr(point, "timestamp", None)
                pt_utc = _parse_utc_timestamp(raw_ts)
                if pt_utc is None:
                    continue  # unparseable timestamp -> not a usable datapoint

                # Floor to the minute to identify the complete minute bucket
                bucket = pt_utc.replace(second=0, microsecond=0)

                # Must be within [window_start_utc, metric_end_utc) (spec 9.3.4)
                if bucket < window_start_utc or bucket >= metric_end_utc:
                    continue

                usable_bucket_totals[bucket] = usable_bucket_totals.get(bucket, 0.0) + total

    observed_count = len(usable_bucket_totals)

    if observed_count == 0:
        return ("UNKNOWN_NO_DATA", None, expected_buckets, 0, window_start_utc, metric_end_utc)

    # Any positive bucket_total means activity (spec 9.3.10)
    for bucket_total in usable_bucket_totals.values():
        if bucket_total > 0:
            return ("ACTIVE", None, None, None, None, None)

    # Azure Monitor minute coverage can be sparse or arrive late; this rule intentionally
    # fails closed — insufficient coverage produces UNKNOWN rather than a false ZERO.
    coverage_ratio = observed_count / expected_buckets
    if coverage_ratio < _COVERAGE_ACCEPTABLE:
        return (
            "UNKNOWN_LOW_COVERAGE",
            None,
            expected_buckets,
            observed_count,
            window_start_utc,
            metric_end_utc,
        )

    return (
        "ZERO",
        coverage_ratio,
        expected_buckets,
        observed_count,
        window_start_utc,
        metric_end_utc,
    )


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_openai_provisioned_deployments(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Azure OpenAI provisioned deployments with zero AzureOpenAIRequests while
    retaining positive PTU capacity.

    Detection logic (spec 4, 8, 9):
    - model_format == "OpenAI" (exact, case-sensitive; establishes OpenAI scope per spec 9.1.4)
    - sku_name in documented provisioned-managed set
    - Account and deployment provisioning_state both exactly "Succeeded"
    - ptu_capacity > 0 (billing-relevant per spec 9.1.7)
    - created_at resolves to known UTC timestamp; age >= effective idle_days
    - AzureOpenAIRequests == 0 across the rolling UTC window defined in spec 9.3

    IAM permissions:
    - Microsoft.CognitiveServices/accounts/read
    - Microsoft.CognitiveServices/accounts/deployments/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    # spec 6.3: minimum 1; soft upper bound avoids multi-month metric queries
    effective_idle_days = min(max(idle_days, 1), _MAX_IDLE_DAYS)

    cs_client = client or CognitiveServicesManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    region_filter_norm = _norm_location(region_filter) if region_filter else None

    # Subscription-wide account inventory: propagate if this fails (spec 12)
    for account in cs_client.accounts.list():
        # spec 8.1: account.id guard
        account_id = getattr(account, "id", None)
        if not account_id:
            continue

        # spec 8.2: account.name guard
        account_name = getattr(account, "name", None)
        if not account_name:
            continue

        # spec 8.5: account location must resolve
        location_raw = getattr(account, "location", None) or ""
        location_norm = _norm_location(location_raw)
        if not location_norm:
            continue  # unresolved location -> skip (spec 7)

        # spec 8.6: region filter — exact lowercase equality
        if region_filter_norm and location_norm != region_filter_norm:
            continue

        # spec 8.7: account provisioning_state must be exactly "Succeeded"
        # Check both snake_case (SDK) and camelCase (raw shape) field names.
        acct_props = getattr(account, "properties", None)
        account_prov_state = None
        if acct_props is not None:
            account_prov_state = getattr(acct_props, "provisioning_state", None)
            if account_prov_state is None:
                account_prov_state = getattr(acct_props, "provisioningState", None)
        if account_prov_state != "Succeeded":
            continue

        account_kind = getattr(account, "kind", None)

        rg = _extract_resource_group(account_id)
        if not rg:
            continue

        try:
            for deployment in cs_client.deployments.list(rg, account_name):
                try:
                    # spec 8.3: deployment.id guard
                    dep_id = getattr(deployment, "id", None)
                    if not dep_id:
                        continue

                    # spec 8.4: deployment.name guard
                    dep_name = getattr(deployment, "name", None)
                    if not dep_name:
                        continue

                    dep_props = getattr(deployment, "properties", None)

                    # spec 8.8: deployment provisioning_state must be exactly "Succeeded"
                    # Check both snake_case (SDK) and camelCase (raw shape) field names.
                    dep_prov_state = None
                    if dep_props is not None:
                        dep_prov_state = getattr(dep_props, "provisioning_state", None)
                        if dep_prov_state is None:
                            dep_prov_state = getattr(dep_props, "provisioningState", None)
                    if dep_prov_state != "Succeeded":
                        continue

                    # spec 8.9: model_format must be exactly "OpenAI" (case-sensitive)
                    model = getattr(dep_props, "model", None) if dep_props is not None else None
                    model_format = getattr(model, "format", None) if model is not None else None
                    if model_format != "OpenAI":
                        continue

                    model_name = getattr(model, "name", None) if model is not None else None
                    model_version = getattr(model, "version", None) if model is not None else None

                    # spec 8.10: sku_name must be in documented provisioned-managed set
                    sku = getattr(deployment, "sku", None)
                    sku_name = getattr(sku, "name", None) if sku is not None else None
                    if sku_name not in _PROVISIONED_SKUS:
                        continue

                    # spec 8.11: ptu_capacity must be a known integer > 0
                    ptu_capacity = None
                    if sku is not None:
                        raw_capacity = getattr(sku, "capacity", None)
                        if raw_capacity is not None:
                            try:
                                ptu_capacity = int(raw_capacity)
                            except (TypeError, ValueError):
                                pass
                    if ptu_capacity is None or ptu_capacity <= 0:
                        continue

                    # spec 8.12 / 9.2: created_at from systemData.createdAt
                    sys_data = getattr(deployment, "system_data", None) or getattr(
                        deployment, "systemData", None
                    )
                    created_at = None
                    if sys_data is not None:
                        raw_created = getattr(sys_data, "created_at", None)
                        if raw_created is None:
                            raw_created = getattr(sys_data, "createdAt", None)
                        created_at = _parse_utc_timestamp(raw_created)

                    if created_at is None:
                        continue  # spec 8.12: required
                    if created_at > now:
                        continue  # spec 9.2.3: future created_at -> skip
                    age_days = (now - created_at).days
                    if age_days < effective_idle_days:
                        continue  # spec 8.12 / 9.2.4: age gate

                    # spec 8.13: traffic metric must resolve to ZERO per spec 9.3
                    (
                        metric_result,
                        coverage_ratio,
                        expected_bucket_count,
                        observed_bucket_count,
                        metric_window_start_utc,
                        metric_end_utc,
                    ) = _query_openai_requests(
                        mon_client, account_id, dep_name, effective_idle_days
                    )
                    if metric_result != "ZERO":
                        continue  # ACTIVE or UNKNOWN_* -> skip

                    # spec 9.4: confidence from metric coverage
                    if coverage_ratio >= _COVERAGE_HIGH:
                        confidence = ConfidenceLevel.HIGH
                    else:
                        confidence = ConfidenceLevel.MEDIUM

                    # spec 9.4: risk always HIGH
                    risk = RiskLevel.HIGH

                    # spec 9.3.13: idle_since_days = effective idle window
                    idle_since_days = effective_idle_days

                    # Tags: deployment tags when present; otherwise {} (spec 7)
                    dep_tags = getattr(deployment, "tags", None)
                    tags = dep_tags if isinstance(dep_tags, dict) else {}

                    # spec 11.2: signals_used
                    signals_used = [
                        f"Deployment model_format is 'OpenAI' with provisioned SKU '{sku_name}'",
                        "Account and deployment provisioning states are 'Succeeded'",
                        (
                            f"Deployment age is {age_days} days "
                            f"(>= configured idle window of {effective_idle_days} days)"
                        ),
                        f"Deployment retains {ptu_capacity} PTU(s) of provisioned capacity — billed hourly while the deployment exists",
                        (
                            f"{_METRIC_NAME} metric result is ZERO with "
                            f">={_COVERAGE_ACCEPTABLE:.2%} coverage "
                            f"across a {effective_idle_days}-day rolling UTC window "
                            f"({observed_bucket_count}/{expected_bucket_count} minute buckets, "
                            f"coverage: {coverage_ratio:.2%}, aggregation: {_METRIC_AGGREGATION})"
                        ),
                    ]

                    details = {
                        "account_name": account_name,
                        "resource_group": rg,
                        "subscription_id": subscription_id,
                        "account_location": location_norm,
                        "account_kind": account_kind,
                        "deployment_name": dep_name,
                        "deployment_provisioning_state": dep_prov_state,
                        "sku_name": sku_name,
                        "ptu_capacity": ptu_capacity,
                        "model_format": model_format,
                        "model_name": model_name,
                        "model_version": model_version,
                        "created_at": created_at.isoformat(),
                        "age_days": age_days,
                        "idle_days_requested": idle_days,
                        "idle_days_threshold": effective_idle_days,
                        "idle_since_days": idle_since_days,
                        "metric_name": _METRIC_NAME,
                        "metric_aggregation": _METRIC_AGGREGATION,
                        "metric_result_reason": metric_result,
                        "metric_coverage_ratio": coverage_ratio,
                        "metric_expected_bucket_count": expected_bucket_count,
                        "metric_observed_bucket_count": observed_bucket_count,
                        # Window timestamps are always non-None for ZERO results; guarded
                        # defensively so future code changes can't produce a silent AttributeError.
                        "metric_window_start_utc": (
                            metric_window_start_utc.isoformat()
                            if metric_window_start_utc is not None
                            else None
                        ),
                        "metric_end_utc": (
                            metric_end_utc.isoformat() if metric_end_utc is not None else None
                        ),
                        "tags": tags,
                    }

                    title = f"Idle Azure OpenAI Provisioned Deployment: {dep_name}"
                    summary = (
                        f"Azure OpenAI provisioned deployment '{dep_name}' "
                        f"({sku_name}, {ptu_capacity} PTU) in account '{account_name}' "
                        f"has received zero API requests for {effective_idle_days} days "
                        f"while retaining positive PTU capacity, continuing to incur hourly PTU charges."
                    )
                    reason = (
                        f"AzureOpenAIRequests is zero across a {effective_idle_days}-day rolling "
                        f"window while deployment retains {ptu_capacity} PTU(s) of provisioned capacity"
                    )

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id=_RULE_ID,
                            resource_type=_RESOURCE_TYPE,
                            resource_id=dep_id,
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
                                    "Business-owner intent or planned future traffic",
                                    "Spillover/failover policy intent beyond observed request activity",
                                    "Reservation coverage, reservation cancellation implications, or other commercial commitments",
                                    "Client-side retries or other application semantics not visible from management and Azure Monitor surfaces",
                                ],
                                time_window=f"{effective_idle_days} days",
                            ),
                            details=details,
                        )
                    )

                except PermissionError:
                    raise
                except Exception:
                    continue  # spec 12: malformed or failed per-deployment record -> skip

        except PermissionError:
            raise
        except Exception:
            continue  # spec 12: per-account deployment listing failure -> skip account

    return findings
