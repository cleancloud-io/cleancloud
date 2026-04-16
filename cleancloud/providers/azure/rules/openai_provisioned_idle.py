import math
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

# Azure SDK (top-level imports for CI fail-fast)
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.monitor import MonitorManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "azure.openai.provisioned_deployment.idle",
    "category": "ai",
    "service": "cognitiveservices",
    "cost_impact": "high",
}

# Provisioned SKU names — these bill by PTU regardless of usage
_PROVISIONED_SKUS = frozenset(
    {
        "ProvisionedManaged",
        "GlobalProvisionedManaged",
        "DataZoneProvisionedManaged",
    }
)

# Account kinds that host Azure OpenAI deployments
_OPENAI_KINDS = frozenset({"OpenAI", "AIServices"})

# On-demand PTU cost: $2/PTU/hour × 730 hours/month
# Reserved pricing is lower (~$1,000–$1,200/PTU/month) — we report on-demand as the ceiling.
_PTU_MONTHLY_COST_USD = 1_460.0

# Azure Monitor metric names to check for request activity (tried in order)
_REQUEST_METRICS = (
    "AzureOpenAIRequests",
    "ProcessedPromptTokens",
)


def find_idle_openai_provisioned_deployments(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    monitor_client: Optional[Any] = None,
    idle_days: int = 7,
) -> List[Finding]:
    """
    Find Azure OpenAI provisioned deployments (PTUs) with zero API requests.

    Provisioned Throughput Units (PTUs) reserve dedicated model capacity and
    bill continuously at ~$1,460/PTU/month (on-demand) regardless of traffic.
    A provisioned deployment with zero requests is paying for capacity that is
    delivering zero value — typically a forgotten dev/test deployment, a
    proof-of-concept that was never decommissioned, or a migration where traffic
    moved to a different deployment but the old one was left running.

    This is the Azure equivalent of an idle SageMaker Provisioned endpoint:
    same always-on billing model, same abandonment pattern.

    Detection logic:
    - Account kind is OpenAI or AIServices
    - Deployment SKU is ProvisionedManaged, GlobalProvisionedManaged, or
      DataZoneProvisionedManaged (capacity-based billing, not token-based)
    - Azure Monitor AzureOpenAIRequests (or ProcessedPromptTokens) sum is 0
      over the idle window, scoped to this deployment via dimension filter

    Metric strategy:
    - Query AzureOpenAIRequests with ModelDeploymentName dimension filter
      (per-deployment signal — most reliable)
    - Fall back to ProcessedPromptTokens with same filter if AzureOpenAIRequests
      returns no timeseries (metric or dimension unsupported in this region)
    - If both per-deployment queries return no data, result is ("no_data", None).
      Account-level aggregation is NOT used as a fallback: a zero account total only
      covers deployments that emit the metric; deployments that don't are invisible,
      making account-level zero an unsafe basis for a finding.
    - Conservative: return None (assume active) on any API exception

    Confidence:
    - HIGH: Per-deployment metric confirms zero requests, deployment age >= idle_days
    - MEDIUM: Per-deployment metric confirms zero, age >= ceil(75% of idle_days) but
      < idle_days; OR per-deployment metric confirms zero, age unknown; OR metrics
      unavailable and deployment age >= 2× idle_days (age-only fallback)

    IAM permissions:
    - Microsoft.CognitiveServices/accounts/read
    - Microsoft.CognitiveServices/accounts/deployments/read
    - Microsoft.Insights/metrics/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    idle_days = max(idle_days, 3)

    cs_client = client or CognitiveServicesManagementClient(
        credential=credential, subscription_id=subscription_id
    )
    mon_client = monitor_client or MonitorManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "")

    try:
        for account in cs_client.accounts.list():
            # Only Azure OpenAI accounts
            if getattr(account, "kind", None) not in _OPENAI_KINDS:
                continue

            location_raw = account.location or ""
            if region_filter and _norm(location_raw) != _norm(region_filter):
                continue

            rg = _parse_resource_group(account.id)
            if not rg:
                continue

            try:
                for deployment in cs_client.deployments.list(rg, account.name):
                    sku_name = getattr(deployment.sku, "name", None) if deployment.sku else None
                    if sku_name not in _PROVISIONED_SKUS:
                        continue

                    ptu_capacity = getattr(deployment.sku, "capacity", None) or 0
                    model_name = None
                    if deployment.properties:
                        model = getattr(deployment.properties, "model", None)
                        if model:
                            model_name = getattr(model, "name", None)

                    # Age from system_data
                    age_days: Optional[int] = None
                    created_at = None
                    if deployment.system_data:
                        created_at = getattr(deployment.system_data, "created_at", None)
                    if created_at is not None:
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=timezone.utc)
                        age_days = max((now - created_at).days, 0)
                        if age_days < max(idle_days // 2, 3):
                            continue  # too new to classify

                    effective_window = (
                        min(idle_days, age_days) if age_days is not None else idle_days
                    )
                    if effective_window < 3:
                        continue

                    # Check request activity via Azure Monitor
                    idle_signal = _check_requests(
                        mon_client,
                        account.id,
                        deployment.name,
                        effective_window,
                    )
                    # idle_signal:
                    #   ("per_deployment", metric_name) — zero confirmed at deployment level
                    #   ("active", None)                — has traffic, skip
                    #   ("no_data", None)               — metrics returned no timeseries (unsupported)
                    #   None                            — all metric calls failed (transient), skip

                    if idle_signal is None or idle_signal[0] == "active":
                        continue  # transient error or definitively active — skip

                    signal_scope, idle_metric = idle_signal

                    if signal_scope == "no_data":
                        # Age-only fallback: metrics unsupported, but deployment is very old
                        if age_days is not None and age_days >= idle_days * 2:
                            signal_scope = "age_only"
                            idle_metric = "none"
                            confidence = ConfidenceLevel.MEDIUM
                        else:
                            continue  # not enough signal

                    elif (
                        signal_scope == "per_deployment"
                        and age_days is not None
                        and age_days >= idle_days
                    ):
                        confidence = ConfidenceLevel.HIGH
                    elif (
                        signal_scope == "per_deployment"
                        and age_days is not None
                        and age_days >= math.ceil(idle_days * 0.75)
                    ):
                        # 75–100% of idle_days: metric confirms zero requests but the
                        # deployment hasn't fully cleared the observation window yet.
                        # Surface as MEDIUM rather than skipping — early waste is still
                        # waste, but we avoid HIGH until the full window is satisfied.
                        # ceil ensures "75%" is never rounded down (e.g. idle_days=7
                        # gives ceil(5.25)=6, so age=5 is correctly excluded).
                        confidence = ConfidenceLevel.MEDIUM
                    elif signal_scope == "per_deployment" and age_days is None:
                        confidence = ConfidenceLevel.MEDIUM
                    else:
                        # age_days < ceil(75% of idle_days): too early to be confident.
                        # Prefer false negatives over false positives here.
                        continue

                    monthly_cost = ptu_capacity * _PTU_MONTHLY_COST_USD if ptu_capacity else None

                    # Risk scales with PTU cost — PTUs are always significant
                    if monthly_cost and monthly_cost >= 10_000:
                        risk = RiskLevel.HIGH
                    elif monthly_cost and monthly_cost >= 2_000:
                        risk = RiskLevel.MEDIUM
                    else:
                        risk = RiskLevel.MEDIUM  # even small PTU allocations are expensive

                    signals = [
                        (
                            f"No Azure Monitor metric data available; deployment age ({age_days} days) "
                            f"exceeds {idle_days * 2} days"
                            if signal_scope == "age_only"
                            else f"Zero API requests for {effective_window} days "
                            f"(Azure Monitor: {idle_metric}, scope: {signal_scope.replace('_', ' ')})"
                        ),
                        f"Provisioned SKU: {sku_name} — bills continuously regardless of usage",
                        f"PTU capacity: {ptu_capacity} PTU(s)",
                    ]
                    if model_name:
                        signals.append(f"Model: {model_name}")
                    if age_days is not None:
                        signals.append(f"Deployment age: {age_days} days")
                    if monthly_cost:
                        signals.append(
                            f"Estimated cost: ~${monthly_cost:,.0f}/month on-demand "
                            f"({ptu_capacity} PTU × $1,460/PTU — reserved pricing is lower)"
                        )

                    evidence = Evidence(
                        signals_used=signals,
                        signals_not_checked=[
                            "Deployments used as failover/backup capacity only",
                            "Scheduled batch processing with infrequent job submissions",
                            "PTU reservation commitment — deleting may forfeit reserved capacity",
                            "Internal tooling with very low but non-zero request rates",
                        ],
                        time_window=f"{effective_window} days",
                    )

                    _confidence_reasons = {
                        "age_only": "no_metric_data_deployment_age_only",
                        "per_deployment": (
                            "per_deployment_metric_zero_age_confirmed"
                            if age_days is not None and age_days >= idle_days
                            else (
                                "per_deployment_metric_zero_age_partial"
                                if age_days is not None
                                else "per_deployment_metric_zero_age_unknown"
                            )
                        ),
                    }

                    details = {
                        "account_name": account.name,
                        "deployment_name": deployment.name,
                        "sku_name": sku_name,
                        "ptu_capacity": ptu_capacity,
                        "location": location_raw,
                        "idle_days_threshold": idle_days,
                        "idle_signal_scope": signal_scope,
                        "confidence_reason": _confidence_reasons.get(signal_scope, signal_scope),
                    }
                    if model_name:
                        details["model"] = model_name
                    if age_days is not None:
                        details["age_days"] = age_days
                    if account.tags:
                        details["tags"] = account.tags

                    if signal_scope == "age_only":
                        title = f"Possibly Idle Azure OpenAI Provisioned Deployment ({ptu_capacity} PTU, No Metric Data for {age_days}+ Days)"
                        summary = (
                            f"Azure OpenAI provisioned deployment '{deployment.name}' "
                            f"({sku_name}, {ptu_capacity} PTU) in account '{account.name}' "
                            f"has been running for {age_days} days with no Azure Monitor metric data "
                            f"available to confirm activity. PTU charges continue regardless."
                        )
                        reason = (
                            f"No Azure Monitor data available after {age_days} days "
                            f"({ptu_capacity} PTU billed continuously — activity unconfirmed)"
                        )
                    else:
                        title = f"Idle Azure OpenAI Provisioned Deployment ({ptu_capacity} PTU, No Requests for {effective_window}+ Days)"
                        summary = (
                            f"Azure OpenAI provisioned deployment '{deployment.name}' "
                            f"({sku_name}, {ptu_capacity} PTU) in account '{account.name}' "
                            f"has received zero API requests for {effective_window}+ days "
                            f"but continues to accrue PTU charges."
                        )
                        reason = (
                            f"Provisioned deployment has zero API requests for {effective_window}+ days "
                            f"({ptu_capacity} PTU billed continuously)"
                        )

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id="azure.openai.provisioned_deployment.idle",
                            resource_type="azure.openai.provisioned_deployment",
                            resource_id=deployment.id,
                            region=location_raw,
                            title=title,
                            summary=summary,
                            reason=reason,
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=evidence,
                            details=details,
                            estimated_monthly_cost_usd=monthly_cost,
                        )
                    )

            except PermissionError:
                raise  # propagate from _check_requests (e.g. missing metrics/read)
            except Exception as acct_err:
                msg = str(acct_err)
                if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
                    raise PermissionError(
                        "Missing required permissions: "
                        "Microsoft.CognitiveServices/accounts/read, "
                        "Microsoft.CognitiveServices/accounts/deployments/read, "
                        "Microsoft.Insights/metrics/read"
                    ) from acct_err
                continue  # skip this account on transient error

    except PermissionError:
        raise
    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: "
                "Microsoft.CognitiveServices/accounts/read, "
                "Microsoft.CognitiveServices/accounts/deployments/read"
            ) from e
        raise

    return findings


def _check_requests(
    monitor_client: Any,
    account_id: str,
    deployment_name: str,
    days: int,
) -> Optional[tuple]:
    """Check whether a deployment had any API requests in the past `days` days.

    Returns:
        ("per_deployment", metric_name) — deployment-level zero confirmed
        ("active", None)               — deployment or account has traffic (do not flag)
        ("no_data", None)              — metrics API responded but returned no timeseries
                                         for any metric. Can mean: metric unsupported in
                                         this region, dimension filter unsupported, or
                                         ingestion lag. Age-only fallback may apply in
                                         the caller for deployments >= 2× idle_days.
        None                           — all metric calls failed with transient errors;
                                         conservative skip (do not flag)

    Account-level aggregation is intentionally NOT used as an idle signal. A zero
    account-level total only confirms all deployments on the account emitting that
    metric are idle — deployments that do not emit the metric are invisible to it,
    making it an unsafe basis for a finding.

    Auth errors (403/AuthorizationFailed) are re-raised as PermissionError so the
    caller can surface them as a skipped-rule signal rather than silent no-findings.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(days, 1))
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    timespan = f"{start.strftime(fmt)}/{now.strftime(fmt)}"

    had_successful_call = False  # tracks whether any metric API call returned without exception

    for metric_name in _REQUEST_METRICS:
        try:
            # 1. Per-deployment query via ModelDeploymentName dimension filter
            response = monitor_client.metrics.list(
                account_id,
                metricnames=metric_name,
                timespan=timespan,
                interval="P1D",
                aggregation="Total",
                filter=f"ModelDeploymentName eq '{deployment_name}'",
            )
            had_successful_call = True
            has_timeseries = False
            seen_datapoints = 0
            for metric in response.value:
                for ts in metric.timeseries:
                    has_timeseries = True
                    for point in ts.data:
                        if point.total is not None:
                            seen_datapoints += 1
                            if point.total > 0:
                                return ("active", None)  # deployment has traffic
            # Require at least one explicit data point: an all-None timeseries means
            # Azure returned the metric structure but ingested no measurements
            # (ingestion gap or very new deployment). Treat as no_data rather than
            # idle to avoid false positives from empty metric shells.
            if has_timeseries and seen_datapoints > 0:
                return ("per_deployment", metric_name)  # timeseries with explicit zeros confirmed

            # No per-deployment timeseries — dimension filter unsupported for this
            # deployment. Do NOT fall back to account-level aggregation: a zero
            # account total only covers deployments that emit this metric; deployments
            # that do not emit it are invisible and would be falsely flagged as idle.
            # Fall through to try the next metric instead.

        except Exception as e:
            msg = str(e)
            if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
                raise PermissionError(
                    "Missing required permissions: Microsoft.Insights/metrics/read"
                ) from e
            continue  # transient error — try next metric

    # All metrics tried: distinguish "API responded with no data" from "all calls failed"
    return ("no_data", None) if had_successful_call else None


def _parse_resource_group(resource_id: str) -> Optional[str]:
    """Extract resource group name from an Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        rg_index = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[rg_index + 1]
    except (StopIteration, IndexError):
        return None
