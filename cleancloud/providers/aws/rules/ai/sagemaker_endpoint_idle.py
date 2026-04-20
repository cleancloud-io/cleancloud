from datetime import datetime, timedelta, timezone
from typing import List, NamedTuple, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.sagemaker.endpoint.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}

# GPU/accelerator instance families — significantly more expensive than CPU
_GPU_FAMILIES = (
    "ml.g4dn",
    "ml.g5",
    "ml.p2",
    "ml.p3",
    "ml.p4d",
    "ml.p4de",
    "ml.p5",
    "ml.trn1",
    "ml.inf1",
    "ml.inf2",
)

# Approximate monthly cost by instance type (on-demand, us-east-1)
_MONTHLY_COST_BY_FAMILY = {
    "ml.g4dn.xlarge": 531.0,
    "ml.g4dn.2xlarge": 941.0,
    "ml.g4dn.4xlarge": 1_633.0,
    "ml.g4dn.12xlarge": 2_817.0,
    "ml.g5.xlarge": 600.0,
    "ml.g5.2xlarge": 1_008.0,
    "ml.g5.4xlarge": 1_838.0,
    "ml.g5.12xlarge": 5_443.0,
    "ml.p3.2xlarge": 2_754.0,
    "ml.p3.8xlarge": 11_016.0,
    "ml.p4d.24xlarge": 23_596.0,
    "ml.p4de.24xlarge": 29_908.0,
    "ml.p5.48xlarge": 71_774.0,
    # Trainium
    "ml.trn1.2xlarge": 978.0,
    "ml.trn1.32xlarge": 15_695.0,
    "ml.trn1n.32xlarge": 18_089.0,
    # Inferentia
    "ml.inf1.xlarge": 166.0,
    "ml.inf1.2xlarge": 264.0,
    "ml.inf1.6xlarge": 793.0,
    "ml.inf1.24xlarge": 3_170.0,
    # Inferentia2
    "ml.inf2.xlarge": 554.0,
    "ml.inf2.8xlarge": 4_427.0,
    "ml.inf2.24xlarge": 13_283.0,
    "ml.inf2.48xlarge": 26_566.0,
    "ml.m5.large": 94.0,
    "ml.m5.xlarge": 188.0,
    "ml.m5.2xlarge": 376.0,
    "ml.c5.large": 85.0,
    "ml.c5.xlarge": 171.0,
    "ml.t2.medium": 40.0,
    "ml.t3.medium": 42.0,
}
# No default cost fallback — when instance type is unknown, cost is None.
# Using a hardcoded default ($150) for unknown types misleads cost aggregation.

# Serverless Inference provisioned concurrency: ~$0.0051/unit-hour (us-east-1 on-demand).
# Monthly ≈ 0.0051 × 24 × 30 ≈ $3.67 per provisioned concurrency unit.
# Approximate us-east-1 rate; other regions vary. Serverless endpoints with provisioned
# concurrency incur this reservation charge continuously, even when idle.
_SERVERLESS_PROVISIONED_COST_PER_UNIT_MONTHLY = 3.67  # approx us-east-1 on-demand


class InvocationCheckResult(NamedTuple):
    """Structured return type for _check_invocations.

    Using a NamedTuple instead of a raw tuple prevents positional misuse and
    makes the caller's intent explicit when reading each field by name.
    """

    has_traffic: bool  # True when at least one variant has confirmed invocations
    active_variants: list  # variant names with detected invocations (per-variant mode)
    idle_variants: list  # variant names with zero invocations (per-variant mode)
    total_datapoints: int  # total CW datapoints seen across all queries
    queried_with_variants: bool  # True if per-variant dimensions were used
    fetch_failed: bool  # True if a CloudWatch API error occurred


def find_idle_sagemaker_endpoints(
    session: boto3.Session,
    region: str,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find SageMaker inference endpoints with zero invocations.

    SageMaker endpoints incur continuous charges while InService, regardless
    of whether they receive any traffic. GPU-backed endpoints cost $500–$23K/month.
    Endpoints deployed for experiments or demos are frequently abandoned.

    Detection logic:
    - Endpoint is in InService state
    - Endpoint has billable compute: at least one running instance (DesiredInstanceCount > 0)
      OR at least one serverless variant with provisioned concurrency > 0
    - Zero Invocations over the effective idle window, queried per-variant
      (CloudWatch AWS/SageMaker namespace, EndpointName + VariantName dimensions)

    Confidence:
    - HIGH:   per-variant query, full idle window coverage (age >= idle_days)
    - MEDIUM: per-variant query, partial window (age >= 75% of idle_days); OR partial
              variant waste (some variants idle, some active — reliable data, uncertain intent)
    - LOW:    CloudWatch metric fetch failed; idle status unverified

    IAM permissions:
    - sagemaker:ListEndpoints
    - sagemaker:DescribeEndpoint
    - sagemaker:DescribeEndpointConfig
    - cloudwatch:GetMetricStatistics
    """
    sagemaker = session.client("sagemaker", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = sagemaker.get_paginator("list_endpoints")

        for page in paginator.paginate(StatusEquals="InService"):
            for endpoint in page.get("Endpoints", []):
                endpoint_name = endpoint["EndpointName"]

                # Calculate age — normalize to UTC to handle timezone-naive timestamps
                # from older boto3 versions, which would otherwise raise TypeError.
                # Use total_seconds()/86400 instead of .days — both floor-divide but
                # the float form is used for idle_ratio precision; int() for comparisons.
                create_time = endpoint.get("CreationTime")
                age_days: float = 0.0
                if create_time:
                    if create_time.tzinfo is None:
                        create_time = create_time.replace(tzinfo=timezone.utc)
                    age_days = (now - create_time).total_seconds() / 86400

                # Describe endpoint — get cost, GPU flag, variant info
                (
                    monthly_cost,
                    is_gpu,
                    variant_count,
                    total_instances,
                    primary_instance_type,
                    variant_names,
                    total_provisioned_concurrency,
                ) = _describe_endpoint(sagemaker, endpoint_name)

                # Skip if no billable compute:
                # - Instance-backed: DesiredInstanceCount must be > 0
                # - Serverless: ProvisionedConcurrency must be > 0
                # Serverless endpoints without provisioned concurrency have no idle cost.
                if total_instances == 0 and total_provisioned_concurrency == 0:
                    continue

                # Use effective window: can't look back further than the endpoint's age.
                # int() here so downstream comparisons and string formatting are clean.
                effective_window = min(idle_days, int(age_days))

                # Skip if effective window is too small to draw a reliable conclusion
                if effective_window < 3:
                    continue

                # Check invocations per variant — CloudWatch publishes Invocations
                # with {EndpointName, VariantName} dimensions; querying EndpointName
                # alone returns empty datapoints regardless of actual traffic.
                result = _check_invocations(
                    cloudwatch, endpoint_name, variant_names, effective_window
                )

                if result.has_traffic and not result.idle_variants and not result.fetch_failed:
                    continue  # all variants have confirmed traffic — fully active, skip

                if not result.queried_with_variants:
                    # EndpointName-only fallback — structurally unreliable for idle detection.
                    # Empty results may mean "no traffic" or "wrong dimension set"; we cannot
                    # distinguish the two. Skip rather than emit a low-quality finding.
                    continue

                active_variants = result.active_variants
                idle_variants = result.idle_variants
                total_datapoints = result.total_datapoints
                fetch_failed = result.fetch_failed

                partial_waste = len(active_variants) > 0 and len(idle_variants) > 0

                # Confidence tiers (explicit):
                # LOW    → CW fetch failed (per-variant path); traffic status unverified
                # MEDIUM → partial waste (reliable per-variant data; uncertainty is intent)
                #          OR per-variant query but partial time window (75–99% of threshold)
                # HIGH   → per-variant query + full window coverage
                if fetch_failed:
                    confidence = ConfidenceLevel.LOW
                elif partial_waste:
                    # Per-variant data is reliable; some variants have confirmed zero traffic.
                    # Uncertainty is about intent, not data quality → MEDIUM is appropriate.
                    confidence = ConfidenceLevel.MEDIUM
                elif effective_window >= idle_days:
                    confidence = ConfidenceLevel.HIGH
                elif effective_window >= int(idle_days * 0.75):
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    continue  # too borderline for a confident finding

                # idle_ratio: how many multiples of the threshold the endpoint has been running.
                # >= 2.0 means a GPU endpoint has been burning money for 2× the idle window.
                idle_ratio = round(age_days / idle_days, 2) if idle_days > 0 else 0.0
                idle_variant_ratio = (
                    len(idle_variants) / variant_count if variant_count > 0 else 0.0
                )

                # CRITICAL requires: GPU + fully idle (not partial_waste) + 2× overage.
                # partial_waste means some variants are still active — capping at HIGH avoids
                # over-escalating when the endpoint isn't wholly abandoned.
                if is_gpu and not partial_waste and idle_ratio >= 2.0:
                    risk = RiskLevel.CRITICAL
                elif is_gpu:
                    risk = RiskLevel.HIGH
                elif monthly_cost is None:
                    # Unknown cost — could be an expensive unlisted type; don't under-report
                    risk = RiskLevel.HIGH
                elif partial_waste:
                    # Scale risk by fraction of idle variants: ≥50% idle → HIGH, else MEDIUM
                    risk = RiskLevel.HIGH if idle_variant_ratio >= 0.5 else RiskLevel.MEDIUM
                else:
                    risk = RiskLevel.MEDIUM

                compute_signal = (
                    f"Total running instances (DesiredInstanceCount): {total_instances}"
                    if total_instances > 0
                    else f"Serverless provisioned concurrency: {total_provisioned_concurrency} unit(s)"
                )
                signals = [
                    "Endpoint state: InService",
                    f"Endpoint age: {int(age_days)} days",
                    compute_signal,
                ]

                if fetch_failed:
                    signals.insert(
                        0,
                        "CloudWatch Invocations metric fetch failed (transient/throttle error) "
                        "— idle status unverified",
                    )
                elif partial_waste:
                    signals.insert(
                        0,
                        f"Partial variant waste: {len(idle_variants)} of {variant_count} variant(s) "
                        f"have zero invocations for {effective_window} days "
                        f"(idle: {', '.join(idle_variants)}; "
                        f"active: {', '.join(active_variants)})",
                    )
                else:
                    signals.insert(
                        0,
                        f"Zero recorded invocations for {effective_window} days across all "
                        f"{len(idle_variants)} variant(s) "
                        f"({total_datapoints} total datapoints observed — "
                        "SageMaker omits zero-invocation datapoints, so this is the expected idle state)",
                    )

                if primary_instance_type:
                    signals.append(f"Instance type: {primary_instance_type}")
                else:
                    signals.append("Instance type: unknown — could not fetch endpoint config")
                if is_gpu:
                    signals.append("GPU/accelerator-backed instance — high hourly cost")
                if variant_count > 1:
                    signals.append(f"Production variants: {variant_count}")

                signals_not_checked = [
                    "Scheduled or batch invocation patterns",
                    "Internal health-check invocations",
                    "Planned future usage",
                    "Shadow mode / canary deployments",
                ]
                if fetch_failed:
                    signals_not_checked.insert(
                        0,
                        "Invocations — CloudWatch fetch failed; traffic status unverified",
                    )
                if monthly_cost is None:
                    signals_not_checked.insert(
                        0,
                        "Cost — instance type unknown; actual cost may be significantly higher "
                        "(e.g. ml.p5.48xlarge: ~$71K/month, ml.p4d.24xlarge: ~$23K/month)",
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{effective_window} days",
                )

                if fetch_failed:
                    title = "SageMaker Endpoint Requires Invocation Verification"
                    summary = (
                        f"SageMaker endpoint '{endpoint_name}' could not be verified as idle — "
                        "CloudWatch Invocations metric was unreadable (transient/throttle error)."
                    )
                    reason = "SageMaker Invocations metric could not be fetched; idle status is unconfirmed"
                elif partial_waste:
                    title = (
                        f"SageMaker Endpoint Partial Variant Waste "
                        f"({len(idle_variants)} of {variant_count} variants idle)"
                    )
                    summary = (
                        f"SageMaker endpoint '{endpoint_name}' has {len(idle_variants)} variant(s) "
                        f"with zero invocations for {effective_window} days while other variants remain active."
                    )
                    reason = (
                        f"{len(idle_variants)} of {variant_count} endpoint variants "
                        f"have zero invocations for {effective_window} days"
                    )
                else:
                    title = f"Idle SageMaker Endpoint (No Invocations for {effective_window} Days)"
                    summary = (
                        f"SageMaker endpoint '{endpoint_name}' has received zero invocations "
                        f"for {effective_window} days but remains InService, incurring continuous charges."
                    )
                    reason = f"SageMaker endpoint has zero invocations for {effective_window} days"

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.sagemaker.endpoint.idle",
                        resource_type="aws.sagemaker.endpoint",
                        resource_id=endpoint_name,
                        region=region,
                        estimated_monthly_cost_usd=monthly_cost,
                        title=title,
                        summary=summary,
                        reason=reason,
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "endpoint_name": endpoint_name,
                            "instance_type": primary_instance_type,
                            "is_gpu": is_gpu,
                            "variant_count": variant_count,
                            "idle_variant_count": len(idle_variants),
                            "active_variant_count": len(active_variants),
                            "total_instances": total_instances,
                            "total_provisioned_concurrency": total_provisioned_concurrency,
                            "age_days": int(age_days),
                            "idle_window_days": effective_window,
                            "idle_days_threshold": idle_days,
                            "idle_ratio": idle_ratio,
                            "invocation_datapoints_observed": total_datapoints,
                            "estimated_monthly_cost": (
                                f"~${monthly_cost:,.0f}/month (us-east-1 on-demand approx)"
                                if monthly_cost is not None
                                else "unknown — instance type not available; may be significantly higher"
                            ),
                            "cost_note": (
                                "instance type unknown; cost omitted — verify before dismissing"
                                if monthly_cost is None
                                else "approximate us-east-1 on-demand; region-dependent"
                            ),
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "sagemaker:ListEndpoints, sagemaker:DescribeEndpoint, "
                "sagemaker:DescribeEndpointConfig, cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _check_invocations(
    cloudwatch, endpoint_name: str, variant_names: list, days: int
) -> InvocationCheckResult:
    """Check per-variant invocations for the endpoint over the past `days` days.

    CloudWatch publishes SageMaker Invocations with *both* EndpointName and VariantName
    dimensions. Querying with EndpointName alone returns empty datapoints regardless of
    actual traffic. Each variant is queried independently.

    Note: SageMaker does NOT publish zero-value Invocations datapoints. An idle endpoint
    genuinely returns no datapoints — so empty results are the expected idle state when
    queried with the correct per-variant dimensions. With EndpointName-only (fallback),
    empty results are unreliable and cannot be treated as confirmed idle.

    The caller is responsible for checking `queried_with_variants` before treating
    empty idle_variants as a reliable idle signal. When `queried_with_variants=False`,
    the caller should skip the endpoint rather than emit a low-quality finding.

    Period=3600 (hourly) is intentional — finer granularity catches sparse traffic
    that a daily period might lump into zero-datapoint gaps.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))

    if not variant_names:
        # EndpointName-only fallback — known to return empty data for active endpoints.
        # queried_with_variants=False signals to the caller to skip rather than flag.
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/SageMaker",
                MetricName="Invocations",
                Dimensions=[{"Name": "EndpointName", "Value": endpoint_name}],
                StartTime=start_time,
                EndTime=now,
                Period=3600,
                Statistics=["Sum"],
            )
            datapoints = response.get("Datapoints", [])
            has_traffic = any(dp.get("Sum", 0) > 0 for dp in datapoints)
            return InvocationCheckResult(
                has_traffic=has_traffic,
                active_variants=[],
                idle_variants=[],
                total_datapoints=len(datapoints),
                queried_with_variants=False,
                fetch_failed=False,
            )
        except Exception:
            return InvocationCheckResult(
                has_traffic=True,
                active_variants=[],
                idle_variants=[],
                total_datapoints=0,
                queried_with_variants=False,
                fetch_failed=True,
            )

    # Per-variant query — correct dimension set for SageMaker Invocations.
    active_variants: list = []
    idle_variants: list = []
    total_datapoints = 0

    for variant_name in variant_names:
        dimensions = [
            {"Name": "EndpointName", "Value": endpoint_name},
            {"Name": "VariantName", "Value": variant_name},
        ]
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/SageMaker",
                MetricName="Invocations",
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=now,
                Period=3600,
                Statistics=["Sum"],
            )
            datapoints = response.get("Datapoints", [])
            total_datapoints += len(datapoints)
            if any(dp.get("Sum", 0) > 0 for dp in datapoints):
                active_variants.append(variant_name)
            else:
                idle_variants.append(variant_name)

        except Exception:
            # CloudWatch API failure — treat this variant as active and surface the failure.
            return InvocationCheckResult(
                has_traffic=True,
                active_variants=active_variants + [variant_name],
                idle_variants=idle_variants,
                total_datapoints=total_datapoints,
                queried_with_variants=True,
                fetch_failed=True,
            )

    # has_traffic=True if ANY variant has confirmed invocations.
    # The caller separately checks idle_variants to detect partial waste.
    has_traffic = len(active_variants) > 0
    return InvocationCheckResult(
        has_traffic=has_traffic,
        active_variants=active_variants,
        idle_variants=idle_variants,
        total_datapoints=total_datapoints,
        queried_with_variants=True,
        fetch_failed=False,
    )


def _is_gpu_instance(itype: str) -> bool:
    """Return True if the instance type is a GPU or accelerator family.

    Uses explicit prefix matching against known families first, then falls back
    to family-letter heuristics so newly released types (ml.g6e, ml.p6, etc.)
    are caught without requiring a code update.
    """
    if any(itype.startswith(fam) for fam in _GPU_FAMILIES):
        return True
    # Fallback: match by the family letter in the second dot-segment (e.g. ml.g6e.xlarge → "g6e")
    parts = itype.split(".")
    if len(parts) >= 2:
        family = parts[1]
        return any(family.startswith(p) for p in ("g", "p", "inf", "trn"))
    return False


def _describe_endpoint(
    sagemaker, endpoint_name: str
) -> Tuple[Optional[float], bool, int, int, Optional[str], list, int]:
    """Return (monthly_cost, is_gpu, variant_count, total_instances, primary_instance_type,
    variant_names, total_provisioned_concurrency).

    Instance type lives in the endpoint *config* (describe_endpoint_config), not in
    the endpoint summary (describe_endpoint ProductionVariantSummary has no InstanceType
    field — only DesiredInstanceCount). We make two calls: one for instance counts/serverless
    config, one for instance types/ServerlessConfig, then pair them by VariantName.

    Cost is computed per-variant:
    - Instance-backed: DesiredInstanceCount × per-instance monthly cost, summed across variants
    - Serverless with provisioned concurrency: units × $3.67/unit/month (us-east-1)
    GPU flag is True if any variant uses an accelerator instance.

    total_provisioned_concurrency is the sum of ProvisionedConcurrency across all serverless
    variants. A serverless endpoint with provisioned concurrency > 0 incurs cost even when idle.

    variant_names is returned so the caller can query CloudWatch per-variant without
    an extra describe_endpoint call.

    Returns (None, False, 0, 0, None, [], 0) on failure so the endpoint is skipped.

    Cost is None if ANY instance-backed variant has an unknown instance type — a partial
    sum would look accurate but silently underreport real spend (an unknown variant could
    be ml.p5 at $71K/month). Either all costs are known or we return None.
    """
    try:
        endpoint = sagemaker.describe_endpoint(EndpointName=endpoint_name)
        variants = endpoint.get("ProductionVariants", [])
        if not variants:
            return None, False, 0, 0, None, [], 0

        # Fetch instance types and ServerlessConfig from the endpoint config.
        # InstanceType and ServerlessConfig live in describe_endpoint_config, not in
        # the ProductionVariantSummary returned by describe_endpoint.
        config_name = endpoint.get("EndpointConfigName", "")
        instance_type_by_variant: dict = {}
        serverless_cfg_by_variant: dict = {}
        try:
            config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
            for cv in config.get("ProductionVariants", []):
                itype = cv.get("InstanceType")
                if itype:
                    instance_type_by_variant[cv["VariantName"]] = itype
                slcfg = cv.get("ServerlessConfig")
                if slcfg:
                    serverless_cfg_by_variant[cv["VariantName"]] = slcfg
        except Exception:
            pass  # config inaccessible — costs/GPU will use defaults

        accumulated_cost = 0.0
        all_costs_known = True
        is_gpu = False
        total_instances = 0
        total_provisioned_concurrency = 0
        primary_instance_type: Optional[str] = None
        variant_names = []

        for i, v in enumerate(variants):
            variant_name = v.get("VariantName", "")
            itype = instance_type_by_variant.get(variant_name)
            count = v.get("DesiredInstanceCount") or 0
            total_instances += count

            # Serverless provisioned concurrency — check runtime state (DescribeEndpoint)
            # first, then fall back to static config (DescribeEndpointConfig).
            # Both DesiredServerlessConfig and CurrentServerlessConfig are standard fields
            # on ProductionVariantSummary (boto3 botocore model: DescribeEndpointOutput);
            # they are NOT dead code. CurrentServerlessConfig = currently deployed state,
            # DesiredServerlessConfig = target state. We take max() to avoid undercounting
            # during in-progress updates where one may lag the other.
            ep_sl = v.get("DesiredServerlessConfig") or v.get("CurrentServerlessConfig") or {}
            cfg_sl = serverless_cfg_by_variant.get(variant_name, {})
            provisioned_concurrency = max(
                ep_sl.get("ProvisionedConcurrency") or 0,
                cfg_sl.get("ProvisionedConcurrency") or 0,
            )
            total_provisioned_concurrency += provisioned_concurrency

            if variant_name:
                variant_names.append(variant_name)

            if i == 0:
                primary_instance_type = itype

            if count > 0:
                # Instance-backed variant — cost depends on known instance type.
                cost_per_instance = _MONTHLY_COST_BY_FAMILY.get(itype)
                if cost_per_instance is not None:
                    accumulated_cost += cost_per_instance * count
                else:
                    # Unknown instance type makes the total unreliable — don't return
                    # a partial sum that silently underreports real spend.
                    all_costs_known = False
            elif provisioned_concurrency > 0:
                # Serverless variant with provisioned concurrency — cost is deterministic.
                # Does not affect all_costs_known; serverless pricing is well-defined.
                accumulated_cost += (
                    provisioned_concurrency * _SERVERLESS_PROVISIONED_COST_PER_UNIT_MONTHLY
                )
            # else: serverless without provisioned concurrency or instance at zero → no cost

            if itype and _is_gpu_instance(itype):
                is_gpu = True

        total_monthly_cost: Optional[float] = accumulated_cost if all_costs_known else None

        return (
            total_monthly_cost,
            is_gpu,
            len(variants),
            total_instances,
            primary_instance_type,
            variant_names,
            total_provisioned_concurrency,
        )

    except Exception:
        # Unknown state — return zero instances so the endpoint is skipped rather
        # than flagged with assumed cost and instance count.
        return None, False, 0, 0, None, [], 0
