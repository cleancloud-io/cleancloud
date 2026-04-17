from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

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
_DEFAULT_MONTHLY_COST = 150.0


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
    - Endpoint has at least one running instance (DesiredInstanceCount > 0)
    - Zero Invocations over the effective idle window (CloudWatch AWS/SageMaker)

    Confidence:
    - HIGH: Zero invocations over the full idle window (age >= idle_days)
    - MEDIUM: Zero invocations, age >= 75% of idle_days threshold

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
                # from older boto3 versions, which would otherwise raise TypeError
                create_time = endpoint.get("CreationTime")
                age_days = 0
                if create_time:
                    if create_time.tzinfo is None:
                        create_time = create_time.replace(tzinfo=timezone.utc)
                    age_days = (now - create_time).days

                # Skip endpoints younger than half the idle threshold —
                # too new to reliably classify as abandoned
                if age_days < max(idle_days // 2, 7):
                    continue

                # Describe endpoint — get cost, GPU flag, variant info
                (
                    monthly_cost,
                    is_gpu,
                    variant_count,
                    total_instances,
                    primary_instance_type,
                ) = _describe_endpoint(sagemaker, endpoint_name)

                # Skip scaled-to-zero endpoints — no running instances, no compute cost
                if total_instances == 0:
                    continue

                # Use effective window: can't look back further than the endpoint's age
                effective_window = min(idle_days, age_days)

                # Skip if effective window is too small to draw a reliable conclusion
                if effective_window < 3:
                    continue

                # Check invocations over the effective window
                has_invocations = _check_invocations(cloudwatch, endpoint_name, effective_window)
                if has_invocations:
                    continue

                # Confidence based on the observed CloudWatch window, not just age.
                # effective_window is the period we actually checked for zero invocations —
                # using it directly ties confidence to the strength of the signal.
                if effective_window >= idle_days:
                    confidence = ConfidenceLevel.HIGH
                elif effective_window >= int(idle_days * 0.75):
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    continue  # too borderline for a confident finding

                # idle_ratio: how many multiples of the threshold the endpoint has been running.
                # >= 2.0 means a GPU endpoint has been burning money for 2× the idle window.
                idle_ratio = round(age_days / idle_days, 2) if idle_days > 0 else 0.0
                if is_gpu and idle_ratio >= 2.0:
                    risk = RiskLevel.CRITICAL
                elif is_gpu:
                    risk = RiskLevel.HIGH
                else:
                    risk = RiskLevel.MEDIUM

                signals = [
                    f"Zero recorded invocations for {effective_window} days (CloudWatch metric)",
                    "Endpoint state: InService",
                    f"Endpoint age: {age_days} days",
                    f"Total running instances (DesiredInstanceCount): {total_instances}",
                ]
                if primary_instance_type:
                    signals.append(f"Instance type: {primary_instance_type}")
                if is_gpu:
                    signals.append("GPU-backed instance — high hourly cost")
                if variant_count > 1:
                    signals.append(f"Production variants: {variant_count}")

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Scheduled or batch invocation patterns",
                        "Internal health-check invocations",
                        "Planned future usage",
                        "Shadow mode / canary deployments",
                    ],
                    time_window=f"{effective_window} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.sagemaker.endpoint.idle",
                        resource_type="aws.sagemaker.endpoint",
                        resource_id=endpoint_name,
                        region=region,
                        estimated_monthly_cost_usd=monthly_cost,
                        title=f"Idle SageMaker Endpoint (No Invocations for {effective_window} Days)",
                        summary=(
                            f"SageMaker endpoint '{endpoint_name}' has received zero invocations "
                            f"for {effective_window} days but remains InService, incurring continuous charges."
                        ),
                        reason=f"SageMaker endpoint has zero invocations for {effective_window} days",
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "endpoint_name": endpoint_name,
                            "instance_type": primary_instance_type,
                            "is_gpu": is_gpu,
                            "variant_count": variant_count,
                            "total_instances": total_instances,
                            "age_days": age_days,
                            "idle_window_days": effective_window,
                            "idle_days_threshold": idle_days,
                            "idle_ratio": idle_ratio,
                            "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                            "cost_source": f"approximate_{region}",
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


def _check_invocations(cloudwatch, endpoint_name: str, days: int) -> bool:
    """Return True if the endpoint received any invocations in the past `days` days.

    CloudWatch only publishes SageMaker Invocations data when invocations actually occur.
    An endpoint that has never been called will have no metric series — empty datapoints.
    This function is only called after the age guard ensures the endpoint is ≥7 days old,
    so empty datapoints reliably indicates a genuinely idle endpoint.

    Returns True (assume active) only on CloudWatch API failure (ClientError).
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))

    try:
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/SageMaker",
            MetricName="Invocations",
            Dimensions=[{"Name": "EndpointName", "Value": endpoint_name}],
            StartTime=start_time,
            EndTime=now,
            Period=3600,  # 1 hour — more datapoints, more reliable for sparse traffic
            Statistics=["Sum"],
        )
        datapoints = response.get("Datapoints", [])
        # Empty datapoints: CloudWatch never recorded any invocations.
        # The age guard guarantees this endpoint is ≥7 days old, so "no data" means idle.
        if not datapoints:
            return False
        return any(dp.get("Sum", 0) > 0 for dp in datapoints)

    except ClientError:
        # CloudWatch API failure (permissions, throttle, regional outage).
        # Treat as active — better to miss a true idle endpoint than to flag a
        # healthy one. The endpoint will be re-evaluated on the next scan.
        return True


def _describe_endpoint(
    sagemaker, endpoint_name: str
) -> Tuple[float, bool, int, int, Optional[str]]:
    """Return (monthly_cost, is_gpu, variant_count, total_instances, primary_instance_type).

    Instance type lives in the endpoint *config* (describe_endpoint_config), not in
    the endpoint summary (describe_endpoint ProductionVariantSummary has no InstanceType
    field — only DesiredInstanceCount). We make two calls: one for instance counts,
    one for instance types, then pair them by VariantName.

    Cost is computed per-variant using DesiredInstanceCount × per-instance cost, summed
    across all variants. GPU flag is True if any variant uses an accelerator instance.

    Returns (0, False, 0, 0, None) on failure so the endpoint is skipped rather than
    flagged with assumed values.
    """
    try:
        endpoint = sagemaker.describe_endpoint(EndpointName=endpoint_name)
        variants = endpoint.get("ProductionVariants", [])
        if not variants:
            return _DEFAULT_MONTHLY_COST, False, 0, 0, None

        # Fetch instance types from the endpoint config
        config_name = endpoint.get("EndpointConfigName", "")
        instance_type_by_variant: dict = {}
        try:
            config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
            for cv in config.get("ProductionVariants", []):
                itype = cv.get("InstanceType")
                if itype:
                    instance_type_by_variant[cv["VariantName"]] = itype
        except ClientError:
            pass  # config inaccessible — costs/GPU will use defaults

        total_monthly_cost = 0.0
        is_gpu = False
        total_instances = 0
        primary_instance_type: Optional[str] = None

        for i, v in enumerate(variants):
            itype = instance_type_by_variant.get(v.get("VariantName", ""))
            count = v.get("DesiredInstanceCount") or 0
            total_instances += count

            if i == 0:
                primary_instance_type = itype

            cost_per_instance = _MONTHLY_COST_BY_FAMILY.get(itype, _DEFAULT_MONTHLY_COST)
            total_monthly_cost += cost_per_instance * count

            if itype and any(itype.startswith(fam) for fam in _GPU_FAMILIES):
                is_gpu = True

        return (
            total_monthly_cost,
            is_gpu,
            len(variants),
            total_instances,
            primary_instance_type,
        )

    except ClientError:
        # Unknown state — return zero instances so the endpoint is skipped rather
        # than flagged with assumed cost and instance count.
        return 0.0, False, 0, 0, None
