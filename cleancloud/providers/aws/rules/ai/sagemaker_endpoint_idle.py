"""
Rule: aws.sagemaker.endpoint.idle

    (spec — docs/specs/aws/ai/sagemaker_endpoint_idle.md)

Intent:
    Detect SageMaker inference endpoints that are currently InService, still have billable
    compute allocated, and show no observed InvokeEndpoint request activity for the
    configured lookback window, so they can be reviewed as cleanup candidates.

    This is a read-only review-candidate rule. Not proof that the endpoint is safe to
    delete, and not proof that there are no other traffic patterns.

Exclusions:
    - endpoint_arn or endpoint_name absent (malformed identity)
    - creation_time_utc or last_modified_time_utc absent, naive, or reference_time future
    - age_days < idle_days_threshold (too new)
    - DescribeEndpoint failure (insufficient evidence for this item)
    - DescribeEndpointConfig failure (insufficient evidence for this item)
    - AsyncInferenceConfig present (out of scope — async traffic not detectable)
    - no billable production variants
    - any evaluated variant has positive Invocations Sum
    - CloudWatch retrieval failure for any variant

Detection:
    - InService endpoint, age >= idle_days_threshold
    - not an async endpoint (AsyncInferenceConfig absent)
    - at least one billable production variant
    - no observed InvokeEndpoint traffic across all billable variants

Key rules:
    - resource_id = endpoint_arn (not endpoint_name)
    - reference_time = max(creation_time_utc, last_modified_time_utc)
    - DescribeEndpoint / DescribeEndpointConfig: permission failure → FAIL RULE; transient failure → SKIP ITEM
    - CloudWatch per-variant: permission failure → FAIL RULE; transient failure → SKIP ITEM
    - No datapoints → weaker idle evidence (MEDIUM confidence)
    - Positive invocations → SKIP ITEM
    - estimated_monthly_cost_usd = None
    - Confidence: HIGH (all variants had datapoints + zero) or MEDIUM (any no-datapoint variant)
    - Risk: HIGH (accelerator-backed: g*, p*, inf*, trn*) or MEDIUM (other)

Blind spots:
    - InvokeEndpointAsync traffic and async endpoint intent
    - Multi-model endpoint per-model burstiness and model-loading behavior
    - Shadow production variant intent
    - Inference-component-specific traffic review
    - Managed instance scaling floor/warm-capacity intent
    - Scheduled future usage, failover intent, or reserved warm capacity intent
    - Exact region-specific pricing impact

APIs:
    - sagemaker:ListEndpoints
    - sagemaker:DescribeEndpoint
    - sagemaker:DescribeEndpointConfig
    - cloudwatch:GetMetricStatistics
"""

import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATUS = "InService"
_CW_NAMESPACE = "AWS/SageMaker"
_CW_METRIC = "Invocations"

_FINDING_TITLE = "Idle SageMaker endpoint review candidate"

_SIGNALS_NOT_CHECKED = (
    "InvokeEndpointAsync traffic and async endpoint intent",
    "Multi-model endpoint per-model burstiness and model-loading behavior",
    "Shadow production variant intent",
    "Inference-component-specific traffic review",
    "Managed instance scaling floor/warm-capacity intent",
    "Scheduled future usage, failover intent, or reserved warm capacity intent",
    "Exact region-specific pricing impact",
)

RULE_METADATA = {
    "id": "aws.sagemaker.endpoint.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _choose_period(idle_days: int) -> int:
    """Return the smallest legal CloudWatch period for the requested lookback.

    Two constraints must both be satisfied:

    1. Datapoints ≤ 1440:
           period ≥ ceil(idle_days × 86400 / 1440)

    2. Period must be a multiple of the granularity for the lookback age,
       matching CloudWatch's retention-tier alignment rules:
           ≤ 15 days  → multiple of 60 s   (1-minute tier)
           ≤ 63 days  → multiple of 300 s  (5-minute tier)
           > 63 days  → multiple of 3600 s (1-hour tier)

    The selected period is the smallest integer satisfying both.
    """
    window_seconds = idle_days * 86400
    min_period = math.ceil(window_seconds / 1440)
    if idle_days <= 15:
        granularity = 60
    elif idle_days <= 63:
        granularity = 300
    else:
        granularity = 3600
    return math.ceil(min_period / granularity) * granularity


def _is_gpu_instance(instance_type: str) -> bool:
    """Return True if the instance type is GPU/accelerator-backed (g*, p*, inf*, trn*)."""
    parts = instance_type.split(".")
    if len(parts) >= 2:
        family = parts[1]
        return any(family.startswith(prefix) for prefix in ("g", "p", "inf", "trn"))
    return False


def _normalize_endpoint_summary(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListEndpoints item to the canonical field shape.

    Returns None when required identity or timestamp fields are absent or invalid —
    the caller must skip the item. All rule logic operates only on the returned dict.
    """
    if not isinstance(item, dict):
        return None

    endpoint_arn = _str(item.get("EndpointArn"))
    if endpoint_arn is None:
        return None

    endpoint_name = _str(item.get("EndpointName"))
    if endpoint_name is None:
        return None

    endpoint_status = _str(item.get("EndpointStatus"))
    if endpoint_status is None:
        return None

    # CreationTime (required; absent, naive, or future → skip)
    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)

    # LastModifiedTime (required; absent, naive, or future → skip)
    raw_lmt = item.get("LastModifiedTime")
    if not isinstance(raw_lmt, datetime):
        return None
    if raw_lmt.tzinfo is None:
        return None
    last_modified_time_utc = raw_lmt.astimezone(timezone.utc)

    # reference_time = max(creation, last_modified) — future reference → skip
    reference_time_utc = max(creation_time_utc, last_modified_time_utc)
    if reference_time_utc > now_utc:
        return None

    age_days = int((now_utc - reference_time_utc).total_seconds() // 86400)

    return {
        "resource_id": endpoint_arn,
        "endpoint_arn": endpoint_arn,
        "endpoint_name": endpoint_name,
        "endpoint_status": endpoint_status,
        "creation_time_utc": creation_time_utc,
        "last_modified_time_utc": last_modified_time_utc,
        "reference_time_utc": reference_time_utc,
        "age_days": age_days,
    }


def _normalize_variant(
    rv: dict,
    config_variants_by_name: Dict[str, dict],
) -> Optional[dict]:
    """Normalize a runtime production variant from DescribeEndpoint.ProductionVariants.

    Runtime state from DescribeEndpoint is the authoritative evaluation set.
    DescribeEndpointConfig.ProductionVariants are joined by VariantName for
    enrichment only and must not be the canonical billing driver.

    Returns None when variant_name is absent — caller must skip the variant.
    """
    variant_name = _str(rv.get("VariantName"))
    if variant_name is None:
        return None

    # Runtime state — authoritative for billing determination
    raw_count = rv.get("CurrentInstanceCount")
    current_instance_count = raw_count if isinstance(raw_count, int) else None

    current_sl = rv.get("CurrentServerlessConfig") or {}
    raw_prov = current_sl.get("ProvisionedConcurrency")
    current_serverless_provisioned_concurrency = raw_prov if isinstance(raw_prov, int) else None

    managed_instance_scaling_present = rv.get("ManagedInstanceScaling") is not None

    # Config enrichment (contextual only — not the billing driver)
    cfg_v = config_variants_by_name.get(variant_name, {})
    instance_type = _str(cfg_v.get("InstanceType"))
    cfg_sl = cfg_v.get("ServerlessConfig") or {}
    raw_cfg_prov = cfg_sl.get("ProvisionedConcurrency")
    configured_serverless_provisioned_concurrency = (
        raw_cfg_prov if isinstance(raw_cfg_prov, int) else None
    )

    is_serverless_variant = bool(cfg_sl) or rv.get("CurrentServerlessConfig") is not None

    # Billing determination (runtime state authoritative per spec)
    instance_billable = (current_instance_count or 0) > 0
    serverless_billable = (current_serverless_provisioned_concurrency or 0) > 0
    is_billable = instance_billable or serverless_billable

    if instance_billable and serverless_billable:
        billable_compute_mode = "mixed"
    elif instance_billable:
        billable_compute_mode = "instance"
    elif serverless_billable:
        billable_compute_mode = "serverless_provisioned"
    else:
        billable_compute_mode = "none"

    return {
        "variant_name": variant_name,
        "current_instance_count": current_instance_count,
        "current_serverless_provisioned_concurrency": current_serverless_provisioned_concurrency,
        "configured_serverless_provisioned_concurrency": configured_serverless_provisioned_concurrency,
        "instance_type": instance_type,
        "managed_instance_scaling_present": managed_instance_scaling_present,
        "is_serverless_variant": is_serverless_variant,
        "is_billable": is_billable,
        "billable_compute_mode": billable_compute_mode,
    }


def _get_variant_invocations(
    cloudwatch,
    endpoint_name: str,
    variant_name: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[Tuple[float, bool]]:
    """Fetch Invocations Sum for a single production variant over the observation window.

    Returns (total_sum, had_datapoints) on success:
    - had_datapoints=True:  datapoints present; total_sum is the aggregate Sum (>= 0.0)
    - had_datapoints=False: no datapoints — weaker idle evidence (no published metric series)

    Returns None on transient API failure — caller must SKIP ITEM.
    Raises PermissionError on missing IAM permission — FAIL RULE.

    Dimensions must be EndpointName + VariantName (the documented published pair).
    EndpointName-only queries are not canonical and are not used as a fallback.
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=_CW_METRIC,
            Dimensions=[
                {"Name": "EndpointName", "Value": endpoint_name},
                {"Name": "VariantName", "Value": variant_name},
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=["Sum"],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        return None  # Other API error → caller SKIP ITEM
    except BotoCoreError:
        return None  # Transport/connection error → caller SKIP ITEM

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return 0.0, False  # No metric series — weaker idle evidence
    return sum(dp.get("Sum", 0.0) for dp in datapoints), True


def find_idle_sagemaker_endpoints(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    period = _choose_period(idle_days_threshold)
    findings: List[Finding] = []

    # Step 1: Retrieve and fully paginate ListEndpoints (FAIL RULE on failure)
    try:
        paginator = sagemaker.get_paginator("list_endpoints")
        pages = list(paginator.paginate(StatusEquals=_ELIGIBLE_STATUS))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError(
                "Missing required IAM permission: sagemaker:ListEndpoints"
            ) from exc
        raise
    except BotoCoreError:
        raise

    for page in pages:
        for raw_item in page.get("Endpoints", []):
            # Step 2: Normalize endpoint summary
            n = _normalize_endpoint_summary(raw_item, now)
            if n is None:
                continue

            # Step 3: Age gate
            if n["age_days"] < idle_days_threshold:
                continue

            # Step 4: DescribeEndpoint (SKIP ITEM on transient failure; FAIL RULE on permission)
            try:
                desc = sagemaker.describe_endpoint(EndpointName=n["endpoint_name"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] in (
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                ):
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeEndpoint"
                    ) from exc
                continue  # Other API error → SKIP ITEM
            except BotoCoreError:
                continue  # Transport/connection error → SKIP ITEM

            # Step 5: Re-check EndpointStatus from DescribeEndpoint
            if _str(desc.get("EndpointStatus")) != _ELIGIBLE_STATUS:
                continue

            # Step 6: Resolve EndpointConfigName (required for DescribeEndpointConfig)
            config_name = _str(desc.get("EndpointConfigName"))
            if config_name is None:
                continue

            # Step 6: DescribeEndpointConfig (SKIP ITEM on transient failure; FAIL RULE on permission)
            try:
                config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] in (
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                ):
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeEndpointConfig"
                    ) from exc
                continue  # Other API error → SKIP ITEM
            except BotoCoreError:
                continue  # Transport/connection error → SKIP ITEM

            # Step 7: Async scope check — AsyncInferenceConfig present → SKIP ITEM
            if config.get("AsyncInferenceConfig") is not None:
                continue

            # Steps 8–10: Normalize runtime variants; join config for enrichment only
            config_variants_by_name: Dict[str, dict] = {
                cv.get("VariantName"): cv
                for cv in config.get("ProductionVariants", [])
                if cv.get("VariantName")
            }

            normalized_variants = []
            for rv in desc.get("ProductionVariants", []):
                nv = _normalize_variant(rv, config_variants_by_name)
                if nv is None:
                    continue
                normalized_variants.append(nv)

            if not normalized_variants:
                continue

            # Steps 11–12: Determine billable variants
            billable_variants = [v for v in normalized_variants if v["is_billable"]]
            if not billable_variants:
                continue

            # Steps 13–14: CloudWatch Invocations per billable variant
            skip_item = False
            no_datapoint_variant_count = 0
            total_invocations_sum = 0.0
            all_had_datapoints = True

            for v in billable_variants:
                result = _get_variant_invocations(
                    cloudwatch,
                    n["endpoint_name"],
                    v["variant_name"],
                    window_start,
                    now,
                    period,
                )
                if result is None:
                    # CloudWatch API failure → SKIP ITEM
                    skip_item = True
                    break

                inv_sum, had_datapoints = result
                if not had_datapoints:
                    no_datapoint_variant_count += 1
                    all_had_datapoints = False

                if inv_sum > 0:
                    # Observed traffic → SKIP ITEM
                    skip_item = True
                    break

                total_invocations_sum += inv_sum

            if skip_item:
                continue

            # Step 15: Emit finding

            # Confidence
            confidence = ConfidenceLevel.HIGH if all_had_datapoints else ConfidenceLevel.MEDIUM

            # Risk: HIGH for accelerator-backed, MEDIUM otherwise
            is_gpu_or_accelerator_backed = any(
                _is_gpu_instance(v["instance_type"])
                for v in billable_variants
                if v["instance_type"]
            )
            risk = RiskLevel.HIGH if is_gpu_or_accelerator_backed else RiskLevel.MEDIUM

            # Endpoint-level billable_compute_mode
            instance_billable_present = any(
                v["billable_compute_mode"] in ("instance", "mixed") for v in billable_variants
            )
            serverless_billable_present = any(
                v["billable_compute_mode"] in ("serverless_provisioned", "mixed")
                for v in billable_variants
            )
            if instance_billable_present and serverless_billable_present:
                endpoint_billable_compute_mode = "mixed"
            elif instance_billable_present:
                endpoint_billable_compute_mode = "instance"
            else:
                endpoint_billable_compute_mode = "serverless_provisioned"

            total_current_instance_count = sum(
                (v["current_instance_count"] or 0) for v in billable_variants
            )
            total_provisioned_concurrency = sum(
                (v["current_serverless_provisioned_concurrency"] or 0) for v in billable_variants
            )

            signals_used = [
                f"Endpoint status is '{_ELIGIBLE_STATUS}' (serving capacity)",
                (
                    f"Endpoint age is {n['age_days']} days, meeting the {idle_days_threshold}-day "
                    f"threshold using the later of creation time and last-modified time"
                ),
                "Async inference was excluded: DescribeEndpointConfig.AsyncInferenceConfig absent",
                (
                    f"Billable compute remains allocated across {len(billable_variants)} "
                    f"production variant(s)"
                ),
                (
                    f"No observed positive InvokeEndpoint traffic across all evaluated runtime "
                    f"production variants over the {idle_days_threshold}-day observation window"
                ),
            ]
            if no_datapoint_variant_count > 0:
                signals_used.append(
                    f"{no_datapoint_variant_count} variant(s) returned no CloudWatch datapoints "
                    "— treated as lower-confidence 'no recorded invocation metrics' evidence, "
                    "not as proven zero traffic"
                )

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.endpoint.idle",
                    resource_type="aws.sagemaker.endpoint",
                    resource_id=n["endpoint_arn"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker endpoint {n['endpoint_name']} has no observed InvokeEndpoint "
                        f"traffic in the last {idle_days_threshold} days while billable compute "
                        f"remains allocated"
                    ),
                    reason=(
                        f"InService SageMaker endpoint shows no observed InvokeEndpoint traffic "
                        f"in the last {idle_days_threshold} days while billable compute remains "
                        f"allocated"
                    ),
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-sagemaker-endpoint-review-candidate",
                        "endpoint_arn": n["endpoint_arn"],
                        "endpoint_name": n["endpoint_name"],
                        "endpoint_status": "InService",
                        "endpoint_config_name": config_name,
                        "creation_time": n["creation_time_utc"].isoformat(),
                        "last_modified_time": n["last_modified_time_utc"].isoformat(),
                        "reference_time": n["reference_time_utc"].isoformat(),
                        "evaluation_window_start": window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "age_days": n["age_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "variant_names_evaluated": [v["variant_name"] for v in billable_variants],
                        "billable_variant_count": len(billable_variants),
                        "billable_compute_mode": endpoint_billable_compute_mode,
                        "total_current_instance_count": total_current_instance_count,
                        "total_provisioned_concurrency": total_provisioned_concurrency,
                        "invocation_metric_namespace": _CW_NAMESPACE,
                        "invocation_metric_name": _CW_METRIC,
                        "invocation_dimensions": "EndpointName + VariantName",
                        "traffic_detected": False,
                        "no_datapoint_variant_count": no_datapoint_variant_count,
                        "total_invocations_sum": total_invocations_sum,
                        # Optional context
                        "instance_types": sorted(
                            {v["instance_type"] for v in billable_variants if v["instance_type"]}
                        ),
                        "is_gpu_or_accelerator_backed": is_gpu_or_accelerator_backed,
                        "managed_instance_scaling_present": any(
                            v["managed_instance_scaling_present"] for v in billable_variants
                        ),
                    },
                )
            )

    return findings
