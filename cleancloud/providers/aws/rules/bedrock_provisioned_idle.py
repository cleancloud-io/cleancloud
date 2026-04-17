import math
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.bedrock.provisioned_throughput.idle",
    "category": "ai",
    "service": "bedrock",
    "cost_impact": "high",
}

# Upper-bound monthly cost per Model Unit (no-commitment, us-east-1).
# Actual cost varies by region, commitment term, and AWS pricing changes.
# Reserved (1-month / 6-month) pricing is 25–60% lower — no-commitment is the ceiling.
# Match against the model ID prefix extracted from the foundation model ARN.
_MONTHLY_COST_PER_MU = {
    "anthropic.claude-3-opus": 7_300.0,
    "anthropic.claude-3-5-sonnet": 2_600.0,
    "anthropic.claude-3-sonnet": 2_600.0,
    "anthropic.claude-3-5-haiku": 600.0,
    "anthropic.claude-3-haiku": 600.0,
    "meta.llama3": 1_000.0,
    "meta.llama2": 500.0,
    "amazon.titan": 200.0,
    "mistral": 500.0,
    "cohere": 400.0,
}
_DEFAULT_MONTHLY_COST_PER_MU = 600.0


def find_idle_bedrock_provisioned_throughputs(
    session: boto3.Session,
    region: str,
    idle_days: int = 7,
) -> List[Finding]:
    """
    Find AWS Bedrock Provisioned Throughput reservations with zero invocations.

    Bedrock Provisioned Throughput reserves dedicated model capacity (Model Units)
    and bills continuously at up to ~$7,300/MU/month (no-commitment Claude 3 Opus),
    regardless of whether any inference requests are made. A provisioned throughput
    with zero invocations is paying for model capacity delivering zero value —
    typically an abandoned experiment, a proof-of-concept never decommissioned, or
    a migration where traffic moved to on-demand but the reservation was left running.

    This is the AWS equivalent of Azure OpenAI Provisioned Deployments and SageMaker
    Provisioned Inference Endpoints: same always-on billing model, same abandonment
    pattern.

    Detection logic:
    - Provisioned throughput is in InService state
    - Zero Invocations over the effective idle window (CloudWatch AWS/Bedrock,
      Invocations metric). Two ModelId dimension values are queried in order:
      1. Provisioned model ARN (primary — most specific)
      2. Base model ID with version suffix extracted from the foundation model ARN
         (e.g. anthropic.claude-3-sonnet-20240229-v1:0) — AWS inconsistently emits
         metrics under either dimension; if either shows traffic the reservation is
         treated as active (conservative)
    - CloudWatch does not publish Invocations data unless invocations occur —
      empty datapoints (after the age guard) reliably indicate an idle reservation

    Confidence:
    - HIGH: Zero invocations over the full idle window (effective_window >= idle_days)
    - MEDIUM: Zero invocations, effective_window >= ceil(75% of idle_days) but < idle_days

    Risk:
    - CRITICAL: idle_ratio >= 2.0 (reservation has been idle for 2× the threshold)
    - HIGH: all other cases (all MU reservations are always-on significant spend)

    IAM permissions:
    - bedrock:ListProvisionedModelThroughputs
    - cloudwatch:GetMetricStatistics
    """
    # Clamp to a minimum of 3 days so that effective_window never falls below the
    # < 3 guard and silently returns no findings for very small idle_days values.
    idle_days = max(idle_days, 3)

    bedrock = session.client("bedrock", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = bedrock.get_paginator("list_provisioned_model_throughputs")

        for page in paginator.paginate(statusEquals="InService"):
            for item in page.get("provisionedModelSummaries", []):
                name = item["provisionedModelName"]
                provisioned_arn = item["provisionedModelArn"]
                model_arn = item.get("modelArn") or item.get("foundationModelArn", "")
                desired_units = item.get("desiredModelUnits") or 0
                commitment = item.get("commitmentDuration", "NoCommitment")

                # Age guard — normalize timezone to handle boto3 returning tz-naive datetimes
                create_time = item.get("creationTime")
                age_days = 0
                if create_time:
                    if create_time.tzinfo is None:
                        create_time = create_time.replace(tzinfo=timezone.utc)
                    age_days = max((now - create_time).days, 0)

                # Skip reservations too new to be classified.
                # Use ceil(50%) consistent with the ceil(75%) MEDIUM threshold —
                # avoids the off-by-one that integer division introduces for odd idle_days
                # (e.g. 7//2=3 vs ceil(0.5×7)=4). Floor of 3 ensures we never skip
                # on age alone when idle_days is very small.
                if age_days < max(math.ceil(idle_days * 0.5), 3):
                    continue

                # Skip reservations with zero model units — InService with 0 units
                # shouldn't happen in practice, but would produce a cost-less HIGH/CRITICAL
                # finding which is misleading. Skip rather than flag.
                if desired_units <= 0:
                    continue

                # Cap the observation window to the reservation's actual age
                effective_window = min(idle_days, age_days)
                if effective_window < 3:
                    continue

                # Check whether any invocations occurred over the effective window.
                # Tries provisioned model ARN first, then base model ID fallback
                # (AWS inconsistently emits metrics under either dimension).
                has_invocations = _check_invocations(
                    cloudwatch, provisioned_arn, model_arn, effective_window
                )
                if has_invocations:
                    continue

                # Confidence tied to the strength of the zero-invocation signal
                if effective_window >= idle_days:
                    confidence = ConfidenceLevel.HIGH
                elif effective_window >= math.ceil(idle_days * 0.75):
                    # ceil(75%): reservation is close to the full threshold but hasn't
                    # crossed it yet. Surface as MEDIUM rather than skipping —
                    # early idle spend is still spend.
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    # Too early to be confident — prefer false negatives over false positives.
                    continue

                monthly_cost_per_mu = _cost_per_mu(model_arn)
                monthly_cost = monthly_cost_per_mu * desired_units if desired_units else None
                model_family = _parse_model_family(model_arn)

                idle_ratio = round(age_days / idle_days, 2) if idle_days > 0 else 0.0
                risk = RiskLevel.CRITICAL if idle_ratio >= 2.0 else RiskLevel.HIGH

                signals = [
                    f"Zero invocations over {effective_window}+ days (CloudWatch AWS/Bedrock)",
                    f"Reservation status: InService ({desired_units} Model Unit(s))",
                    f"Commitment term: {commitment}",
                    f"Reservation age: {age_days} days",
                ]
                if model_family:
                    signals.append(f"Model family: {model_family}")
                if monthly_cost:
                    signals.append(
                        f"Estimated upper-bound cost: ~${monthly_cost:,.0f}/month "
                        f"({desired_units} MU × ${monthly_cost_per_mu:,.0f}/MU, no-commitment us-east-1 — "
                        f"reserved terms and other regions may be lower; verify current rates)"
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Committed reservation term — deleting may forfeit prepaid capacity",
                        "Scheduled batch workloads with infrequent submission windows",
                        "Failover or backup capacity intentionally kept warm",
                        "Internal tooling with very low but non-zero request rates",
                    ],
                    time_window=f"{effective_window} days",
                )

                details = {
                    "provisioned_model_name": name,
                    "provisioned_model_arn": provisioned_arn,
                    "model_arn": model_arn,
                    "model_family": model_family,
                    "desired_model_units": desired_units,
                    "commitment_duration": commitment,
                    "age_days": age_days,
                    "idle_window_days": effective_window,
                    "idle_days_threshold": idle_days,
                    "idle_ratio": idle_ratio,
                }
                if monthly_cost:
                    details["estimated_monthly_cost"] = (
                        f"upper-bound ~${monthly_cost:,.0f}/month (no-commitment pricing)"
                    )

                title = (
                    f"Idle Bedrock Provisioned Throughput "
                    f"({desired_units} MU, No Invocations for {effective_window} Days)"
                )
                summary = (
                    f"Bedrock Provisioned Throughput '{name}' ({desired_units} MU, "
                    f"{model_family or model_arn}) has received zero invocations for "
                    f"{effective_window} days but continues to accrue reservation charges."
                )
                reason = (
                    f"Bedrock Provisioned Throughput has zero invocations for "
                    f"{effective_window} days ({desired_units} MU billed continuously)"
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.bedrock.provisioned_throughput.idle",
                        resource_type="aws.bedrock.provisioned_throughput",
                        resource_id=name,
                        region=region,
                        estimated_monthly_cost_usd=monthly_cost,
                        title=title,
                        summary=summary,
                        reason=reason,
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details=details,
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "bedrock:ListProvisionedModelThroughputs, "
                "cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _check_invocations(cloudwatch, provisioned_arn: str, model_arn: str, days: int) -> bool:
    """Return True if the provisioned throughput received any invocations in the past `days` days.

    CloudWatch only publishes Bedrock Invocations data when invocations actually occur.
    A reservation that has never been called will have no metric series — empty datapoints.
    The age guard in the caller ensures the reservation is old enough before this is
    called, so empty datapoints reliably indicates a genuinely idle reservation.

    AWS may emit metrics under the provisioned model ARN or (inconsistently) under the
    base foundation model ID. We query with the provisioned ARN first; if that returns
    no datapoints we retry with the base model ID extracted from model_arn. If either
    query shows activity we treat the reservation as active (conservative).

    The window is widened by 1 day to reduce boundary misses when a sparse datapoint
    falls just outside the nominal period end.

    Returns True (assume active) on any CloudWatch API failure — better to miss a true
    idle reservation than to flag an active one.
    """
    now = datetime.now(timezone.utc)
    # +1 day buffer: CloudWatch may place a sparse datapoint just outside the
    # nominal window boundary. Widening avoids classifying it as idle.
    start_time = now - timedelta(days=max(days, 1) + 1)

    def _query(model_id_value: str) -> Optional[bool]:
        """Query one ModelId dimension value. Returns True=active, False=idle, None=transient error.

        Auth errors (AccessDenied / AccessDeniedException / UnauthorizedOperation) are
        re-raised as PermissionError so the scan framework can surface the missing
        cloudwatch:GetMetricStatistics permission rather than silently skipping resources.
        """
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/Bedrock",
                MetricName="Invocations",
                Dimensions=[{"Name": "ModelId", "Value": model_id_value}],
                StartTime=start_time,
                EndTime=now,
                Period=86400,
                Statistics=["Sum"],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return False  # no data = zero invocations for this dimension value
            return any(dp.get("Sum", 0) > 0 for dp in datapoints)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "UnauthorizedOperation",
                "AccessDenied",
                "AccessDeniedException",
            ):
                raise PermissionError(
                    "Missing required IAM permissions: cloudwatch:GetMetricStatistics"
                ) from e
            return None  # transient error (throttle, outage) — caller treats as active

    # Primary: provisioned model ARN (most specific, preferred)
    result = _query(provisioned_arn)
    if result is None:
        return True  # conservative on API failure
    if result:
        return True  # active — has traffic under provisioned ARN

    # Fallback: base model ID (AWS inconsistently emits under foundation model ID).
    # Use _extract_model_id_for_cw (preserves :0 version suffix) rather than
    # _extract_model_id (strips version) so the CloudWatch dimension value matches
    # what AWS actually emits (e.g. "anthropic.claude-3-sonnet-20240229-v1:0").
    base_model_id = _extract_model_id_for_cw(model_arn)
    if base_model_id and base_model_id != provisioned_arn:
        result = _query(base_model_id)
        if result is None:
            return True  # conservative on API failure
        if result:
            return True  # active — metrics found under base model ID

    return False  # neither dimension shows activity


def _extract_model_id(model_arn: str) -> Optional[str]:
    """Safely extract the bare model ID from a Bedrock model ARN or model ID string.

    Foundation model ARN format:
        arn:aws:bedrock:REGION::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0
    Returns:
        anthropic.claude-3-sonnet-20240229-v1   (lowercase, no version suffix)
        None if extraction fails or input is empty

    Used for family-prefix matching and cost lookup — version suffix not needed.
    For CloudWatch dimension queries use _extract_model_id_for_cw instead.
    """
    if not model_arn:
        return None
    try:
        return model_arn.rsplit("/", 1)[-1].split(":")[0].lower() or None
    except Exception:
        return None


def _extract_model_id_for_cw(model_arn: str) -> Optional[str]:
    """Extract the model ID for use as a CloudWatch ModelId dimension value.

    Unlike _extract_model_id, this preserves the version suffix (e.g. :0) so the
    dimension value matches what AWS actually emits in CloudWatch metrics:
        anthropic.claude-3-sonnet-20240229-v1:0  (not anthropic.claude-3-sonnet-20240229-v1)

    Foundation model ARN format:
        arn:aws:bedrock:REGION::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0
    Returns:
        anthropic.claude-3-sonnet-20240229-v1:0  (lowercase, version suffix retained)
        None if extraction fails or input is empty
    """
    if not model_arn:
        return None
    try:
        return model_arn.rsplit("/", 1)[-1].lower() or None
    except Exception:
        return None


def _parse_model_family(model_arn: str) -> Optional[str]:
    """Extract a human-readable model family label from a Bedrock model ARN or model ID."""
    model_id = _extract_model_id(model_arn)
    if not model_id:
        return None
    # Match known prefixes — longest first to avoid partial matches
    # (e.g. anthropic.claude-3-5-sonnet before anthropic.claude-3-sonnet)
    for prefix in sorted(_MONTHLY_COST_PER_MU, key=len, reverse=True):
        if model_id.startswith(prefix):
            return prefix
    return model_id


def _cost_per_mu(model_arn: str) -> float:
    """Return approximate monthly cost per Model Unit for the given model ARN."""
    family = _parse_model_family(model_arn)
    if family:
        return _MONTHLY_COST_PER_MU.get(family, _DEFAULT_MONTHLY_COST_PER_MU)
    return _DEFAULT_MONTHLY_COST_PER_MU
