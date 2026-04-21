"""
Rule: aws.bedrock.provisioned_throughput.idle

    (spec — docs/specs/aws/ai/bedrock_provisioned_idle.md)

Intent:
    Detect Amazon Bedrock Provisioned Throughputs that are currently InService
    and show no observed runtime request activity for the configured observation
    window, so they can be reviewed as potential FinOps cleanup or rightsizing
    candidates.

    This is a read-only review-candidate rule. Not proof that the throughput
    is safe to delete, not proof that no one intends to use it, and not proof
    that immediate savings are available if the throughput is under commitment.

Exclusions:
    - provisioned_model_arn absent (malformed identity)
    - normalized_status absent or not "InService"
    - creation_time_utc absent, naive, or in the future
    - age_days < idle_days_threshold (too new to evaluate)
    - any required activity metric returns no datapoints (insufficient evidence)
    - any required activity metric has Sum > 0 (observed runtime activity)

Detection:
    - InService Provisioned Throughput older than threshold
    - all 4 required CloudWatch activity metrics return datapoints
    - all observed Sum values are exactly 0 over the observation window

Key rules:
    - Required metrics: Invocations, InvocationClientErrors,
      InvocationServerErrors, InvocationThrottles (Sum).
    - ModelId dimension must be provisionedModelArn only.
    - Missing CloudWatch datapoints → SKIP ITEM (not zero).
    - CloudWatch API failure → FAIL RULE.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH always.
    - Risk: HIGH always.

Blind spots:
    - Whether the throughput is intentionally kept warm for failover or rare
      batch windows
    - Whether a commitment term prevents immediate deletion
    - Whether future traffic is expected soon
    - Application/business criticality
    - Exact current pricing and immediate avoidable savings

APIs:
    - bedrock:ListProvisionedModelThroughputs
    - cloudwatch:GetMetricStatistics
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 7
_ELIGIBLE_STATUS = "InService"
_CW_NAMESPACE = "AWS/Bedrock"
_CW_DIM = "ModelId"

# Required runtime-activity metrics in evaluation order
_REQUIRED_METRICS: Tuple[str, ...] = (
    "Invocations",
    "InvocationClientErrors",
    "InvocationServerErrors",
    "InvocationThrottles",
)

_FINDING_TITLE = "Idle Bedrock Provisioned Throughput review candidate"

_SIGNALS_NOT_CHECKED = (
    "Whether the throughput is intentionally kept warm for failover or rare batch windows",
    "Whether a commitment term prevents immediate deletion",
    "Whether future traffic is expected soon",
    "Application/business criticality",
    "Exact current pricing and immediate avoidable savings",
)

RULE_METADATA = {
    "id": "aws.bedrock.provisioned_throughput.idle",
    "category": "ai",
    "service": "bedrock",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _choose_period(idle_days: int) -> int:
    """Return a deterministic Period compliant with CloudWatch retention rules.

    idle_days * 86400 is a multiple of 60, 300, and 3600, satisfying all three
    CloudWatch retention constraints for the chosen lookback window.
    """
    return idle_days * 86400


def _normalize_provisioned_throughput(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListProvisionedModelThroughputs item to the canonical field shape.

    Returns None when required identity/status/age fields are absent or invalid —
    the caller must skip the item. All rule logic must operate only on the
    returned normalized dict.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity (required; absent → skip) ---
    # resource_id must be provisionedModelArn, not the friendly name.
    provisioned_model_arn = _str(item.get("provisionedModelArn"))
    if provisioned_model_arn is None:
        return None

    # --- Status (required; absent → skip) ---
    normalized_status = _str(item.get("status"))
    if normalized_status is None:
        return None

    # --- creationTime (required; absent, naive, or future → skip) ---
    raw_ct = item.get("creationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        # Naive datetime — cannot safely compare to UTC; treat as absent → skip.
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc:
        # Future creationTime is invalid → skip.
        return None
    age_days = int((now_utc - creation_time_utc).total_seconds() // 86400)

    # --- Optional context fields ---
    provisioned_model_name = _str(item.get("provisionedModelName"))
    model_arn = _str(item.get("modelArn"))
    foundation_model_arn = _str(item.get("foundationModelArn"))
    commitment_duration = _str(item.get("commitmentDuration"))

    raw_model_units = item.get("modelUnits")
    model_units = raw_model_units if isinstance(raw_model_units, int) else None

    raw_desired = item.get("desiredModelUnits")
    desired_model_units = raw_desired if isinstance(raw_desired, int) else None

    # Contextual timestamps (naive → null; does not suppress detection)
    commitment_expiration_time_utc = None
    raw_exp = item.get("commitmentExpirationTime")
    if isinstance(raw_exp, datetime) and raw_exp.tzinfo is not None:
        commitment_expiration_time_utc = raw_exp.astimezone(timezone.utc)

    last_modified_time_utc = None
    raw_lmt = item.get("lastModifiedTime")
    if isinstance(raw_lmt, datetime) and raw_lmt.tzinfo is not None:
        last_modified_time_utc = raw_lmt.astimezone(timezone.utc)

    return {
        "resource_id": provisioned_model_arn,
        "provisioned_model_arn": provisioned_model_arn,
        "provisioned_model_name": provisioned_model_name,
        "normalized_status": normalized_status,
        "creation_time_utc": creation_time_utc,
        "age_days": age_days,
        "model_arn": model_arn,
        "foundation_model_arn": foundation_model_arn,
        "model_units": model_units,
        "desired_model_units": desired_model_units,
        "commitment_duration": commitment_duration,
        "commitment_expiration_time_utc": commitment_expiration_time_utc,
        "last_modified_time_utc": last_modified_time_utc,
    }


def _get_metric_sum(
    cloudwatch,
    provisioned_model_arn: str,
    metric_name: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[float]:
    """Fetch a single Bedrock runtime-activity metric Sum over the observation window.

    Returns None if no datapoints (insufficient evidence → caller must SKIP ITEM).
    Returns the aggregated Sum (>= 0.0) if datapoints are present.
    Raises ClientError / BotoCoreError / PermissionError on API failure (caller → FAIL RULE).

    ModelId dimension is always provisionedModelArn — no undocumented fallback dimensions.
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[{"Name": _CW_DIM, "Value": provisioned_model_arn}],
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
        raise
    except BotoCoreError:
        raise

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None  # No datapoints → insufficient evidence → SKIP ITEM

    return sum(dp.get("Sum", 0.0) for dp in datapoints)


def find_idle_bedrock_provisioned_throughputs(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    bedrock = session.client("bedrock", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    try:
        paginator = bedrock.get_paginator("list_provisioned_model_throughputs")
        pages = list(paginator.paginate(statusEquals=_ELIGIBLE_STATUS))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError(
                "Missing required IAM permission: bedrock:ListProvisionedModelThroughputs"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    period = _choose_period(idle_days_threshold)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("provisionedModelSummaries", []):
            # --- Step 1: Normalize ---
            n = _normalize_provisioned_throughput(raw_item, now)
            if n is None:
                continue

            # --- Step 2: EXCLUSION RULES ---

            # EXCLUSION: status must be InService
            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            # EXCLUSION: too young to evaluate
            if n["age_days"] < idle_days_threshold:
                continue

            # --- Step 3: CloudWatch activity metrics ---
            # All 4 required metrics must return datapoints and all Sums must be zero.
            # Missing datapoints → SKIP ITEM. API failure → FAIL RULE (propagates).
            skip_item = False
            for metric_name in _REQUIRED_METRICS:
                metric_sum = _get_metric_sum(
                    cloudwatch,
                    n["provisioned_model_arn"],
                    metric_name,
                    window_start,
                    now,
                    period,
                )
                if metric_sum is None:
                    # No datapoints → insufficient trusted evidence → SKIP ITEM
                    skip_item = True
                    break
                if metric_sum > 0:
                    # Observed runtime activity → not idle → SKIP ITEM
                    skip_item = True
                    break

            if skip_item:
                continue

            # --- Step 4: EMIT ---
            signals_used = [
                f"Provisioned Throughput status is '{_ELIGIBLE_STATUS}' (serving capacity)",
                f"Age is {n['age_days']} days, meeting the {idle_days_threshold}-day threshold",
                f"All required Bedrock runtime activity metrics queried under "
                f"ModelId = {n['provisioned_model_arn']}",
                f"No observed runtime request activity over the {idle_days_threshold}-day "
                f"observation window for metrics: {', '.join(_REQUIRED_METRICS)}",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.bedrock.provisioned_throughput.idle",
                    resource_type="aws.bedrock.provisioned_throughput",
                    resource_id=n["provisioned_model_arn"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"Bedrock Provisioned Throughput {n['provisioned_model_arn']} "
                        f"has no observed runtime request activity in the last "
                        f"{idle_days_threshold} days"
                    ),
                    reason=(
                        f"Provisioned Throughput has no observed Bedrock runtime request "
                        f"activity over the {idle_days_threshold}-day observation window"
                    ),
                    risk=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-bedrock-provisioned-throughput-review-candidate",
                        "provisioned_model_arn": n["provisioned_model_arn"],
                        "provisioned_model_name": n["provisioned_model_name"],
                        "normalized_status": n["normalized_status"],
                        "creation_time": n["creation_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "model_arn": n["model_arn"],
                        "foundation_model_arn": n["foundation_model_arn"],
                        "model_units": n["model_units"],
                        "desired_model_units": n["desired_model_units"],
                        "commitment_duration": n["commitment_duration"],
                        "commitment_expiration_time": (
                            n["commitment_expiration_time_utc"].isoformat()
                            if n["commitment_expiration_time_utc"]
                            else None
                        ),
                        "activity_metrics_checked": list(_REQUIRED_METRICS),
                        "last_modified_time": (
                            n["last_modified_time_utc"].isoformat()
                            if n["last_modified_time_utc"]
                            else None
                        ),
                    },
                )
            )

    return findings
