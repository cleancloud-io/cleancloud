"""
Rule: aws.sagemaker.training_job.long_running

    (spec — docs/specs/aws/ai/sagemaker_training_job_long_running.md)

Intent:
    Detect SageMaker training jobs that are still InProgress and have remained
    active longer than the configured review threshold, so they can be reviewed
    as possible runaway, stuck, or forgotten jobs.

    This is a CleanCloud-derived review heuristic based on SageMaker training-job
    metadata, not an AWS-native long-running finding. It is a read-only
    review-candidate rule — not a stop-safe rule.

Exclusions:
    - training_job_name or training_job_arn absent (malformed inventory item)
    - list or describe status absent or not "InProgress"
    - CreationTime absent, naive, or future beyond clock_skew_tolerance_seconds
    - TrainingStartTime future beyond clock_skew_tolerance_seconds
    - TrainingStartTime < CreationTime beyond clock_skew_tolerance_seconds
    - elapsed_runtime_hours < long_running_hours_threshold

Detection:
    - InProgress training job
    - elapsed_runtime_hours >= long_running_hours_threshold
    - runtime anchor: TrainingStartTime when present, else CreationTime

Key rules:
    - ListTrainingJobs paginated WITHOUT StatusEquals (filtered client-side)
    - resource_id = TrainingJobArn from describe; falls back to list-level ARN
    - estimated_monthly_cost_usd = None
    - Confidence: HIGH when exceeded_applicable_runtime_limit; MEDIUM otherwise
    - Risk: HIGH for accelerator-backed (g*, p*, inf*, trn*); MEDIUM otherwise
    - applicable_runtime_limit_seconds: MaxWaitTimeInSeconds for Spot when present;
      else MaxRuntimeInSeconds when TrainingStartTime is present; else null
    - ListTrainingJobs failure → FAIL RULE; permission failure → FAIL RULE
    - DescribeTrainingJob permission failure → FAIL RULE
    - DescribeTrainingJob non-permission failure → SKIP ITEM
    - clock_skew_tolerance_seconds = 300

Blind spots:
    - Actual model-progress or convergence state
    - Exact price impact or savings impact
    - Whether long pending time is actively billable compute
    - Warm-pool-only post-job billing

APIs:
    - sagemaker:ListTrainingJobs
    - sagemaker:DescribeTrainingJob
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_LONG_RUNNING_HOURS_THRESHOLD = 24
_ELIGIBLE_STATUS = "InProgress"
_CLOCK_SKEW_TOLERANCE_SECONDS = 300

# Accelerator instance type prefixes — used for HIGH risk determination
_ACCELERATOR_PREFIXES = ("ml.g", "ml.p", "ml.inf", "ml.trn")

_FINDING_TITLE = "Long-running SageMaker training job review candidate"
_FINDING_REASON = (
    "InProgress SageMaker training job has exceeded the configured long-running threshold"
)

_SIGNALS_NOT_CHECKED = (
    "Actual model-progress or convergence state",
    "Exact price impact or savings impact",
    "Whether long pending time is actively billable compute",
    "Warm-pool-only post-job billing",
)

RULE_METADATA = {
    "id": "aws.sagemaker.training_job.long_running",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _is_accelerator_backed(instance_type: Optional[str]) -> bool:
    """Return True when the instance type is an accelerator (g*, p*, inf*, trn*)."""
    if not instance_type:
        return False
    return any(instance_type.startswith(prefix) for prefix in _ACCELERATOR_PREFIXES)


def _is_job_accelerator_backed(
    instance_type: Optional[str],
    instance_groups: Optional[list],
) -> bool:
    """Return True when any instance in the job (homogeneous or heterogeneous) is accelerator."""
    if instance_groups and isinstance(instance_groups, list):
        for group in instance_groups:
            if isinstance(group, dict):
                gt = _str(group.get("InstanceType"))
                if _is_accelerator_backed(gt):
                    return True
    return _is_accelerator_backed(instance_type)


def _normalize_list_item(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListTrainingJobs item to canonical list-level fields.

    Returns None when required fields are absent or invalid — caller must skip item.
    """
    if not isinstance(item, dict):
        return None

    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)

    # --- Identity (required; absent → skip) ---
    training_job_name = _str(item.get("TrainingJobName"))
    if training_job_name is None:
        return None

    training_job_arn = _str(item.get("TrainingJobArn"))
    if training_job_arn is None:
        return None

    # --- Status (required; absent → skip) ---
    list_status = _str(item.get("TrainingJobStatus"))
    if list_status is None:
        return None

    # --- CreationTime (required; absent, naive, future beyond skew → skip) ---
    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc + skew_tol:
        return None

    job_age_hours = int((now_utc - creation_time_utc).total_seconds() // 3600)

    # --- LastModifiedTime (optional; naive → null; future beyond skew → skip item) ---
    last_modified_time_utc = None
    raw_lmt = item.get("LastModifiedTime")
    if isinstance(raw_lmt, datetime):
        if raw_lmt.tzinfo is None:
            pass  # naive → null
        else:
            lmt = raw_lmt.astimezone(timezone.utc)
            if lmt > now_utc + skew_tol:
                return None  # future beyond skew → skip item
            last_modified_time_utc = lmt

    list_secondary_status = _str(item.get("SecondaryStatus"))

    return {
        "training_job_name": training_job_name,
        "training_job_arn": training_job_arn,
        "list_status": list_status,
        "creation_time_utc": creation_time_utc,
        "job_age_hours": job_age_hours,
        "last_modified_time_utc": last_modified_time_utc,
        "list_secondary_status": list_secondary_status,
    }


def _normalize_describe(response: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a DescribeTrainingJob response to canonical describe-level fields.

    Returns None when required fields are absent or invalid — caller must skip item.
    """
    if not isinstance(response, dict):
        return None

    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)

    # --- resource_id = TrainingJobArn (fall back to list ARN handled by caller) ---
    training_job_arn = _str(response.get("TrainingJobArn"))

    # --- describe_status (required; absent → skip) ---
    describe_status = _str(response.get("TrainingJobStatus"))
    if describe_status is None:
        return None

    # --- TrainingStartTime (optional; naive → null; future beyond skew → skip item) ---
    training_start_time_utc = None
    raw_tst = response.get("TrainingStartTime")
    if isinstance(raw_tst, datetime):
        if raw_tst.tzinfo is None:
            pass  # naive → null
        else:
            tst = raw_tst.astimezone(timezone.utc)
            if tst > now_utc + skew_tol:
                return None  # future beyond skew → skip item
            training_start_time_utc = tst

    # --- SecondaryStatus (optional) ---
    describe_secondary_status = _str(response.get("SecondaryStatus"))

    # --- EnableManagedSpotTraining ---
    enable_managed_spot_training = bool(response.get("EnableManagedSpotTraining", False))

    # --- StoppingCondition (optional; degrade safely) ---
    stopping = response.get("StoppingCondition")
    if not isinstance(stopping, dict):
        stopping = {}

    raw_max_runtime = stopping.get("MaxRuntimeInSeconds")
    max_runtime_seconds = (
        raw_max_runtime if isinstance(raw_max_runtime, int) and raw_max_runtime > 0 else None
    )

    raw_max_wait = stopping.get("MaxWaitTimeInSeconds")
    max_wait_time_seconds = (
        raw_max_wait if isinstance(raw_max_wait, int) and raw_max_wait > 0 else None
    )

    raw_max_pending = stopping.get("MaxPendingTimeInSeconds")
    max_pending_time_seconds = (
        raw_max_pending if isinstance(raw_max_pending, int) and raw_max_pending > 0 else None
    )

    # --- ResourceConfig (optional; degrade safely) ---
    resource_config = response.get("ResourceConfig")
    if not isinstance(resource_config, dict):
        resource_config = {}

    instance_type = _str(resource_config.get("InstanceType"))

    raw_instance_count = resource_config.get("InstanceCount")
    instance_count = raw_instance_count if isinstance(raw_instance_count, int) else None

    raw_instance_groups = resource_config.get("InstanceGroups")
    instance_groups = raw_instance_groups if isinstance(raw_instance_groups, list) else None

    # --- ServerlessJobConfig (optional; presence flag only) ---
    raw_serverless = response.get("ServerlessJobConfig")
    serverless_job_config_present = raw_serverless is not None

    # --- WarmPoolStatus (optional) ---
    warm_pool = response.get("WarmPoolStatus")
    warm_pool_status = None
    if isinstance(warm_pool, dict):
        warm_pool_status = _str(warm_pool.get("Status"))

    return {
        "resource_id": training_job_arn,  # may be None; caller falls back to list ARN
        "describe_status": describe_status,
        "training_start_time_utc": training_start_time_utc,
        "describe_secondary_status": describe_secondary_status,
        "enable_managed_spot_training": enable_managed_spot_training,
        "max_runtime_seconds": max_runtime_seconds,
        "max_wait_time_seconds": max_wait_time_seconds,
        "max_pending_time_seconds": max_pending_time_seconds,
        "instance_type": instance_type,
        "instance_count": instance_count,
        "instance_groups": instance_groups,
        "serverless_job_config_present": serverless_job_config_present,
        "warm_pool_status": warm_pool_status,
    }


def find_long_running_sagemaker_training_jobs(
    session: boto3.Session,
    region: str,
    long_running_hours_threshold: int = _DEFAULT_LONG_RUNNING_HOURS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)

    # Spec 8: paginate WITHOUT StatusEquals — filter InProgress client-side.
    # AWS documents that StatusEquals + MaxResults filters after paging, which can
    # silently miss InProgress jobs when pagination is truncated.
    try:
        paginator = sagemaker.get_paginator("list_training_jobs")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError(
                "Missing required IAM permission: sagemaker:ListTrainingJobs"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    evaluation_window_start = now - timedelta(seconds=long_running_hours_threshold * 3600)
    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("TrainingJobSummaries", []):
            # --- Step 1: Normalize list item ---
            nl = _normalize_list_item(raw_item, now)
            if nl is None:
                continue

            # --- Step 2: List-level exclusion rules ---
            if nl["list_status"] != _ELIGIBLE_STATUS:
                continue

            # --- Step 3: DescribeTrainingJob ---
            try:
                raw_describe = sagemaker.describe_training_job(
                    TrainingJobName=nl["training_job_name"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] in (
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                ):
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeTrainingJob"
                    ) from exc
                continue  # non-permission error (e.g. ResourceNotFound) → SKIP ITEM
            except BotoCoreError:
                continue  # transport error → SKIP ITEM

            # --- Step 4: Normalize describe response ---
            nd = _normalize_describe(raw_describe, now)
            if nd is None:
                continue

            # --- Step 5: Re-check describe status ---
            if nd["describe_status"] != _ELIGIBLE_STATUS:
                continue

            # --- Step 6: Timestamp consistency ---
            # TrainingStartTime < CreationTime beyond skew tolerance → skip
            if nd["training_start_time_utc"] is not None:
                if nd["training_start_time_utc"] < nl["creation_time_utc"] - skew_tol:
                    continue

            # --- Step 7: Compute derived fields ---
            resource_id = nd["resource_id"] or nl["training_job_arn"]
            training_start_time = nd["training_start_time_utc"]

            if training_start_time is not None:
                runtime_anchor_type = "training_start_time"
                active_training_hours = int((now - training_start_time).total_seconds() // 3600)
                elapsed_runtime_hours = active_training_hours
            else:
                runtime_anchor_type = "creation_time"
                active_training_hours = None
                elapsed_runtime_hours = nl["job_age_hours"]

            # applicable_runtime_limit_seconds per spec 3
            if nd["enable_managed_spot_training"] and nd["max_wait_time_seconds"] is not None:
                applicable_runtime_limit_seconds = nd["max_wait_time_seconds"]
            elif training_start_time is not None and nd["max_runtime_seconds"] is not None:
                applicable_runtime_limit_seconds = nd["max_runtime_seconds"]
            else:
                applicable_runtime_limit_seconds = None

            unbounded_runtime_limit = applicable_runtime_limit_seconds is None

            exceeded_applicable_runtime_limit = (
                applicable_runtime_limit_seconds is not None
                and elapsed_runtime_hours * 3600 > applicable_runtime_limit_seconds
            )

            # --- Step 8: Threshold check ---
            if elapsed_runtime_hours < long_running_hours_threshold:
                continue

            # --- Step 9: Emit ---
            is_accelerator_backed = _is_job_accelerator_backed(
                nd["instance_type"], nd["instance_groups"]
            )
            risk = RiskLevel.HIGH if is_accelerator_backed else RiskLevel.MEDIUM
            confidence = (
                ConfidenceLevel.HIGH
                if exceeded_applicable_runtime_limit
                else ConfidenceLevel.MEDIUM
            )

            signals_used = [
                f"Training job primary status is '{_ELIGIBLE_STATUS}'",
                f"elapsed_runtime_hours ({elapsed_runtime_hours}h) met or exceeded the "
                f"configured threshold ({long_running_hours_threshold}h)",
                f"Runtime anchor used: {runtime_anchor_type}",
                (
                    "Job exceeded the applicable SageMaker stopping-condition limit"
                    if exceeded_applicable_runtime_limit
                    else "No applicable stopping-condition limit was exceeded"
                ),
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.training_job.long_running",
                    resource_type="aws.sagemaker.training_job",
                    resource_id=resource_id,
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker training job '{nl['training_job_name']}' has been "
                        f"InProgress for {elapsed_runtime_hours} hours, exceeding the "
                        f"{long_running_hours_threshold}-hour threshold"
                    ),
                    reason=_FINDING_REASON,
                    risk=risk,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{long_running_hours_threshold} hours",
                    ),
                    details={
                        # Required fields
                        "evaluation_path": "long-running-sagemaker-training-job-review-candidate",
                        "training_job_arn": resource_id,
                        "training_job_name": nl["training_job_name"],
                        "normalized_status": _ELIGIBLE_STATUS,
                        "creation_time": nl["creation_time_utc"].isoformat(),
                        "training_start_time": (
                            training_start_time.isoformat() if training_start_time else None
                        ),
                        "runtime_anchor_type": runtime_anchor_type,
                        "elapsed_runtime_hours": elapsed_runtime_hours,
                        "job_age_hours": nl["job_age_hours"],
                        "active_training_hours": active_training_hours,
                        "long_running_hours_threshold": long_running_hours_threshold,
                        "evaluation_window_start": evaluation_window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "enable_managed_spot_training": nd["enable_managed_spot_training"],
                        "applicable_runtime_limit_seconds": applicable_runtime_limit_seconds,
                        "unbounded_runtime_limit": unbounded_runtime_limit,
                        "exceeded_applicable_runtime_limit": exceeded_applicable_runtime_limit,
                        # Optional context fields
                        "secondary_status": nd["describe_secondary_status"],
                        "max_runtime_seconds": nd["max_runtime_seconds"],
                        "max_wait_time_seconds": nd["max_wait_time_seconds"],
                        "max_pending_time_seconds": nd["max_pending_time_seconds"],
                        "instance_type": nd["instance_type"],
                        "instance_count": nd["instance_count"],
                        "instance_groups": nd["instance_groups"],
                        "serverless_job_config_present": nd["serverless_job_config_present"],
                        "warm_pool_status": nd["warm_pool_status"],
                        "is_accelerator_backed": is_accelerator_backed,
                    },
                )
            )

    return findings
