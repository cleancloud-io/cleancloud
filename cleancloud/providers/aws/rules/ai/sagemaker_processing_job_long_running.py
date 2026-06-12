"""
Rule: aws.sagemaker.processing_job.long_running

    (spec — docs/specs/aws/ai/sagemaker_processing_job_long_running.md)

Intent:
    Detect SageMaker processing jobs that are still InProgress and have remained
    active longer than the configured review threshold, so they can be reviewed
    as possible hung, stuck, or forgotten jobs.

    This is a CleanCloud-derived review heuristic based on SageMaker
    processing-job metadata, not an AWS-native long-running finding. It is a
    read-only review-candidate rule — not a stop-safe rule.

Exclusions:
    - processing_job_name or processing_job_arn absent (malformed inventory item)
    - list or describe status absent or not "InProgress"
    - CreationTime absent, naive, or future beyond clock_skew_tolerance_seconds
    - ProcessingStartTime future beyond clock_skew_tolerance_seconds
    - ProcessingStartTime < CreationTime beyond clock_skew_tolerance_seconds
    - elapsed_runtime_hours < long_running_hours_threshold

Detection:
    - InProgress processing job
    - elapsed_runtime_hours >= long_running_hours_threshold
    - runtime anchor: ProcessingStartTime when present, else CreationTime

Key rules:
    - ListProcessingJobs paginated WITHOUT StatusEquals (filtered client-side as
      a conservative completeness choice)
    - resource_id = ProcessingJobArn from describe; falls back to list-level ARN
    - estimated_monthly_cost_usd = None
    - Confidence: HIGH when exceeded_applicable_runtime_limit; MEDIUM otherwise
    - Risk: HIGH for accelerator-backed (ml.g*, ml.p*, ml.inf*, ml.trn*);
      MEDIUM otherwise
    - configured_runtime_limit_seconds: MaxRuntimeInSeconds when present; the
      value becomes applicable only after ProcessingStartTime exists
    - ListProcessingJobs failure → FAIL RULE; permission failure → FAIL RULE
    - DescribeProcessingJob permission failure → FAIL RULE
    - DescribeProcessingJob non-permission failure → SKIP ITEM
    - clock_skew_tolerance_seconds = 300

Blind spots:
    - Actual processing-container progress state
    - Exact price impact or savings impact
    - Whether long pending time is actively billable compute

APIs:
    - sagemaker:ListProcessingJobs
    - sagemaker:DescribeProcessingJob
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.errors import is_permission_error

_DEFAULT_LONG_RUNNING_HOURS_THRESHOLD = 24
_ELIGIBLE_STATUS = "InProgress"
_CLOCK_SKEW_TOLERANCE_SECONDS = 300
_ACCELERATOR_PREFIXES = ("ml.g", "ml.p", "ml.inf", "ml.trn")

_FINDING_TITLE = "Long-running SageMaker processing job review candidate"
_FINDING_REASON = (
    "InProgress SageMaker processing job has exceeded the configured long-running threshold"
)

_SIGNALS_NOT_CHECKED = (
    "Actual processing-container progress state",
    "Exact price impact or savings impact",
    "Whether long pending time is actively billable compute",
)

RULE_METADATA = {
    "id": "aws.sagemaker.processing_job.long_running",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _is_accelerator_backed(instance_type: Optional[str]) -> bool:
    """Return True when the instance type is an accelerator (ml.g*, ml.p*, ml.inf*, ml.trn*)."""
    if not instance_type:
        return False
    return any(instance_type.startswith(prefix) for prefix in _ACCELERATOR_PREFIXES)


def _normalize_list_item(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListProcessingJobs item to canonical list-level fields."""
    if not isinstance(item, dict):
        return None

    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)

    processing_job_name = _str(item.get("ProcessingJobName"))
    if processing_job_name is None:
        return None

    processing_job_arn = _str(item.get("ProcessingJobArn"))
    if processing_job_arn is None:
        return None

    list_status = _str(item.get("ProcessingJobStatus"))
    if list_status is None:
        return None

    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime) or raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc + skew_tol:
        return None

    job_age_seconds = max(0, (now_utc - creation_time_utc).total_seconds())
    job_age_hours = int(job_age_seconds // 3600)

    last_modified_time_utc = None
    raw_lmt = item.get("LastModifiedTime")
    if isinstance(raw_lmt, datetime) and raw_lmt.tzinfo is not None:
        lmt = raw_lmt.astimezone(timezone.utc)
        if lmt <= now_utc + skew_tol:
            last_modified_time_utc = lmt

    return {
        "processing_job_name": processing_job_name,
        "processing_job_arn": processing_job_arn,
        "list_status": list_status,
        "creation_time_utc": creation_time_utc,
        "job_age_hours": job_age_hours,
        "last_modified_time_utc": last_modified_time_utc,
    }


def _normalize_describe(response: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a DescribeProcessingJob response to canonical describe-level fields."""
    if not isinstance(response, dict):
        return None

    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)

    resource_id = _str(response.get("ProcessingJobArn"))

    describe_status = _str(response.get("ProcessingJobStatus"))
    if describe_status is None:
        return None

    processing_start_time_utc = None
    raw_pst = response.get("ProcessingStartTime")
    if isinstance(raw_pst, datetime):
        if raw_pst.tzinfo is None:
            pass
        else:
            pst = raw_pst.astimezone(timezone.utc)
            if pst > now_utc + skew_tol:
                return None
            processing_start_time_utc = pst

    stopping = response.get("StoppingCondition")
    if not isinstance(stopping, dict):
        stopping = {}

    raw_configured_limit = stopping.get("MaxRuntimeInSeconds")
    configured_runtime_limit_seconds = (
        raw_configured_limit
        if isinstance(raw_configured_limit, int)
        and not isinstance(raw_configured_limit, bool)
        and raw_configured_limit > 0
        else None
    )

    processing_resources = response.get("ProcessingResources")
    if not isinstance(processing_resources, dict):
        processing_resources = {}
    cluster_config = processing_resources.get("ClusterConfig")
    if not isinstance(cluster_config, dict):
        cluster_config = {}

    instance_type = _str(cluster_config.get("InstanceType"))
    raw_instance_count = cluster_config.get("InstanceCount")
    instance_count = raw_instance_count if isinstance(raw_instance_count, int) else None

    return {
        "resource_id": resource_id,
        "describe_status": describe_status,
        "processing_start_time_utc": processing_start_time_utc,
        "configured_runtime_limit_seconds": configured_runtime_limit_seconds,
        "instance_type": instance_type,
        "instance_count": instance_count,
    }


def find_long_running_sagemaker_processing_jobs(
    session: boto3.Session,
    region: str,
    long_running_hours_threshold: int = _DEFAULT_LONG_RUNNING_HOURS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)

    # Spec 8: paginate without StatusEquals and filter InProgress client-side.
    try:
        paginator = sagemaker.get_paginator("list_processing_jobs")
        page_iterator = paginator.paginate()
    except ClientError as exc:
        if is_permission_error(exc):
            raise PermissionError(
                "Missing required IAM permission: sagemaker:ListProcessingJobs"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    evaluation_window_start = now - timedelta(seconds=long_running_hours_threshold * 3600)
    skew_tol = timedelta(seconds=_CLOCK_SKEW_TOLERANCE_SECONDS)
    findings: List[Finding] = []

    for page in page_iterator:
        for raw_item in page.get("ProcessingJobSummaries", []):
            nl = _normalize_list_item(raw_item, now)
            if nl is None:
                continue
            if nl["list_status"] != _ELIGIBLE_STATUS:
                continue

            try:
                raw_describe = sagemaker.describe_processing_job(
                    ProcessingJobName=nl["processing_job_name"]
                )
            except ClientError as exc:
                if is_permission_error(exc):
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeProcessingJob"
                    ) from exc
                continue
            except BotoCoreError:
                continue

            nd = _normalize_describe(raw_describe, now)
            if nd is None:
                continue
            if nd["describe_status"] != _ELIGIBLE_STATUS:
                continue

            processing_start_time = nd["processing_start_time_utc"]
            if processing_start_time is not None:
                if processing_start_time < nl["creation_time_utc"] - skew_tol:
                    continue

            resource_id = nd["resource_id"] or nl["processing_job_arn"]
            processing_job_arn = resource_id

            if processing_start_time is not None:
                runtime_anchor_type = "processing_start_time"
                runtime_anchor_label = "ProcessingStartTime"
                active_seconds = max(0, (now - processing_start_time).total_seconds())
                active_processing_hours = int(active_seconds // 3600)
                elapsed_runtime_hours = active_processing_hours
                elapsed_runtime_seconds = active_seconds
            else:
                runtime_anchor_type = "creation_time"
                runtime_anchor_label = "CreationTime"
                active_processing_hours = None
                elapsed_runtime_hours = nl["job_age_hours"]
                elapsed_runtime_seconds = max(0, (now - nl["creation_time_utc"]).total_seconds())

            applicable_runtime_limit_seconds = (
                nd["configured_runtime_limit_seconds"]
                if processing_start_time is not None
                else None
            )
            unbounded_runtime_limit = applicable_runtime_limit_seconds is None
            exceeded_applicable_runtime_limit = (
                applicable_runtime_limit_seconds is not None
                and elapsed_runtime_seconds > applicable_runtime_limit_seconds
            )

            if elapsed_runtime_hours < long_running_hours_threshold:
                continue

            is_accelerator_backed = _is_accelerator_backed(nd["instance_type"])
            risk = RiskLevel.HIGH if is_accelerator_backed else RiskLevel.MEDIUM
            confidence = (
                ConfidenceLevel.HIGH
                if exceeded_applicable_runtime_limit
                else ConfidenceLevel.MEDIUM
            )

            signals_used = [
                f"Processing job primary status is '{_ELIGIBLE_STATUS}'",
                f"elapsed_runtime_hours ({elapsed_runtime_hours}h) met or exceeded the "
                f"configured threshold ({long_running_hours_threshold}h)",
                f"Runtime anchor used: {runtime_anchor_label}",
                (
                    "Job exceeded the SageMaker MaxRuntimeInSeconds limit"
                    if exceeded_applicable_runtime_limit
                    else "SageMaker MaxRuntimeInSeconds limit was not exceeded or was not yet applicable"
                ),
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.processing_job.long_running",
                    resource_type="aws.sagemaker.processing_job",
                    resource_id=resource_id,
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker processing job '{nl['processing_job_name']}' has been "
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
                        "evaluation_path": "long-running-sagemaker-processing-job-review-candidate",
                        "processing_job_arn": processing_job_arn,
                        "processing_job_name": nl["processing_job_name"],
                        "normalized_status": _ELIGIBLE_STATUS,
                        "creation_time": nl["creation_time_utc"].isoformat(),
                        "processing_start_time": (
                            processing_start_time.isoformat() if processing_start_time else None
                        ),
                        "runtime_anchor_type": runtime_anchor_type,
                        "elapsed_runtime_hours": elapsed_runtime_hours,
                        "job_age_hours": nl["job_age_hours"],
                        "active_processing_hours": active_processing_hours,
                        "long_running_hours_threshold": long_running_hours_threshold,
                        "evaluation_window_start": evaluation_window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "configured_runtime_limit_seconds": nd["configured_runtime_limit_seconds"],
                        "applicable_runtime_limit_seconds": applicable_runtime_limit_seconds,
                        "unbounded_runtime_limit": unbounded_runtime_limit,
                        "exceeded_applicable_runtime_limit": exceeded_applicable_runtime_limit,
                        "instance_type": nd["instance_type"],
                        "instance_count": nd["instance_count"],
                        "is_accelerator_backed": is_accelerator_backed,
                    },
                )
            )

    return findings
