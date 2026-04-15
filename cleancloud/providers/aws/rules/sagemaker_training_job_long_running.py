import math
from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.sagemaker.training_job.long_running",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}

# GPU/accelerator instance families — high hourly cost, runaway jobs are critical
_GPU_FAMILIES = (
    "ml.g4dn",
    "ml.g5",
    "ml.g6",  # NVIDIA L4 (2024)
    "ml.g6e",  # NVIDIA L40S (2024)
    "ml.g7",  # future NVIDIA GPU family
    "ml.p2",
    "ml.p3",
    "ml.p4d",
    "ml.p4de",
    "ml.p5",
    "ml.p5en",  # NVIDIA H200 (2024)
    "ml.p6",  # NVIDIA B200 (2025)
    "ml.trn1",
    "ml.trn2",  # Trainium2 (2024)
    "ml.inf1",
    "ml.inf2",
)

# Approximate on-demand hourly cost per instance (us-east-1 baseline).
# Pricing is a static estimate — actual cost varies by region, Reserved/Savings Plan
# discounts, and AWS price changes. Use as a directional signal, not a billing reference.
_HOURLY_COST_BY_INSTANCE = {
    # General purpose
    "ml.m5.large": 0.13,
    "ml.m5.xlarge": 0.23,
    "ml.m5.2xlarge": 0.46,
    "ml.m5.4xlarge": 0.92,
    "ml.m5.12xlarge": 2.76,
    "ml.m5.24xlarge": 5.53,
    # Compute optimised
    "ml.c5.xlarge": 0.19,
    "ml.c5.2xlarge": 0.34,
    "ml.c5.4xlarge": 0.68,
    "ml.c5.9xlarge": 1.53,
    "ml.c5.18xlarge": 3.06,
    # NVIDIA T4 (G4dn)
    "ml.g4dn.xlarge": 0.74,
    "ml.g4dn.2xlarge": 1.31,
    "ml.g4dn.4xlarge": 2.27,
    "ml.g4dn.8xlarge": 3.04,
    "ml.g4dn.12xlarge": 3.91,
    "ml.g4dn.16xlarge": 6.08,
    # NVIDIA A10G (G5)
    "ml.g5.xlarge": 0.83,
    "ml.g5.2xlarge": 1.40,
    "ml.g5.4xlarge": 2.55,
    "ml.g5.8xlarge": 3.50,
    "ml.g5.12xlarge": 7.54,
    "ml.g5.16xlarge": 7.00,
    "ml.g5.24xlarge": 10.50,
    "ml.g5.48xlarge": 21.00,
    # NVIDIA L4 (G6)
    "ml.g6.xlarge": 0.97,
    "ml.g6.2xlarge": 1.52,
    "ml.g6.4xlarge": 2.47,
    "ml.g6.8xlarge": 4.51,
    "ml.g6.12xlarge": 6.76,
    "ml.g6.16xlarge": 8.76,
    "ml.g6.48xlarge": 23.07,
    # V100 (P3)
    "ml.p3.2xlarge": 3.83,
    "ml.p3.8xlarge": 15.30,
    "ml.p3.16xlarge": 28.15,
    "ml.p3dn.24xlarge": 35.86,
    # A100 (P4d/P4de)
    "ml.p4d.24xlarge": 32.77,
    "ml.p4de.24xlarge": 40.96,
    # H100 (P5)
    "ml.p5.48xlarge": 98.32,
    # Trainium
    "ml.trn1.2xlarge": 1.34,
    "ml.trn1.32xlarge": 21.50,
    "ml.trn1n.32xlarge": 24.78,
    # Inferentia
    "ml.inf1.xlarge": 0.23,
    "ml.inf1.2xlarge": 0.37,
    "ml.inf1.6xlarge": 1.10,
    "ml.inf1.24xlarge": 4.40,
    # Inferentia2
    "ml.inf2.xlarge": 0.77,
    "ml.inf2.8xlarge": 6.15,
    "ml.inf2.24xlarge": 18.45,
    "ml.inf2.48xlarge": 36.90,
}
_DEFAULT_HOURLY_COST = 0.50
_DEFAULT_HOURLY_COST_GPU = 4.00

# A job running beyond this multiple of the threshold is almost certainly runaway
_RUNAWAY_MULTIPLIER = 3

# SecondaryStatus values that indicate the job is stuck before training even started
_STUCK_EARLY_STATUSES = frozenset(
    {
        "Starting",
        "LaunchingMLInstances",
        "PreparingTrainingStack",
        "Downloading",
        "DownloadingTrainingImage",
    }
)


def find_long_running_sagemaker_training_jobs(
    session: boto3.Session,
    region: str,
    long_running_hours: int = 24,
) -> List[Finding]:
    """
    Find SageMaker training jobs that have been InProgress longer than expected.

    Most training jobs complete in minutes to a few hours. A job still InProgress
    after 24 hours is unusual and warrants review — it may be:
    - Hung or stalled (waiting on data, deadlocked distributed workers, OOM loop)
    - A runaway job that was submitted with incorrect hyperparameters
    - A forgotten job from a cancelled project that was never stopped

    GPU-backed training jobs (P3, P4d, P5, G4dn, G5, G6, Trn1) are especially costly:
    a hung ml.p3.16xlarge runs at ~$28/hour; ml.p4d.24xlarge at ~$33/hour; ml.p5.48xlarge
    at ~$98/hour. Distributed jobs (instance_count > 1) multiply this cost linearly.

    Detection logic:
    - Job status is InProgress (only InProgress jobs incur compute charges)
    - Duration (now - CreationTime) exceeds long_running_hours
    - DescribeTrainingJob is called for instance type/count, SecondaryStatus,
      StoppingCondition.MaxRuntimeInSeconds / MaxWaitTimeInSeconds,
      EnableManagedSpotTraining, and ResourceConfig.InstanceGroups (heterogeneous clusters)

    Confidence:
    - HIGH (deterministic): wall-clock duration exceeds the effective stopping limit:
        * On-demand jobs: MaxRuntimeInSeconds exceeded
        * Managed spot jobs: MaxWaitTimeInSeconds exceeded (MaxRuntimeInSeconds counts
          only active compute time, not wait time, so it is not a wall-clock signal)
    - HIGH: duration >= long_running_hours × 3 — clearly excessive for almost any workload;
      OR SecondaryStatus is a stuck-early state (Starting, Downloading, etc.) at threshold
    - MEDIUM: duration >= long_running_hours — worth reviewing, could be legitimate large run

    Heterogeneous clusters:
    - ResourceConfig.InstanceGroups is read when present; cost and instance count are
      aggregated across all groups. GPU presence is determined per group by instance
      family (_GPU_FAMILIES), not inferred from the aggregated burn rate.

    Cost reported:
    - Accrued cost so far: duration_hours × total_hourly_rate (all instances combined)
    - cost_type in details is "accrued_to_date" to distinguish from monthly projections.
    - estimated_monthly_cost_usd is intentionally None — training jobs are transient,
      not recurring monthly expenses; setting it would corrupt monthly savings totals.
    - Pricing is a static estimate (us-east-1 baseline); actual cost varies by region
      and discount plan.

    IAM permissions required:
    - sagemaker:ListTrainingJobs
    - sagemaker:DescribeTrainingJob
    """
    long_running_hours = max(long_running_hours, 1)

    sagemaker = session.client("sagemaker", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = sagemaker.get_paginator("list_training_jobs")
        for page in paginator.paginate(StatusEquals="InProgress"):
            for job in page.get("TrainingJobSummaries", []):
                job_name = job["TrainingJobName"]
                job_arn = job.get("TrainingJobArn", "")

                creation_time = job.get("CreationTime")
                if creation_time is None:
                    continue
                if creation_time.tzinfo is None:
                    creation_time = creation_time.replace(tzinfo=timezone.utc)

                duration_hours = (now - creation_time).total_seconds() / 3600

                # Skip jobs that haven't reached 75% of the threshold — too early
                if duration_hours < long_running_hours * 0.75:
                    continue

                # Describe to get instance type, count, secondary status, and stopping condition
                describe_result = _describe_training_job(sagemaker, job_name)
                if describe_result is None:
                    # Non-auth describe failure — skip rather than guess
                    continue

                instance_type = describe_result["instance_type"]
                instance_count = describe_result["instance_count"]
                is_heterogeneous = describe_result["is_heterogeneous"]
                is_gpu = describe_result["is_gpu"]
                instance_groups_list = describe_result["instance_groups"]
                training_image = describe_result["training_image"]
                secondary_status = describe_result["secondary_status"]
                max_runtime_seconds = describe_result["max_runtime_seconds"]
                max_wait_time_seconds = describe_result["max_wait_time_seconds"]
                enable_managed_spot = describe_result["enable_managed_spot"]

                # For heterogeneous clusters _describe_training_job pre-computes the
                # total burn rate across all instance groups. For homogeneous jobs we
                # compute it here from instance_type × instance_count.
                if is_heterogeneous:
                    hourly_rate_total = describe_result["hourly_rate_total"] or 0.0
                    # Meaningful per-instance rate is undefined for mixed clusters;
                    # store zero so details["hourly_rate_per_instance"] is not misleading.
                    hourly_rate = 0.0
                else:
                    hourly_rate = _HOURLY_COST_BY_INSTANCE.get(
                        instance_type,
                        _DEFAULT_HOURLY_COST_GPU if is_gpu else _DEFAULT_HOURLY_COST,
                    )
                    hourly_rate_total = hourly_rate * instance_count

                burn_rate = round(hourly_rate_total, 2)
                duration_h = math.floor(duration_hours)
                accrued_cost = round(hourly_rate_total * duration_hours, 2)
                overrun_hours = max(0, duration_hours - long_running_hours)
                duration_seconds = duration_hours * 3600

                # --- Confidence ---
                # MaxRuntimeInSeconds exceeded: deterministic only for on-demand jobs.
                # For managed spot training the wall-clock stopping limit is
                # MaxWaitTimeInSeconds; MaxRuntimeInSeconds counts only active compute
                # time (excluding wait), so exceeding it does not mean the job is broken.
                if enable_managed_spot:
                    exceeded_max_runtime = bool(
                        max_wait_time_seconds and duration_seconds > max_wait_time_seconds
                    )
                else:
                    exceeded_max_runtime = bool(
                        max_runtime_seconds and duration_seconds > max_runtime_seconds
                    )

                is_stuck_early = secondary_status in _STUCK_EARLY_STATUSES

                if exceeded_max_runtime:
                    confidence = ConfidenceLevel.HIGH
                elif duration_hours >= long_running_hours * _RUNAWAY_MULTIPLIER:
                    confidence = ConfidenceLevel.HIGH
                elif is_stuck_early and duration_hours >= long_running_hours:
                    # Stuck in a pre-training phase at threshold — stronger signal than
                    # mere duration, since no training progress is being made at all
                    confidence = ConfidenceLevel.HIGH
                elif duration_hours >= long_running_hours:
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    # 75–100% of threshold: early warning for GPU only
                    if is_gpu:
                        confidence = ConfidenceLevel.MEDIUM
                    else:
                        continue

                # --- Risk ---
                if is_gpu and confidence == ConfidenceLevel.HIGH:
                    risk = RiskLevel.CRITICAL
                elif is_gpu:
                    risk = RiskLevel.HIGH
                elif confidence == ConfidenceLevel.HIGH:
                    risk = RiskLevel.HIGH
                else:
                    risk = RiskLevel.MEDIUM

                if is_heterogeneous and instance_groups_list:
                    # Build a compact label: "ml.p3.16xlarge + 4×ml.m5.xlarge (5 total)"
                    group_parts = [
                        (
                            f"{g['instance_count']}×{g['instance_type']}"
                            if g["instance_count"] > 1
                            else g["instance_type"]
                        )
                        for g in instance_groups_list
                    ]
                    instance_label = f"{' + '.join(group_parts)} ({instance_count} total)"
                elif instance_count > 1:
                    instance_label = f"{instance_type} × {instance_count}"
                else:
                    instance_label = instance_type or ""
                title = (
                    f"Long-Running Training Job ({duration_h}h"
                    + (f", {instance_label}" if instance_label else "")
                    + ")"
                )

                burn_rate_detail = (
                    f"${burn_rate:.2f}/hr total across {instance_count} instances (heterogeneous cluster)"
                    if is_heterogeneous
                    else f"${hourly_rate:.2f}/hr × {instance_count} instance(s)"
                )
                threshold_detail = (
                    f"exceeded by {math.floor(overrun_hours)}h"
                    if overrun_hours > 0
                    else f"{math.floor((long_running_hours - duration_hours) * 10) / 10:.0f}h below threshold (early warning)"
                )
                signals = [
                    f"Job status: InProgress for {duration_h}h "
                    f"(threshold: {long_running_hours}h, {threshold_detail})",
                    f"Burn rate: ~${burn_rate:.2f}/hour ({burn_rate_detail})",
                ]
                if secondary_status:
                    signals.append(
                        f"SecondaryStatus: {secondary_status}"
                        + (
                            " — stuck in pre-training phase, no training progress being made"
                            if is_stuck_early
                            else ""
                        )
                    )
                if enable_managed_spot:
                    if exceeded_max_runtime and max_wait_time_seconds:
                        max_wt_h = round(max_wait_time_seconds / 3600, 1)
                        signals.append(
                            f"Managed spot job exceeded MaxWaitTimeInSeconds: "
                            f"wall-clock limit {max_wt_h}h, elapsed {duration_h}h"
                        )
                    elif max_wait_time_seconds:
                        max_wt_h = round(max_wait_time_seconds / 3600, 1)
                        signals.append(
                            f"Managed spot training — MaxWaitTimeInSeconds: {max_wt_h}h configured"
                        )
                    if max_runtime_seconds:
                        max_h = round(max_runtime_seconds / 3600, 1)
                        signals.append(
                            f"MaxRuntimeInSeconds (compute-only, not wall-clock): {max_h}h"
                        )
                else:
                    if exceeded_max_runtime and max_runtime_seconds:
                        max_h = round(max_runtime_seconds / 3600, 1)
                        signals.append(
                            f"MaxRuntimeInSeconds exceeded: configured limit {max_h}h, "
                            f"elapsed {duration_h}h — job outlived its own stopping condition"
                        )
                    elif max_runtime_seconds:
                        max_h = round(max_runtime_seconds / 3600, 1)
                        signals.append(f"MaxRuntimeInSeconds: {max_h}h configured")
                if instance_label:
                    # For heterogeneous clusters the label already encodes all group types;
                    # for homogeneous jobs append GPU tag for clarity.
                    gpu_tag = " (GPU/accelerator)" if is_gpu and not is_heterogeneous else ""
                    signals.append(f"Instance: {instance_label}{gpu_tag}")
                if instance_count > 1:
                    signals.append(
                        f"Distributed training ({instance_count} instances) — "
                        f"long durations may be expected for large-scale jobs"
                    )
                signals.append(
                    f"Accrued cost: ~${accrued_cost:,.2f} "
                    f"(${burn_rate:.2f}/hr × {duration_h}h elapsed, "
                    f"us-east-1 baseline — actual cost varies by region and discounts)"
                )
                if training_image:
                    image_short = training_image.rsplit("/", 1)[-1]
                    signals.append(f"Training image: {image_short}")

                not_checked = [
                    "Intentional long-running distributed training (LLM pre-training, large fine-tunes)",
                    "Checkpoint saving — job may be making progress without frequent status updates",
                    "Warm pools — job may be using SageMaker managed warm pools and billing differs",
                ] + (
                    []
                    if enable_managed_spot
                    else [
                        "Spot training — if using spot instances, cost and interruption semantics differ"
                    ]
                )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=not_checked,
                    time_window=f"{duration_h} hours",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.sagemaker.training_job.long_running",
                        resource_type="aws.sagemaker.training_job",
                        resource_id=job_arn or job_name,
                        region=region,
                        title=title,
                        summary=(
                            f"SageMaker training job '{job_name}' has been InProgress for "
                            f"{duration_h} hours"
                            + (f" on {instance_label}" if instance_label else "")
                            + f", accruing ~${accrued_cost:,.2f} so far"
                            + (
                                (
                                    " (exceeded MaxWaitTimeInSeconds — spot wall-clock limit)"
                                    if enable_managed_spot and max_wait_time_seconds
                                    else " (exceeded configured MaxRuntimeInSeconds)"
                                )
                                if exceeded_max_runtime
                                else ""
                            )
                            + f". Most training jobs complete in under {long_running_hours} hours."
                        ),
                        reason=(
                            f"Training job has been InProgress for {duration_h}h "
                            f"(threshold: {long_running_hours}h)"
                            + (
                                (
                                    f"; exceeded MaxWaitTimeInSeconds ({round(max_wait_time_seconds / 3600, 1)}h spot wall-clock limit)"
                                    if enable_managed_spot and max_wait_time_seconds
                                    else (
                                        f"; exceeded MaxRuntimeInSeconds ({round(max_runtime_seconds / 3600, 1)}h)"
                                        if max_runtime_seconds
                                        else ""
                                    )
                                )
                                if exceeded_max_runtime
                                else ""
                            )
                        ),
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        # Training jobs are transient, not recurring monthly expenses.
                        # estimated_monthly_cost_usd is left None to avoid corrupting
                        # monthly savings totals; accrued cost lives in details only.
                        estimated_monthly_cost_usd=None,
                        details={
                            "job_name": job_name,
                            "instance_type": instance_type or None,
                            "instance_count": instance_count,
                            "is_heterogeneous_cluster": is_heterogeneous,
                            "instance_groups": instance_groups_list or None,
                            "is_gpu": is_gpu,
                            "secondary_status": secondary_status or None,
                            "is_stuck_early": is_stuck_early,
                            "enable_managed_spot": enable_managed_spot,
                            "max_runtime_seconds": max_runtime_seconds,
                            "max_wait_time_seconds": max_wait_time_seconds,
                            "exceeded_max_runtime": exceeded_max_runtime,
                            "duration_hours": round(duration_hours, 2),
                            "long_running_hours_threshold": long_running_hours,
                            "hourly_rate_per_instance": (
                                None if is_heterogeneous else round(hourly_rate, 4)
                            ),
                            "burn_rate_per_hour": burn_rate,
                            "overrun_hours": round(overrun_hours, 2),
                            "accrued_cost_usd": accrued_cost,
                            "cost_type": "accrued_to_date",
                            "pricing_source": "static_estimate_us_east_1",
                            "training_image": training_image or None,
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "Missing required IAM permissions: sagemaker:ListTrainingJobs"
            ) from e
        raise

    return findings


def _describe_training_job(sagemaker, job_name: str) -> Optional[dict]:
    """Fetch instance config, secondary status, stopping condition, and training image.

    Handles heterogeneous clusters: if ResourceConfig.InstanceGroups is present,
    aggregates instance_count and computes a weighted hourly_rate_total across groups.
    Caller receives a flat view regardless of cluster shape.

    Returns None on non-auth errors (transient failures) so the caller can skip
    rather than produce a finding with unknown instance details.
    Raises PermissionError on auth failures so the caller can surface the gap.
    """
    try:
        resp = sagemaker.describe_training_job(TrainingJobName=job_name)
        resource_config = resp.get("ResourceConfig", {})
        algorithm = resp.get("AlgorithmSpecification", {})
        stopping = resp.get("StoppingCondition", {})

        # Heterogeneous cluster: InstanceGroups overrides InstanceType/InstanceCount.
        # Each group has its own InstanceType and InstanceCount.
        instance_groups = resource_config.get("InstanceGroups") or []
        if instance_groups:
            total_count = 0
            total_hourly = 0.0
            has_gpu = False
            group_summary = []  # [{"instance_type": ..., "instance_count": ...}, ...]
            for group in instance_groups:
                gtype = group.get("InstanceType", "")
                gcount = group.get("InstanceCount", 1)
                group_is_gpu = bool(gtype and any(gtype.startswith(f) for f in _GPU_FAMILIES))
                rate = _HOURLY_COST_BY_INSTANCE.get(
                    gtype,
                    _DEFAULT_HOURLY_COST_GPU if group_is_gpu else _DEFAULT_HOURLY_COST,
                )
                total_count += gcount
                total_hourly += rate * gcount
                if group_is_gpu:
                    has_gpu = True
                group_summary.append({"instance_type": gtype, "instance_count": gcount})
            return {
                "instance_type": None,  # no single type for a heterogeneous cluster
                "instance_count": total_count,
                "is_heterogeneous": True,
                "is_gpu": has_gpu,
                "hourly_rate_total": round(total_hourly, 4),
                "instance_groups": group_summary,
                "training_image": algorithm.get("TrainingImage", ""),
                "secondary_status": resp.get("SecondaryStatus", ""),
                "max_runtime_seconds": stopping.get("MaxRuntimeInSeconds") or None,
                "max_wait_time_seconds": stopping.get("MaxWaitTimeInSeconds") or None,
                "enable_managed_spot": bool(resp.get("EnableManagedSpotTraining", False)),
            }
        else:
            instance_type = resource_config.get("InstanceType", "")
            instance_count = resource_config.get("InstanceCount", 1)
            is_gpu = bool(instance_type and any(instance_type.startswith(f) for f in _GPU_FAMILIES))
            return {
                "instance_type": instance_type,
                "instance_count": instance_count,
                "is_heterogeneous": False,
                "is_gpu": is_gpu,
                "hourly_rate_total": None,  # caller computes from instance_type × instance_count
                "instance_groups": None,
                "training_image": algorithm.get("TrainingImage", ""),
                "secondary_status": resp.get("SecondaryStatus", ""),
                "max_runtime_seconds": stopping.get("MaxRuntimeInSeconds") or None,
                "max_wait_time_seconds": stopping.get("MaxWaitTimeInSeconds") or None,
                "enable_managed_spot": bool(resp.get("EnableManagedSpotTraining", False)),
            }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "Missing required IAM permissions: sagemaker:DescribeTrainingJob"
            ) from e
        return None
