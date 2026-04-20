from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_training_job_long_running import (
    find_long_running_sagemaker_training_jobs,
)

_REGION = "us-east-1"


def _make_job(
    name="train-job-1",
    arn=None,
    age_hours=48,
):
    now = datetime.now(timezone.utc)
    return {
        "TrainingJobName": name,
        "TrainingJobArn": arn or f"arn:aws:sagemaker:us-east-1:123456789012:training-job/{name}",
        "CreationTime": now - timedelta(hours=age_hours),
        "TrainingJobStatus": "InProgress",
    }


def _make_session(
    jobs=None,
    instance_type="ml.m5.xlarge",
    instance_count=1,
    training_image="763104351884.dkr.ecr.us-east-1.amazonaws.com/pytorch-training:2.0.0-gpu-py310",
    secondary_status="Training",
    max_runtime_seconds=None,
    max_wait_time_seconds=None,
    enable_managed_spot=False,
    instance_groups=None,  # list of {"InstanceType": ..., "InstanceCount": ...} for heterogeneous
    describe_side_effect=None,
):
    sagemaker = MagicMock()

    page = {"TrainingJobSummaries": jobs or []}
    paginator = MagicMock()
    paginator.paginate.return_value = [page]
    sagemaker.get_paginator.return_value = paginator

    if describe_side_effect:
        sagemaker.describe_training_job.side_effect = describe_side_effect
    else:
        stopping = {}
        if max_runtime_seconds is not None:
            stopping["MaxRuntimeInSeconds"] = max_runtime_seconds
        if max_wait_time_seconds is not None:
            stopping["MaxWaitTimeInSeconds"] = max_wait_time_seconds

        resource_config: dict = {}
        if instance_groups is not None:
            resource_config["InstanceGroups"] = instance_groups
        else:
            resource_config["InstanceType"] = instance_type
            resource_config["InstanceCount"] = instance_count

        sagemaker.describe_training_job.return_value = {
            "ResourceConfig": resource_config,
            "AlgorithmSpecification": {
                "TrainingImage": training_image,
            },
            "SecondaryStatus": secondary_status,
            "StoppingCondition": stopping,
            "EnableManagedSpotTraining": enable_managed_spot,
        }

    session = MagicMock()
    session.client.return_value = sagemaker
    return session, sagemaker


def _auth_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "Access Denied"}}, "op")


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_long_running_job_detected():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.sagemaker.training_job.long_running"
    assert f.resource_type == "aws.sagemaker.training_job"
    assert f.provider == "aws"
    assert f.region == _REGION


def test_short_job_not_flagged():
    """Job running for only 6h with 24h threshold should not be flagged."""
    job = _make_job(age_hours=6)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings == []


def test_job_at_75pct_threshold_not_flagged_for_cpu():
    """CPU job at 75% of threshold (18h for 24h threshold) is below the medium floor — skip."""
    job = _make_job(age_hours=17)  # 17h < 18h = 24 * 0.75
    session, _ = _make_session(jobs=[job], instance_type="ml.m5.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings == []


def test_no_jobs_returns_empty():
    session, _ = _make_session(jobs=[])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION)
    assert findings == []


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_at_3x_threshold():
    """Job running >= 3× threshold → HIGH confidence."""
    job = _make_job(age_hours=75)  # 75h >= 3×24=72h
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_medium_confidence_at_1x_threshold():
    """Job running >= threshold but < 3× → MEDIUM confidence."""
    job = _make_job(age_hours=30)  # 30h >= 24h but < 72h
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_gpu_job_flagged_at_75pct_threshold_as_medium():
    """GPU job at 75–100% of threshold is surfaced as early MEDIUM warning."""
    job = _make_job(age_hours=19)  # 19h >= 24*0.75=18h, < 24h, GPU instance
    session, _ = _make_session(jobs=[job], instance_type="ml.g5.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["is_gpu"] is True


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_critical_risk_gpu_high_confidence():
    """GPU instance + HIGH confidence (3×) → CRITICAL risk."""
    job = _make_job(age_hours=75)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.16xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].risk.value == "critical"


def test_high_risk_gpu_medium_confidence():
    """GPU instance + MEDIUM confidence → HIGH risk."""
    job = _make_job(age_hours=30)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.2xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].risk.value == "high"


def test_high_risk_cpu_high_confidence():
    """CPU instance + HIGH confidence → HIGH risk."""
    job = _make_job(age_hours=75)
    session, _ = _make_session(jobs=[job], instance_type="ml.m5.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].risk.value == "high"


def test_medium_risk_cpu_medium_confidence():
    """CPU instance + MEDIUM confidence → MEDIUM risk."""
    job = _make_job(age_hours=30)
    session, _ = _make_session(jobs=[job], instance_type="ml.m5.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def test_accrued_cost_single_instance():
    """Accrued cost = duration_hours × hourly_rate × 1; estimated_monthly_cost_usd is None."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.16xlarge", instance_count=1)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    f = findings[0]
    # Training jobs are transient — monthly cost field must not be set
    assert f.estimated_monthly_cost_usd is None
    # Accrued cost lives in details: $28.15/hr × 1 × ~48h ≈ $1,351
    assert f.details["accrued_cost_usd"] > 0
    assert f.details["hourly_rate_per_instance"] == 28.15
    assert f.details["instance_count"] == 1
    assert f.details["cost_type"] == "accrued_to_date"


def test_accrued_cost_distributed_job():
    """Accrued cost multiplied by instance_count for distributed training."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.2xlarge", instance_count=4)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    f = findings[0]
    # $3.83/hr × 4 instances × ~48h ≈ $734
    assert f.details["instance_count"] == 4
    assert f.estimated_monthly_cost_usd is None
    # Accrued cost should be ~4× single instance cost
    single_cost = 3.83 * 1 * f.details["duration_hours"]
    assert abs(f.details["accrued_cost_usd"] - single_cost * 4) < 1.0


def test_unknown_instance_type_uses_cpu_default():
    """Unknown CPU instance type uses $0.50/hr default."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.m7i.xlarge")  # not in table
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["hourly_rate_per_instance"] == 0.50


def test_unknown_gpu_instance_type_uses_gpu_default():
    """Unknown GPU instance type uses $4.00/hr GPU floor."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.g7.xlarge")  # future SKU
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_gpu"] is True
    assert findings[0].details["hourly_rate_per_instance"] == 4.00


# ---------------------------------------------------------------------------
# GPU family detection
# ---------------------------------------------------------------------------


def test_p3_instance_detected_as_gpu():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.16xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_gpu"] is True


def test_g6_instance_detected_as_gpu():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.g6.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_gpu"] is True


def test_trn1_instance_detected_as_gpu():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.trn1.32xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_gpu"] is True


def test_m5_instance_not_gpu():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.m5.xlarge")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_gpu"] is False


# ---------------------------------------------------------------------------
# Details and title
# ---------------------------------------------------------------------------


def test_details_contain_required_fields():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.16xlarge", instance_count=2)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    d = findings[0].details
    assert "job_name" in d
    assert "instance_type" in d
    assert "instance_count" in d
    assert "is_gpu" in d
    assert "duration_hours" in d
    assert "long_running_hours_threshold" in d
    assert "accrued_cost_usd" in d
    assert "cost_type" in d
    assert d["cost_type"] == "accrued_to_date"
    assert "pricing_source" in d
    assert d["pricing_source"] == "static_estimate_us_east_1"
    assert "secondary_status" in d
    assert "max_runtime_seconds" in d
    assert "exceeded_max_runtime" in d
    assert "is_stuck_early" in d


def test_title_includes_duration_and_instance():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.16xlarge", instance_count=1)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    title = findings[0].title
    assert "Long-Running" in title
    assert "ml.p3.16xlarge" in title
    assert "h" in title  # duration in hours


def test_title_includes_instance_count_for_distributed():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.2xlarge", instance_count=8)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert "× 8" in findings[0].title


def test_resource_id_uses_arn_when_available():
    job = _make_job(age_hours=48, arn="arn:aws:sagemaker:us-east-1:123:training-job/myjob")
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].resource_id == "arn:aws:sagemaker:us-east-1:123:training-job/myjob"


# ---------------------------------------------------------------------------
# Naive datetime handling
# ---------------------------------------------------------------------------


def test_naive_creation_time_does_not_raise():
    """Naive CreationTime (no tzinfo) should be normalised to UTC without raising."""
    now = datetime.now(timezone.utc)
    job = _make_job(age_hours=48)
    job["CreationTime"] = (now - timedelta(hours=48)).replace(tzinfo=None)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_list_training_jobs_auth_error_raises_permission_error():
    sagemaker = MagicMock()
    sagemaker.get_paginator.return_value.paginate.side_effect = _auth_error()
    session = MagicMock()
    session.client.return_value = sagemaker
    with pytest.raises(PermissionError, match="sagemaker:ListTrainingJobs"):
        find_long_running_sagemaker_training_jobs(session, _REGION)


def test_describe_training_job_auth_error_raises_permission_error():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], describe_side_effect=_auth_error())
    with pytest.raises(PermissionError, match="sagemaker:DescribeTrainingJob"):
        find_long_running_sagemaker_training_jobs(session, _REGION)


def test_describe_transient_error_skips_job():
    """Non-auth describe failure should skip the job, not abort the scan."""
    job1 = _make_job(name="job-1", age_hours=48)
    job2 = _make_job(name="job-2", age_hours=48)

    sagemaker = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"TrainingJobSummaries": [job1, job2]}]
    sagemaker.get_paginator.return_value = paginator

    call_count = [0]

    def _describe(**kwargs):
        call_count[0] += 1
        if kwargs["TrainingJobName"] == "job-1":
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": ""}}, "op")
        return {
            "ResourceConfig": {"InstanceType": "ml.m5.xlarge", "InstanceCount": 1},
            "AlgorithmSpecification": {"TrainingImage": ""},
        }

    sagemaker.describe_training_job.side_effect = _describe
    session = MagicMock()
    session.client.return_value = sagemaker

    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1  # job-1 skipped, job-2 found
    assert findings[0].details["job_name"] == "job-2"


def test_long_running_hours_minimum_clamped():
    """long_running_hours=0 should be clamped to 1, not divide by zero."""
    job = _make_job(age_hours=2)
    session, _ = _make_session(jobs=[job])
    # Should not raise
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=0)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# MaxRuntimeInSeconds (issue 4)
# ---------------------------------------------------------------------------


def test_exceeded_max_runtime_forces_high_confidence():
    """Job elapsed > MaxRuntimeInSeconds → HIGH confidence regardless of multiplier."""
    # 30h elapsed, threshold=24h (would normally be MEDIUM at 1×), but max_runtime=86400s (24h)
    # elapsed 30h = 108000s > 86400s → exceeded → HIGH
    job = _make_job(age_hours=30)
    session, _ = _make_session(jobs=[job], max_runtime_seconds=86_400)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"
    assert findings[0].details["exceeded_max_runtime"] is True


def test_within_max_runtime_does_not_override_confidence():
    """Job within MaxRuntimeInSeconds uses normal duration-based confidence."""
    # 30h elapsed, max_runtime=7 days (604800s) — not exceeded → MEDIUM at 1× threshold
    job = _make_job(age_hours=30)
    session, _ = _make_session(jobs=[job], max_runtime_seconds=604_800)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert findings[0].details["exceeded_max_runtime"] is False


def test_no_max_runtime_uses_duration_logic():
    """Absent StoppingCondition falls back to duration-based confidence normally."""
    job = _make_job(age_hours=75)  # 75h >= 3×24=72h → HIGH
    session, _ = _make_session(jobs=[job], max_runtime_seconds=None)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].confidence.value == "high"
    assert findings[0].details["exceeded_max_runtime"] is False
    assert findings[0].details["max_runtime_seconds"] is None


def test_exceeded_max_runtime_in_signals():
    """MaxRuntimeInSeconds exceeded should appear in evidence signals."""
    job = _make_job(age_hours=30)
    session, _ = _make_session(jobs=[job], max_runtime_seconds=86_400)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "MaxRuntimeInSeconds exceeded" in signal_text


# ---------------------------------------------------------------------------
# SecondaryStatus (issue 2)
# ---------------------------------------------------------------------------


def test_secondary_status_included_in_details():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], secondary_status="Training")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["secondary_status"] == "Training"
    assert findings[0].details["is_stuck_early"] is False


def test_stuck_early_status_boosts_to_high_confidence():
    """Job at 1× threshold but SecondaryStatus=Downloading → HIGH confidence."""
    job = _make_job(age_hours=25)  # 25h >= 24h threshold, < 72h (3×)
    session, _ = _make_session(jobs=[job], secondary_status="Downloading")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"
    assert findings[0].details["is_stuck_early"] is True


def test_starting_status_is_stuck_early():
    job = _make_job(age_hours=25)
    session, _ = _make_session(jobs=[job], secondary_status="Starting")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_stuck_early"] is True


def test_normal_training_status_not_stuck_early():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], secondary_status="Training")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["is_stuck_early"] is False


def test_secondary_status_in_signals():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], secondary_status="Downloading")
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "Downloading" in signal_text
    assert "pre-training phase" in signal_text


# ---------------------------------------------------------------------------
# Distributed training signal (issue 3)
# ---------------------------------------------------------------------------


def test_distributed_job_signal_in_evidence():
    """Distributed job (instance_count > 1) gets an explanatory signal."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.2xlarge", instance_count=8)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "Distributed training" in signal_text
    assert "8 instances" in signal_text


def test_single_instance_no_distributed_signal():
    """Single-instance job should NOT get the distributed signal."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.m5.xlarge", instance_count=1)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "Distributed" not in signal_text


# ---------------------------------------------------------------------------
# Pricing transparency (issue 1)
# ---------------------------------------------------------------------------


def test_pricing_source_in_details():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["pricing_source"] == "static_estimate_us_east_1"


def test_cost_type_is_accrued_to_date():
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert findings[0].details["cost_type"] == "accrued_to_date"


def test_pricing_disclaimer_in_signals():
    """Cost signal should mention us-east-1 baseline and regional variance."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job])
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "us-east-1 baseline" in signal_text
    assert "varies by region" in signal_text


# ---------------------------------------------------------------------------
# Managed spot training (issue 2)
# ---------------------------------------------------------------------------


def test_spot_job_max_runtime_not_exceeded_when_within_max_wait():
    """Spot job: MaxRuntimeInSeconds exceeded but MaxWaitTimeInSeconds not → not exceeded."""
    # 30h elapsed; MaxRuntimeInSeconds=86400 (24h) would fire for on-demand,
    # but this is spot so we compare against MaxWaitTimeInSeconds=259200 (72h).
    job = _make_job(age_hours=30)
    session, _ = _make_session(
        jobs=[job],
        max_runtime_seconds=86_400,  # 24h — would be exceeded for on-demand
        max_wait_time_seconds=259_200,  # 72h — NOT exceeded
        enable_managed_spot=True,
    )
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    # Should NOT be treated as exceeded (wall-clock limit is MaxWaitTimeInSeconds)
    assert findings[0].details["exceeded_max_runtime"] is False
    assert findings[0].details["enable_managed_spot"] is True


def test_spot_job_exceeded_max_wait_time_is_high_confidence():
    """Spot job: elapsed > MaxWaitTimeInSeconds → HIGH confidence."""
    # 80h elapsed, MaxWaitTimeInSeconds=259200 (72h)
    job = _make_job(age_hours=80)
    session, _ = _make_session(
        jobs=[job],
        max_wait_time_seconds=259_200,  # 72h — elapsed 80h > 72h
        enable_managed_spot=True,
    )
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"
    assert findings[0].details["exceeded_max_runtime"] is True
    assert findings[0].details["max_wait_time_seconds"] == 259_200


def test_spot_job_signal_mentions_max_wait_not_max_runtime():
    """Spot job exceeded: signal must reference MaxWaitTimeInSeconds, not MaxRuntimeInSeconds."""
    job = _make_job(age_hours=80)
    session, _ = _make_session(
        jobs=[job],
        max_wait_time_seconds=259_200,
        enable_managed_spot=True,
    )
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    signal_text = " ".join(findings[0].evidence.signals_used)
    assert "MaxWaitTimeInSeconds" in signal_text
    assert "MaxRuntimeInSeconds exceeded" not in signal_text


def test_spot_job_not_checked_list_excludes_spot_note():
    """Spot jobs: 'Spot training' not-checked note should be dropped (we know it's spot)."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], enable_managed_spot=True)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    not_checked_text = " ".join(findings[0].evidence.signals_not_checked)
    assert "Spot training" not in not_checked_text


def test_ondemand_job_not_checked_includes_spot_note():
    """On-demand jobs: not-checked list should still mention spot semantics."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], enable_managed_spot=False)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    not_checked_text = " ".join(findings[0].evidence.signals_not_checked)
    assert "Spot training" in not_checked_text


# ---------------------------------------------------------------------------
# Heterogeneous clusters (issue 3)
# ---------------------------------------------------------------------------


def test_heterogeneous_cluster_cost_aggregated():
    """InstanceGroups with mixed types: burn rate and accrued cost aggregate all groups."""
    job = _make_job(age_hours=48)
    # Group 1: 1× ml.p3.16xlarge @ $28.15/hr; Group 2: 4× ml.m5.xlarge @ $0.23/hr
    # Total hourly = 28.15 + 4×0.23 = 29.07/hr
    session, _ = _make_session(
        jobs=[job],
        instance_groups=[
            {"InstanceType": "ml.p3.16xlarge", "InstanceCount": 1},
            {"InstanceType": "ml.m5.xlarge", "InstanceCount": 4},
        ],
    )
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    assert len(findings) == 1
    f = findings[0]
    assert f.details["is_heterogeneous_cluster"] is True
    assert f.details["instance_count"] == 5  # 1 + 4
    assert f.details["instance_type"] is None  # no single type for heterogeneous
    assert f.details["instance_groups"] is not None
    assert len(f.details["instance_groups"]) == 2
    assert f.details["hourly_rate_per_instance"] is None  # not meaningful for mixed clusters
    expected_burn = round(28.15 + 4 * 0.23, 2)
    assert abs(f.details["burn_rate_per_hour"] - expected_burn) < 0.05


def test_heterogeneous_cluster_gpu_detected_by_family_not_rate():
    """GPU detection uses _GPU_FAMILIES per group, not total burn rate heuristic.

    A large CPU-only cluster must NOT be misclassified as GPU even if its total burn
    rate exceeds _DEFAULT_HOURLY_COST_GPU. A cheap GPU group must still be detected.
    """
    job = _make_job(age_hours=48)

    # High-cost CPU-only: 24× ml.m5.24xlarge @ $5.53/hr each = $132.72/hr total — would
    # exceed _DEFAULT_HOURLY_COST_GPU ($4.00) if rate-based, but no GPU families present.
    session_cpu, _ = _make_session(
        jobs=[job],
        instance_groups=[
            {"InstanceType": "ml.m5.24xlarge", "InstanceCount": 24},
        ],
    )
    findings_cpu = find_long_running_sagemaker_training_jobs(
        session_cpu, _REGION, long_running_hours=24
    )
    assert findings_cpu[0].details["is_gpu"] is False, "CPU-only cluster must not be flagged as GPU"

    # Cheap GPU group: 1× ml.g4dn.xlarge @ $0.74/hr — well below _DEFAULT_HOURLY_COST_GPU
    # but is still a GPU instance by family.
    session_gpu, _ = _make_session(
        jobs=[job],
        instance_groups=[
            {"InstanceType": "ml.g4dn.xlarge", "InstanceCount": 1},
            {"InstanceType": "ml.m5.large", "InstanceCount": 2},
        ],
    )
    findings_gpu = find_long_running_sagemaker_training_jobs(
        session_gpu, _REGION, long_running_hours=24
    )
    assert (
        findings_gpu[0].details["is_gpu"] is True
    ), "Cluster with GPU group must be flagged as GPU"
    assert findings_gpu[0].risk.value in ("high", "critical")


def test_heterogeneous_cluster_instance_label_includes_all_groups():
    """Instance label for a heterogeneous cluster must show all group types."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(
        jobs=[job],
        instance_groups=[
            {"InstanceType": "ml.p3.2xlarge", "InstanceCount": 2},
            {"InstanceType": "ml.m5.large", "InstanceCount": 4},
        ],
    )
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    title = findings[0].title
    # Both types must appear in title/label
    assert "ml.p3.2xlarge" in title
    assert "ml.m5.large" in title


def test_homogeneous_cluster_not_flagged_as_heterogeneous():
    """Standard homogeneous job must not set is_heterogeneous_cluster."""
    job = _make_job(age_hours=48)
    session, _ = _make_session(jobs=[job], instance_type="ml.p3.2xlarge", instance_count=2)
    findings = find_long_running_sagemaker_training_jobs(session, _REGION, long_running_hours=24)
    f = findings[0]
    assert f.details["is_heterogeneous_cluster"] is False
    assert f.details["instance_type"] == "ml.p3.2xlarge"
    assert f.details["instance_groups"] is None
    assert f.details["hourly_rate_per_instance"] == 3.83
