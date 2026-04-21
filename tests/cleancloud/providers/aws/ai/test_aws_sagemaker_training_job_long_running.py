from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_training_job_long_running import (
    RULE_METADATA,
    _is_accelerator_backed,
    _is_job_accelerator_backed,
    _normalize_describe,
    _normalize_list_item,
    find_long_running_sagemaker_training_jobs,
)

_REGION = "us-east-1"
_ARN_PREFIX = "arn:aws:sagemaker:us-east-1:123456789012:training-job"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_list_job(
    name="train-job-1",
    arn=None,
    age_hours=48,
    status="InProgress",
    secondary_status="Training",
    lmt_hours=None,
):
    """Return a raw ListTrainingJobs item."""
    now = datetime.now(timezone.utc)
    item = {
        "TrainingJobName": name,
        "TrainingJobArn": arn or f"{_ARN_PREFIX}/{name}",
        "TrainingJobStatus": status,
        "CreationTime": now - timedelta(hours=age_hours),
        "SecondaryStatus": secondary_status,
    }
    if lmt_hours is not None:
        item["LastModifiedTime"] = now - timedelta(hours=lmt_hours)
    return item


def _make_describe(
    name="train-job-1",
    arn=None,
    status="InProgress",
    training_start_hours=None,
    secondary_status="Training",
    enable_spot=False,
    max_runtime_seconds=None,
    max_wait_time_seconds=None,
    max_pending_time_seconds=None,
    instance_type="ml.m5.xlarge",
    instance_count=1,
    instance_groups=None,
    serverless=False,
    warm_pool_status=None,
):
    """Return a raw DescribeTrainingJob response."""
    now = datetime.now(timezone.utc)
    result = {
        "TrainingJobArn": arn or f"{_ARN_PREFIX}/{name}",
        "TrainingJobName": name,
        "TrainingJobStatus": status,
        "SecondaryStatus": secondary_status,
        "EnableManagedSpotTraining": enable_spot,
    }
    if training_start_hours is not None:
        result["TrainingStartTime"] = now - timedelta(hours=training_start_hours)

    stopping = {}
    if max_runtime_seconds is not None:
        stopping["MaxRuntimeInSeconds"] = max_runtime_seconds
    if max_wait_time_seconds is not None:
        stopping["MaxWaitTimeInSeconds"] = max_wait_time_seconds
    if max_pending_time_seconds is not None:
        stopping["MaxPendingTimeInSeconds"] = max_pending_time_seconds
    result["StoppingCondition"] = stopping

    resource_config: dict = {}
    if instance_groups is not None:
        resource_config["InstanceGroups"] = instance_groups
    else:
        resource_config["InstanceType"] = instance_type
        resource_config["InstanceCount"] = instance_count
    result["ResourceConfig"] = resource_config

    if serverless:
        result["ServerlessJobConfig"] = {}

    if warm_pool_status is not None:
        result["WarmPoolStatus"] = {"Status": warm_pool_status}

    return result


def _make_session(
    jobs=None,
    describe_response=None,
    describe_side_effect=None,
    list_side_effect=None,
):
    """Build a mock boto3 session."""
    sagemaker = MagicMock()

    # List paginator
    if list_side_effect is not None:
        paginator = MagicMock()
        paginator.paginate.side_effect = list_side_effect
        sagemaker.get_paginator.return_value = paginator
    else:
        page = {"TrainingJobSummaries": jobs or []}
        paginator = MagicMock()
        paginator.paginate.return_value = [page]
        sagemaker.get_paginator.return_value = paginator

    # Describe
    if describe_side_effect is not None:
        sagemaker.describe_training_job.side_effect = describe_side_effect
    elif describe_response is not None:
        sagemaker.describe_training_job.return_value = describe_response
    else:
        sagemaker.describe_training_job.return_value = _make_describe()

    session = MagicMock()
    session.client.return_value = sagemaker
    return session, sagemaker


def _auth_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "Access Denied"}}, "op")


def _transient_error(code="ThrottlingException"):
    return ClientError({"Error": {"Code": code, "Message": "Throttled"}}, "op")


# ---------------------------------------------------------------------------
# TestMustEmit — basic detection
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_basic_long_running_job_detected(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.sagemaker.training_job.long_running"
        assert f.resource_type == "aws.sagemaker.training_job"
        assert f.provider == "aws"
        assert f.region == _REGION

    def test_exact_threshold_emits(self):
        """Job at exactly the threshold (24h) emits."""
        job = _make_list_job(age_hours=24)
        desc = _make_describe(training_start_hours=24)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert len(findings) == 1

    def test_creation_time_anchor_when_no_training_start(self):
        """When TrainingStartTime absent, CreationTime is used as anchor."""
        job = _make_list_job(age_hours=30)
        desc = _make_describe()  # no training_start_hours → no TrainingStartTime
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert len(findings) == 1
        assert findings[0].details["runtime_anchor_type"] == "creation_time"
        assert findings[0].details["training_start_time"] is None

    def test_training_start_time_anchor(self):
        """When TrainingStartTime present, it is used as anchor."""
        job = _make_list_job(age_hours=50)
        desc = _make_describe(training_start_hours=26)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.details["runtime_anchor_type"] == "training_start_time"
        assert f.details["training_start_time"] is not None
        assert f.details["active_training_hours"] == 26

    def test_no_jobs_returns_empty(self):
        session, _ = _make_session(jobs=[])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings == []

    def test_resource_id_from_describe_arn(self):
        custom_arn = f"{_ARN_PREFIX}/myjob"
        job = _make_list_job(age_hours=48, arn=custom_arn)
        desc = _make_describe(arn=custom_arn)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].resource_id == custom_arn

    def test_resource_id_falls_back_to_list_arn_when_describe_arn_absent(self):
        list_arn = f"{_ARN_PREFIX}/fallback-job"
        job = _make_list_job(name="fallback-job", age_hours=48, arn=list_arn)
        # Describe response without TrainingJobArn field
        desc = _make_describe()
        desc.pop("TrainingJobArn", None)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].resource_id == list_arn

    def test_estimated_monthly_cost_is_none(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestMustSkipListLevel — list-level exclusion rules
# ---------------------------------------------------------------------------


class TestMustSkipListLevel:
    def test_name_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["TrainingJobName"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_arn_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["TrainingJobArn"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_status_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["TrainingJobStatus"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_non_inprogress_status_skipped(self):
        for status in ("Completed", "Failed", "Stopping", "Stopped"):
            job = _make_list_job(age_hours=48, status=status)
            session, _ = _make_session(jobs=[job])
            findings = find_long_running_sagemaker_training_jobs(session, _REGION)
            assert findings == [], f"Expected skip for status {status}"

    def test_creation_time_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["CreationTime"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_creation_time_naive_skipped(self):
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = datetime.now() - timedelta(hours=48)  # no tzinfo
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_creation_time_future_beyond_skew_skipped(self):
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_last_modified_time_future_beyond_skew_skips_item(self):
        job = _make_list_job(age_hours=48)
        job["LastModifiedTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_short_job_below_threshold_skipped(self):
        job = _make_list_job(age_hours=6)
        desc = _make_describe()
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert (
            find_long_running_sagemaker_training_jobs(
                session, _REGION, long_running_hours_threshold=24
            )
            == []
        )

    def test_item_not_dict_skipped(self):
        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"TrainingJobSummaries": ["not-a-dict"]}]
        sagemaker.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sagemaker
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []


# ---------------------------------------------------------------------------
# TestMustSkipDescribeLevel — describe-level exclusion rules
# ---------------------------------------------------------------------------


class TestMustSkipDescribeLevel:
    def test_describe_status_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        del desc["TrainingJobStatus"]
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_describe_status_not_inprogress_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(status="Completed")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_training_start_time_naive_treated_as_null_uses_creation_time(self):
        """Naive TrainingStartTime normalizes to null → CreationTime used as anchor."""
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        desc["TrainingStartTime"] = datetime.now() - timedelta(hours=46)  # naive
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        # Item is still emitted using creation_time anchor
        assert len(findings) == 1
        assert findings[0].details["runtime_anchor_type"] == "creation_time"

    def test_training_start_time_future_beyond_skew_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        desc["TrainingStartTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_training_start_before_creation_beyond_skew_skipped(self):
        """TrainingStartTime that is before CreationTime by more than 300s → skip."""
        now = datetime.now(timezone.utc)
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = now - timedelta(hours=48)
        desc = _make_describe()
        # TrainingStartTime 1 hour before CreationTime — exceeds skew tolerance of 300s
        desc["TrainingStartTime"] = now - timedelta(hours=49)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_training_start_within_skew_of_creation_emits(self):
        """TrainingStartTime within clock_skew_tolerance_seconds before CreationTime → emit."""
        now = datetime.now(timezone.utc)
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = now - timedelta(hours=48)
        desc = _make_describe()
        # TrainingStartTime 200s before CreationTime — within 300s skew tolerance
        desc["TrainingStartTime"] = (now - timedelta(hours=48)) - timedelta(seconds=200)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings) == 1

    def test_elapsed_below_threshold_after_describe_skipped(self):
        """Job with TrainingStartTime only 12h ago is below 24h threshold."""
        job = _make_list_job(age_hours=50)  # old creation time, but…
        desc = _make_describe(training_start_hours=12)  # only running 12h
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert (
            find_long_running_sagemaker_training_jobs(
                session, _REGION, long_running_hours_threshold=24
            )
            == []
        )


# ---------------------------------------------------------------------------
# TestMustFailRule — failure model
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_list_permission_error_access_denied_raises(self):
        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = _auth_error("AccessDeniedException")
        sagemaker.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sagemaker
        with pytest.raises(PermissionError, match="sagemaker:ListTrainingJobs"):
            find_long_running_sagemaker_training_jobs(session, _REGION)

    def test_list_permission_error_unauthorized_raises(self):
        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = _auth_error("UnauthorizedOperation")
        sagemaker.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sagemaker
        with pytest.raises(PermissionError, match="sagemaker:ListTrainingJobs"):
            find_long_running_sagemaker_training_jobs(session, _REGION)

    def test_list_non_permission_error_reraises(self):
        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = _transient_error()
        sagemaker.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sagemaker
        with pytest.raises(ClientError):
            find_long_running_sagemaker_training_jobs(session, _REGION)

    def test_list_botocore_error_reraises(self):
        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = BotoCoreError()
        sagemaker.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sagemaker
        with pytest.raises(BotoCoreError):
            find_long_running_sagemaker_training_jobs(session, _REGION)

    def test_describe_permission_error_raises(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(
            jobs=[job], describe_side_effect=_auth_error("AccessDeniedException")
        )
        with pytest.raises(PermissionError, match="sagemaker:DescribeTrainingJob"):
            find_long_running_sagemaker_training_jobs(session, _REGION)


# ---------------------------------------------------------------------------
# TestDescribeSkipItem — non-permission describe failures → SKIP ITEM
# ---------------------------------------------------------------------------


class TestDescribeSkipItem:
    def test_describe_transient_error_skips_job(self):
        job1 = _make_list_job(name="job-1", age_hours=48)
        job2 = _make_list_job(name="job-2", age_hours=48)
        desc2 = _make_describe(name="job-2")

        def _describe(**kwargs):
            if kwargs["TrainingJobName"] == "job-1":
                raise _transient_error()
            return desc2

        session, sagemaker = _make_session(jobs=[job1, job2])
        sagemaker.describe_training_job.side_effect = _describe

        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings) == 1
        assert findings[0].details["training_job_name"] == "job-2"

    def test_describe_resource_not_found_skips_job(self):
        job = _make_list_job(age_hours=48)
        err = ClientError({"Error": {"Code": "ResourceNotFound", "Message": "not found"}}, "op")
        session, _ = _make_session(jobs=[job], describe_side_effect=err)
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_describe_botocore_error_skips_job(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job], describe_side_effect=BotoCoreError())
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []

    def test_describe_returns_non_dict_skips_job(self):
        job = _make_list_job(age_hours=48)
        session, sagemaker = _make_session(jobs=[job])
        sagemaker.describe_training_job.return_value = "bad-response"
        assert find_long_running_sagemaker_training_jobs(session, _REGION) == []


# ---------------------------------------------------------------------------
# TestRuntimeAnchor — runtime anchor selection logic
# ---------------------------------------------------------------------------


class TestRuntimeAnchor:
    def test_anchor_is_training_start_time_when_present(self):
        job = _make_list_job(age_hours=100)
        desc = _make_describe(training_start_hours=50)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert findings[0].details["runtime_anchor_type"] == "training_start_time"
        assert findings[0].details["elapsed_runtime_hours"] == 50
        assert findings[0].details["active_training_hours"] == 50

    def test_anchor_is_creation_time_when_no_training_start(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()  # no training start
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert findings[0].details["runtime_anchor_type"] == "creation_time"
        assert findings[0].details["active_training_hours"] is None
        assert findings[0].details["elapsed_runtime_hours"] == findings[0].details["job_age_hours"]

    def test_short_training_start_with_old_creation_time_uses_training_start(self):
        """Job created 72h ago but only started training 12h ago → not emitted (12h < 24h)."""
        job = _make_list_job(age_hours=72)
        desc = _make_describe(training_start_hours=12)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert findings == []

    def test_job_age_hours_always_based_on_creation_time(self):
        job = _make_list_job(age_hours=60)
        desc = _make_describe(training_start_hours=30)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["job_age_hours"] == 60
        assert findings[0].details["active_training_hours"] == 30


# ---------------------------------------------------------------------------
# TestStoppingCondition — applicable_runtime_limit_seconds logic
# ---------------------------------------------------------------------------


class TestStoppingCondition:
    def test_spot_uses_max_wait_time_as_limit(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(
            training_start_hours=48,
            enable_spot=True,
            max_wait_time_seconds=259_200,  # 72h
            max_runtime_seconds=86_400,  # 24h — not used for spot
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["applicable_runtime_limit_seconds"] == 259_200
        # 48h elapsed (172800s) < 72h (259200s) → not exceeded
        assert findings[0].details["exceeded_applicable_runtime_limit"] is False

    def test_spot_exceeds_max_wait_time(self):
        job = _make_list_job(age_hours=80)
        desc = _make_describe(
            training_start_hours=80,
            enable_spot=True,
            max_wait_time_seconds=259_200,  # 72h — exceeded by 80h
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["exceeded_applicable_runtime_limit"] is True

    def test_spot_no_max_wait_time_falls_back_to_max_runtime(self):
        """Spot + no MaxWaitTimeInSeconds: falls back to MaxRuntimeInSeconds per spec §3."""
        job = _make_list_job(age_hours=48)
        desc = _make_describe(
            training_start_hours=48,
            enable_spot=True,
            max_runtime_seconds=86_400,  # fallback when MaxWaitTimeInSeconds absent
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        # 48h = 172800s > 86400s → exceeded
        assert findings[0].details["applicable_runtime_limit_seconds"] == 86_400
        assert findings[0].details["exceeded_applicable_runtime_limit"] is True

    def test_spot_no_max_wait_no_max_runtime_unbounded(self):
        """Spot with neither MaxWaitTimeInSeconds nor MaxRuntimeInSeconds → unbounded."""
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, enable_spot=True)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["applicable_runtime_limit_seconds"] is None
        assert findings[0].details["unbounded_runtime_limit"] is True

    def test_non_spot_with_training_start_uses_max_runtime(self):
        job = _make_list_job(age_hours=50)
        desc = _make_describe(
            training_start_hours=30,
            enable_spot=False,
            max_runtime_seconds=86_400,  # 24h — exceeded by 30h
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["applicable_runtime_limit_seconds"] == 86_400
        assert findings[0].details["exceeded_applicable_runtime_limit"] is True

    def test_non_spot_without_training_start_ignores_max_runtime(self):
        """MaxRuntimeInSeconds only applies when TrainingStartTime is present."""
        job = _make_list_job(age_hours=30)
        desc = _make_describe(
            enable_spot=False,
            max_runtime_seconds=86_400,  # present, but no TrainingStartTime
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["applicable_runtime_limit_seconds"] is None
        assert findings[0].details["unbounded_runtime_limit"] is True

    def test_no_stopping_condition_unbounded(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        desc["StoppingCondition"] = {}
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["applicable_runtime_limit_seconds"] is None
        assert findings[0].details["unbounded_runtime_limit"] is True

    def test_stopping_condition_non_dict_degrades_safely(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        desc["StoppingCondition"] = "bad"
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings) == 1
        assert findings[0].details["max_runtime_seconds"] is None

    def test_max_pending_time_emitted_as_optional_context(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, max_pending_time_seconds=3600)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["max_pending_time_seconds"] == 3600


# ---------------------------------------------------------------------------
# TestConfidenceModel — HIGH when exceeded_applicable_runtime_limit, MEDIUM otherwise
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_confidence_when_exceeded_applicable_limit(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(
            training_start_hours=30,
            max_runtime_seconds=86_400,  # 24h exceeded by 30h
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_threshold_met_no_limit_exceeded(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(training_start_hours=30)  # no stopping condition
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].confidence.value == "medium"

    def test_medium_confidence_when_within_applicable_limit(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(
            training_start_hours=30,
            max_runtime_seconds=604_800,  # 7 days — not exceeded
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].confidence.value == "medium"
        assert findings[0].details["exceeded_applicable_runtime_limit"] is False

    def test_high_confidence_spot_exceeded_max_wait(self):
        job = _make_list_job(age_hours=80)
        desc = _make_describe(
            training_start_hours=80,
            enable_spot=True,
            max_wait_time_seconds=259_200,  # 72h — exceeded
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# TestRiskModel — HIGH (accelerator) or MEDIUM
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_high_risk_gpu_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, instance_type="ml.p3.16xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_g5_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, instance_type="ml.g5.xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_trn1_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, instance_type="ml.trn1.32xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_inf_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, instance_type="ml.inf1.xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_medium_risk_cpu_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, instance_type="ml.m5.xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "medium"

    def test_high_risk_from_accelerator_in_instance_groups(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(
            training_start_hours=48,
            instance_groups=[
                {"InstanceType": "ml.g4dn.xlarge", "InstanceCount": 1},
                {"InstanceType": "ml.m5.large", "InstanceCount": 4},
            ],
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "high"
        assert findings[0].details["is_accelerator_backed"] is True

    def test_medium_risk_cpu_only_instance_groups(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(
            training_start_hours=48,
            instance_groups=[
                {"InstanceType": "ml.m5.xlarge", "InstanceCount": 4},
                {"InstanceType": "ml.c5.4xlarge", "InstanceCount": 2},
            ],
        )
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].risk.value == "medium"
        assert findings[0].details["is_accelerator_backed"] is False

    def test_no_critical_risk_level_emitted(self):
        """Spec §13: no CRITICAL risk — max is HIGH."""
        for instance_type in ("ml.p4d.24xlarge", "ml.g5.48xlarge", "ml.trn1n.32xlarge"):
            job = _make_list_job(age_hours=48)
            desc = _make_describe(
                training_start_hours=48,
                instance_type=instance_type,
                max_runtime_seconds=3600,  # force HIGH confidence too
            )
            session, _ = _make_session(jobs=[job], describe_response=desc)
            findings = find_long_running_sagemaker_training_jobs(session, _REGION)
            assert findings[0].risk.value != "critical", f"Got CRITICAL for {instance_type}"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].estimated_monthly_cost_usd is None

    def test_no_accrued_cost_in_details(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        d = findings[0].details
        assert "accrued_cost_usd" not in d
        assert "hourly_rate_per_instance" not in d
        assert "burn_rate_per_hour" not in d
        assert "cost_type" not in d
        assert "pricing_source" not in d


# ---------------------------------------------------------------------------
# TestNormalizeListItem — unit tests for _normalize_list_item
# ---------------------------------------------------------------------------


class TestNormalizeListItem:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_valid_item_normalizes(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
            "SecondaryStatus": "Training",
        }
        result = _normalize_list_item(item, now)
        assert result is not None
        assert result["training_job_name"] == "job-1"
        assert result["list_status"] == "InProgress"
        assert result["job_age_hours"] == 24

    def test_non_dict_returns_none(self):
        assert _normalize_list_item("bad", datetime.now(timezone.utc)) is None

    def test_empty_name_returns_none(self):
        now = self._now()
        item = {
            "TrainingJobName": "",
            "TrainingJobArn": f"{_ARN_PREFIX}/x",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
        }
        assert _normalize_list_item(item, now) is None

    def test_naive_creation_time_returns_none(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now.replace(tzinfo=None) - timedelta(hours=24),
        }
        assert _normalize_list_item(item, now) is None

    def test_creation_time_not_datetime_returns_none(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": "2024-01-01T00:00:00Z",  # string, not datetime
        }
        assert _normalize_list_item(item, now) is None

    def test_future_creation_time_beyond_skew_returns_none(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now + timedelta(seconds=600),
        }
        assert _normalize_list_item(item, now) is None

    def test_naive_lmt_is_null(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
            "LastModifiedTime": (now - timedelta(hours=12)).replace(tzinfo=None),
        }
        result = _normalize_list_item(item, now)
        assert result is not None
        assert result["last_modified_time_utc"] is None

    def test_future_lmt_beyond_skew_returns_none(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
            "LastModifiedTime": now + timedelta(seconds=600),
        }
        assert _normalize_list_item(item, now) is None

    def test_secondary_status_optional_null_when_absent(self):
        now = self._now()
        item = {
            "TrainingJobName": "job-1",
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
        }
        result = _normalize_list_item(item, now)
        assert result["list_secondary_status"] is None


# ---------------------------------------------------------------------------
# TestNormalizeDescribe — unit tests for _normalize_describe
# ---------------------------------------------------------------------------


class TestNormalizeDescribe:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_valid_response_normalizes(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "EnableManagedSpotTraining": False,
            "StoppingCondition": {"MaxRuntimeInSeconds": 3600},
            "ResourceConfig": {"InstanceType": "ml.m5.xlarge", "InstanceCount": 1},
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["describe_status"] == "InProgress"
        assert result["max_runtime_seconds"] == 3600
        assert result["instance_type"] == "ml.m5.xlarge"

    def test_non_dict_returns_none(self):
        assert _normalize_describe("bad", datetime.now(timezone.utc)) is None

    def test_missing_status_returns_none(self):
        now = self._now()
        resp = {"TrainingJobArn": f"{_ARN_PREFIX}/job-1"}
        assert _normalize_describe(resp, now) is None

    def test_naive_training_start_treated_as_null(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "TrainingStartTime": (now - timedelta(hours=24)).replace(tzinfo=None),
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["training_start_time_utc"] is None

    def test_future_training_start_beyond_skew_returns_none(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "TrainingStartTime": now + timedelta(seconds=600),
        }
        assert _normalize_describe(resp, now) is None

    def test_resource_config_non_dict_degrades_to_null_fields(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "ResourceConfig": "bad",
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["instance_type"] is None
        assert result["instance_count"] is None

    def test_stopping_condition_non_dict_degrades_to_null_fields(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "StoppingCondition": None,
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["max_runtime_seconds"] is None
        assert result["max_wait_time_seconds"] is None

    def test_serverless_job_config_present_flag(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "ServerlessJobConfig": {},
        }
        result = _normalize_describe(resp, now)
        assert result["serverless_job_config_present"] is True

    def test_serverless_job_config_absent_is_false(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
        }
        result = _normalize_describe(resp, now)
        assert result["serverless_job_config_present"] is False

    def test_warm_pool_status_extracted(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "WarmPoolStatus": {"Status": "Available"},
        }
        result = _normalize_describe(resp, now)
        assert result["warm_pool_status"] == "Available"

    def test_warm_pool_status_absent_is_null(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
        }
        result = _normalize_describe(resp, now)
        assert result["warm_pool_status"] is None

    def test_zero_max_runtime_treated_as_null(self):
        now = self._now()
        resp = {
            "TrainingJobArn": f"{_ARN_PREFIX}/job-1",
            "TrainingJobStatus": "InProgress",
            "StoppingCondition": {"MaxRuntimeInSeconds": 0},
        }
        result = _normalize_describe(resp, now)
        assert result["max_runtime_seconds"] is None


# ---------------------------------------------------------------------------
# TestIsAcceleratorBacked — unit tests for _is_accelerator_backed
# ---------------------------------------------------------------------------


class TestIsAcceleratorBacked:
    def test_g_prefix_is_accelerator(self):
        assert _is_accelerator_backed("ml.g5.xlarge") is True

    def test_p_prefix_is_accelerator(self):
        assert _is_accelerator_backed("ml.p3.16xlarge") is True

    def test_inf_prefix_is_accelerator(self):
        assert _is_accelerator_backed("ml.inf1.xlarge") is True

    def test_trn_prefix_is_accelerator(self):
        assert _is_accelerator_backed("ml.trn1.32xlarge") is True

    def test_m_prefix_not_accelerator(self):
        assert _is_accelerator_backed("ml.m5.xlarge") is False

    def test_c_prefix_not_accelerator(self):
        assert _is_accelerator_backed("ml.c5.4xlarge") is False

    def test_none_not_accelerator(self):
        assert _is_accelerator_backed(None) is False

    def test_empty_string_not_accelerator(self):
        assert _is_accelerator_backed("") is False


class TestIsJobAcceleratorBacked:
    def test_accelerator_instance_type(self):
        assert _is_job_accelerator_backed("ml.p3.2xlarge", None) is True

    def test_non_accelerator_instance_type(self):
        assert _is_job_accelerator_backed("ml.m5.xlarge", None) is False

    def test_accelerator_in_groups(self):
        groups = [
            {"InstanceType": "ml.m5.xlarge", "InstanceCount": 4},
            {"InstanceType": "ml.g4dn.xlarge", "InstanceCount": 1},
        ]
        assert _is_job_accelerator_backed(None, groups) is True

    def test_no_accelerator_in_groups(self):
        groups = [
            {"InstanceType": "ml.m5.xlarge", "InstanceCount": 4},
            {"InstanceType": "ml.c5.2xlarge", "InstanceCount": 2},
        ]
        assert _is_job_accelerator_backed(None, groups) is False

    def test_groups_with_bad_dict_entries_graceful(self):
        groups = ["not-a-dict", {"InstanceType": "ml.p3.2xlarge", "InstanceCount": 1}]
        assert _is_job_accelerator_backed(None, groups) is True

    def test_none_groups_falls_back_to_instance_type(self):
        assert _is_job_accelerator_backed("ml.g5.xlarge", None) is True


# ---------------------------------------------------------------------------
# TestDetailsContract — required and optional details fields per spec §11
# ---------------------------------------------------------------------------


class TestDetailsContract:
    _REQUIRED = [
        "evaluation_path",
        "training_job_arn",
        "training_job_name",
        "normalized_status",
        "creation_time",
        "training_start_time",
        "runtime_anchor_type",
        "elapsed_runtime_hours",
        "job_age_hours",
        "active_training_hours",
        "long_running_hours_threshold",
        "evaluation_window_start",
        "evaluation_window_end",
        "enable_managed_spot_training",
        "applicable_runtime_limit_seconds",
        "unbounded_runtime_limit",
        "exceeded_applicable_runtime_limit",
    ]

    _OPTIONAL = [
        "secondary_status",
        "max_runtime_seconds",
        "max_wait_time_seconds",
        "max_pending_time_seconds",
        "instance_type",
        "instance_count",
        "instance_groups",
        "serverless_job_config_present",
        "warm_pool_status",
        "is_accelerator_backed",
    ]

    def test_all_required_fields_present(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        d = findings[0].details
        for field in self._REQUIRED:
            assert field in d, f"Missing required field: {field}"

    def test_all_optional_fields_present(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        d = findings[0].details
        for field in self._OPTIONAL:
            assert field in d, f"Missing optional field: {field}"

    def test_evaluation_path_value(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert (
            findings[0].details["evaluation_path"]
            == "long-running-sagemaker-training-job-review-candidate"
        )

    def test_normalized_status_value(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["normalized_status"] == "InProgress"

    def test_evaluation_window_values_are_iso_strings(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        d = findings[0].details
        # Should not raise
        datetime.fromisoformat(d["evaluation_window_start"])
        datetime.fromisoformat(d["evaluation_window_end"])

    def test_creation_time_is_iso_string(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        datetime.fromisoformat(findings[0].details["creation_time"])

    def test_serverless_job_config_present_in_details(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, serverless=True)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["serverless_job_config_present"] is True

    def test_warm_pool_status_in_details(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48, warm_pool_status="Available")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["warm_pool_status"] == "Available"

    def test_instance_groups_in_details(self):
        job = _make_list_job(age_hours=48)
        groups = [
            {"InstanceType": "ml.p3.2xlarge", "InstanceCount": 2},
            {"InstanceType": "ml.m5.large", "InstanceCount": 4},
        ]
        desc = _make_describe(training_start_hours=48, instance_groups=groups)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].details["instance_groups"] == groups
        assert findings[0].details["instance_type"] is None  # no single type for hetero


# ---------------------------------------------------------------------------
# TestTitleAndReason — fixed strings per spec §14
# ---------------------------------------------------------------------------


class TestTitleAndReason:
    def test_fixed_title(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].title == "Long-running SageMaker training job review candidate"

    def test_fixed_reason(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert findings[0].reason == (
            "InProgress SageMaker training job has exceeded the configured "
            "long-running threshold"
        )

    def test_title_does_not_include_instance_type(self):
        """Title is a fixed string — must not dynamically embed instance info."""
        job = _make_list_job(age_hours=48)
        desc = _make_describe(instance_type="ml.p3.16xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert "ml.p3.16xlarge" not in findings[0].title


# ---------------------------------------------------------------------------
# TestEvidenceContract — required evidence wording per spec §11
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_signals_used_mentions_inprogress_status(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        signal_text = " ".join(findings[0].evidence.signals_used)
        assert "InProgress" in signal_text

    def test_signals_used_mentions_elapsed_runtime_hours(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        signal_text = " ".join(findings[0].evidence.signals_used)
        assert "elapsed_runtime_hours" in signal_text or "48" in signal_text

    def test_signals_used_mentions_runtime_anchor(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(training_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        signal_text = " ".join(findings[0].evidence.signals_used)
        assert "training_start_time" in signal_text or "anchor" in signal_text.lower()

    def test_signals_not_checked_present(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings[0].evidence.signals_not_checked) > 0

    def test_signals_not_checked_mentions_model_progress(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        not_checked_text = " ".join(findings[0].evidence.signals_not_checked)
        assert "model" in not_checked_text.lower() or "progress" in not_checked_text.lower()

    def test_exceeded_limit_signal_when_applicable(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(training_start_hours=30, max_runtime_seconds=86_400)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        signal_text = " ".join(findings[0].evidence.signals_used)
        assert "stopping" in signal_text.lower() or "limit" in signal_text.lower()

    def test_no_limit_exceeded_signal_when_not_applicable(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(training_start_hours=30)  # no limit
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        signal_text = " ".join(findings[0].evidence.signals_used)
        assert "No applicable stopping-condition limit was exceeded" in signal_text


# ---------------------------------------------------------------------------
# TestPagination — multi-page support
# ---------------------------------------------------------------------------


class TestPagination:
    def test_jobs_across_multiple_pages_all_evaluated(self):
        job1 = _make_list_job(name="job-1", age_hours=48)
        job2 = _make_list_job(name="job-2", age_hours=48)
        job3 = _make_list_job(name="job-3", age_hours=48)

        sagemaker = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"TrainingJobSummaries": [job1, job2]},
            {"TrainingJobSummaries": [job3]},
        ]
        sagemaker.get_paginator.return_value = paginator
        sagemaker.describe_training_job.return_value = _make_describe(training_start_hours=48)
        session = MagicMock()
        session.client.return_value = sagemaker

        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings) == 3

    def test_paginator_called_without_status_equals(self):
        """Spec §8: ListTrainingJobs must NOT use StatusEquals parameter."""
        job = _make_list_job(age_hours=48)
        session, sagemaker = _make_session(jobs=[job])
        find_long_running_sagemaker_training_jobs(session, _REGION)
        paginator = sagemaker.get_paginator.return_value
        call_kwargs = paginator.paginate.call_args
        # Should be called with no arguments OR without StatusEquals
        if call_kwargs is not None:
            kwargs = call_kwargs.kwargs if call_kwargs.kwargs else {}
            args = call_kwargs.args if call_kwargs.args else ()
            assert "StatusEquals" not in kwargs
            if len(args) > 0 and isinstance(args[0], dict):
                assert "StatusEquals" not in args[0]

    def test_client_created_with_correct_region(self):
        session, sagemaker = _make_session(jobs=[])
        find_long_running_sagemaker_training_jobs(session, "eu-west-1")
        session.client.assert_called_once_with("sagemaker", region_name="eu-west-1")

    def test_mixed_statuses_only_inprogress_evaluated(self):
        """Jobs with non-InProgress list status are filtered client-side."""
        job_ip = _make_list_job(name="running", age_hours=48, status="InProgress")
        job_cp = _make_list_job(name="done", age_hours=48, status="Completed")
        job_fa = _make_list_job(name="failed", age_hours=48, status="Failed")
        session, sagemaker = _make_session(jobs=[job_ip, job_cp, job_fa])
        sagemaker.describe_training_job.return_value = _make_describe(training_start_hours=48)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        # Only the InProgress job is described and emitted
        assert len(findings) == 1
        assert sagemaker.describe_training_job.call_count == 1


# ---------------------------------------------------------------------------
# TestCustomThreshold
# ---------------------------------------------------------------------------


class TestCustomThreshold:
    def test_custom_48h_threshold_emits_at_49h(self):
        job = _make_list_job(age_hours=49)
        desc = _make_describe(training_start_hours=49)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=48
        )
        assert len(findings) == 1
        assert findings[0].details["long_running_hours_threshold"] == 48

    def test_custom_48h_threshold_skips_at_47h(self):
        job = _make_list_job(age_hours=47)
        desc = _make_describe(training_start_hours=47)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=48
        )
        assert findings == []

    def test_default_threshold_is_24h(self):
        job = _make_list_job(age_hours=24)
        desc = _make_describe(training_start_hours=24)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_training_jobs(session, _REGION)
        assert len(findings) == 1
        assert findings[0].details["long_running_hours_threshold"] == 24


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "aws.sagemaker.training_job.long_running"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "sagemaker"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"


# ---------------------------------------------------------------------------
# TestMultipleJobs
# ---------------------------------------------------------------------------


class TestMultipleJobs:
    def test_only_long_running_jobs_emitted(self):
        """Mix of jobs: only those above threshold emit."""
        job_long = _make_list_job(name="long", age_hours=48)
        job_short = _make_list_job(name="short", age_hours=6)

        desc_long = _make_describe(name="long", training_start_hours=48)
        desc_short = _make_describe(name="short", training_start_hours=6)

        def _describe(**kwargs):
            if kwargs["TrainingJobName"] == "long":
                return desc_long
            return desc_short

        session, sagemaker = _make_session(jobs=[job_long, job_short])
        sagemaker.describe_training_job.side_effect = _describe

        findings = find_long_running_sagemaker_training_jobs(
            session, _REGION, long_running_hours_threshold=24
        )
        assert len(findings) == 1
        assert findings[0].details["training_job_name"] == "long"
