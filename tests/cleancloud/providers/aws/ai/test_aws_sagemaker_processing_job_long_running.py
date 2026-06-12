from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_processing_job_long_running import (
    RULE_METADATA,
    _is_accelerator_backed,
    _normalize_describe,
    _normalize_list_item,
    find_long_running_sagemaker_processing_jobs,
)

_REGION = "us-east-1"
_ARN_PREFIX = "arn:aws:sagemaker:us-east-1:123456789012:processing-job"


def _make_list_job(
    name="processing-job-1",
    arn=None,
    age_hours=48,
    status="InProgress",
    lmt_hours=None,
):
    now = datetime.now(timezone.utc)
    item = {
        "ProcessingJobName": name,
        "ProcessingJobArn": arn or f"{_ARN_PREFIX}/{name}",
        "ProcessingJobStatus": status,
        "CreationTime": now - timedelta(hours=age_hours),
    }
    if lmt_hours is not None:
        item["LastModifiedTime"] = now - timedelta(hours=lmt_hours)
    return item


def _make_describe(
    name="processing-job-1",
    arn=None,
    status="InProgress",
    processing_start_hours=None,
    max_runtime_seconds=None,
    instance_type="ml.m5.xlarge",
    instance_count=1,
):
    now = datetime.now(timezone.utc)
    result = {
        "ProcessingJobArn": arn or f"{_ARN_PREFIX}/{name}",
        "ProcessingJobName": name,
        "ProcessingJobStatus": status,
        "ProcessingResources": {
            "ClusterConfig": {
                "InstanceType": instance_type,
                "InstanceCount": instance_count,
            }
        },
        "StoppingCondition": {},
    }
    if processing_start_hours is not None:
        result["ProcessingStartTime"] = now - timedelta(hours=processing_start_hours)
    if max_runtime_seconds is not None:
        result["StoppingCondition"]["MaxRuntimeInSeconds"] = max_runtime_seconds
    return result


def _make_session(
    jobs=None,
    describe_response=None,
    describe_side_effect=None,
    pages=None,
    list_side_effect=None,
):
    sagemaker = MagicMock()

    paginator = MagicMock()
    if list_side_effect is not None:
        paginator.paginate.side_effect = list_side_effect
    else:
        paginator.paginate.return_value = pages or [{"ProcessingJobSummaries": jobs or []}]
    sagemaker.get_paginator.return_value = paginator

    if describe_side_effect is not None:
        sagemaker.describe_processing_job.side_effect = describe_side_effect
    elif describe_response is not None:
        sagemaker.describe_processing_job.return_value = describe_response
    else:
        sagemaker.describe_processing_job.return_value = _make_describe()

    session = MagicMock()
    session.client.return_value = sagemaker
    return session, sagemaker


def _auth_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "Access denied"}}, "op")


def _transient_error(code="ThrottlingException"):
    return ClientError({"Error": {"Code": code, "Message": "Throttled"}}, "op")


class TestMustEmit:
    def test_basic_long_running_job_detected(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.sagemaker.processing_job.long_running"
        assert f.resource_type == "aws.sagemaker.processing_job"
        assert f.provider == "aws"
        assert f.region == _REGION

    def test_exact_threshold_emits(self):
        job = _make_list_job(age_hours=24)
        desc = _make_describe(processing_start_hours=24)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert len(findings) == 1

    def test_creation_time_anchor_when_no_processing_start(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe()
        desc.pop("ProcessingStartTime", None)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert len(findings) == 1
        assert findings[0].details["runtime_anchor_type"] == "creation_time"
        assert findings[0].details["processing_start_time"] is None

    def test_processing_start_time_anchor(self):
        job = _make_list_job(age_hours=50)
        desc = _make_describe(processing_start_hours=26)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.details["runtime_anchor_type"] == "processing_start_time"
        assert f.details["processing_start_time"] is not None
        assert f.details["active_processing_hours"] == 26

    def test_resource_id_falls_back_to_list_arn_when_describe_arn_absent(self):
        list_arn = f"{_ARN_PREFIX}/fallback-job"
        job = _make_list_job(name="fallback-job", age_hours=48, arn=list_arn)
        desc = _make_describe()
        desc.pop("ProcessingJobArn", None)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].resource_id == list_arn

    def test_estimated_monthly_cost_is_none(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job])

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].estimated_monthly_cost_usd is None

    def test_paginated_results_across_multiple_pages(self):
        job1 = _make_list_job(name="job-1", age_hours=48)
        job2 = _make_list_job(name="job-2", age_hours=6)
        job3 = _make_list_job(name="job-3", age_hours=72)
        pages = [
            {"ProcessingJobSummaries": [job1]},
            {"ProcessingJobSummaries": [job2, job3]},
        ]
        desc1 = _make_describe(name="job-1", processing_start_hours=48)
        desc2 = _make_describe(name="job-2", processing_start_hours=6)
        desc3 = _make_describe(name="job-3", processing_start_hours=72)

        def _describe(**kwargs):
            return {
                "job-1": desc1,
                "job-2": desc2,
                "job-3": desc3,
            }[kwargs["ProcessingJobName"]]

        session, sagemaker = _make_session(pages=pages)
        sagemaker.describe_processing_job.side_effect = _describe

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert [f.details["processing_job_name"] for f in findings] == ["job-1", "job-3"]
        sagemaker.get_paginator.return_value.paginate.assert_called_once_with()


class TestMustSkipListLevel:
    def test_name_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["ProcessingJobName"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_arn_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["ProcessingJobArn"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_status_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["ProcessingJobStatus"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_non_inprogress_status_skipped(self):
        for status in ("Completed", "Failed", "Stopping", "Stopped"):
            job = _make_list_job(age_hours=48, status=status)
            session, _ = _make_session(jobs=[job])
            assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_creation_time_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        del job["CreationTime"]
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_creation_time_naive_skipped(self):
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = datetime.now() - timedelta(hours=48)
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_creation_time_future_beyond_skew_skipped(self):
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job])
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_last_modified_time_future_beyond_skew_becomes_null_not_skip(self):
        job = _make_list_job(age_hours=48)
        job["LastModifiedTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job])

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert len(findings) == 1

    def test_short_job_below_threshold_skipped(self):
        job = _make_list_job(age_hours=6)
        desc = _make_describe()
        session, _ = _make_session(jobs=[job], describe_response=desc)

        assert (
            find_long_running_sagemaker_processing_jobs(
                session, _REGION, long_running_hours_threshold=24
            )
            == []
        )

    def test_item_not_dict_skipped(self):
        session, sagemaker = _make_session()
        sagemaker.get_paginator.return_value.paginate.return_value = [
            {"ProcessingJobSummaries": ["not-a-dict"]}
        ]
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []


class TestMustSkipDescribeLevel:
    def test_describe_status_absent_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        del desc["ProcessingJobStatus"]
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_describe_status_not_inprogress_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(status="Completed")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_processing_start_time_naive_treated_as_null_uses_creation_time(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        desc["ProcessingStartTime"] = datetime.now() - timedelta(hours=46)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert len(findings) == 1
        assert findings[0].details["runtime_anchor_type"] == "creation_time"

    def test_processing_start_time_future_beyond_skew_skipped(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe()
        desc["ProcessingStartTime"] = datetime.now(timezone.utc) + timedelta(seconds=600)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_processing_start_before_creation_beyond_skew_skipped(self):
        now = datetime.now(timezone.utc)
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = now - timedelta(hours=48)
        desc = _make_describe()
        desc["ProcessingStartTime"] = now - timedelta(hours=49)
        session, _ = _make_session(jobs=[job], describe_response=desc)
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_processing_start_within_skew_of_creation_emits(self):
        now = datetime.now(timezone.utc)
        job = _make_list_job(age_hours=48)
        job["CreationTime"] = now - timedelta(hours=48)
        desc = _make_describe()
        desc["ProcessingStartTime"] = (now - timedelta(hours=48)) - timedelta(seconds=200)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert len(findings) == 1

    def test_elapsed_below_threshold_after_describe_skipped(self):
        job = _make_list_job(age_hours=50)
        desc = _make_describe(processing_start_hours=12)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        assert (
            find_long_running_sagemaker_processing_jobs(
                session, _REGION, long_running_hours_threshold=24
            )
            == []
        )


class TestMustFailRule:
    def test_list_permission_error_access_denied_raises(self):
        session, sagemaker = _make_session()
        sagemaker.get_paginator.return_value.paginate.side_effect = _auth_error()

        with pytest.raises(PermissionError, match="sagemaker:ListProcessingJobs"):
            find_long_running_sagemaker_processing_jobs(session, _REGION)

    def test_list_non_permission_error_reraises(self):
        session, sagemaker = _make_session()
        sagemaker.get_paginator.return_value.paginate.side_effect = _transient_error()

        with pytest.raises(ClientError):
            find_long_running_sagemaker_processing_jobs(session, _REGION)

    def test_list_botocore_error_reraises(self):
        session, sagemaker = _make_session()
        sagemaker.get_paginator.return_value.paginate.side_effect = BotoCoreError()

        with pytest.raises(BotoCoreError):
            find_long_running_sagemaker_processing_jobs(session, _REGION)

    def test_describe_permission_error_raises(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(
            jobs=[job], describe_side_effect=_auth_error("AccessDeniedException")
        )

        with pytest.raises(PermissionError, match="sagemaker:DescribeProcessingJob"):
            find_long_running_sagemaker_processing_jobs(session, _REGION)


class TestDescribeSkipItem:
    def test_describe_transient_error_skips_job(self):
        job1 = _make_list_job(name="job-1", age_hours=48)
        job2 = _make_list_job(name="job-2", age_hours=48)
        desc2 = _make_describe(name="job-2", processing_start_hours=48)

        def _describe(**kwargs):
            if kwargs["ProcessingJobName"] == "job-1":
                raise _transient_error()
            return desc2

        session, sagemaker = _make_session(jobs=[job1, job2])
        sagemaker.describe_processing_job.side_effect = _describe

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert len(findings) == 1
        assert findings[0].details["processing_job_name"] == "job-2"

    def test_describe_resource_not_found_skips_job(self):
        job = _make_list_job(age_hours=48)
        err = ClientError({"Error": {"Code": "ResourceNotFound", "Message": "not found"}}, "op")
        session, _ = _make_session(jobs=[job], describe_side_effect=err)
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_describe_botocore_error_skips_job(self):
        job = _make_list_job(age_hours=48)
        session, _ = _make_session(jobs=[job], describe_side_effect=BotoCoreError())
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []

    def test_describe_returns_non_dict_skips_job(self):
        job = _make_list_job(age_hours=48)
        session, sagemaker = _make_session(jobs=[job])
        sagemaker.describe_processing_job.return_value = "bad-response"
        assert find_long_running_sagemaker_processing_jobs(session, _REGION) == []


class TestRuntimeLimit:
    def test_configured_limit_captured_but_not_applicable_before_processing_starts(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(max_runtime_seconds=86_400)
        desc.pop("ProcessingStartTime", None)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].details["configured_runtime_limit_seconds"] == 86_400
        assert findings[0].details["applicable_runtime_limit_seconds"] is None
        assert findings[0].details["unbounded_runtime_limit"] is True

    def test_processing_start_uses_configured_limit_as_applicable_limit(self):
        job = _make_list_job(age_hours=50)
        desc = _make_describe(processing_start_hours=30, max_runtime_seconds=86_400)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].details["configured_runtime_limit_seconds"] == 86_400
        assert findings[0].details["applicable_runtime_limit_seconds"] == 86_400

    def test_no_stopping_condition_is_unbounded(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48)
        desc["StoppingCondition"] = {}
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].details["applicable_runtime_limit_seconds"] is None
        assert findings[0].details["unbounded_runtime_limit"] is True

    def test_stopping_condition_non_dict_degrades_safely(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48)
        desc["StoppingCondition"] = "bad"
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert len(findings) == 1
        assert findings[0].details["configured_runtime_limit_seconds"] is None

    def test_exceeded_runtime_limit_uses_seconds_not_floored_hours(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(max_runtime_seconds=86_400)
        desc["ProcessingStartTime"] = datetime.now(timezone.utc) - timedelta(hours=24, seconds=1)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(
            session, _REGION, long_running_hours_threshold=24
        )

        assert findings[0].details["active_processing_hours"] == 24
        assert findings[0].details["exceeded_applicable_runtime_limit"] is True


class TestConfidenceModel:
    def test_high_confidence_when_exceeded_limit(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(processing_start_hours=30, max_runtime_seconds=86_400)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_no_applicable_limit(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe()
        desc.pop("ProcessingStartTime", None)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].confidence.value == "medium"

    def test_medium_confidence_when_limit_not_exceeded(self):
        job = _make_list_job(age_hours=30)
        desc = _make_describe(processing_start_hours=30, max_runtime_seconds=604_800)
        session, _ = _make_session(jobs=[job], describe_response=desc)

        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)

        assert findings[0].confidence.value == "medium"
        assert findings[0].details["exceeded_applicable_runtime_limit"] is False


class TestRiskModel:
    def test_high_risk_gpu_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48, instance_type="ml.p3.16xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_inf_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48, instance_type="ml.inf1.xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)
        assert findings[0].risk.value == "high"

    def test_medium_risk_cpu_instance(self):
        job = _make_list_job(age_hours=48)
        desc = _make_describe(processing_start_hours=48, instance_type="ml.m5.xlarge")
        session, _ = _make_session(jobs=[job], describe_response=desc)
        findings = find_long_running_sagemaker_processing_jobs(session, _REGION)
        assert findings[0].risk.value == "medium"


class TestNormalizeListItem:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_valid_item_normalizes(self):
        now = self._now()
        item = {
            "ProcessingJobName": "job-1",
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
        }
        result = _normalize_list_item(item, now)
        assert result is not None
        assert result["processing_job_name"] == "job-1"
        assert result["list_status"] == "InProgress"
        assert result["job_age_hours"] == 24

    def test_non_dict_returns_none(self):
        assert _normalize_list_item("bad", datetime.now(timezone.utc)) is None

    def test_naive_creation_time_returns_none(self):
        now = self._now()
        item = {
            "ProcessingJobName": "job-1",
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "CreationTime": now.replace(tzinfo=None) - timedelta(hours=24),
        }
        assert _normalize_list_item(item, now) is None

    def test_naive_last_modified_time_is_null(self):
        now = self._now()
        item = {
            "ProcessingJobName": "job-1",
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
            "LastModifiedTime": (now - timedelta(hours=12)).replace(tzinfo=None),
        }
        result = _normalize_list_item(item, now)
        assert result is not None
        assert result["last_modified_time_utc"] is None

    def test_future_last_modified_time_is_null(self):
        now = self._now()
        item = {
            "ProcessingJobName": "job-1",
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "CreationTime": now - timedelta(hours=24),
            "LastModifiedTime": now + timedelta(seconds=600),
        }
        result = _normalize_list_item(item, now)
        assert result is not None
        assert result["last_modified_time_utc"] is None


class TestNormalizeDescribe:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_valid_response_normalizes(self):
        now = self._now()
        resp = {
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "StoppingCondition": {"MaxRuntimeInSeconds": 3600},
            "ProcessingResources": {
                "ClusterConfig": {"InstanceType": "ml.m5.xlarge", "InstanceCount": 1}
            },
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["describe_status"] == "InProgress"
        assert result["configured_runtime_limit_seconds"] == 3600
        assert result["instance_type"] == "ml.m5.xlarge"

    def test_non_dict_returns_none(self):
        assert _normalize_describe("bad", datetime.now(timezone.utc)) is None

    def test_missing_status_returns_none(self):
        now = self._now()
        resp = {"ProcessingJobArn": f"{_ARN_PREFIX}/job-1"}
        assert _normalize_describe(resp, now) is None

    def test_naive_processing_start_treated_as_null(self):
        now = self._now()
        resp = {
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "ProcessingStartTime": (now - timedelta(hours=24)).replace(tzinfo=None),
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["processing_start_time_utc"] is None

    def test_future_processing_start_returns_none(self):
        now = self._now()
        resp = {
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "ProcessingStartTime": now + timedelta(seconds=600),
        }
        assert _normalize_describe(resp, now) is None

    def test_processing_resources_non_dict_degrades_to_null_fields(self):
        now = self._now()
        resp = {
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "ProcessingResources": "bad",
        }
        result = _normalize_describe(resp, now)
        assert result is not None
        assert result["instance_type"] is None
        assert result["instance_count"] is None

    def test_zero_max_runtime_treated_as_null(self):
        now = self._now()
        resp = {
            "ProcessingJobArn": f"{_ARN_PREFIX}/job-1",
            "ProcessingJobStatus": "InProgress",
            "StoppingCondition": {"MaxRuntimeInSeconds": 0},
        }
        result = _normalize_describe(resp, now)
        assert result["configured_runtime_limit_seconds"] is None


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

    def test_none_not_accelerator(self):
        assert _is_accelerator_backed(None) is False


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "aws.sagemaker.processing_job.long_running"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "sagemaker"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
