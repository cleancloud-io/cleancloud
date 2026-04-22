from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_notebook_idle import (
    RULE_METADATA,
    _is_accelerator_backed,
    _normalize_notebook,
    find_idle_sagemaker_notebooks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_THRESHOLD = 14
_ARN_PREFIX = "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance"


def _make_session(sagemaker_mock):
    session = MagicMock()
    session.client.return_value = sagemaker_mock
    return session


def _make_nb(
    name="ml-research-nb",
    instance_type="ml.t3.medium",
    age_days=30,
    stale_days=None,
    status="InService",
    lifecycle_config=None,
    default_code_repo=None,
    additional_code_repos=None,
):
    """Build a NotebookInstanceSummary list entry.

    stale_days controls LastModifiedTime age (defaults to same as age_days).
    """
    now = datetime.now(timezone.utc)
    if stale_days is None:
        stale_days = age_days
    nb = {
        "NotebookInstanceName": name,
        "NotebookInstanceArn": f"{_ARN_PREFIX}/{name}",
        "NotebookInstanceStatus": status,
        "InstanceType": instance_type,
        "CreationTime": now - timedelta(days=age_days),
        "LastModifiedTime": now - timedelta(days=stale_days),
    }
    if lifecycle_config is not None:
        nb["NotebookInstanceLifecycleConfigName"] = lifecycle_config
    if default_code_repo is not None:
        nb["DefaultCodeRepository"] = default_code_repo
    if additional_code_repos is not None:
        nb["AdditionalCodeRepositories"] = additional_code_repos
    return nb


def _paginate(items):
    paginator = MagicMock()
    paginator.paginate.return_value = [{"NotebookInstances": items}]
    return paginator


def _run(items, threshold=_DEFAULT_THRESHOLD, region="us-east-1"):
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(items)
    return find_idle_sagemaker_notebooks(_make_session(sm), region, threshold)


def _arn(name):
    return f"{_ARN_PREFIX}/{name}"


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_basic_cpu_notebook_emitted(self):
        findings = _run([_make_nb(age_days=30)])
        assert len(findings) == 1

    def test_basic_gpu_notebook_emitted(self):
        findings = _run([_make_nb(instance_type="ml.p3.2xlarge", age_days=30)])
        assert len(findings) == 1

    def test_exactly_at_threshold_emitted(self):
        """age_days == threshold and stale_days == threshold → emit."""
        findings = _run([_make_nb(age_days=14, stale_days=14)])
        assert len(findings) == 1

    def test_resource_id_is_arn_not_name(self):
        findings = _run([_make_nb("my-nb", age_days=30)])
        assert findings[0].resource_id == _arn("my-nb")

    def test_resource_type(self):
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].resource_type == "aws.sagemaker.notebook"

    def test_provider(self):
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].provider == "aws"

    def test_rule_id(self):
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].rule_id == "aws.sagemaker.notebook.idle"

    def test_region_preserved(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "ap-southeast-1")
        assert findings[0].region == "ap-southeast-1"

    def test_no_notebooks_returns_empty(self):
        assert _run([]) == []

    def test_summary_contains_notebook_name(self):
        findings = _run([_make_nb("fraud-model-dev", age_days=30)])
        assert "fraud-model-dev" in findings[0].summary


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_missing_arn_skipped(self):
        nb = _make_nb(age_days=30)
        del nb["NotebookInstanceArn"]
        assert _run([nb]) == []

    def test_empty_arn_skipped(self):
        nb = _make_nb(age_days=30)
        nb["NotebookInstanceArn"] = ""
        assert _run([nb]) == []

    def test_missing_name_skipped(self):
        nb = _make_nb(age_days=30)
        del nb["NotebookInstanceName"]
        assert _run([nb]) == []

    def test_empty_name_skipped(self):
        nb = _make_nb(age_days=30)
        nb["NotebookInstanceName"] = ""
        assert _run([nb]) == []

    def test_missing_status_skipped(self):
        nb = _make_nb(age_days=30)
        del nb["NotebookInstanceStatus"]
        assert _run([nb]) == []

    def test_stopped_status_skipped(self):
        assert _run([_make_nb(age_days=30, status="Stopped")]) == []

    def test_pending_status_skipped(self):
        assert _run([_make_nb(age_days=30, status="Pending")]) == []

    def test_stopping_status_skipped(self):
        assert _run([_make_nb(age_days=30, status="Stopping")]) == []

    def test_missing_creation_time_skipped(self):
        nb = _make_nb(age_days=30)
        del nb["CreationTime"]
        assert _run([nb]) == []

    def test_naive_creation_time_skipped(self):
        nb = _make_nb(age_days=30)
        nb["CreationTime"] = datetime.now() - timedelta(days=30)
        assert nb["CreationTime"].tzinfo is None
        assert _run([nb]) == []

    def test_future_creation_time_skipped(self):
        nb = _make_nb(age_days=30)
        nb["CreationTime"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run([nb]) == []

    def test_missing_last_modified_time_skipped(self):
        nb = _make_nb(age_days=30)
        del nb["LastModifiedTime"]
        assert _run([nb]) == []

    def test_naive_last_modified_time_skipped(self):
        nb = _make_nb(age_days=30)
        nb["LastModifiedTime"] = datetime.now() - timedelta(days=30)
        assert nb["LastModifiedTime"].tzinfo is None
        assert _run([nb]) == []

    def test_future_last_modified_time_skipped(self):
        nb = _make_nb(age_days=30)
        nb["LastModifiedTime"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run([nb]) == []

    def test_lmt_before_creation_time_skipped(self):
        """LastModifiedTime < CreationTime is inconsistent → skip."""
        now = datetime.now(timezone.utc)
        nb = {
            "NotebookInstanceName": "nb",
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceStatus": "InService",
            "InstanceType": "ml.t3.medium",
            "CreationTime": now - timedelta(days=20),
            "LastModifiedTime": now - timedelta(days=30),  # before CreationTime
        }
        assert _run([nb]) == []

    def test_too_young_skipped(self):
        """age_days < idle_days_threshold → skip."""
        assert _run([_make_nb(age_days=13, stale_days=13)]) == []

    def test_age_zero_skipped(self):
        assert _run([_make_nb(age_days=0, stale_days=0)]) == []

    def test_not_stale_enough_skipped(self):
        """age_days >= threshold but stale_days < threshold → skip."""
        assert _run([_make_nb(age_days=30, stale_days=5)]) == []

    def test_age_just_below_threshold_skipped(self):
        """age_days = threshold - 1 → skip."""
        assert _run([_make_nb(age_days=13, stale_days=30)]) == []

    def test_stale_just_below_threshold_skipped(self):
        """stale_days = threshold - 1 → skip."""
        assert _run([_make_nb(age_days=30, stale_days=13)]) == []

    def test_non_dict_item_skipped(self):
        """Non-dict items in the response list are silently skipped."""
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"NotebookInstances": [None, "bad", 42]}]
        sm.get_paginator.return_value = paginator
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def _paginate_error(self, error_code):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": error_code, "Message": "denied"}},
            "ListNotebookInstances",
        )
        sm.get_paginator.return_value = paginator
        return sm

    def test_access_denied_raises_permission_error(self):
        sm = self._paginate_error("AccessDenied")
        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")
        assert "sagemaker:ListNotebookInstances" in str(exc_info.value)

    def test_unauthorized_operation_raises_permission_error(self):
        sm = self._paginate_error("UnauthorizedOperation")
        with pytest.raises(PermissionError):
            find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    def test_access_denied_exception_raises_permission_error(self):
        sm = self._paginate_error("AccessDeniedException")
        with pytest.raises(PermissionError):
            find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    def test_non_permission_client_error_propagates(self):
        sm = self._paginate_error("InternalFailure")
        with pytest.raises(ClientError):
            find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    def test_botocore_error_propagates(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = BotoCoreError()
        sm.get_paginator.return_value = paginator
        with pytest.raises(BotoCoreError):
            find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_always_medium_cpu(self):
        findings = _run([_make_nb(instance_type="ml.t3.medium", age_days=30)])
        assert findings[0].confidence.value == "medium"

    def test_confidence_always_medium_gpu(self):
        findings = _run([_make_nb(instance_type="ml.p3.2xlarge", age_days=30)])
        assert findings[0].confidence.value == "medium"

    def test_confidence_always_medium_at_threshold(self):
        findings = _run([_make_nb(age_days=14, stale_days=14)])
        assert findings[0].confidence.value == "medium"

    def test_no_high_confidence_emitted(self):
        """Spec: No HIGH-confidence finding may be emitted."""
        items = [
            _make_nb("cpu", age_days=30),
            _make_nb("gpu", instance_type="ml.p3.2xlarge", age_days=60),
        ]
        findings = _run(items)
        for f in findings:
            assert f.confidence.value != "high"

    def test_lifecycle_config_does_not_affect_confidence(self):
        """Lifecycle config must not affect eligibility or confidence (spec 4)."""
        nb = _make_nb(age_days=30, lifecycle_config="auto-stop")
        findings = _run([nb])
        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    @pytest.mark.parametrize(
        "instance_type",
        [
            "ml.g4dn.xlarge",
            "ml.g5.2xlarge",
            "ml.p3.2xlarge",
            "ml.p3.8xlarge",
            "ml.p4d.24xlarge",
            "ml.p5.48xlarge",
            "ml.inf1.xlarge",
            "ml.inf2.8xlarge",
            "ml.trn1.2xlarge",
            "ml.trn1n.32xlarge",
        ],
    )
    def test_accelerator_instance_is_high_risk(self, instance_type):
        findings = _run([_make_nb(instance_type=instance_type, age_days=30)])
        assert findings[0].risk.value == "high"

    @pytest.mark.parametrize(
        "instance_type",
        [
            "ml.t3.medium",
            "ml.m5.xlarge",
            "ml.c5.xlarge",
            "ml.r5.large",
        ],
    )
    def test_cpu_instance_is_medium_risk(self, instance_type):
        findings = _run([_make_nb(instance_type=instance_type, age_days=30)])
        assert findings[0].risk.value == "medium"

    def test_no_critical_risk_emitted(self):
        """Spec: risk model only allows HIGH or MEDIUM — no CRITICAL."""
        items = [
            _make_nb("gpu-long", instance_type="ml.p3.2xlarge", age_days=60),
            _make_nb("gpu-short", instance_type="ml.g5.xlarge", age_days=14),
        ]
        findings = _run(items)
        for f in findings:
            assert f.risk.value != "critical"

    def test_missing_instance_type_is_medium_risk(self):
        nb = _make_nb(age_days=30)
        del nb["InstanceType"]
        findings = _run([nb])
        assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_cost_is_none(self):
        """Spec 7: estimated_monthly_cost_usd = null."""
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].estimated_monthly_cost_usd is None

    def test_gpu_estimated_cost_is_none(self):
        findings = _run([_make_nb(instance_type="ml.p3.2xlarge", age_days=30)])
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_returns_none_for_non_dict(self):
        assert _normalize_notebook(None, self._now()) is None
        assert _normalize_notebook("bad", self._now()) is None
        assert _normalize_notebook(42, self._now()) is None

    def test_returns_none_when_arn_missing(self):
        now = self._now()
        item = {
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_when_name_missing(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_when_status_missing(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_for_naive_creation_time(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": datetime.now() - timedelta(days=30),  # naive
            "LastModifiedTime": now - timedelta(days=30),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_for_future_creation_time(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now + timedelta(days=1),
            "LastModifiedTime": now - timedelta(days=30),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_for_naive_last_modified_time(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": datetime.now() - timedelta(days=30),  # naive
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_for_future_last_modified_time(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now + timedelta(days=1),
        }
        assert _normalize_notebook(item, now) is None

    def test_returns_none_when_lmt_before_creation_time(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=10),
            "LastModifiedTime": now - timedelta(days=20),
        }
        assert _normalize_notebook(item, now) is None

    def test_age_days_computed_correctly(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
        }
        n = _normalize_notebook(item, now)
        assert n is not None
        assert n["age_days"] == 30

    def test_stale_control_plane_days_computed_correctly(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=20),
        }
        n = _normalize_notebook(item, now)
        assert n is not None
        assert n["stale_control_plane_days"] == 20

    def test_additional_code_repos_filters_non_strings(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
            "AdditionalCodeRepositories": ["repo-a", None, 42, "", "repo-b"],
        }
        n = _normalize_notebook(item, now)
        assert n is not None
        assert n["additional_code_repositories"] == ["repo-a", "repo-b"]

    def test_additional_code_repos_empty_when_absent(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
        }
        n = _normalize_notebook(item, now)
        assert n is not None
        assert n["additional_code_repositories"] == []

    def test_empty_string_instance_type_normalizes_to_none(self):
        now = self._now()
        item = {
            "NotebookInstanceArn": _arn("nb"),
            "NotebookInstanceName": "nb",
            "NotebookInstanceStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
            "InstanceType": "",
        }
        n = _normalize_notebook(item, now)
        assert n is not None
        assert n["instance_type"] is None


# ---------------------------------------------------------------------------
# TestIsAcceleratorBacked
# ---------------------------------------------------------------------------


class TestIsAcceleratorBacked:
    @pytest.mark.parametrize(
        "instance_type,expected",
        [
            ("ml.g4dn.xlarge", True),
            ("ml.g5.2xlarge", True),
            ("ml.p2.xlarge", True),
            ("ml.p3.2xlarge", True),
            ("ml.p4d.24xlarge", True),
            ("ml.p5.48xlarge", True),
            ("ml.inf1.xlarge", True),
            ("ml.inf2.8xlarge", True),
            ("ml.trn1.2xlarge", True),
            ("ml.trn1n.32xlarge", True),
            ("ml.t3.medium", False),
            ("ml.m5.xlarge", False),
            ("ml.c5.xlarge", False),
            ("ml.r5.large", False),
            (None, False),
            ("", False),
        ],
    )
    def test_accelerator_classification(self, instance_type, expected):
        assert _is_accelerator_backed(instance_type) is expected


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def _finding(self):
        nb = _make_nb(
            "my-nb",
            "ml.g4dn.xlarge",
            age_days=30,
            stale_days=25,
            lifecycle_config="auto-stop",
            default_code_repo="my-repo",
            additional_code_repos=["extra-repo"],
        )
        return _run([nb])[0]

    def test_evaluation_path(self):
        assert (
            self._finding().details["evaluation_path"] == "idle-sagemaker-notebook-review-candidate"
        )

    def test_notebook_instance_arn(self):
        assert self._finding().details["notebook_instance_arn"] == _arn("my-nb")

    def test_notebook_instance_name(self):
        assert self._finding().details["notebook_instance_name"] == "my-nb"

    def test_normalized_status(self):
        assert self._finding().details["normalized_status"] == "InService"

    def test_instance_type(self):
        assert self._finding().details["instance_type"] == "ml.g4dn.xlarge"

    def test_creation_time_present(self):
        assert "creation_time" in self._finding().details

    def test_last_modified_time_present(self):
        assert "last_modified_time" in self._finding().details

    def test_age_days(self):
        assert self._finding().details["age_days"] == 30

    def test_stale_control_plane_days(self):
        assert self._finding().details["stale_control_plane_days"] == 25

    def test_idle_days_threshold(self):
        assert self._finding().details["idle_days_threshold"] == 14

    def test_evaluation_window_start_present(self):
        assert "evaluation_window_start" in self._finding().details

    def test_evaluation_window_end_present(self):
        assert "evaluation_window_end" in self._finding().details

    def test_lifecycle_config_name_present(self):
        assert self._finding().details["lifecycle_config_name"] == "auto-stop"

    def test_lifecycle_config_name_none_when_absent(self):
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].details["lifecycle_config_name"] is None

    def test_default_code_repository_present(self):
        assert self._finding().details["default_code_repository"] == "my-repo"

    def test_additional_code_repositories_present(self):
        assert self._finding().details["additional_code_repositories"] == ["extra-repo"]

    def test_is_gpu_or_accelerator_backed_true(self):
        assert self._finding().details["is_gpu_or_accelerator_backed"] is True

    def test_is_gpu_or_accelerator_backed_false_for_cpu(self):
        findings = _run([_make_nb(instance_type="ml.t3.medium", age_days=30)])
        assert findings[0].details["is_gpu_or_accelerator_backed"] is False

    def test_no_cost_table_fields(self):
        """Old cost table fields must not appear in details."""
        d = self._finding().details
        assert "estimated_monthly_cost" not in d
        assert "cost_source" not in d
        assert "idle_ratio" not in d
        assert "is_gpu" not in d
        assert "notebook_name" not in d
        assert "idle_since_days" not in d


# ---------------------------------------------------------------------------
# TestTitleAndReason
# ---------------------------------------------------------------------------


class TestTitleAndReason:
    def test_title_is_spec_mandated(self):
        findings = _run([_make_nb(age_days=30)])
        assert findings[0].title == "Idle SageMaker notebook review candidate"

    def test_reason_contains_spec_wording(self):
        findings = _run([_make_nb(age_days=30)])
        assert "InService SageMaker notebook instance" in findings[0].reason
        assert "stale control-plane timestamp state" in findings[0].reason
        assert "14 days" in findings[0].reason

    def test_reason_uses_configured_threshold(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", 7)
        assert "7 days" in findings[0].reason


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _evidence(self):
        return _run([_make_nb(age_days=30)])[0].evidence

    def test_signals_used_non_empty(self):
        assert len(self._evidence().signals_used) > 0

    def test_signals_used_mentions_inservice(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "InService" in sigs

    def test_signals_used_mentions_last_modified_time(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "LastModifiedTime" in sigs

    def test_signals_used_mentions_low_fidelity_heuristic(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "low-fidelity" in sigs

    def test_signals_used_mentions_not_direct_signal(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "not a direct signal" in sigs

    def test_signals_not_checked_non_empty(self):
        assert len(self._evidence().signals_not_checked) > 0

    def test_signals_not_checked_mentions_kernel(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "kernel" in not_checked.lower() or "Jupyter" in not_checked

    def test_signals_not_checked_mentions_cloudwatch_logs(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "CloudWatch Logs" in not_checked

    def test_signals_not_checked_mentions_control_plane_actions(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "control-plane" in not_checked


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_aggregated(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"NotebookInstances": [_make_nb("nb-p1", age_days=30)]},
            {"NotebookInstances": [_make_nb("nb-p2", age_days=30)]},
            {"NotebookInstances": [_make_nb("nb-p3", age_days=30)]},
        ]
        sm.get_paginator.return_value = paginator
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")
        assert len(findings) == 3

    def test_paginator_called_with_inservice_filter(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([])
        find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")
        sm.get_paginator.return_value.paginate.assert_called_once_with(StatusEquals="InService")

    def test_mixed_valid_and_skip_across_pages(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"NotebookInstances": [_make_nb("idle", age_days=30)]},
            {"NotebookInstances": [_make_nb("young", age_days=3)]},
        ]
        sm.get_paginator.return_value = paginator
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")
        assert len(findings) == 1
        assert findings[0].details["notebook_instance_name"] == "idle"


# ---------------------------------------------------------------------------
# TestMultipleNotebooks
# ---------------------------------------------------------------------------


class TestMultipleNotebooks:
    def test_only_idle_notebooks_emitted(self):
        items = [
            _make_nb("idle-gpu", "ml.p3.2xlarge", age_days=30),
            _make_nb("active-nb", "ml.t3.medium", age_days=30, stale_days=2),
            _make_nb("idle-cpu", "ml.m5.xlarge", age_days=14),
            _make_nb("young-nb", "ml.t3.medium", age_days=5),
        ]
        findings = _run(items)
        assert len(findings) == 2
        arns = {f.resource_id for f in findings}
        assert _arn("idle-gpu") in arns
        assert _arn("idle-cpu") in arns
        assert _arn("active-nb") not in arns
        assert _arn("young-nb") not in arns


# ---------------------------------------------------------------------------
# TestCustomThreshold
# ---------------------------------------------------------------------------


class TestCustomThreshold:
    def test_custom_threshold_7_days(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([_make_nb(age_days=7, stale_days=7)])
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", 7)
        assert len(findings) == 1

    def test_age_just_below_custom_threshold_skipped(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([_make_nb(age_days=6, stale_days=6)])
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", 7)
        assert findings == []

    def test_custom_threshold_stored_in_details(self):
        sm = MagicMock()
        sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])
        findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", 7)
        assert findings[0].details["idle_days_threshold"] == 7


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "aws.sagemaker.notebook.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "sagemaker"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
