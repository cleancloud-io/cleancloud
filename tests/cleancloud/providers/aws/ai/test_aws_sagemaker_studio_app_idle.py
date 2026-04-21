from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_studio_app_idle import (
    RULE_METADATA,
    _is_accelerator_backed,
    _normalize_describe,
    _normalize_list_item,
    find_idle_sagemaker_studio_apps,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_DOMAIN = "d-abc1234567"
_ACCOUNT = "123456789012"
_ARN_PREFIX = f"arn:aws:sagemaker:{_REGION}:{_ACCOUNT}:app"


def _app_arn(domain_id, owner, app_type, app_name):
    return f"{_ARN_PREFIX}/{domain_id}/{owner}/{app_type}/{app_name}"


def _make_list_app(
    app_name="my-kernel",
    app_type="KernelGateway",
    domain_id=_DOMAIN,
    user_profile="jdoe",
    space_name=None,
    status="InService",
    age_days=30,
    instance_type=None,
):
    """Build a ListApps AppDetails item (no LUAT — that comes from describe)."""
    now = datetime.now(timezone.utc)
    app = {
        "DomainId": domain_id,
        "AppName": app_name,
        "AppType": app_type,
        "Status": status,
        "CreationTime": now - timedelta(days=age_days),
    }
    if space_name is not None:
        app["SpaceName"] = space_name
    else:
        app["UserProfileName"] = user_profile
    if instance_type:
        app["ResourceSpec"] = {"InstanceType": instance_type}
    return app


def _make_describe(
    app_name="my-kernel",
    app_type="KernelGateway",
    domain_id=_DOMAIN,
    owner="jdoe",
    status="InService",
    last_activity_days=30,
    last_health_check_days=None,
    instance_type="ml.t3.medium",
    app_arn=None,
):
    """Build a DescribeApp response."""
    now = datetime.now(timezone.utc)
    if app_arn is None:
        app_arn = _app_arn(domain_id, owner, app_type, app_name)
    resp = {
        "AppArn": app_arn,
        "Status": status,
        "ResourceSpec": {"InstanceType": instance_type},
        "LastUserActivityTimestamp": now - timedelta(days=last_activity_days),
    }
    if last_health_check_days is not None:
        resp["LastHealthCheckTimestamp"] = now - timedelta(days=last_health_check_days)
    return resp


def _make_session(list_apps, describe_return=None, describe_side_effect=None):
    """Return session mock with list_apps paginator and describe_app configured."""
    sm = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Apps": list_apps}]
    sm.get_paginator.return_value = paginator
    if describe_side_effect is not None:
        sm.describe_app.side_effect = describe_side_effect
    elif describe_return is not None:
        sm.describe_app.return_value = describe_return
    session = MagicMock()
    session.client.return_value = sm
    return session, sm


def _run(
    list_apps,
    describe_return=None,
    describe_side_effect=None,
    threshold=7,
    region=_REGION,
):
    """Run find_idle_sagemaker_studio_apps with given mocks."""
    if describe_return is None and describe_side_effect is None:
        # Default: app with LUAT 30 days ago, no LHCT
        describe_return = _make_describe()
    session, _ = _make_session(list_apps, describe_return, describe_side_effect)
    return find_idle_sagemaker_studio_apps(session, region, threshold)


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_kernel_gateway_emitted(self):
        app = _make_list_app(app_type="KernelGateway", age_days=30)
        findings = _run([app])
        assert len(findings) == 1

    def test_jupyter_lab_emitted(self):
        app = _make_list_app(app_type="JupyterLab", age_days=30)
        findings = _run([app])
        assert len(findings) == 1

    def test_code_editor_emitted(self):
        app = _make_list_app(app_type="CodeEditor", age_days=30)
        findings = _run([app])
        assert len(findings) == 1

    def test_resource_id_is_app_arn(self):
        app = _make_list_app(app_name="k1", app_type="KernelGateway", age_days=30)
        expected_arn = _app_arn(_DOMAIN, "jdoe", "KernelGateway", "k1")
        desc = _make_describe(app_name="k1", app_arn=expected_arn)
        findings = _run([app], describe_return=desc)
        assert findings[0].resource_id == expected_arn

    def test_provider(self):
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].provider == "aws"

    def test_rule_id(self):
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].rule_id == "aws.sagemaker.studio_app.idle"

    def test_resource_type(self):
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].resource_type == "aws.sagemaker.studio_app"

    def test_region_preserved(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        session, _ = _make_session([app], describe_return=desc)
        findings = find_idle_sagemaker_studio_apps(session, "ap-southeast-1", 7)
        assert findings[0].region == "ap-southeast-1"

    def test_exactly_at_threshold_emitted(self):
        app = _make_list_app(age_days=7)
        desc = _make_describe(last_activity_days=7)
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1

    def test_no_apps_returns_empty(self):
        assert _run([]) == []


# ---------------------------------------------------------------------------
# TestMustSkip — list-level
# ---------------------------------------------------------------------------


class TestMustSkipListLevel:
    def test_missing_domain_id_skipped(self):
        app = _make_list_app(age_days=30)
        del app["DomainId"]
        assert _run([app]) == []

    def test_empty_domain_id_skipped(self):
        app = _make_list_app(age_days=30)
        app["DomainId"] = ""
        assert _run([app]) == []

    def test_missing_app_name_skipped(self):
        app = _make_list_app(age_days=30)
        del app["AppName"]
        assert _run([app]) == []

    def test_missing_app_type_skipped(self):
        app = _make_list_app(age_days=30)
        del app["AppType"]
        assert _run([app]) == []

    def test_missing_status_skipped(self):
        app = _make_list_app(age_days=30)
        del app["Status"]
        assert _run([app]) == []

    def test_stopped_status_skipped(self):
        assert _run([_make_list_app(status="Stopped", age_days=30)]) == []

    def test_deleted_status_skipped(self):
        assert _run([_make_list_app(status="Deleted", age_days=30)]) == []

    def test_pending_status_skipped(self):
        assert _run([_make_list_app(status="Pending", age_days=30)]) == []

    def test_jupyter_server_excluded(self):
        assert _run([_make_list_app(app_type="JupyterServer", age_days=30)]) == []

    def test_tensor_board_excluded(self):
        assert _run([_make_list_app(app_type="TensorBoard", age_days=30)]) == []

    def test_canvas_excluded(self):
        assert _run([_make_list_app(app_type="Canvas", age_days=30)]) == []

    def test_r_studio_excluded(self):
        assert _run([_make_list_app(app_type="RStudioServerPro", age_days=30)]) == []

    def test_missing_creation_time_skipped(self):
        app = _make_list_app(age_days=30)
        del app["CreationTime"]
        assert _run([app]) == []

    def test_naive_creation_time_skipped(self):
        app = _make_list_app(age_days=30)
        app["CreationTime"] = datetime.now() - timedelta(days=30)
        assert app["CreationTime"].tzinfo is None
        assert _run([app]) == []

    def test_future_creation_time_skipped(self):
        app = _make_list_app(age_days=30)
        app["CreationTime"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run([app]) == []

    def test_owner_context_absent_skipped(self):
        """Both space_name and user_profile_name absent → SKIP ITEM (not 'unknown')."""
        app = _make_list_app(age_days=30)
        app.pop("UserProfileName", None)
        app.pop("SpaceName", None)
        assert _run([app]) == []

    def test_non_dict_item_skipped(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Apps": [None, "bad", 42]}]
        sm.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sm
        assert find_idle_sagemaker_studio_apps(session, _REGION, 7) == []


# ---------------------------------------------------------------------------
# TestMustSkip — describe-level
# ---------------------------------------------------------------------------


class TestMustSkipDescribeLevel:
    def test_missing_app_arn_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        del desc["AppArn"]
        assert _run([app], describe_return=desc) == []

    def test_empty_app_arn_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        desc["AppArn"] = ""
        assert _run([app], describe_return=desc) == []

    def test_missing_describe_status_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        del desc["Status"]
        assert _run([app], describe_return=desc) == []

    def test_describe_status_not_inservice_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(status="Deleting")
        assert _run([app], describe_return=desc) == []

    def test_missing_luat_skipped(self):
        """Missing LastUserActivityTimestamp → SKIP ITEM (no CreationTime fallback)."""
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        del desc["LastUserActivityTimestamp"]
        assert _run([app], describe_return=desc) == []

    def test_naive_luat_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        desc["LastUserActivityTimestamp"] = datetime.now() - timedelta(days=30)
        assert desc["LastUserActivityTimestamp"].tzinfo is None
        assert _run([app], describe_return=desc) == []

    def test_future_luat_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        desc["LastUserActivityTimestamp"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run([app], describe_return=desc) == []

    def test_luat_before_creation_time_skipped(self):
        """LastUserActivityTimestamp < CreationTime → inconsistent state → SKIP."""
        # Use a single shared now to avoid microsecond drift between helpers
        now = datetime.now(timezone.utc)
        app = _make_list_app(age_days=10)
        app["CreationTime"] = now - timedelta(days=10)  # CT = 10 days ago
        desc = _make_describe(last_activity_days=30)
        # Override LUAT to be 30 days ago — clearly before CT (10 days ago)
        desc["LastUserActivityTimestamp"] = now - timedelta(days=30)
        assert _run([app], describe_return=desc) == []

    def test_luat_equals_lhct_skipped(self):
        """Exact equality: LUAT == LHCT → treated as health-check-driven → SKIP ITEM."""
        # last_activity_days < age_days ensures LUAT is clearly after CT
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=20)
        ts = desc["LastUserActivityTimestamp"]
        desc["LastHealthCheckTimestamp"] = ts  # exact same object → equality skip
        assert _run([app], describe_return=desc) == []

    def test_idle_since_days_below_threshold_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=3)  # 3 < 7 threshold
        assert _run([app], describe_return=desc) == []

    def test_future_lhct_skips_item(self):
        """Future LastHealthCheckTimestamp → SKIP ITEM."""
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        desc["LastHealthCheckTimestamp"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run([app], describe_return=desc) == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def _list_error(self, code):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": code, "Message": "denied"}}, "ListApps"
        )
        sm.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sm
        return session

    def test_list_apps_access_denied_raises_permission_error(self):
        session = self._list_error("AccessDenied")
        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_studio_apps(session, _REGION, 7)
        assert "sagemaker:ListApps" in str(exc_info.value)

    def test_list_apps_unauthorized_operation_raises_permission_error(self):
        session = self._list_error("UnauthorizedOperation")
        with pytest.raises(PermissionError):
            find_idle_sagemaker_studio_apps(session, _REGION, 7)

    def test_list_apps_access_denied_exception_raises_permission_error(self):
        session = self._list_error("AccessDeniedException")
        with pytest.raises(PermissionError):
            find_idle_sagemaker_studio_apps(session, _REGION, 7)

    def test_list_apps_non_permission_client_error_propagates(self):
        session = self._list_error("InternalFailure")
        with pytest.raises(ClientError):
            find_idle_sagemaker_studio_apps(session, _REGION, 7)

    def test_list_apps_botocore_error_propagates(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = BotoCoreError()
        sm.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sm
        with pytest.raises(BotoCoreError):
            find_idle_sagemaker_studio_apps(session, _REGION, 7)

    def test_describe_app_access_denied_raises_permission_error(self):
        app = _make_list_app(age_days=30)
        err = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeApp"
        )
        session, _ = _make_session([app], describe_side_effect=err)
        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_studio_apps(session, _REGION, 7)
        assert "sagemaker:DescribeApp" in str(exc_info.value)

    def test_describe_app_unauthorized_operation_raises_permission_error(self):
        app = _make_list_app(age_days=30)
        err = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "DescribeApp"
        )
        session, _ = _make_session([app], describe_side_effect=err)
        with pytest.raises(PermissionError):
            find_idle_sagemaker_studio_apps(session, _REGION, 7)


# ---------------------------------------------------------------------------
# TestDescribeSkipItem — non-permission describe failures → SKIP ITEM
# ---------------------------------------------------------------------------


class TestDescribeSkipItem:
    def test_resource_not_found_skips_app(self):
        app = _make_list_app(age_days=30)
        err = ClientError(
            {"Error": {"Code": "ResourceNotFound", "Message": "not found"}}, "DescribeApp"
        )
        assert _run([app], describe_side_effect=err) == []

    def test_throttling_exception_skips_app(self):
        app = _make_list_app(age_days=30)
        err = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "throttled"}}, "DescribeApp"
        )
        assert _run([app], describe_side_effect=err) == []

    def test_botocore_error_on_describe_skips_app(self):
        app = _make_list_app(age_days=30)
        assert _run([app], describe_side_effect=BotoCoreError()) == []


# ---------------------------------------------------------------------------
# TestHealthCheckContract
# ---------------------------------------------------------------------------


class TestHealthCheckContract:
    def test_exact_equality_luat_lhct_skipped(self):
        """Spec §6.1: exact equality LUAT == LHCT → SKIP ITEM."""
        # last_activity_days < age_days ensures LUAT is clearly after CT
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=20)
        ts = desc["LastUserActivityTimestamp"]
        desc["LastHealthCheckTimestamp"] = ts  # exact same object → equality skip
        assert _run([app], describe_return=desc) == []

    def test_luat_different_from_lhct_emits(self):
        """LUAT != LHCT → usable_activity_signal = true → emit."""
        # Use last_activity_days < age_days to ensure LUAT is clearly after CT
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=20, last_health_check_days=1)  # clearly different
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1

    def test_lhct_absent_emits(self):
        """No LHCT → health check guard cannot fire → usable signal → emit."""
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=20)
        desc.pop("LastHealthCheckTimestamp", None)
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1

    def test_luat_different_from_lhct_emits_when_idle(self):
        """LUAT 25 days ago, LHCT 1 minute ago: not equal → usable signal → emit."""
        # Use last_activity_days < age_days to ensure LUAT is clearly after CT
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=25, last_health_check_days=None)
        # LHCT 1 minute ago — different from LUAT → usable signal
        desc["LastHealthCheckTimestamp"] = datetime.now(timezone.utc) - timedelta(minutes=1)
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1

    def test_naive_lhct_treated_as_null_not_compared(self):
        """Naive LHCT → normalized to null → health check guard cannot fire → emit."""
        # last_activity_days < age_days ensures LUAT is clearly after CT
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=20)
        desc["LastHealthCheckTimestamp"] = (datetime.now(timezone.utc) - timedelta(days=1)).replace(
            tzinfo=None
        )
        assert desc["LastHealthCheckTimestamp"].tzinfo is None
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1  # naive LHCT → null → guard does not fire

    def test_usable_activity_signal_true_in_details(self):
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].details["usable_activity_signal"] is True


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_always_high_cpu(self):
        findings = _run([_make_list_app(instance_type="ml.t3.medium", age_days=30)])
        assert findings[0].confidence.value == "high"

    def test_confidence_always_high_gpu(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(instance_type="ml.p3.2xlarge")
        findings = _run([app], describe_return=desc)
        assert findings[0].confidence.value == "high"

    def test_confidence_always_high_at_exact_threshold(self):
        app = _make_list_app(age_days=7)
        desc = _make_describe(last_activity_days=7)
        findings = _run([app], describe_return=desc)
        assert findings[0].confidence.value == "high"

    def test_no_medium_confidence_emitted(self):
        """Spec §12: No MEDIUM/LOW finding should be emitted."""
        apps = [
            _make_list_app("a1", age_days=30),
            _make_list_app("a2", age_days=14),
        ]
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Apps": apps}]
        sm.get_paginator.return_value = paginator
        sm.describe_app.return_value = _make_describe()
        session = MagicMock()
        session.client.return_value = sm
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 7)
        for f in findings:
            assert f.confidence.value == "high"

    def test_luat_absent_skips_not_medium(self):
        """Missing LUAT must SKIP, not emit MEDIUM (spec §6.1 + §12)."""
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        del desc["LastUserActivityTimestamp"]
        assert _run([app], describe_return=desc) == []


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    @pytest.mark.parametrize(
        "instance_type",
        [
            "ml.g4dn.xlarge",
            "ml.g5.2xlarge",
            "ml.g6.xlarge",
            "ml.p3.2xlarge",
            "ml.p4d.24xlarge",
            "ml.p5.48xlarge",
            "ml.inf1.xlarge",
            "ml.inf2.8xlarge",
            "ml.trn1.2xlarge",
            "ml.trn2.48xlarge",
        ],
    )
    def test_accelerator_is_high_risk(self, instance_type):
        app = _make_list_app(age_days=30)
        desc = _make_describe(instance_type=instance_type)
        findings = _run([app], describe_return=desc)
        assert findings[0].risk.value == "high"

    @pytest.mark.parametrize(
        "instance_type",
        ["ml.t3.medium", "ml.m5.xlarge", "ml.c5.xlarge", "ml.r5.large"],
    )
    def test_cpu_is_medium_risk(self, instance_type):
        app = _make_list_app(age_days=30)
        desc = _make_describe(instance_type=instance_type)
        findings = _run([app], describe_return=desc)
        assert findings[0].risk.value == "medium"

    def test_no_critical_risk_emitted(self):
        """Spec §13: only HIGH or MEDIUM — no CRITICAL."""
        apps = [
            _make_list_app("gpu1", age_days=60),
            _make_list_app("gpu2", age_days=60),
        ]
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Apps": apps}]
        sm.get_paginator.return_value = paginator
        sm.describe_app.return_value = _make_describe(
            instance_type="ml.p3.2xlarge", last_activity_days=60
        )
        session = MagicMock()
        session.client.return_value = sm
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 7)
        for f in findings:
            assert f.risk.value != "critical"

    def test_missing_instance_type_is_medium_risk(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        del desc["ResourceSpec"]
        findings = _run([app], describe_return=desc)
        assert findings[0].risk.value == "medium"

    def test_describe_instance_type_preferred_over_list(self):
        """DescribeApp ResourceSpec.InstanceType takes precedence over ListApps."""
        app = _make_list_app(age_days=30, instance_type="ml.t3.medium")
        desc = _make_describe(instance_type="ml.p3.2xlarge")  # overrides list
        findings = _run([app], describe_return=desc)
        assert findings[0].details["instance_type"] == "ml.p3.2xlarge"
        assert findings[0].risk.value == "high"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_cost_is_none(self):
        """Spec §7: estimated_monthly_cost_usd = null."""
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].estimated_monthly_cost_usd is None

    def test_gpu_estimated_cost_is_none(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(instance_type="ml.p3.2xlarge")
        findings = _run([app], describe_return=desc)
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestNormalizeListItem
# ---------------------------------------------------------------------------


class TestNormalizeListItem:
    def _now(self):
        return datetime.now(timezone.utc)

    def _base(self, now):
        return {
            "DomainId": _DOMAIN,
            "AppName": "nb",
            "AppType": "KernelGateway",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
            "UserProfileName": "jdoe",
        }

    def test_returns_none_for_non_dict(self):
        now = self._now()
        assert _normalize_list_item(None, now) is None
        assert _normalize_list_item(42, now) is None

    def test_returns_none_when_domain_id_missing(self):
        now = self._now()
        item = self._base(now)
        del item["DomainId"]
        assert _normalize_list_item(item, now) is None

    def test_returns_none_when_app_name_missing(self):
        now = self._now()
        item = self._base(now)
        del item["AppName"]
        assert _normalize_list_item(item, now) is None

    def test_returns_none_when_app_type_missing(self):
        now = self._now()
        item = self._base(now)
        del item["AppType"]
        assert _normalize_list_item(item, now) is None

    def test_returns_none_when_status_missing(self):
        now = self._now()
        item = self._base(now)
        del item["Status"]
        assert _normalize_list_item(item, now) is None

    def test_returns_none_for_naive_creation_time(self):
        now = self._now()
        item = self._base(now)
        item["CreationTime"] = datetime.now() - timedelta(days=30)
        assert _normalize_list_item(item, now) is None

    def test_returns_none_for_future_creation_time(self):
        now = self._now()
        item = self._base(now)
        item["CreationTime"] = now + timedelta(days=1)
        assert _normalize_list_item(item, now) is None

    def test_returns_none_when_owner_context_absent(self):
        now = self._now()
        item = self._base(now)
        del item["UserProfileName"]
        assert _normalize_list_item(item, now) is None

    def test_space_name_owner_type(self):
        now = self._now()
        item = self._base(now)
        del item["UserProfileName"]
        item["SpaceName"] = "my-space"
        n = _normalize_list_item(item, now)
        assert n is not None
        assert n["owner_type"] == "space"
        assert n["owner_name"] == "my-space"

    def test_user_profile_owner_type(self):
        now = self._now()
        item = self._base(now)
        n = _normalize_list_item(item, now)
        assert n is not None
        assert n["owner_type"] == "user_profile"
        assert n["owner_name"] == "jdoe"

    def test_space_name_preferred_over_user_profile(self):
        """When both present, SpaceName is used (space takes precedence)."""
        now = self._now()
        item = self._base(now)
        item["SpaceName"] = "my-space"  # both present
        n = _normalize_list_item(item, now)
        assert n is not None
        assert n["owner_type"] == "space"
        assert n["owner_name"] == "my-space"

    def test_age_days_computed(self):
        now = self._now()
        item = self._base(now)
        n = _normalize_list_item(item, now)
        assert n["age_days"] == 30

    def test_instance_type_from_resource_spec(self):
        now = self._now()
        item = self._base(now)
        item["ResourceSpec"] = {"InstanceType": "ml.g5.xlarge"}
        n = _normalize_list_item(item, now)
        assert n["instance_type"] == "ml.g5.xlarge"

    def test_instance_type_null_when_absent(self):
        now = self._now()
        item = self._base(now)
        n = _normalize_list_item(item, now)
        assert n["instance_type"] is None

    def test_non_dict_resource_spec_normalized_to_null(self):
        """Truthy non-dict ResourceSpec must not raise AttributeError — normalizes to null."""
        now = self._now()
        item = self._base(now)
        item["ResourceSpec"] = "bad-string-value"
        n = _normalize_list_item(item, now)
        assert n is not None
        assert n["instance_type"] is None


# ---------------------------------------------------------------------------
# TestNormalizeDescribe
# ---------------------------------------------------------------------------


class TestNormalizeDescribe:
    def _now(self):
        return datetime.now(timezone.utc)

    def _base(self, now):
        return {
            "AppArn": _app_arn(_DOMAIN, "jdoe", "KernelGateway", "nb"),
            "Status": "InService",
            "LastUserActivityTimestamp": now - timedelta(days=30),
        }

    def test_returns_none_for_non_dict(self):
        assert _normalize_describe(None, self._now()) is None

    def test_returns_none_when_arn_missing(self):
        now = self._now()
        item = self._base(now)
        del item["AppArn"]
        assert _normalize_describe(item, now) is None

    def test_returns_none_when_status_missing(self):
        now = self._now()
        item = self._base(now)
        del item["Status"]
        assert _normalize_describe(item, now) is None

    def test_returns_none_when_luat_missing(self):
        now = self._now()
        item = self._base(now)
        del item["LastUserActivityTimestamp"]
        assert _normalize_describe(item, now) is None

    def test_returns_none_for_naive_luat(self):
        now = self._now()
        item = self._base(now)
        item["LastUserActivityTimestamp"] = datetime.now() - timedelta(days=30)
        assert _normalize_describe(item, now) is None

    def test_returns_none_for_future_luat(self):
        now = self._now()
        item = self._base(now)
        item["LastUserActivityTimestamp"] = now + timedelta(days=1)
        assert _normalize_describe(item, now) is None

    def test_returns_none_for_future_lhct(self):
        now = self._now()
        item = self._base(now)
        item["LastHealthCheckTimestamp"] = now + timedelta(days=1)
        assert _normalize_describe(item, now) is None

    def test_naive_lhct_normalized_to_null(self):
        now = self._now()
        item = self._base(now)
        item["LastHealthCheckTimestamp"] = (now - timedelta(days=1)).replace(tzinfo=None)
        n = _normalize_describe(item, now)
        assert n is not None
        assert n["last_health_check_time_utc"] is None

    def test_absent_lhct_normalized_to_null(self):
        now = self._now()
        item = self._base(now)
        n = _normalize_describe(item, now)
        assert n is not None
        assert n["last_health_check_time_utc"] is None

    def test_valid_lhct_normalized(self):
        now = self._now()
        item = self._base(now)
        item["LastHealthCheckTimestamp"] = now - timedelta(hours=1)
        n = _normalize_describe(item, now)
        assert n is not None
        assert n["last_health_check_time_utc"] is not None

    def test_non_dict_resource_spec_normalized_to_null(self):
        """Truthy non-dict ResourceSpec must not raise AttributeError — normalizes to null."""
        now = self._now()
        item = self._base(now)
        item["ResourceSpec"] = "bad-string-value"
        n = _normalize_describe(item, now)
        assert n is not None
        assert n["describe_instance_type"] is None


# ---------------------------------------------------------------------------
# TestIsAcceleratorBacked
# ---------------------------------------------------------------------------


class TestIsAcceleratorBacked:
    @pytest.mark.parametrize(
        "instance_type,expected",
        [
            ("ml.g4dn.xlarge", True),
            ("ml.g5.2xlarge", True),
            ("ml.g6.xlarge", True),
            ("ml.p3.2xlarge", True),
            ("ml.p4d.24xlarge", True),
            ("ml.p5.48xlarge", True),
            ("ml.inf1.xlarge", True),
            ("ml.inf2.8xlarge", True),
            ("ml.trn1.2xlarge", True),
            ("ml.trn2.48xlarge", True),
            ("ml.t3.medium", False),
            ("ml.m5.xlarge", False),
            ("ml.c5.xlarge", False),
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
        app = _make_list_app(
            app_name="my-app",
            app_type="JupyterLab",
            domain_id=_DOMAIN,
            user_profile="jdoe",
            age_days=30,
        )
        desc = _make_describe(
            app_name="my-app",
            app_type="JupyterLab",
            owner="jdoe",
            last_activity_days=25,
            last_health_check_days=1,
            instance_type="ml.g5.xlarge",
        )
        return _run([app], describe_return=desc)[0]

    def test_evaluation_path(self):
        assert (
            self._finding().details["evaluation_path"]
            == "idle-sagemaker-studio-app-review-candidate"
        )

    def test_app_arn_present(self):
        assert "app_arn" in self._finding().details
        assert self._finding().details["app_arn"].startswith("arn:aws:sagemaker:")

    def test_app_name(self):
        assert self._finding().details["app_name"] == "my-app"

    def test_app_type(self):
        assert self._finding().details["app_type"] == "JupyterLab"

    def test_domain_id(self):
        assert self._finding().details["domain_id"] == _DOMAIN

    def test_owner_type_user_profile(self):
        assert self._finding().details["owner_type"] == "user_profile"

    def test_owner_name(self):
        assert self._finding().details["owner_name"] == "jdoe"

    def test_normalized_status(self):
        assert self._finding().details["normalized_status"] == "InService"

    def test_creation_time_present(self):
        assert "creation_time" in self._finding().details

    def test_last_user_activity_time_present(self):
        assert "last_user_activity_time" in self._finding().details

    def test_last_health_check_time_present(self):
        assert self._finding().details["last_health_check_time"] is not None

    def test_last_health_check_time_none_when_absent(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe()
        desc.pop("LastHealthCheckTimestamp", None)
        f = _run([app], describe_return=desc)[0]
        assert f.details["last_health_check_time"] is None

    def test_age_days(self):
        assert self._finding().details["age_days"] == 30

    def test_idle_since_days(self):
        assert self._finding().details["idle_since_days"] == 25

    def test_idle_days_threshold(self):
        assert self._finding().details["idle_days_threshold"] == 7

    def test_evaluation_window_start_present(self):
        assert "evaluation_window_start" in self._finding().details

    def test_evaluation_window_end_present(self):
        assert "evaluation_window_end" in self._finding().details

    def test_usable_activity_signal_true(self):
        assert self._finding().details["usable_activity_signal"] is True

    def test_instance_type(self):
        assert self._finding().details["instance_type"] == "ml.g5.xlarge"

    def test_user_profile_name_in_details(self):
        assert self._finding().details["user_profile_name"] == "jdoe"

    def test_space_name_null_when_user_profile(self):
        assert self._finding().details["space_name"] is None

    def test_is_gpu_or_accelerator_backed_true(self):
        assert self._finding().details["is_gpu_or_accelerator_backed"] is True

    def test_is_gpu_or_accelerator_backed_false_for_cpu(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(instance_type="ml.t3.medium")
        f = _run([app], describe_return=desc)[0]
        assert f.details["is_gpu_or_accelerator_backed"] is False

    def test_no_old_cost_fields(self):
        """Old cost table fields must not appear in details."""
        d = self._finding().details
        for key in (
            "idle_ratio",
            "waste_score",
            "estimated_monthly_cost",
            "cost_basis",
            "confidence_note",
            "idle_signal_source",
            "is_gpu",
            "owner",
        ):
            assert key not in d, f"unexpected old field '{key}' in details"


# ---------------------------------------------------------------------------
# TestTitleAndReason
# ---------------------------------------------------------------------------


class TestTitleAndReason:
    def test_title_is_spec_mandated(self):
        findings = _run([_make_list_app(age_days=30)])
        assert findings[0].title == "Idle SageMaker Studio app review candidate"

    def test_reason_contains_spec_wording(self):
        findings = _run([_make_list_app(age_days=30)])
        assert "InService SageMaker Studio app" in findings[0].reason
        assert "usable activity timestamp" in findings[0].reason
        assert "7 days" in findings[0].reason

    def test_reason_uses_configured_threshold(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=30)
        session, _ = _make_session([app], describe_return=desc)
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 14)
        assert "14 days" in findings[0].reason


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _evidence(self):
        return _run([_make_list_app(age_days=30)])[0].evidence

    def test_signals_used_non_empty(self):
        assert len(self._evidence().signals_used) > 0

    def test_signals_used_mentions_inservice(self):
        assert "InService" in " ".join(self._evidence().signals_used)

    def test_signals_used_mentions_supported_scope(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "supported scope" in sigs

    def test_signals_used_mentions_usable_activity_signal(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "usable_activity_signal" in sigs

    def test_signals_used_mentions_health_check_exclusion(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "LastHealthCheckTimestamp" in sigs

    def test_signals_not_checked_non_empty(self):
        assert len(self._evidence().signals_not_checked) > 0

    def test_signals_not_checked_mentions_background_kernel(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "kernel" in not_checked.lower() or "background" in not_checked.lower()

    def test_signals_not_checked_mentions_storage_cost(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "storage" in not_checked.lower()


# ---------------------------------------------------------------------------
# TestSpaceBasedApps
# ---------------------------------------------------------------------------


class TestSpaceBasedApps:
    def test_space_based_app_emitted(self):
        app = _make_list_app(age_days=30, space_name="my-space", user_profile=None)
        desc = _make_describe(owner="my-space")
        findings = _run([app], describe_return=desc)
        assert len(findings) == 1
        assert findings[0].details["owner_type"] == "space"
        assert findings[0].details["owner_name"] == "my-space"
        assert findings[0].details["space_name"] == "my-space"
        assert findings[0].details["user_profile_name"] is None

    def test_describe_called_with_space_name_kwarg(self):
        app = _make_list_app(age_days=30, space_name="my-space", user_profile=None)
        desc = _make_describe(owner="my-space")
        session, sm = _make_session([app], describe_return=desc)
        find_idle_sagemaker_studio_apps(session, _REGION, 7)
        kwargs = sm.describe_app.call_args[1]
        assert "SpaceName" in kwargs
        assert kwargs["SpaceName"] == "my-space"
        assert "UserProfileName" not in kwargs

    def test_describe_called_with_user_profile_kwarg(self):
        app = _make_list_app(age_days=30, user_profile="alice")
        desc = _make_describe(owner="alice")
        session, sm = _make_session([app], describe_return=desc)
        find_idle_sagemaker_studio_apps(session, _REGION, 7)
        kwargs = sm.describe_app.call_args[1]
        assert "UserProfileName" in kwargs
        assert kwargs["UserProfileName"] == "alice"
        assert "SpaceName" not in kwargs


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_aggregated(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Apps": [_make_list_app("a1", age_days=30)]},
            {"Apps": [_make_list_app("a2", age_days=30)]},
            {"Apps": [_make_list_app("a3", age_days=30)]},
        ]
        sm.get_paginator.return_value = paginator
        sm.describe_app.return_value = _make_describe()
        session = MagicMock()
        session.client.return_value = sm
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 7)
        assert len(findings) == 3

    def test_paginator_called_without_status_filter(self):
        """ListApps spec: no StatusEquals filter — all apps returned, filtered in code."""
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Apps": []}]
        sm.get_paginator.return_value = paginator
        session = MagicMock()
        session.client.return_value = sm
        find_idle_sagemaker_studio_apps(session, _REGION, 7)
        # paginate() called with no arguments
        sm.get_paginator.return_value.paginate.assert_called_once_with()

    def test_mixed_valid_and_skip_across_pages(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Apps": [_make_list_app("idle1", age_days=30)]},
            {"Apps": [_make_list_app("js", app_type="JupyterServer", age_days=30)]},
        ]
        sm.get_paginator.return_value = paginator
        sm.describe_app.return_value = _make_describe()
        session = MagicMock()
        session.client.return_value = sm
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 7)
        assert len(findings) == 1
        assert findings[0].details["app_name"] == "idle1"


# ---------------------------------------------------------------------------
# TestCustomThreshold
# ---------------------------------------------------------------------------


class TestCustomThreshold:
    def test_custom_threshold_14_days(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=14)
        session, _ = _make_session([app], describe_return=desc)
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 14)
        assert len(findings) == 1

    def test_just_below_custom_threshold_skipped(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=13)
        session, _ = _make_session([app], describe_return=desc)
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 14)
        assert findings == []

    def test_custom_threshold_stored_in_details(self):
        app = _make_list_app(age_days=30)
        desc = _make_describe(last_activity_days=30)
        session, _ = _make_session([app], describe_return=desc)
        findings = find_idle_sagemaker_studio_apps(session, _REGION, 14)
        assert findings[0].details["idle_days_threshold"] == 14


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "aws.sagemaker.studio_app.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "sagemaker"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
