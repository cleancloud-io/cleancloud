from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_domain_idle import (
    RULE_METADATA,
    _check_idle_shutdown,
    _enrich_domain,
    _normalize_domain,
    find_idle_sagemaker_domains,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_THRESHOLD = 30
_ARN_PREFIX = "arn:aws:sagemaker:us-east-1:123456789012:domain"


def _make_session(sagemaker_mock):
    session = MagicMock()
    session.client.return_value = sagemaker_mock
    return session


def _make_domain(
    domain_id="d-abc123",
    name="ml-research",
    age_days=60,
    status="InService",
):
    """Build a ListDomains response entry."""
    now = datetime.now(timezone.utc)
    return {
        "DomainId": domain_id,
        "DomainArn": f"{_ARN_PREFIX}/{domain_id}",
        "DomainName": name,
        "Status": status,
        "CreationTime": now - timedelta(days=age_days),
        "LastModifiedTime": now - timedelta(days=age_days - 1),
    }


def _describe_response(
    domain_id="d-abc123",
    efs_id="fs-abc123",
    efs_creation="Automatic",
    network_access="PublicInternetOnly",
    auth_mode="IAM",
    idle_shutdown=False,
):
    """Build a DescribeDomain response."""
    resp = {
        "DomainId": domain_id,
        "HomeEfsFileSystemId": efs_id,
        "HomeEfsFileSystemCreation": efs_creation,
        "AppNetworkAccessType": network_access,
        "AuthMode": auth_mode,
        "DefaultUserSettings": {},
        "DefaultSpaceSettings": {},
    }
    if idle_shutdown:
        resp["DefaultUserSettings"] = {
            "JupyterLabAppSettings": {
                "AppLifecycleManagement": {
                    "IdleSettings": {
                        "LifecycleManagement": "Enabled",
                    }
                }
            }
        }
    return resp


def _make_apps(*statuses):
    """Build a ListApps response with the given app statuses."""
    apps = []
    for i, status in enumerate(statuses):
        apps.append(
            {
                "AppName": f"app-{i}",
                "AppType": "JupyterLab",
                "Status": status,
                "DomainId": "d-abc123",
                "CreationTime": datetime.now(timezone.utc) - timedelta(days=5),
            }
        )
    return apps


def _setup_sagemaker(
    domains=None,
    describe_response=None,
    apps=None,
    describe_side_effect=None,
    list_apps_side_effect=None,
):
    """Wire up a fully mocked SageMaker client."""
    sm = MagicMock()

    # ListDomains paginator
    domain_paginator = MagicMock()
    domain_paginator.paginate.return_value = [{"Domains": domains or []}]

    # ListApps paginator
    apps_paginator = MagicMock()
    if list_apps_side_effect:
        apps_paginator.paginate.side_effect = list_apps_side_effect
    else:
        apps_paginator.paginate.return_value = [{"Apps": apps if apps is not None else []}]

    def get_paginator(name):
        if name == "list_domains":
            return domain_paginator
        if name == "list_apps":
            return apps_paginator
        raise ValueError(f"Unexpected paginator: {name}")

    sm.get_paginator.side_effect = get_paginator

    # DescribeDomain
    if describe_side_effect:
        sm.describe_domain.side_effect = describe_side_effect
    else:
        sm.describe_domain.return_value = describe_response or _describe_response()

    return sm


def _run(
    domains=None,
    describe_response=None,
    apps=None,
    threshold=_DEFAULT_THRESHOLD,
    region="us-east-1",
    describe_side_effect=None,
    list_apps_side_effect=None,
):
    sm = _setup_sagemaker(
        domains=domains,
        describe_response=describe_response,
        apps=apps,
        describe_side_effect=describe_side_effect,
        list_apps_side_effect=list_apps_side_effect,
    )
    return find_idle_sagemaker_domains(_make_session(sm), region, threshold)


def _arn(domain_id):
    return f"{_ARN_PREFIX}/{domain_id}"


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    """Spec §16: scenarios 1-3."""

    def test_idle_domain_no_apps_emits(self):
        """Scenario 1: InService domain older than threshold, zero apps."""
        findings = _run(domains=[_make_domain(age_days=60)], apps=[])
        assert len(findings) == 1

    def test_idle_domain_all_deleted_apps_emits(self):
        """Scenario 2: all apps Deleted."""
        findings = _run(
            domains=[_make_domain(age_days=60)],
            apps=_make_apps("Deleted", "Deleted"),
        )
        assert len(findings) == 1

    def test_idle_domain_all_failed_apps_emits(self):
        """Scenario 3: all apps Failed."""
        findings = _run(
            domains=[_make_domain(age_days=60)],
            apps=_make_apps("Failed"),
        )
        assert len(findings) == 1

    def test_idle_domain_mixed_non_billable_emits(self):
        """Mix of Deleted, Deleting, Failed → still idle."""
        findings = _run(
            domains=[_make_domain(age_days=60)],
            apps=_make_apps("Deleted", "Deleting", "Failed"),
        )
        assert len(findings) == 1

    def test_resource_id_is_domain_arn(self):
        findings = _run(domains=[_make_domain(domain_id="d-xyz789", age_days=60)])
        assert findings[0].resource_id == _arn("d-xyz789")

    def test_resource_type(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].resource_type == "aws.sagemaker.domain"

    def test_provider(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].provider == "aws"

    def test_rule_id(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].rule_id == "aws.sagemaker.domain.idle"

    def test_region_preserved(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            region="ap-southeast-1",
        )
        assert findings[0].region == "ap-southeast-1"

    def test_no_domains_returns_empty(self):
        assert _run(domains=[]) == []

    def test_summary_contains_domain_name(self):
        findings = _run(
            domains=[_make_domain(name="fraud-model-studio", age_days=60)],
        )
        assert "fraud-model-studio" in findings[0].summary

    def test_exactly_at_threshold_emits(self):
        findings = _run(domains=[_make_domain(age_days=30)])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    """Spec §16: scenarios 4-15."""

    def test_pending_domain_skipped(self):
        """Scenario 4."""
        assert _run(domains=[_make_domain(age_days=60, status="Pending")]) == []

    def test_updating_domain_skipped(self):
        """Scenario 5."""
        assert _run(domains=[_make_domain(age_days=60, status="Updating")]) == []

    def test_deleting_domain_skipped(self):
        """Scenario 6."""
        assert _run(domains=[_make_domain(age_days=60, status="Deleting")]) == []

    def test_failed_domain_skipped(self):
        """Scenario 7."""
        assert _run(domains=[_make_domain(age_days=60, status="Failed")]) == []

    def test_domain_too_young_skipped(self):
        """Scenario 8."""
        assert _run(domains=[_make_domain(age_days=29)]) == []

    def test_missing_domain_arn_skipped(self):
        """Scenario 9."""
        d = _make_domain(age_days=60)
        del d["DomainArn"]
        assert _run(domains=[d]) == []

    def test_empty_domain_arn_skipped(self):
        d = _make_domain(age_days=60)
        d["DomainArn"] = ""
        assert _run(domains=[d]) == []

    def test_missing_domain_id_skipped(self):
        """Scenario 10."""
        d = _make_domain(age_days=60)
        del d["DomainId"]
        assert _run(domains=[d]) == []

    def test_empty_domain_id_skipped(self):
        d = _make_domain(age_days=60)
        d["DomainId"] = ""
        assert _run(domains=[d]) == []

    def test_missing_creation_time_skipped(self):
        """Scenario 11."""
        d = _make_domain(age_days=60)
        del d["CreationTime"]
        assert _run(domains=[d]) == []

    def test_naive_creation_time_skipped(self):
        d = _make_domain(age_days=60)
        d["CreationTime"] = datetime.now() - timedelta(days=60)
        assert d["CreationTime"].tzinfo is None
        assert _run(domains=[d]) == []

    def test_future_creation_time_skipped(self):
        d = _make_domain(age_days=60)
        d["CreationTime"] = datetime.now(timezone.utc) + timedelta(days=1)
        assert _run(domains=[d]) == []

    def test_missing_status_skipped(self):
        d = _make_domain(age_days=60)
        del d["Status"]
        assert _run(domains=[d]) == []

    def test_empty_status_skipped(self):
        d = _make_domain(age_days=60)
        d["Status"] = ""
        assert _run(domains=[d]) == []

    def test_domain_with_inservice_app_skipped(self):
        """Scenario 12."""
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=_make_apps("InService"),
            )
            == []
        )

    def test_domain_with_pending_app_skipped(self):
        """Scenario 13."""
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=_make_apps("Pending"),
            )
            == []
        )

    def test_domain_with_unclassifiable_app_status_skipped(self):
        """Scenario 14: app with missing Status → skip domain."""
        bad_app = {"AppName": "app-0", "AppType": "JupyterLab", "DomainId": "d-abc123"}
        # No Status key
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=[bad_app],
            )
            == []
        )

    def test_domain_with_unknown_app_status_skipped(self):
        """Scenario 14: app with undocumented Status value → skip domain."""
        bad_app = {
            "AppName": "app-0",
            "AppType": "JupyterLab",
            "Status": "SomeNewStatus",
            "DomainId": "d-abc123",
        }
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=[bad_app],
            )
            == []
        )

    def test_domain_with_empty_app_status_skipped(self):
        bad_app = {
            "AppName": "app-0",
            "Status": "",
            "DomainId": "d-abc123",
        }
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=[bad_app],
            )
            == []
        )

    def test_describe_domain_non_permission_failure_skips(self):
        """Scenario 15: DescribeDomain throttle/not-found → skip item, rule continues."""
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_side_effect=ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
                "DescribeDomain",
            ),
        )
        assert findings == []

    def test_describe_domain_botocore_error_skips(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_side_effect=BotoCoreError(),
        )
        assert findings == []

    def test_mixed_billable_and_non_billable_apps_skipped(self):
        """One InService app among Deleted apps → skip."""
        assert (
            _run(
                domains=[_make_domain(age_days=60)],
                apps=_make_apps("Deleted", "InService", "Deleted"),
            )
            == []
        )

    def test_non_dict_app_entry_skips_domain(self):
        """Non-dict app entry is unclassifiable → skip domain."""
        sm = _setup_sagemaker(
            domains=[_make_domain(age_days=60)],
        )
        # Override apps paginator to return non-dict entry
        apps_paginator = MagicMock()
        apps_paginator.paginate.return_value = [{"Apps": [None, "bad"]}]

        original_get_paginator = sm.get_paginator.side_effect

        def patched_get_paginator(name):
            if name == "list_apps":
                return apps_paginator
            return original_get_paginator(name)

        sm.get_paginator.side_effect = patched_get_paginator
        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert findings == []

    def test_non_dict_item_in_domains_skipped(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Domains": [None, "bad", 42]}]
        sm.get_paginator.return_value = paginator
        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert findings == []

    def test_age_zero_skipped(self):
        assert _run(domains=[_make_domain(age_days=0)]) == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    """Spec §16: scenarios 16-18."""

    def test_list_domains_preflight_permission_denied_fails(self):
        """Pre-flight direct call catches permission error before paginator."""
        sm = MagicMock()
        sm.list_domains.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListDomains",
        )
        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert "sagemaker:ListDomains" in str(exc_info.value)
        # Paginator should never be called if pre-flight fails
        sm.get_paginator.assert_not_called()

    def test_list_domains_paginator_permission_denied_fails(self):
        """Scenario 16 (permission variant) — paginator also catches."""
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListDomains",
        )
        sm.get_paginator.return_value = paginator
        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert "sagemaker:ListDomains" in str(exc_info.value)

    def test_list_domains_other_client_error_propagates(self):
        """Scenario 16 (non-permission variant)."""
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "InternalFailure", "Message": "oops"}},
            "ListDomains",
        )
        sm.get_paginator.return_value = paginator
        with pytest.raises(ClientError):
            find_idle_sagemaker_domains(_make_session(sm), "us-east-1")

    def test_list_domains_botocore_error_propagates(self):
        sm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = BotoCoreError()
        sm.get_paginator.return_value = paginator
        with pytest.raises(BotoCoreError):
            find_idle_sagemaker_domains(_make_session(sm), "us-east-1")

    def test_list_apps_permission_denied_fails(self):
        """Scenario 17."""
        with pytest.raises(PermissionError) as exc_info:
            _run(
                domains=[_make_domain(age_days=60)],
                list_apps_side_effect=ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "ListApps",
                ),
            )
        assert "sagemaker:ListApps" in str(exc_info.value)

    def test_list_apps_other_client_error_propagates(self):
        with pytest.raises(ClientError):
            _run(
                domains=[_make_domain(age_days=60)],
                list_apps_side_effect=ClientError(
                    {"Error": {"Code": "InternalFailure", "Message": "oops"}},
                    "ListApps",
                ),
            )

    def test_list_apps_botocore_error_propagates(self):
        with pytest.raises(BotoCoreError):
            _run(
                domains=[_make_domain(age_days=60)],
                list_apps_side_effect=BotoCoreError(),
            )

    def test_describe_domain_permission_denied_fails(self):
        """Scenario 18."""
        with pytest.raises(PermissionError) as exc_info:
            _run(
                domains=[_make_domain(age_days=60)],
                describe_side_effect=ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "DescribeDomain",
                ),
            )
        assert "sagemaker:DescribeDomain" in str(exc_info.value)

    def test_describe_domain_access_denied_fails(self):
        with pytest.raises(PermissionError):
            _run(
                domains=[_make_domain(age_days=60)],
                describe_side_effect=ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "DescribeDomain",
                ),
            )

    def test_describe_domain_unauthorized_operation_fails(self):
        with pytest.raises(PermissionError):
            _run(
                domains=[_make_domain(age_days=60)],
                describe_side_effect=ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
                    "DescribeDomain",
                ),
            )


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_always_high(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].confidence.value == "high"

    def test_confidence_high_with_efs(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_response=_describe_response(efs_id="fs-123"),
        )
        assert findings[0].confidence.value == "high"

    def test_confidence_high_without_efs(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_response=_describe_response(efs_id=None),
        )
        assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_efs_present_is_high_risk(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_response=_describe_response(efs_id="fs-abc123"),
        )
        assert findings[0].risk.value == "high"

    def test_efs_absent_is_medium_risk(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_response=_describe_response(efs_id=None),
        )
        assert findings[0].risk.value == "medium"

    def test_efs_empty_string_is_medium_risk(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            describe_response=_describe_response(efs_id=""),
        )
        assert findings[0].risk.value == "medium"

    def test_no_critical_risk_emitted(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        for f in findings:
            assert f.risk.value != "critical"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_cost_is_none(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_returns_none_for_non_dict(self):
        assert _normalize_domain(None, self._now()) is None
        assert _normalize_domain("bad", self._now()) is None
        assert _normalize_domain(42, self._now()) is None

    def test_returns_none_when_arn_missing(self):
        now = self._now()
        item = {
            "DomainId": "d-abc",
            "DomainName": "test",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
        }
        assert _normalize_domain(item, now) is None

    def test_returns_none_when_domain_id_missing(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainName": "test",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
        }
        assert _normalize_domain(item, now) is None

    def test_returns_none_when_status_missing(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "CreationTime": now - timedelta(days=30),
        }
        assert _normalize_domain(item, now) is None

    def test_returns_none_for_naive_creation_time(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": datetime.now() - timedelta(days=30),
        }
        assert _normalize_domain(item, now) is None

    def test_returns_none_for_future_creation_time(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now + timedelta(days=1),
        }
        assert _normalize_domain(item, now) is None

    def test_age_days_computed_correctly(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now - timedelta(days=45),
        }
        n = _normalize_domain(item, now)
        assert n is not None
        assert n["age_days"] == 45

    def test_domain_name_optional(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
        }
        n = _normalize_domain(item, now)
        assert n is not None
        assert n["domain_name"] is None

    def test_last_modified_time_optional(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
        }
        n = _normalize_domain(item, now)
        assert n is not None
        assert n["last_modified_time_utc"] is None

    def test_naive_last_modified_time_normalized_to_none(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": datetime.now() - timedelta(days=10),  # naive
        }
        n = _normalize_domain(item, now)
        assert n is not None
        assert n["last_modified_time_utc"] is None

    def test_future_last_modified_time_normalized_to_none(self):
        now = self._now()
        item = {
            "DomainArn": _arn("d-abc"),
            "DomainId": "d-abc",
            "Status": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now + timedelta(days=1),
        }
        n = _normalize_domain(item, now)
        assert n is not None
        assert n["last_modified_time_utc"] is None


# ---------------------------------------------------------------------------
# TestEnrichment
# ---------------------------------------------------------------------------


class TestEnrichment:
    def test_enrich_extracts_efs_id(self):
        resp = _describe_response(efs_id="fs-abc123")
        e = _enrich_domain(resp)
        assert e["home_efs_file_system_id"] == "fs-abc123"

    def test_enrich_efs_id_none_when_absent(self):
        resp = _describe_response()
        del resp["HomeEfsFileSystemId"]
        e = _enrich_domain(resp)
        assert e["home_efs_file_system_id"] is None

    def test_enrich_auth_mode(self):
        resp = _describe_response(auth_mode="SSO")
        e = _enrich_domain(resp)
        assert e["auth_mode"] == "SSO"

    def test_idle_shutdown_default_false(self):
        resp = _describe_response(idle_shutdown=False)
        e = _enrich_domain(resp)
        assert e["idle_shutdown_configured"] is False

    def test_idle_shutdown_true_when_configured(self):
        resp = _describe_response(idle_shutdown=True)
        e = _enrich_domain(resp)
        assert e["idle_shutdown_configured"] is True

    def test_idle_shutdown_from_default_space_settings(self):
        resp = _describe_response()
        resp["DefaultSpaceSettings"] = {
            "CodeEditorAppSettings": {
                "AppLifecycleManagement": {
                    "IdleSettings": {
                        "LifecycleManagement": "Enabled",
                    }
                }
            }
        }
        e = _enrich_domain(resp)
        assert e["idle_shutdown_configured"] is True


# ---------------------------------------------------------------------------
# TestIdleShutdownCheck
# ---------------------------------------------------------------------------


class TestIdleShutdownCheck:
    def test_enabled_in_jupyterlab(self):
        settings = {
            "JupyterLabAppSettings": {
                "AppLifecycleManagement": {"IdleSettings": {"LifecycleManagement": "Enabled"}}
            }
        }
        assert _check_idle_shutdown(settings) is True

    def test_enabled_in_code_editor(self):
        settings = {
            "CodeEditorAppSettings": {
                "AppLifecycleManagement": {"IdleSettings": {"LifecycleManagement": "Enabled"}}
            }
        }
        assert _check_idle_shutdown(settings) is True

    def test_disabled(self):
        settings = {
            "JupyterLabAppSettings": {
                "AppLifecycleManagement": {"IdleSettings": {"LifecycleManagement": "Disabled"}}
            }
        }
        assert _check_idle_shutdown(settings) is False

    def test_empty_settings(self):
        assert _check_idle_shutdown({}) is False

    def test_malformed_settings_handled(self):
        assert _check_idle_shutdown({"JupyterLabAppSettings": "not-a-dict"}) is False
        assert (
            _check_idle_shutdown({"JupyterLabAppSettings": {"AppLifecycleManagement": None}})
            is False
        )


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def _finding(self):
        return _run(
            domains=[_make_domain(domain_id="d-test", name="my-domain", age_days=60)],
            describe_response=_describe_response(
                domain_id="d-test",
                efs_id="fs-test",
                efs_creation="Automatic",
                network_access="VpcOnly",
                auth_mode="SSO",
                idle_shutdown=True,
            ),
            apps=_make_apps("Deleted", "Failed"),
        )[0]

    def test_evaluation_path(self):
        assert (
            self._finding().details["evaluation_path"] == "idle-sagemaker-domain-review-candidate"
        )

    def test_domain_arn(self):
        assert self._finding().details["domain_arn"] == _arn("d-test")

    def test_domain_id(self):
        assert self._finding().details["domain_id"] == "d-test"

    def test_domain_name(self):
        assert self._finding().details["domain_name"] == "my-domain"

    def test_normalized_status(self):
        assert self._finding().details["normalized_status"] == "InService"

    def test_creation_time_present(self):
        assert "creation_time" in self._finding().details

    def test_age_days(self):
        assert self._finding().details["age_days"] == 60

    def test_idle_days_threshold(self):
        assert self._finding().details["idle_days_threshold"] == 30

    def test_home_efs_file_system_id(self):
        assert self._finding().details["home_efs_file_system_id"] == "fs-test"

    def test_home_efs_file_system_creation(self):
        assert self._finding().details["home_efs_file_system_creation"] == "Automatic"

    def test_app_network_access_type(self):
        assert self._finding().details["app_network_access_type"] == "VpcOnly"

    def test_auth_mode(self):
        assert self._finding().details["auth_mode"] == "SSO"

    def test_idle_shutdown_configured(self):
        assert self._finding().details["idle_shutdown_configured"] is True

    def test_total_apps_evaluated(self):
        assert self._finding().details["total_apps_evaluated"] == 2

    def test_apps_by_status(self):
        d = self._finding().details["apps_by_status"]
        assert d == {"Deleted": 1, "Failed": 1}

    def test_inservice_app_count_zero(self):
        assert self._finding().details["inservice_app_count"] == 0

    def test_pending_app_count_zero(self):
        assert self._finding().details["pending_app_count"] == 0


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def _evidence(self):
        return _run(domains=[_make_domain(age_days=60)])[0].evidence

    def test_signals_used_non_empty(self):
        assert len(self._evidence().signals_used) > 0

    def test_signals_used_mentions_inservice(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "InService" in sigs

    def test_signals_used_mentions_list_apps(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "ListApps" in sigs

    def test_signals_used_mentions_domain_age(self):
        sigs = " ".join(self._evidence().signals_used)
        assert "domain age" in sigs

    def test_signals_not_checked_mentions_last_user_activity(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "LastUserActivityTimestamp" in not_checked

    def test_signals_not_checked_mentions_health_checks(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "health checks" in not_checked

    def test_signals_not_checked_mentions_point_in_time(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "point-in-time" in not_checked

    def test_signals_not_checked_mentions_efs_storage(self):
        not_checked = " ".join(self._evidence().signals_not_checked)
        assert "EFS storage cost" in not_checked

    def test_time_window(self):
        assert self._evidence().time_window == "30 days"


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_domain_pages_aggregated(self):
        sm = MagicMock()

        domain_paginator = MagicMock()
        domain_paginator.paginate.return_value = [
            {"Domains": [_make_domain("d-1", "dom-1", age_days=60)]},
            {"Domains": [_make_domain("d-2", "dom-2", age_days=60)]},
        ]

        apps_paginator = MagicMock()
        apps_paginator.paginate.return_value = [{"Apps": []}]

        def get_paginator(name):
            if name == "list_domains":
                return domain_paginator
            if name == "list_apps":
                return apps_paginator
            raise ValueError(f"Unexpected: {name}")

        sm.get_paginator.side_effect = get_paginator
        sm.describe_domain.return_value = _describe_response()

        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert len(findings) == 2

    def test_multiple_apps_pages_aggregated(self):
        """Apps across multiple pages are all checked."""
        sm = _setup_sagemaker(domains=[_make_domain(age_days=60)])

        apps_paginator = MagicMock()
        apps_paginator.paginate.return_value = [
            {"Apps": _make_apps("Deleted")},
            {"Apps": _make_apps("InService")},  # second page has active app
        ]

        original = sm.get_paginator.side_effect

        def patched(name):
            if name == "list_apps":
                return apps_paginator
            return original(name)

        sm.get_paginator.side_effect = patched
        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert findings == []


# ---------------------------------------------------------------------------
# TestMultipleDomains
# ---------------------------------------------------------------------------


class TestMultipleDomains:
    def test_only_idle_domains_emitted(self):
        idle = _make_domain("d-idle", "idle-domain", age_days=60)
        young = _make_domain("d-young", "young-domain", age_days=10)

        sm = MagicMock()

        domain_paginator = MagicMock()
        domain_paginator.paginate.return_value = [{"Domains": [idle, young]}]

        apps_paginator = MagicMock()
        apps_paginator.paginate.return_value = [{"Apps": []}]

        def get_paginator(name):
            if name == "list_domains":
                return domain_paginator
            if name == "list_apps":
                return apps_paginator
            raise ValueError(f"Unexpected: {name}")

        sm.get_paginator.side_effect = get_paginator
        sm.describe_domain.return_value = _describe_response()

        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert len(findings) == 1
        assert findings[0].details["domain_id"] == "d-idle"

    def test_describe_failure_skips_one_continues_other(self):
        """DescribeDomain fails for one domain but succeeds for another."""
        d1 = _make_domain("d-fail", "fail-domain", age_days=60)
        d2 = _make_domain("d-ok", "ok-domain", age_days=60)

        sm = MagicMock()

        domain_paginator = MagicMock()
        domain_paginator.paginate.return_value = [{"Domains": [d1, d2]}]

        apps_paginator = MagicMock()
        apps_paginator.paginate.return_value = [{"Apps": []}]

        def get_paginator(name):
            if name == "list_domains":
                return domain_paginator
            if name == "list_apps":
                return apps_paginator
            raise ValueError(f"Unexpected: {name}")

        sm.get_paginator.side_effect = get_paginator

        call_count = [0]

        def describe_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ClientError(
                    {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}},
                    "DescribeDomain",
                )
            return _describe_response(domain_id=kwargs.get("DomainId", "d-ok"))

        sm.describe_domain.side_effect = describe_side_effect

        findings = find_idle_sagemaker_domains(_make_session(sm), "us-east-1")
        assert len(findings) == 1
        assert findings[0].details["domain_id"] == "d-ok"


# ---------------------------------------------------------------------------
# TestCustomThreshold
# ---------------------------------------------------------------------------


class TestCustomThreshold:
    def test_custom_threshold_7_days(self):
        findings = _run(
            domains=[_make_domain(age_days=7)],
            threshold=7,
        )
        assert len(findings) == 1

    def test_age_just_below_custom_threshold_skipped(self):
        findings = _run(
            domains=[_make_domain(age_days=6)],
            threshold=7,
        )
        assert findings == []

    def test_custom_threshold_stored_in_details(self):
        findings = _run(
            domains=[_make_domain(age_days=60)],
            threshold=7,
        )
        assert findings[0].details["idle_days_threshold"] == 7


# ---------------------------------------------------------------------------
# TestTitleAndReason
# ---------------------------------------------------------------------------


class TestTitleAndReason:
    def test_title_is_spec_mandated(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert findings[0].title == "Idle SageMaker domain review candidate"

    def test_reason_contains_key_wording(self):
        findings = _run(domains=[_make_domain(age_days=60)])
        assert "InService SageMaker domain" in findings[0].reason
        assert "60 days old" in findings[0].reason
        assert "no InService or Pending apps" in findings[0].reason

    def test_reason_does_not_imply_inactivity_duration(self):
        """Spec: threshold applies to domain age, not measured inactivity."""
        findings = _run(domains=[_make_domain(age_days=60)])
        assert "for at least" not in findings[0].reason


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "aws.sagemaker.domain.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "sagemaker"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"
