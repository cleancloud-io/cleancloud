from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.sagemaker_studio_app_idle import (
    find_idle_sagemaker_studio_apps,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_DOMAIN = "d-abc1234567"


def _make_app(
    app_name="my-kernel",
    app_type="KernelGateway",
    domain_id=_DOMAIN,
    user_profile="jdoe",
    space_name=None,
    status="InService",
    age_days=30,
    last_activity_days=None,
):
    now = datetime.now(timezone.utc)
    app = {
        "DomainId": domain_id,
        "AppName": app_name,
        "AppType": app_type,
        "Status": status,
        "CreationTime": now - timedelta(days=age_days),
    }
    if space_name:
        app["SpaceName"] = space_name
    else:
        app["UserProfileName"] = user_profile
    if last_activity_days is not None:
        app["LastUserActivityTimestamp"] = now - timedelta(days=last_activity_days)
    return app


def _make_session(
    apps=None,
    instance_type="ml.t3.medium",
    last_activity_days=30,
    describe_side_effect=None,
):
    """Return (session, sagemaker_client) with list_apps paginator and describe_app mocked."""
    now = datetime.now(timezone.utc)

    sagemaker = MagicMock()

    # list_apps paginator
    page = {"Apps": apps or []}
    paginator = MagicMock()
    paginator.paginate.return_value = [page]
    sagemaker.get_paginator.return_value = paginator

    # describe_app default response
    if describe_side_effect:
        sagemaker.describe_app.side_effect = describe_side_effect
    else:
        last_ts = (
            now - timedelta(days=last_activity_days) if last_activity_days is not None else None
        )
        sagemaker.describe_app.return_value = {
            "ResourceSpec": {"InstanceType": instance_type},
            "LastUserActivityTimestamp": last_ts,
        }

    session = MagicMock()
    session.client.return_value = sagemaker
    return session, sagemaker


def _auth_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "Access Denied"}}, "operation")


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_kernel_gateway_idle_detected():
    app = _make_app(app_type="KernelGateway", age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws.sagemaker.studio_app.idle"


def test_jupyter_lab_idle_detected():
    app = _make_app(app_type="JupyterLab", age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1


def test_code_editor_idle_detected():
    app = _make_app(app_type="CodeEditor", age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1


def test_jupyter_server_excluded():
    # JupyterServer is InService but should be excluded (domain-managed infra)
    app = _make_app(app_type="JupyterServer", status="InService", age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


def test_non_inservice_status_skipped():
    app = _make_app(status="Deleted", age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Age guard
# ---------------------------------------------------------------------------


def test_age_guard_skips_new_app():
    # age_days=3, idle_days=7 → age < max(7//2, 7) = 7 → skip
    app = _make_app(age_days=3)
    session, _ = _make_session(apps=[app], last_activity_days=3)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


def test_active_app_skipped():
    # age=30, last_activity=1 day ago → not idle enough
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=1)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence():
    # idle_since_days=14, idle_days=7 → HIGH (>= idle_days)
    app = _make_app(age_days=14)
    session, _ = _make_session(apps=[app], last_activity_days=14)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    from cleancloud.core.confidence import ConfidenceLevel

    assert findings[0].confidence == ConfidenceLevel.HIGH


def test_medium_confidence_borderline():
    # idle_since=6, idle_days=7 → ceil(0.75*7)=6 → MEDIUM; age=7 >= 6
    app = _make_app(age_days=7)
    session, _ = _make_session(apps=[app], last_activity_days=6)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    from cleancloud.core.confidence import ConfidenceLevel

    assert findings[0].confidence == ConfidenceLevel.MEDIUM


def test_below_medium_threshold_skipped():
    # idle_since=5, idle_days=7 → ceil(0.75*7)=6 → 5 < 6 → skip
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=5)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_cpu_risk_is_medium():
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], instance_type="ml.t3.medium", last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    from cleancloud.core.risk import RiskLevel

    assert findings[0].risk == RiskLevel.MEDIUM


def test_gpu_risk_is_high():
    # idle_ratio = 7/7 = 1.0 < 2.0 → HIGH (not CRITICAL)
    app = _make_app(age_days=7)
    session, _ = _make_session(apps=[app], instance_type="ml.g4dn.xlarge", last_activity_days=7)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    from cleancloud.core.risk import RiskLevel

    assert findings[0].risk == RiskLevel.HIGH


def test_gpu_risk_critical_high_idle_ratio():
    # idle_since=30, idle_days=7 → idle_ratio=30/7 ≈ 4.3 >= 2.0 → CRITICAL
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], instance_type="ml.g5.xlarge", last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    from cleancloud.core.risk import RiskLevel

    assert findings[0].risk == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Cost lookup
# ---------------------------------------------------------------------------


def test_cost_known_instance():
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], instance_type="ml.t3.medium", last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings[0].estimated_monthly_cost_usd == 42.0


def test_cost_gpu_instance():
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], instance_type="ml.g4dn.xlarge", last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings[0].estimated_monthly_cost_usd == 531.0


def test_cost_unknown_instance_uses_default():
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], instance_type="ml.x9.supersize", last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings[0].estimated_monthly_cost_usd == 50.0


# ---------------------------------------------------------------------------
# Idle signal source
# ---------------------------------------------------------------------------


def test_fallback_to_creation_time_when_no_last_activity():
    # describe_app returns no LastUserActivityTimestamp
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        # No LastUserActivityTimestamp key
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    details = findings[0].details
    assert "CreationTime" in details["idle_signal_source"]
    # idle_since_days should equal age_days (30)
    assert details["idle_since_days"] == details["age_days"]


def test_fallback_caps_confidence_at_medium():
    """When LastUserActivityTimestamp is absent, confidence is capped at MEDIUM even if
    idle_since_days >= idle_days (would otherwise qualify as HIGH)."""
    app = _make_app(age_days=30)  # well past idle_days=7
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        # No LastUserActivityTimestamp — triggers fallback
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    # Must not be HIGH — fallback signal is weaker than confirmed activity timestamp
    assert findings[0].confidence.value == "medium"


def test_fallback_confidence_note_in_details():
    """confidence_note is populated when using CreationTime fallback, None otherwise."""
    # Fallback case
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {"ResourceSpec": {"InstanceType": "ml.t3.medium"}}
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings[0].details["confidence_note"] is not None
    assert "fallback" in findings[0].details["confidence_note"].lower()

    # Non-fallback case
    app2 = _make_app(age_days=30, last_activity_days=30)
    session2, _ = _make_session(apps=[app2], last_activity_days=30)
    findings2 = find_idle_sagemaker_studio_apps(session2, _REGION, idle_days=7)
    assert findings2[0].details["confidence_note"] is None


def test_gpu_unknown_instance_uses_gpu_floor():
    """GPU instances not in the cost table use _DEFAULT_MONTHLY_COST_GPU ($200), not $50."""
    app = _make_app(age_days=30, last_activity_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.g5.48xlarge"},  # not in the cost table
        "LastUserActivityTimestamp": _make_app(age_days=30)["CreationTime"],
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 200.0


def test_owner_defaults_to_unknown_when_neither_profile_nor_space():
    """owner field falls back to 'unknown' if both UserProfileName and SpaceName are absent."""
    app = _make_app(age_days=30, last_activity_days=30)
    app.pop("UserProfileName", None)
    app.pop("SpaceName", None)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["owner"] == "unknown"


# ---------------------------------------------------------------------------
# Health-check guard (Issue 1)
# ---------------------------------------------------------------------------


def test_luat_matches_lhct_skipped():
    """When LUAT ≈ LHCT (within 5 minutes), the idle signal is unreliable → skip.

    LUAT may have been written by the health check itself, or the user may have
    been active moments before the check ran.  Falling back to age_days would
    falsely flag an actively-used app as idle since creation, so we prefer the
    false negative and skip instead.
    """
    now = datetime.now(timezone.utc)
    lhct = now - timedelta(minutes=2)  # health check 2 min ago
    luat = now - timedelta(minutes=1)  # LUAT 1 min ago — within epsilon of LHCT
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        "LastUserActivityTimestamp": luat,
        "LastHealthCheckTimestamp": lhct,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings == []  # insufficient signal — skip rather than risk false positive


def test_real_user_activity_luat_much_older_than_lhct():
    """LUAT 30 days ago with LHCT 1 minute ago: delta >> epsilon → LUAT is trusted."""
    now = datetime.now(timezone.utc)
    lhct = now - timedelta(minutes=1)
    luat = now - timedelta(days=30)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        "LastUserActivityTimestamp": luat,
        "LastHealthCheckTimestamp": lhct,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "LastUserActivityTimestamp"
    assert findings[0].details["idle_since_days"] == 30


def test_app_active_recently_not_flagged_even_with_health_check():
    """LUAT 1 day ago and LHCT 1 minute ago: delta >> epsilon, LUAT trusted → not flagged."""
    now = datetime.now(timezone.utc)
    lhct = now - timedelta(minutes=1)
    luat = now - timedelta(days=1)  # genuinely recent user activity
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        "LastUserActivityTimestamp": luat,
        "LastHealthCheckTimestamp": lhct,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings == []  # 1 day < 7-day threshold → not flagged


def test_health_check_guard_not_triggered_when_lhct_absent():
    """If LastHealthCheckTimestamp is absent, guard does not fire — LUAT is used as-is."""
    now = datetime.now(timezone.utc)
    luat = now - timedelta(days=30)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        "LastUserActivityTimestamp": luat,
        # No LastHealthCheckTimestamp — guard cannot fire
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "LastUserActivityTimestamp"


def test_mixed_timezone_awareness_does_not_raise():
    """Naive LUAT and aware LHCT (or vice versa) must not raise TypeError.

    boto3 can return naive datetimes in some SDK versions; both timestamps must be
    normalised to UTC-aware before the health-check guard subtraction.
    Guard fires (delta ≤ epsilon) → skip (no finding).
    """
    now = datetime.now(timezone.utc)
    # Naive LUAT (no tzinfo) — simulates older boto3 / moto behaviour
    luat_naive = (now - timedelta(minutes=1)).replace(tzinfo=None)
    # Aware LHCT
    lhct_aware = now - timedelta(minutes=2)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.t3.medium"},
        "LastUserActivityTimestamp": luat_naive,
        "LastHealthCheckTimestamp": lhct_aware,
    }
    # Must not raise TypeError — guard normalises both timestamps first.
    # Guard fires (delta = 1 min ≤ 5 min) → unreliable signal → skip.
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings == []


# ---------------------------------------------------------------------------
# New GPU families (Issue 2)
# ---------------------------------------------------------------------------


def test_g6_instance_detected_as_gpu():
    """ml.g6.xlarge (NVIDIA L4) is classified as GPU — previously would fall through to CPU."""
    now = datetime.now(timezone.utc)
    luat = now - timedelta(days=30)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.g6.xlarge"},
        "LastUserActivityTimestamp": luat,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["is_gpu"] is True
    assert findings[0].details["instance_type"] == "ml.g6.xlarge"
    assert findings[0].estimated_monthly_cost_usd == 700.0


def test_g6e_instance_detected_as_gpu():
    """ml.g6e family (NVIDIA L40S) is classified as GPU."""
    now = datetime.now(timezone.utc)
    luat = now - timedelta(days=30)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.g6e.xlarge"},
        "LastUserActivityTimestamp": luat,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["is_gpu"] is True
    # Unknown size → GPU floor cost, not $50 CPU default
    assert findings[0].estimated_monthly_cost_usd == 200.0


def test_p5en_instance_detected_as_gpu():
    """ml.p5en family (NVIDIA H200) is classified as GPU."""
    now = datetime.now(timezone.utc)
    luat = now - timedelta(days=30)
    app = _make_app(age_days=30)
    session, sagemaker = _make_session(apps=[app])
    sagemaker.describe_app.return_value = {
        "ResourceSpec": {"InstanceType": "ml.p5en.48xlarge"},
        "LastUserActivityTimestamp": luat,
    }
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["is_gpu"] is True
    assert findings[0].estimated_monthly_cost_usd == 200.0  # GPU floor, not CPU $50


# ---------------------------------------------------------------------------
# Space-based apps
# ---------------------------------------------------------------------------


def test_space_based_app_detected():
    app = _make_app(age_days=30, space_name="my-space", user_profile=None)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    assert findings[0].details["owner_type"] == "space"
    assert findings[0].details["owner"] == "my-space"


def test_describe_app_uses_space_name_kwarg():
    app = _make_app(age_days=30, space_name="my-space", user_profile=None)
    session, sagemaker = _make_session(apps=[app], last_activity_days=30)
    find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    call_kwargs = sagemaker.describe_app.call_args[1]
    assert "SpaceName" in call_kwargs
    assert call_kwargs["SpaceName"] == "my-space"
    assert "UserProfileName" not in call_kwargs


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_describe_app_failure_skips_app():
    # Non-auth ClientError from describe_app → skip the app
    app = _make_app(age_days=30)
    error = ClientError({"Error": {"Code": "ResourceNotFound", "Message": "not found"}}, "op")
    session, _ = _make_session(apps=[app], describe_side_effect=error)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 0


def test_list_apps_auth_error_raises_permission_error():
    session = MagicMock()
    sagemaker = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = _auth_error("AccessDeniedException")
    sagemaker.get_paginator.return_value = paginator
    session.client.return_value = sagemaker

    with pytest.raises(PermissionError, match="sagemaker:ListApps"):
        find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)


def test_describe_app_auth_error_raises_permission_error():
    app = _make_app(age_days=30)
    session, _ = _make_session(
        apps=[app], describe_side_effect=_auth_error("AccessDeniedException")
    )

    with pytest.raises(PermissionError, match="sagemaker:DescribeApp"):
        find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)


# ---------------------------------------------------------------------------
# Resource ID and details
# ---------------------------------------------------------------------------


def test_resource_id_format():
    app = _make_app(
        app_name="my-kernel",
        app_type="KernelGateway",
        domain_id=_DOMAIN,
        user_profile="jdoe",
        age_days=30,
    )
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    expected = f"{_DOMAIN}/jdoe/KernelGateway/my-kernel"
    assert findings[0].resource_id == expected


def test_details_fields_present():
    app = _make_app(age_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    details = findings[0].details
    expected_keys = {
        "domain_id",
        "app_name",
        "app_type",
        "owner",
        "owner_type",
        "instance_type",
        "is_gpu",
        "age_days",
        "idle_since_days",
        "idle_signal_source",
        "idle_days_threshold",
        "idle_ratio",
        "waste_score",
        "estimated_monthly_cost",
        "cost_basis",
        "confidence_note",
    }
    assert expected_keys.issubset(details.keys())


def test_waste_score_is_monthly_cost_times_idle_ratio():
    """waste_score = monthly_cost × idle_ratio, rounded to 2dp."""
    # ml.t3.medium = $42/month, idle_since=14, idle_days=7 → idle_ratio=2.0 → waste_score=84.0
    app = _make_app(age_days=30, last_activity_days=14)
    session, _ = _make_session(apps=[app], instance_type="ml.t3.medium", last_activity_days=14)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 1
    details = findings[0].details
    assert details["waste_score"] == round(42.0 * details["idle_ratio"], 2)


def test_cost_basis_in_details():
    app = _make_app(age_days=30, last_activity_days=30)
    session, _ = _make_session(apps=[app], last_activity_days=30)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert findings[0].details["cost_basis"] == "us-east-1 on-demand estimate"


# ---------------------------------------------------------------------------
# Multiple apps
# ---------------------------------------------------------------------------


def test_multiple_apps_independent():
    apps = [
        _make_app(app_name="app-one", age_days=30),
        _make_app(app_name="app-two", app_type="JupyterLab", age_days=20),
    ]
    session, _ = _make_session(apps=apps, last_activity_days=15)
    findings = find_idle_sagemaker_studio_apps(session, _REGION, idle_days=7)
    assert len(findings) == 2
    names = {f.details["app_name"] for f in findings}
    assert names == {"app-one", "app-two"}
