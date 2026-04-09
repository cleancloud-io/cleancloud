from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.sagemaker_notebook_idle import (
    RULE_METADATA,
    find_idle_sagemaker_notebooks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(sagemaker_mock):
    session = MagicMock()
    session.client.return_value = sagemaker_mock
    return session


def _make_nb(
    name="ml-research-nb",
    instance_type="ml.t3.medium",
    age_days=30,
    idle_since_days=None,
):
    """Build a NotebookInstanceSummary list entry.

    idle_since_days controls LastModifiedTime (defaults to same as age_days).
    """
    now = datetime.now(timezone.utc)
    if idle_since_days is None:
        idle_since_days = age_days
    return {
        "NotebookInstanceName": name,
        "NotebookInstanceArn": f"arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/{name}",
        "NotebookInstanceStatus": "InService",
        "InstanceType": instance_type,
        "CreationTime": now - timedelta(days=age_days),
        "LastModifiedTime": now - timedelta(days=idle_since_days),
        "Url": f"{name}.notebook.us-east-1.sagemaker.aws",
    }


def _paginate(items):
    """Return a paginator that yields a single page containing items."""
    paginator = MagicMock()
    paginator.paginate.return_value = [{"NotebookInstances": items}]
    return paginator


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_cpu_notebook_detected():
    """Idle CPU notebook → MEDIUM risk, HIGH confidence."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(instance_type="ml.t3.medium", age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.sagemaker.notebook.idle"
    assert f.resource_type == "aws.sagemaker.notebook"
    assert f.resource_id == "ml-research-nb"
    assert f.confidence.value == "high"
    assert f.risk.value == "medium"
    assert f.details["is_gpu"] is False
    assert f.details["instance_type"] == "ml.t3.medium"
    assert f.details["age_days"] == 30
    assert f.estimated_monthly_cost_usd == 42.0


def test_idle_gpu_notebook_detected_high_risk():
    """GPU notebook idle exactly at threshold (idle_ratio=1.0) → HIGH risk."""
    sm = MagicMock()
    # age_days=14, idle_since_days=14 → idle_ratio=1.0 → HIGH (not CRITICAL)
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.p3.2xlarge", age_days=14, idle_since_days=14)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.details["is_gpu"] is True
    assert f.details["instance_type"] == "ml.p3.2xlarge"
    assert f.estimated_monthly_cost_usd == 2754.0


def test_idle_gpu_notebook_critical_risk_when_very_stale():
    """GPU notebook idle ≥ 2× threshold (idle_ratio ≥ 2.0) → CRITICAL risk."""
    sm = MagicMock()
    # age_days=30, idle_since_days=30, idle_days=14 → idle_ratio=30/14≈2.14 → CRITICAL
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.p3.2xlarge", age_days=30, idle_since_days=30)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "critical"
    assert f.details["is_gpu"] is True
    assert f.details["idle_ratio"] >= 2.0


def test_cpu_notebook_never_reaches_critical():
    """CPU notebooks are capped at MEDIUM regardless of idle_ratio."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.m5.xlarge", age_days=60, idle_since_days=60)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].risk.value == "medium"


def test_critical_boundary_exactly_at_2x():
    """idle_ratio == 2.0 exactly should trigger CRITICAL."""
    sm = MagicMock()
    # idle_days=14, idle_since_days=28 → idle_ratio=2.0
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.g4dn.xlarge", age_days=28, idle_since_days=28)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].risk.value == "critical"
    assert findings[0].details["idle_ratio"] == 2.0


def test_just_below_critical_boundary_is_high():
    """GPU notebook with idle_ratio < 2.0 should be HIGH, not CRITICAL."""
    sm = MagicMock()
    # idle_days=14, idle_since_days=14 → idle_ratio=1.0 → HIGH
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.g5.xlarge", age_days=14, idle_since_days=14)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].risk.value == "high"
    assert findings[0].details["idle_ratio"] == 1.0


def test_no_notebooks_returns_empty():
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([])

    assert find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1") == []


# ---------------------------------------------------------------------------
# Activity signals — LastModifiedTime
# ---------------------------------------------------------------------------


def test_recently_modified_notebook_skipped():
    """Notebook modified recently should NOT be flagged, even if old."""
    sm = MagicMock()
    # age=60 days old but LastModifiedTime only 3 days ago
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=60, idle_since_days=3)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 0


def test_long_idle_since_detected():
    """Notebook idle for 45 days should be flagged HIGH confidence."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.m5.xlarge", age_days=45, idle_since_days=45)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] == 45


def test_missing_last_modified_falls_back_to_age():
    """Missing LastModifiedTime should fall back to age as idle proxy."""
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    del nb["LastModifiedTime"]  # simulate missing field
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    # age >= idle_days → still flagged
    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] == 30


def test_missing_creation_time_uses_neutral_default():
    """Missing CreationTime should use idle_days as a neutral age default, not 0.

    A default of 0 would cause the age guard (age < max(idle_days//2, 7)) to skip
    every notebook whose CreationTime is missing, silently losing findings.
    With age_days = idle_days the notebook passes the guard and is evaluated normally.
    """
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    del nb["CreationTime"]
    # LastModifiedTime is 30 days ago → idle_since_days=30 >= idle_days=14 → HIGH
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    # Should be detected, not silently skipped
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Age guard
# ---------------------------------------------------------------------------


def test_young_notebook_skipped():
    """Notebook younger than minimum threshold should NOT be flagged."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=3)])

    assert find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1") == []


def test_notebook_at_minimum_age_skipped():
    """Notebook at exactly 6 days old (below max(14//2=7, 7)) should be skipped."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=6)])

    assert find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1") == []


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_when_age_and_idle_exceed_threshold():
    """age >= idle_days AND idle_since >= idle_days → HIGH confidence."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=14, idle_since_days=14)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_medium_confidence_at_75_percent_threshold():
    """age and idle_since at 75% of idle_days → MEDIUM confidence."""
    sm = MagicMock()
    # idle_days=14, threshold_medium=int(14*0.75)=10
    # age=11, idle_since=11 → 11 >= 10 but 11 < 14 → MEDIUM
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=11, idle_since_days=11)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_below_medium_threshold_skipped():
    """age and idle_since below 75% threshold → skipped (not enough signal)."""
    sm = MagicMock()
    # age=8, idle_since=8 → 8 < 10 → skip
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=8, idle_since_days=8)])

    assert find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1") == []


def test_old_age_but_low_idle_since_gives_medium_then_skipped():
    """HIGH age but low idle_since (recent activity) → not flagged at all."""
    sm = MagicMock()
    # age=60, idle_since=5 — notebook was touched 5 days ago → skip
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=60, idle_since_days=5)])

    assert find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1") == []


def test_custom_idle_days_threshold_respected():
    """Custom idle_days=7 — notebook idle 7 days should be HIGH confidence."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=7, idle_since_days=7)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", idle_days=7)

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# GPU family detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "instance_type,expected_gpu",
    [
        ("ml.g4dn.xlarge", True),
        ("ml.g5.2xlarge", True),
        ("ml.p3.2xlarge", True),
        ("ml.p3.8xlarge", True),
        ("ml.p4d.24xlarge", True),
        ("ml.inf1.xlarge", True),
        ("ml.trn1.2xlarge", True),
        ("ml.t3.medium", False),
        ("ml.m5.xlarge", False),
        ("ml.c5.xlarge", False),
    ],
)
def test_gpu_family_classification(instance_type, expected_gpu):
    sm = MagicMock()
    # age_days=14, idle_since_days=14 → idle_ratio=1.0 → GPU=HIGH (not CRITICAL), CPU=MEDIUM
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type=instance_type, age_days=14, idle_since_days=14)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["is_gpu"] is expected_gpu
    if expected_gpu:
        assert findings[0].risk.value == "high"
    else:
        assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# Cost lookup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "instance_type,expected_cost",
    [
        ("ml.t3.medium", 42.0),
        ("ml.m5.xlarge", 188.0),
        ("ml.g4dn.xlarge", 531.0),
        ("ml.p3.2xlarge", 2754.0),
        ("ml.p3.8xlarge", 11016.0),
        ("ml.p4d.24xlarge", 23596.0),
    ],
)
def test_cost_lookup_by_instance_type(instance_type, expected_cost):
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(instance_type=instance_type, age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].estimated_monthly_cost_usd == expected_cost


def test_unknown_instance_type_uses_default_cost():
    """Unknown instance type should fall back to default cost, not raise."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(
        [_make_nb(instance_type="ml.futuristic.99xlarge", age_days=30)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 150.0  # _DEFAULT_MONTHLY_COST


def test_missing_instance_type_uses_default_cost():
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    del nb["InstanceType"]
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == 150.0
    assert findings[0].details["is_gpu"] is False


# ---------------------------------------------------------------------------
# Timezone handling
# ---------------------------------------------------------------------------


def test_timezone_naive_create_time_handled():
    """boto3 may return timezone-naive CreationTime; should still age correctly."""
    sm = MagicMock()
    now = datetime.now()  # naive
    nb = _make_nb(age_days=30)
    nb["CreationTime"] = now - timedelta(days=30)
    nb["LastModifiedTime"] = now - timedelta(days=30)
    assert nb["CreationTime"].tzinfo is None
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["age_days"] >= 29


def test_timezone_naive_last_modified_handled():
    """Timezone-naive LastModifiedTime should be normalised correctly."""
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    nb["LastModifiedTime"] = datetime.now() - timedelta(days=20)
    assert nb["LastModifiedTime"].tzinfo is None
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] >= 19


# ---------------------------------------------------------------------------
# Multiple notebooks
# ---------------------------------------------------------------------------


def test_multiple_notebooks_mixed_activity():
    """Only idle notebooks should be flagged; active ones should pass."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(
        [
            _make_nb("idle-gpu", "ml.p3.2xlarge", age_days=30, idle_since_days=30),
            _make_nb("active-nb", "ml.t3.medium", age_days=30, idle_since_days=2),
            _make_nb("idle-cpu", "ml.m5.xlarge", age_days=14, idle_since_days=14),
        ]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 2
    flagged_names = {f.resource_id for f in findings}
    assert "idle-gpu" in flagged_names
    assert "idle-cpu" in flagged_names
    assert "active-nb" not in flagged_names


def test_multiple_pages_aggregated():
    """Results from multiple paginator pages should all be returned."""
    sm = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"NotebookInstances": [_make_nb("nb-page1", age_days=30)]},
        {"NotebookInstances": [_make_nb("nb-page2", age_days=30)]},
    ]
    sm.get_paginator.return_value = paginator

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_permission_error_raised_on_access_denied():
    """AccessDenied on ListNotebookInstances should raise PermissionError."""
    sm = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
        "ListNotebookInstances",
    )
    sm.get_paginator.return_value = paginator

    with pytest.raises(PermissionError) as exc_info:
        find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert "sagemaker:ListNotebookInstances" in str(exc_info.value)


def test_access_denied_exception_raises_permission_error():
    """AccessDeniedException (alternative error code) should also raise PermissionError."""
    sm = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Forbidden"}},
        "ListNotebookInstances",
    )
    sm.get_paginator.return_value = paginator

    with pytest.raises(PermissionError):
        find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")


def test_unexpected_client_error_propagates():
    """Non-permission ClientError (e.g. service error) should propagate, not swallow."""
    sm = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "InternalFailure", "Message": "Service error"}},
        "ListNotebookInstances",
    )
    sm.get_paginator.return_value = paginator

    with pytest.raises(ClientError):
        find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")


# ---------------------------------------------------------------------------
# Finding structure
# ---------------------------------------------------------------------------


def test_finding_fields_complete():
    """All required Finding fields should be populated correctly."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate(
        [_make_nb("my-notebook", "ml.g4dn.xlarge", age_days=30)]
    )

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.provider == "aws"
    assert f.rule_id == "aws.sagemaker.notebook.idle"
    assert f.resource_type == "aws.sagemaker.notebook"
    assert f.resource_id == "my-notebook"
    assert f.region == "us-east-1"
    assert f.detected_at is not None
    assert f.evidence is not None
    assert f.details["notebook_name"] == "my-notebook"
    assert f.details["idle_days_threshold"] == 14
    assert "~$" in f.details["estimated_monthly_cost"]


def test_summary_contains_notebook_name():
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb("fraud-model-dev", age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert "fraud-model-dev" in findings[0].summary


# ---------------------------------------------------------------------------
# Lifecycle config — confidence capping
# ---------------------------------------------------------------------------


def test_lifecycle_config_caps_high_confidence_to_medium():
    """Notebook with a lifecycle config attached should be capped at MEDIUM confidence.

    A lifecycle config signals the notebook is actively managed (auto-stop, env setup).
    This reduces certainty that it is truly abandoned, so HIGH → MEDIUM.
    """
    sm = MagicMock()
    nb = _make_nb(age_days=30, idle_since_days=30)
    nb["NotebookInstanceLifecycleConfigName"] = "auto-stop-idle-60min"
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"
    assert "auto-stop-idle-60min" in str(findings[0].evidence.signals_used)


def test_no_lifecycle_config_preserves_high_confidence():
    """Notebook without a lifecycle config should remain HIGH confidence when threshold met."""
    sm = MagicMock()
    nb = _make_nb(age_days=30, idle_since_days=30)
    nb["NotebookInstanceLifecycleConfigName"] = ""  # empty string → no config
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_lifecycle_config_does_not_promote_medium_to_high():
    """Lifecycle config caps HIGH→MEDIUM but doesn't affect already-MEDIUM findings."""
    sm = MagicMock()
    # age=11, idle=11 → MEDIUM (below threshold_high=14, above threshold_medium=10)
    nb = _make_nb(age_days=11, idle_since_days=11)
    nb["NotebookInstanceLifecycleConfigName"] = "some-config"
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# idle_ratio
# ---------------------------------------------------------------------------


def test_idle_ratio_at_threshold():
    """idle_ratio should be 1.0 when idle_since_days == idle_days."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=14, idle_since_days=14)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].details["idle_ratio"] == 1.0


def test_idle_ratio_above_threshold():
    """idle_ratio > 1.0 when notebook is more stale than the threshold."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=28, idle_since_days=28)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].details["idle_ratio"] == 2.0


# ---------------------------------------------------------------------------
# Details completeness
# ---------------------------------------------------------------------------


def test_details_include_cost_source():
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].details["cost_source"] == "approximate_us-east-1"


def test_details_lifecycle_config_none_when_absent():
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    nb.pop("NotebookInstanceLifecycleConfigName", None)
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].details["lifecycle_config"] is None


def test_details_lifecycle_config_set_when_present():
    sm = MagicMock()
    nb = _make_nb(age_days=30)
    nb["NotebookInstanceLifecycleConfigName"] = "my-lifecycle"
    sm.get_paginator.return_value = _paginate([nb])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert findings[0].details["lifecycle_config"] == "my-lifecycle"


def test_summary_uses_control_plane_wording():
    """Summary should say 'control-plane activity', not 'recorded activity'."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    assert "control-plane" in findings[0].summary
    assert "recorded activity" not in findings[0].summary


def test_title_is_concise():
    """Title should use short form for clean CLI output."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=30)])

    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1")

    title = findings[0].title
    assert title.startswith("Idle SageMaker Notebook (")
    assert "Instance" not in title  # shortened form


def test_idle_days_zero_is_clamped_to_one():
    """idle_days=0 must be clamped to 1 to prevent division-by-zero and bogus confidence."""
    sm = MagicMock()
    sm.get_paginator.return_value = _paginate([_make_nb(age_days=30, idle_since_days=30)])

    # Should not raise, and should not flag every notebook regardless of age
    findings = find_idle_sagemaker_notebooks(_make_session(sm), "us-east-1", idle_days=0)

    # idle_days clamped to 1 → age_guard: age < max(0, 7)=7 → 30 >= 7 → passes
    # threshold_high=1 → 30 >= 1 → HIGH confidence, finding returned
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1  # clamped value stored


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    assert RULE_METADATA["id"] == "aws.sagemaker.notebook.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "sagemaker"
    assert RULE_METADATA["cost_impact"] == "high"
