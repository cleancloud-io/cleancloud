from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.aml_compute_instance_idle import (
    RULE_METADATA,
    find_idle_aml_compute_instances,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_workspace(name="test-workspace", location="eastus", rg="rg-ml"):
    ws_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{name}"
    )
    return SimpleNamespace(id=ws_id, name=name, location=location)


def _make_instance(
    name="dev-instance",
    vm_size="Standard_DS3_v2",
    state="Running",
    age_days=30,
    idle_since_days=None,
    op_name="Start",
    workspace="test-workspace",
    rg="rg-ml",
    system_data_modified_days=None,
):
    """Build a mock ComputeResource for a ComputeInstance.

    idle_since_days controls last_operation.operation_time (defaults to age_days).
    system_data_modified_days, if set, overrides system_data.last_modified_at.
    """
    compute_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{workspace}/computes/{name}"
    )
    now = datetime.now(timezone.utc)

    if idle_since_days is None:
        idle_since_days = age_days

    op_time = now - timedelta(days=idle_since_days) if idle_since_days is not None else None
    last_op = SimpleNamespace(operation_time=op_time, operation_name=op_name)

    ci_props = SimpleNamespace(
        vm_size=vm_size,
        state=state,
        last_operation=last_op,
    )
    compute_obj = SimpleNamespace(
        compute_type="ComputeInstance",
        properties=ci_props,
        created_on=(now - timedelta(days=age_days)) if age_days is not None else None,
    )

    # system_data fallback
    if system_data_modified_days is not None:
        system_data = SimpleNamespace(
            last_modified_at=now - timedelta(days=system_data_modified_days)
        )
    else:
        system_data = None

    return SimpleNamespace(
        id=compute_id,
        name=name,
        properties=compute_obj,
        system_data=system_data,
    )


def _make_client(workspace, instances):
    return SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=lambda rg, ws_name: instances),
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_cpu_instance_detected():
    """Running CPU instance with no recent activity should be flagged as MEDIUM risk."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_DS3_v2", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "azure.ml.compute_instance.idle"
    assert f.resource_type == "azure.ml.compute_instance"
    assert f.provider == "azure"
    assert f.risk.value == "medium"
    assert f.confidence.value == "high"
    assert f.details["is_gpu"] is False
    assert f.details["vm_size"] == "Standard_DS3_v2"
    assert f.details["state"] == "Running"
    assert f.estimated_monthly_cost_usd == 260.0


def test_idle_gpu_instance_detected_high_risk():
    """GPU instance at exactly idle_days threshold (idle_ratio=1.0) -> HIGH risk."""
    ws = _make_workspace()
    # age_days=14, idle_since_days=14 -> idle_ratio=1.0 -> HIGH (not CRITICAL)
    instance = _make_instance(vm_size="Standard_NC6s_v3", age_days=14, idle_since_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.details["is_gpu"] is True
    assert f.estimated_monthly_cost_usd == 2203.0


def test_idle_gpu_instance_critical_when_very_stale():
    """GPU instance idle ≥ 2× threshold -> CRITICAL risk."""
    ws = _make_workspace()
    # age_days=30, idle_since_days=30, idle_days=14 -> idle_ratio≈2.14 -> CRITICAL
    instance = _make_instance(vm_size="Standard_NC12s_v3", age_days=30, idle_since_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert len(findings) == 1
    assert findings[0].risk.value == "critical"
    assert findings[0].details["idle_ratio"] >= 2.0


def test_critical_boundary_exactly_at_2x():
    """idle_ratio == 2.0 exactly -> CRITICAL."""
    ws = _make_workspace()
    # idle_days=14, idle_since_days=28 -> idle_ratio=2.0
    instance = _make_instance(vm_size="Standard_NC6s_v3", age_days=28, idle_since_days=28)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert findings[0].risk.value == "critical"
    assert findings[0].details["idle_ratio"] == 2.0


def test_just_below_critical_is_high():
    """GPU instance with idle_ratio < 2.0 -> HIGH, not CRITICAL."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_NC6s_v3", age_days=14, idle_since_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert findings[0].risk.value == "high"
    assert findings[0].details["idle_ratio"] == 1.0


def test_cpu_instance_never_reaches_critical():
    """CPU instances are capped at MEDIUM regardless of idle_ratio."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_D8s_v3", age_days=60, idle_since_days=60)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert findings[0].risk.value == "medium"


def test_no_instances_returns_empty():
    ws = _make_workspace()
    ml_client = _make_client(ws, [])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# State filtering — only Running incurs charges
# ---------------------------------------------------------------------------


def test_stopped_instance_skipped():
    """Stopped instances do not incur charges — must not be flagged."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_DS3_v2", state="Stopped", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 0


@pytest.mark.parametrize("state", ["Creating", "Deleting", "Starting", "Stopping", "Unknown"])
def test_non_running_states_skipped(state):
    """Only Running state should be flagged."""
    ws = _make_workspace()
    instance = _make_instance(state=state, age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 0


def test_non_compute_instance_type_skipped():
    """AmlCompute clusters must not be picked up by this rule."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30)
    instance.properties.compute_type = "AmlCompute"
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# Age guard
# ---------------------------------------------------------------------------


def test_young_instance_skipped():
    """Instance younger than minimum age guard -> skipped."""
    ws = _make_workspace()
    instance = _make_instance(age_days=3)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_instance_at_boundary_age_skipped():
    """Instance at exactly 6 days (below max(idle_days//2=7, 7)) -> skipped."""
    ws = _make_workspace()
    instance = _make_instance(age_days=6)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_at_full_threshold():
    """idle_since >= idle_days AND age >= idle_days -> HIGH confidence."""
    ws = _make_workspace()
    instance = _make_instance(age_days=14, idle_since_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].confidence.value == "high"


def test_medium_confidence_at_75_percent():
    """idle_since and age at 75% of threshold -> MEDIUM confidence."""
    ws = _make_workspace()
    # idle_days=14, threshold_medium=10, age=11, idle=11 -> MEDIUM
    instance = _make_instance(age_days=11, idle_since_days=11)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].confidence.value == "medium"


def test_below_medium_threshold_skipped():
    """Below 75% threshold -> skipped."""
    ws = _make_workspace()
    # age=8, idle=8 -> 8 < 10 -> skip
    instance = _make_instance(age_days=8, idle_since_days=8)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_recently_active_instance_skipped():
    """Instance active 3 days ago should not be flagged even if old."""
    ws = _make_workspace()
    instance = _make_instance(age_days=60, idle_since_days=3)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_custom_idle_days_respected():
    """Custom idle_days=7 — instance idle 7 days should be HIGH confidence."""
    ws = _make_workspace()
    instance = _make_instance(age_days=7, idle_since_days=7)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client, idle_days=7
    )

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# Idle signal fallbacks
# ---------------------------------------------------------------------------


def test_idle_signal_source_last_operation():
    """idle_signal_source should be 'last_operation' when last_operation.operation_time is present."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].details["idle_signal_source"] == "last_operation"


def test_idle_signal_source_last_modified_at():
    """idle_signal_source should be 'last_modified_at' when falling back to system_data."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=None)
    instance.properties.properties.last_operation = None
    instance.system_data = SimpleNamespace(
        last_modified_at=datetime.now(timezone.utc) - timedelta(days=20)
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].details["idle_signal_source"] == "last_modified_at"


def test_idle_signal_source_age_fallback():
    """idle_signal_source 'age_fallback' caps confidence at MEDIUM — age alone is not an idle signal."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=None)
    instance.properties.properties.last_operation = None
    instance.system_data = None
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].details["idle_signal_source"] == "age_fallback"
    assert findings[0].confidence.value == "medium"


def test_fallback_to_system_data_when_no_last_operation():
    """When last_operation is absent, system_data.last_modified_at should be used."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=None)
    # Remove last_operation
    instance.properties.properties.last_operation = None
    # Supply system_data with 20-day-old modification time
    instance.system_data = SimpleNamespace(
        last_modified_at=datetime.now(timezone.utc) - timedelta(days=20)
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] >= 19


def test_fallback_to_age_when_no_operation_or_system_data():
    """When both last_operation and system_data are absent, age is used as proxy."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=None)
    instance.properties.properties.last_operation = None
    instance.system_data = None
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] == 30


def test_missing_creation_time_uses_neutral_default():
    """Missing created_on should not silently skip the instance."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=20)
    instance.properties.created_on = None  # no creation time
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1


def test_timezone_naive_op_time_handled():
    """Timezone-naive last_operation.operation_time should be normalised."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30)
    instance.properties.properties.last_operation.operation_time = datetime.now() - timedelta(
        days=20
    )  # naive
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_since_days"] >= 19


# ---------------------------------------------------------------------------
# GPU family detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vm_size,expected_gpu",
    [
        ("Standard_NC6s_v3", True),
        ("Standard_NC12s_v3", True),
        ("Standard_ND6s", True),
        ("Standard_ND40rs_v2", True),
        ("Standard_NV6", True),
        ("Standard_DS3_v2", False),
        ("Standard_D4s_v3", False),
        ("Standard_DS11_v2", False),
    ],
)
def test_gpu_family_classification(vm_size, expected_gpu):
    ws = _make_workspace()
    # age_days=14 -> idle_ratio=1.0 -> GPU=HIGH, CPU=MEDIUM
    instance = _make_instance(vm_size=vm_size, age_days=14, idle_since_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

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
    "vm_size,expected_cost",
    [
        ("Standard_DS3_v2", 260.0),
        ("Standard_D4s_v3", 192.0),
        ("Standard_NC6s_v3", 2203.0),
        ("Standard_NC24s_v3", 8812.0),
        ("Standard_ND40rs_v2", 15862.0),
        ("Standard_NV12", 2189.0),
    ],
)
def test_cost_lookup_by_vm_size(vm_size, expected_cost):
    ws = _make_workspace()
    instance = _make_instance(vm_size=vm_size, age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].estimated_monthly_cost_usd == expected_cost


def test_unknown_vm_size_uses_default_cost():
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_FUTURE_99xlarge", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].estimated_monthly_cost_usd == 200.0


def test_vm_size_case_insensitive_lookup():
    """Azure ML may return VM sizes in uppercase or mixed case — cost lookup must handle it."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="STANDARD_NC6S_V3", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].estimated_monthly_cost_usd == 2203.0


# ---------------------------------------------------------------------------
# Region filtering
# ---------------------------------------------------------------------------


def test_region_filter_matches():
    ws = _make_workspace(location="westeurope")
    instance = _make_instance(age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        region_filter="westeurope",
    )

    assert len(findings) == 1


def test_region_filter_excludes():
    ws = _make_workspace(location="westeurope")
    instance = _make_instance(age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        region_filter="eastus",
    )

    assert len(findings) == 0


def test_region_filter_normalises_case_and_spaces():
    """Region filter comparison should be case/space/hyphen insensitive."""
    ws = _make_workspace(location="East US")
    instance = _make_instance(age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        region_filter="eastus",
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Finding structure
# ---------------------------------------------------------------------------


def test_finding_fields_complete():
    ws = _make_workspace(name="ml-prod", rg="rg-prod")
    instance = _make_instance(name="gpu-dev", vm_size="Standard_NC6s_v3", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    f = findings[0]
    assert f.provider == "azure"
    assert f.region == "eastus"
    assert f.detected_at is not None
    assert f.evidence is not None
    assert f.details["instance_name"] == "gpu-dev"
    assert f.details["workspace_name"] == "ml-prod"
    assert f.details["resource_group"] == "rg-prod"
    assert f.details["idle_days_threshold"] == 14
    assert "~$" in f.details["estimated_monthly_cost"]
    assert f.details["cost_source"] == "approximate_eastus"


def test_summary_contains_instance_and_workspace():
    ws = _make_workspace(name="research-ws")
    instance = _make_instance(name="cv-model-dev", age_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert "cv-model-dev" in findings[0].summary
    assert "research-ws" in findings[0].summary
    assert "control-plane" in findings[0].summary


def test_title_format():
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].title == "Idle Azure ML Compute Instance (No Activity for 30 Days)"


def test_idle_days_zero_clamped_to_one():
    """idle_days=0 must be clamped to 1 to prevent division-by-zero."""
    ws = _make_workspace()
    instance = _make_instance(age_days=30, idle_since_days=30)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client, idle_days=0
    )

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1


# ---------------------------------------------------------------------------
# Multiple instances
# ---------------------------------------------------------------------------


def test_multiple_instances_mixed():
    """Only idle Running instances should be flagged."""
    ws = _make_workspace()
    instances = [
        _make_instance("idle-gpu", "Standard_NC6s_v3", age_days=30, idle_since_days=30),
        _make_instance("active-cpu", "Standard_DS3_v2", age_days=30, idle_since_days=2),
        _make_instance("stopped-gpu", "Standard_NC12s_v3", state="Stopped", age_days=30),
        _make_instance("idle-cpu", "Standard_D4s_v3", age_days=14, idle_since_days=14),
    ]
    ml_client = _make_client(ws, instances)

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 2
    names = {f.details["instance_name"] for f in findings}
    assert "idle-gpu" in names
    assert "idle-cpu" in names
    assert "active-cpu" not in names
    assert "stopped-gpu" not in names


# ---------------------------------------------------------------------------
# Permission error handling
# ---------------------------------------------------------------------------


def test_permission_error_on_authorization_failure():
    """AuthorizationFailed in workspaces.list should raise PermissionError."""

    class _ForbiddenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise Exception("AuthorizationFailed: insufficient permissions")

        compute = None

    with pytest.raises(PermissionError) as exc_info:
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_ForbiddenClient()
        )

    assert "Microsoft.MachineLearningServices/workspaces/read" in str(exc_info.value)


def test_403_error_raises_permission_error():
    class _ForbiddenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise Exception("Forbidden (403) — access denied")

        compute = None

    with pytest.raises(PermissionError):
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_ForbiddenClient()
        )


def test_unexpected_error_propagates():
    """Non-permission errors should propagate, not be swallowed."""

    class _BrokenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise RuntimeError("Unexpected SDK error")

        compute = None

    with pytest.raises(RuntimeError):
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_BrokenClient()
        )


def test_compute_list_auth_error_raises_permission_error():
    """AuthorizationFailed on compute.list() must surface as PermissionError, not be swallowed."""
    ws = _make_workspace()

    def _compute_list(rg, ws_name):
        raise Exception("AuthorizationFailed: missing computes/read permission")

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=_compute_list),
    )

    with pytest.raises(PermissionError) as exc_info:
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )

    assert "Microsoft.MachineLearningServices/workspaces/computes/read" in str(exc_info.value)


def test_compute_list_error_skips_workspace_preserves_findings():
    """Transient error in compute.list() for one workspace must not abort findings from others."""
    ws_good = _make_workspace(name="good-ws", location="eastus", rg="rg-good")
    ws_bad = _make_workspace(name="bad-ws", location="eastus", rg="rg-bad")
    good_instance = _make_instance(age_days=30, workspace="good-ws", rg="rg-good")

    call_count = 0

    def _compute_list(rg, ws_name):
        nonlocal call_count
        call_count += 1
        if ws_name == "bad-ws":
            raise RuntimeError("transient SDK timeout")
        return [good_instance]

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws_good, ws_bad]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=_compute_list),
    )

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    # The good workspace finding is preserved; bad workspace is skipped
    assert len(findings) == 1
    assert findings[0].details["workspace_name"] == "good-ws"
    assert call_count == 2  # both workspaces were attempted


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    assert RULE_METADATA["id"] == "azure.ml.compute_instance.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "machinelearning"
    assert RULE_METADATA["cost_impact"] == "high"
