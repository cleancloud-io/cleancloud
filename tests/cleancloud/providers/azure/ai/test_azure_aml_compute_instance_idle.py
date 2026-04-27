"""Tests for azure.ml.compute_instance.idle rule (hardened per spec)."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.ai.aml_compute_instance_idle import (
    RULE_METADATA,
    _extract_resource_group,
    _extract_subscription_id,
    _is_gpu,
    _norm_location,
    _parse_utc_timestamp,
    _resolve_compute_type,
    _resolve_created_at,
    _resolve_location,
    _resolve_modified_at,
    _resolve_provisioning_state,
    _resolve_state,
    _resolve_str_field,
    find_idle_aml_compute_instances,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_workspace(name="test-workspace", rg="rg-ml"):
    ws_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{name}"
    )
    return SimpleNamespace(id=ws_id, name=name)


def _make_instance(
    name="dev-instance",
    vm_size="Standard_DS3_v2",
    state="Running",
    compute_type="ComputeInstance",
    provisioning_state="Succeeded",
    location="eastus",
    age_days=31,
    last_op_time_days=20,  # days ago for lastOperation.operationTime; None = absent
    last_op_name="Start",
    last_op_status="Succeeded",
    modified_days=None,  # days ago for modifiedOn on compute.properties; None = absent
    workspace="test-workspace",
    rg="rg-ml",
    tags=None,
):
    """Build a mock ComputeResource for a ComputeInstance.

    last_op_time_days: days ago for lastOperation.operationTime (None = field absent).
    modified_days:     days ago for compute.properties.modified_on (None = field absent).

    IMPORTANT: last_op_time_days must be strictly less than age_days so that
    op_time > created_on.  When they are equal, spec 9.4.7 skips the instance
    (operationTime == created_at → no proven post-create signal).  The defaults
    (age_days=31, last_op_time_days=20) satisfy this invariant.
    """
    compute_id = (
        f"/subscriptions/sub-123/resourceGroups/{rg}"
        f"/providers/Microsoft.MachineLearningServices/workspaces/{workspace}/computes/{name}"
    )
    now = datetime.now(timezone.utc)

    # Build lastOperation
    if last_op_time_days is not None:
        op_time = now - timedelta(days=last_op_time_days)
        last_op = SimpleNamespace(
            operation_time=op_time,
            operation_name=last_op_name,
            operation_status=last_op_status,
        )
    else:
        last_op = None

    # ComputeInstanceProperties (inner)
    ci_props = SimpleNamespace(
        vm_size=vm_size,
        state=state,
        last_operation=last_op,
    )

    # Compute.properties (outer) — created_on and modifiedOn live here
    created_on = (now - timedelta(days=age_days)) if age_days is not None else None
    modified_on = (now - timedelta(days=modified_days)) if modified_days is not None else None

    compute_obj = SimpleNamespace(
        compute_type=compute_type,
        provisioning_state=provisioning_state,
        created_on=created_on,
        modified_on=modified_on,
        properties=ci_props,
    )

    return SimpleNamespace(
        id=compute_id,
        name=name,
        location=location,
        tags=tags or {},
        properties=compute_obj,
    )


def _make_client(workspace, instances):
    return SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=lambda rg, ws: instances),
    )


# ---------------------------------------------------------------------------
# Unit tests for normalization helpers
# ---------------------------------------------------------------------------


def test_norm_location_lowercase_preserves_spaces_and_hyphens():
    """spec 7: lowercase only — spaces and hyphens are preserved."""
    assert _norm_location("East US") == "east us"
    assert _norm_location("west-europe") == "west-europe"
    assert _norm_location("EastUS") == "eastus"
    assert _norm_location("") == ""


def test_resolve_str_field_sdk_wins():
    obj = SimpleNamespace(compute_type="ComputeInstance", computeType=None)
    assert _resolve_str_field(obj, "compute_type", "computeType") == "ComputeInstance"


def test_resolve_str_field_raw_fallback():
    obj = SimpleNamespace(compute_type=None, computeType="ComputeInstance")
    assert _resolve_str_field(obj, "compute_type", "computeType") == "ComputeInstance"


def test_resolve_str_field_conflict_returns_none():
    obj = SimpleNamespace(compute_type="ComputeInstance", computeType="AmlCompute")
    assert _resolve_str_field(obj, "compute_type", "computeType") is None


def test_resolve_str_field_both_absent_returns_none():
    obj = SimpleNamespace(compute_type=None, computeType=None)
    assert _resolve_str_field(obj, "compute_type", "computeType") is None


def test_extract_resource_group_happy_path():
    rid = "/subscriptions/sub/resourceGroups/my-rg/providers/foo/bar"
    assert _extract_resource_group(rid) == "my-rg"


def test_extract_resource_group_none():
    assert _extract_resource_group(None) is None
    assert _extract_resource_group("") is None


def test_extract_subscription_id_happy_path():
    rid = "/subscriptions/abc-123/resourceGroups/rg/providers/foo"
    assert _extract_subscription_id(rid) == "abc-123"


def test_parse_utc_timestamp_datetime_with_tz():
    dt = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert _parse_utc_timestamp(dt) == dt


def test_parse_utc_timestamp_naive_datetime_becomes_utc():
    dt = datetime(2024, 1, 1, 12, 0)
    result = _parse_utc_timestamp(dt)
    assert result.tzinfo is not None


def test_parse_utc_timestamp_aware_non_utc_converted_to_utc():
    """spec 9.4: aware non-UTC datetimes must be converted to UTC, not returned unchanged."""
    eastern = timezone(timedelta(hours=-5))
    aware_eastern = datetime(2024, 6, 1, 12, 0, 0, tzinfo=eastern)
    result = _parse_utc_timestamp(aware_eastern)
    assert result.tzinfo == timezone.utc
    assert result.hour == 17  # 12:00 -05:00 -> 17:00 UTC


def test_parse_utc_timestamp_utc_unchanged():
    """UTC-aware datetimes stay UTC."""
    dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = _parse_utc_timestamp(dt)
    assert result == dt
    assert result.tzinfo == timezone.utc


def test_parse_utc_timestamp_invalid_string_returns_none():
    assert _parse_utc_timestamp("not-a-date") is None


def test_parse_utc_timestamp_none_returns_none():
    assert _parse_utc_timestamp(None) is None


def test_is_gpu_exact_case_sensitive_prefixes():
    """spec 7: exact case-sensitive prefix matching."""
    assert _is_gpu("Standard_NC6s_v3") is True
    assert _is_gpu("Standard_ND6s") is True
    assert _is_gpu("Standard_NV6") is True
    # Case sensitivity: lowercase prefix is NOT GPU
    assert _is_gpu("standard_nc6s_v3") is False
    assert _is_gpu("STANDARD_NC6s_v3") is False
    # Non-GPU families
    assert _is_gpu("Standard_DS3_v2") is False
    assert _is_gpu("Standard_D4s_v3") is False
    assert _is_gpu(None) is False
    assert _is_gpu("") is False


def test_resolve_location_top_level_wins():
    compute = SimpleNamespace(
        location="eastus",
        properties=SimpleNamespace(compute_location=None, computeLocation=None),
    )
    assert _resolve_location(compute) == "eastus"


def test_resolve_location_normalised_to_lowercase():
    compute = SimpleNamespace(location="East US", properties=None)
    assert _resolve_location(compute) == "east us"


def test_resolve_location_conflict_returns_none():
    compute = SimpleNamespace(
        location="eastus",
        properties=SimpleNamespace(compute_location="westus", computeLocation=None),
    )
    assert _resolve_location(compute) is None


def test_resolve_location_all_absent_returns_none():
    compute = SimpleNamespace(location=None, properties=None)
    assert _resolve_location(compute) is None


def test_resolve_compute_type_from_sdk():
    compute = _make_instance()
    assert _resolve_compute_type(compute) == "ComputeInstance"


def test_resolve_provisioning_state_from_sdk():
    compute = _make_instance()
    assert _resolve_provisioning_state(compute) == "Succeeded"


def test_resolve_state_from_sdk():
    compute = _make_instance()
    assert _resolve_state(compute) == "Running"


def test_resolve_state_strips_surrounding_whitespace():
    """spec 7: state is normalized by surrounding-whitespace trimming."""
    compute = _make_instance()
    compute.properties.properties.state = "  Running  "
    assert _resolve_state(compute) == "Running"


def test_padded_running_state_emits():
    """spec 7: whitespace-padded 'Running' normalizes to 'Running' -> emits."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.properties.state = "  Running  "
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["state"] == "Running"


def test_resolve_created_at_returns_utc():
    compute = _make_instance(age_days=31)
    ts = _resolve_created_at(compute)
    assert ts is not None
    assert ts.tzinfo is not None


def test_resolve_modified_at_present():
    compute = _make_instance(modified_days=20)
    ts = _resolve_modified_at(compute)
    assert ts is not None
    assert ts.tzinfo is not None


def test_resolve_modified_at_absent():
    compute = _make_instance(modified_days=None)
    assert _resolve_modified_at(compute) is None


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_cpu_instance_detected():
    """Running CPU instance with stale last_operation -> MEDIUM risk, MEDIUM confidence."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_DS3_v2", age_days=31, last_op_time_days=20)
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
    assert f.confidence.value == "medium"
    assert f.estimated_monthly_cost_usd is None  # spec 10: always None
    assert f.details["vm_size"] == "Standard_DS3_v2"
    assert f.details["state"] == "Running"
    assert f.details["idle_signal_source"] == "last_operation"


def test_idle_gpu_instance_high_risk():
    """GPU instance -> HIGH risk, MEDIUM confidence (last_operation signal)."""
    ws = _make_workspace()
    # age_days=15, last_op_time_days=14: op_time is 1 day after created_on
    instance = _make_instance(vm_size="Standard_NC6s_v3", age_days=15, last_op_time_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.confidence.value == "medium"
    assert f.estimated_monthly_cost_usd is None


def test_gpu_risk_never_exceeds_high():
    """spec 9.5: no CRITICAL level — GPU is always HIGH regardless of idle duration."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_NC12s_v3", age_days=61, last_op_time_days=60)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
    )

    assert len(findings) == 1
    assert findings[0].risk.value == "high"


def test_cpu_instance_always_medium_risk():
    """CPU instances are always MEDIUM risk."""
    ws = _make_workspace()
    instance = _make_instance(vm_size="Standard_D8s_v3", age_days=61, last_op_time_days=60)
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
# spec 10: estimated_monthly_cost_usd is always None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vm_size",
    [
        "Standard_DS3_v2",
        "Standard_NC6s_v3",
        "Standard_ND40rs_v2",
        "Standard_NV12",
        "Standard_FUTURE_99xlarge",
    ],
)
def test_estimated_monthly_cost_is_always_none(vm_size):
    """spec 10: cost must always be None — no hardcoded price tables."""
    ws = _make_workspace()
    instance = _make_instance(vm_size=vm_size, age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# State and type filtering (spec 8.5, 8.6, 8.7)
# ---------------------------------------------------------------------------


def test_stopped_instance_skipped():
    """Stopped instances are out of scope for this rule."""
    ws = _make_workspace()
    instance = _make_instance(state="Stopped", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


@pytest.mark.parametrize("state", ["Creating", "Deleting", "Starting", "Stopping", "Unknown"])
def test_non_running_states_skipped(state):
    ws = _make_workspace()
    instance = _make_instance(state=state, age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_non_compute_instance_type_skipped():
    """AmlCompute clusters must not be picked up by this rule."""
    ws = _make_workspace()
    instance = _make_instance(compute_type="AmlCompute", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


@pytest.mark.parametrize("pstate", ["Failed", "Creating", "Deleting", "Canceled", "Unknown"])
def test_non_succeeded_provisioning_state_skipped(pstate):
    """spec 8.6: provisioning_state must be exactly 'Succeeded'."""
    ws = _make_workspace()
    instance = _make_instance(provisioning_state=pstate, age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_conflicting_compute_type_skipped():
    """spec 9.1: conflicting SDK+raw compute_type -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.compute_type = "ComputeInstance"
    instance.properties.computeType = "AmlCompute"
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# Location contract (spec 8.4, 8.8, 9.2)
# ---------------------------------------------------------------------------


def test_unresolvable_location_skipped():
    """spec 8.8: unresolvable location -> skip."""
    ws = _make_workspace()
    instance = _make_instance(location=None, age_days=31, last_op_time_days=20)
    instance.location = None
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_region_filter_exact_lowercase_match():
    """spec 8.4: exact lowercase equality for region filter."""
    ws = _make_workspace()
    instance = _make_instance(location="eastus", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        region_filter="eastus",
    )

    assert len(findings) == 1


def test_region_filter_excludes():
    ws = _make_workspace()
    instance = _make_instance(location="westeurope", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123",
            credential=None,
            client=ml_client,
            region_filter="eastus",
        )
        == []
    )


def test_region_filter_normalises_to_lowercase():
    """spec 7: filter is lowercased; compute location is lowercased too."""
    ws = _make_workspace()
    instance = _make_instance(location="East US", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123",
        credential=None,
        client=ml_client,
        region_filter="East US",
    )

    assert len(findings) == 1
    assert findings[0].region == "east us"


def test_compute_location_used_not_workspace_location():
    """spec 9.2: region comes from compute resource, not workspace."""
    ws = _make_workspace()
    # compute location = westeurope, filter for eastus -> exclude
    instance = _make_instance(location="westeurope", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123",
            credential=None,
            client=ml_client,
            region_filter="eastus",
        )
        == []
    )


# ---------------------------------------------------------------------------
# Age contract (spec 8.9, 9.3)
# ---------------------------------------------------------------------------


def test_instance_younger_than_idle_days_skipped():
    """spec 9.3.3: age < idle_days -> skip."""
    ws = _make_workspace()
    # age=13, threshold=14 -> skip
    instance = _make_instance(age_days=14, last_op_time_days=13)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client, idle_days=14
        )
        == []
    )


def test_instance_exactly_idle_days_age_eligible():
    """spec 9.3.3: age == idle_days -> eligible (boundary case)."""
    ws = _make_workspace()
    # age=15, threshold=14: age gate passes; last_op 14 days ago -> idle_since_days=14
    instance = _make_instance(age_days=15, last_op_time_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client, idle_days=14
    )

    assert len(findings) == 1


def test_missing_created_at_skips():
    """spec 8.9: absent created_at -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.created_on = None
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_future_created_at_skips():
    """spec 9.3.2: future created_at -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.created_on = datetime.now(timezone.utc) + timedelta(days=1)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# Lifecycle-activity contract (spec 9.4)
# ---------------------------------------------------------------------------


def test_last_op_time_camelcase_operationtime_used():
    """Gap 1: camelCase operationTime is resolved when snake_case operation_time is absent."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    op_time = instance.properties.properties.last_operation.operation_time
    instance.properties.properties.last_operation.operation_time = None
    instance.properties.properties.last_operation.operationTime = op_time
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "last_operation"


def test_last_op_name_camelcase_operationname_used():
    """Gap 1: camelCase operationName is resolved when snake_case operation_name is absent."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20, last_op_name=None)
    instance.properties.properties.last_operation.operation_name = None
    instance.properties.properties.last_operation.operationName = "Restart"
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["last_operation_name"] == "Restart"


def test_last_op_status_camelcase_operationstatus_used():
    """Gap 1: camelCase operationStatus is resolved when snake_case operation_status is absent."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20, last_op_status=None)
    instance.properties.properties.last_operation.operation_status = None
    instance.properties.properties.last_operation.operationStatus = "Succeeded"
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["last_operation_status"] == "Succeeded"


def test_last_op_time_present_and_stale_emits():
    """spec 9.4.3: lastOperation.operationTime present and stale -> emit."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "last_operation"
    assert findings[0].details["idle_since_days"] >= 19


def test_last_op_time_present_but_unparsable_skips():
    """spec 9.4.4: lastOperation.operationTime present but unparsable -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.properties.last_operation.operation_time = "not-a-valid-timestamp"
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_last_op_time_equals_created_at_skips():
    """spec 9.4.7: operationTime == created_at -> no proven post-create signal -> skip."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_on = now - timedelta(days=30)
    instance = _make_instance(age_days=31, last_op_time_days=20)
    # Force both timestamps to be identical
    instance.properties.created_on = created_on
    instance.properties.properties.last_operation.operation_time = created_on
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_last_op_absent_falls_back_to_modified_on():
    """spec 9.4.8: lastOperation absent + modifiedOn > created_at -> modified_on signal."""
    ws = _make_workspace()
    instance = _make_instance(
        age_days=31,
        last_op_time_days=None,  # no last operation
        modified_days=20,  # modifiedOn 20 days ago (< age_days=31)
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "modified_on"
    assert findings[0].details["idle_since_days"] >= 19


def test_last_op_no_operation_time_falls_back_to_modified_on():
    """spec 9.4.8: lastOperation present but operationTime absent -> try modifiedOn."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20, modified_days=20)
    # Clear operation_time to simulate field absent
    instance.properties.properties.last_operation.operation_time = None
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].details["idle_signal_source"] == "modified_on"


def test_modified_on_equals_created_at_skips():
    """spec 9.4.9: modifiedOn == created_at -> no proven post-create signal -> skip."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_on = now - timedelta(days=30)
    instance = _make_instance(age_days=31, last_op_time_days=None, modified_days=None)
    instance.properties.created_on = created_on
    instance.properties.modified_on = created_on  # equal -> skip
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_modified_on_before_created_at_skips():
    """spec 9.4.8: modifiedOn <= created_at -> must not use -> skip."""
    ws = _make_workspace()
    now = datetime.now(timezone.utc)
    created_on = now - timedelta(days=30)
    instance = _make_instance(age_days=31, last_op_time_days=None, modified_days=None)
    instance.properties.created_on = created_on
    instance.properties.modified_on = created_on - timedelta(days=1)  # before created_on
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_no_lifecycle_signal_skips():
    """spec 9.4.12-13: no lastOperation and no modifiedOn -> fail closed -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=None, modified_days=None)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_system_data_last_modified_not_used():
    """spec 9.4.12: systemData.lastModifiedAt is undocumented -> not used."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=None, modified_days=None)
    # Attach system_data — must NOT trigger a finding
    instance.system_data = SimpleNamespace(
        last_modified_at=datetime.now(timezone.utc) - timedelta(days=20)
    )
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_age_only_fallback_not_used():
    """spec 9.4.13: age-only fallback must not be used to prove idleness."""
    ws = _make_workspace()
    # Very old instance, no lifecycle signal at all
    instance = _make_instance(age_days=365, last_op_time_days=None, modified_days=None)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_future_last_op_time_skips():
    """spec 9.4.11: lifecycle timestamp in the future -> skip (no clock-skew tolerance)."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.properties.properties.last_operation.operation_time = datetime.now(
        timezone.utc
    ) + timedelta(days=1)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_idle_since_days_below_threshold_skips():
    """spec 8.12: floored idle_since_days < effective_idle_days -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=5)  # only 5 days idle
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client, idle_days=14
        )
        == []
    )


def test_recently_active_instance_skipped():
    """Instance active 3 days ago should not be flagged even if old."""
    ws = _make_workspace()
    instance = _make_instance(age_days=61, last_op_time_days=3)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_timezone_naive_op_time_handled():
    """Timezone-naive lastOperation.operationTime is normalized to UTC."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
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
# Confidence contract (spec 9.5)
# ---------------------------------------------------------------------------


def test_confidence_medium_for_last_operation_source():
    """spec 9.5: MEDIUM confidence when idle_signal_source == last_operation."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].confidence.value == "medium"
    assert findings[0].details["idle_signal_source"] == "last_operation"


def test_confidence_low_for_modified_on_source():
    """spec 9.5: LOW confidence when idle_signal_source == modified_on."""
    ws = _make_workspace()
    instance = _make_instance(
        age_days=31,
        last_op_time_days=None,
        modified_days=20,
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].confidence.value == "low"
    assert findings[0].details["idle_signal_source"] == "modified_on"


# ---------------------------------------------------------------------------
# GPU classification (spec 7, 9.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vm_size,expected_risk",
    [
        ("Standard_NC6s_v3", "high"),
        ("Standard_NC12s_v3", "high"),
        ("Standard_ND6s", "high"),
        ("Standard_ND40rs_v2", "high"),
        ("Standard_NV6", "high"),
        ("Standard_DS3_v2", "medium"),
        ("Standard_D4s_v3", "medium"),
        ("Standard_DS11_v2", "medium"),
        # lowercase prefix — NOT GPU (case-sensitive matching)
        ("standard_nc6s_v3", "medium"),
    ],
)
def test_gpu_family_classification(vm_size, expected_risk):
    """spec 7, 9.5: exact case-sensitive GPU prefix classification."""
    ws = _make_workspace()
    # age_days=15, last_op_time_days=14: op_time is 1 day after created_on
    instance = _make_instance(vm_size=vm_size, age_days=15, last_op_time_days=14)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert len(findings) == 1
    assert findings[0].risk.value == expected_risk


# ---------------------------------------------------------------------------
# Custom idle_days threshold
# ---------------------------------------------------------------------------


def test_custom_idle_days_respected():
    """Custom idle_days=7 — instance idle 7 days should emit."""
    ws = _make_workspace()
    # age=8 >= idle_days=7; last_op 7 days ago -> idle_since_days=7 >= 7
    instance = _make_instance(age_days=8, last_op_time_days=7)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client, idle_days=7
    )

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 7


def test_idle_days_zero_clamped_to_one():
    """idle_days=0 must be clamped to 1 (spec 6.3)."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client, idle_days=0
    )

    assert len(findings) == 1
    assert findings[0].details["idle_days_threshold"] == 1


# ---------------------------------------------------------------------------
# Finding shape (spec 11.1, 11.3, 11.4)
# ---------------------------------------------------------------------------


def test_finding_required_fields():
    """spec 11.1: required top-level finding fields."""
    ws = _make_workspace(name="ml-prod", rg="rg-prod")
    instance = _make_instance(
        name="gpu-dev",
        vm_size="Standard_NC6s_v3",
        age_days=31,
        last_op_time_days=20,
        last_op_status="Succeeded",
        workspace="ml-prod",
        rg="rg-prod",
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    f = findings[0]
    assert f.provider == "azure"
    assert f.rule_id == "azure.ml.compute_instance.idle"
    assert f.resource_type == "azure.ml.compute_instance"
    assert f.region == "eastus"
    assert f.estimated_monthly_cost_usd is None
    assert f.detected_at is not None
    assert f.evidence is not None


def test_finding_detail_fields_complete():
    """spec 11.4: all required detail fields are present."""
    ws = _make_workspace(name="ml-prod", rg="rg-prod")
    instance = _make_instance(
        name="gpu-dev",
        vm_size="Standard_NC6s_v3",
        age_days=31,
        last_op_time_days=20,
        last_op_name="Start",
        last_op_status="Succeeded",
        modified_days=25,
        workspace="ml-prod",
        rg="rg-prod",
        tags={"team": "research"},
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    d = findings[0].details
    assert d["instance_name"] == "gpu-dev"
    assert d["workspace_name"] == "ml-prod"
    assert d["resource_group"] == "rg-prod"
    assert d["subscription_id"] == "sub-123"
    assert d["location"] == "eastus"
    assert d["vm_size"] == "Standard_NC6s_v3"
    assert d["compute_type"] == "ComputeInstance"
    assert d["provisioning_state"] == "Succeeded"
    assert d["state"] == "Running"
    assert d["created_at"] is not None
    assert d["modified_at"] is not None
    assert d["last_operation_name"] == "Start"
    assert d["last_operation_time"] is not None
    assert d["last_operation_status"] == "Succeeded"
    assert isinstance(d["idle_since_days"], int)
    assert d["idle_days_threshold"] == 14
    assert d["idle_signal_source"] == "last_operation"
    assert d["tags"] == {"team": "research"}


def test_last_operation_time_none_when_modified_on_signal():
    """spec 11.4: last_operation_time is null when idle_signal_source == modified_on."""
    ws = _make_workspace()
    instance = _make_instance(
        age_days=31,
        last_op_time_days=None,
        modified_days=20,
    )
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    d = findings[0].details
    assert d["idle_signal_source"] == "modified_on"
    assert d["last_operation_time"] is None
    assert d["modified_at"] is not None


def test_modified_at_present_even_when_not_selected_signal():
    """spec 11.4: modified_at included even when last_operation is the idle signal."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20, modified_days=25)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    d = findings[0].details
    assert d["idle_signal_source"] == "last_operation"
    assert d["modified_at"] is not None  # present even though not the selected signal


def test_tags_never_none():
    """spec 7: tags must never be None in output."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20, tags=None)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert findings[0].details["tags"] == {}


def test_idle_since_days_is_floored_integer():
    """spec 9.4.16: idle_since_days must be the floored integer idle duration."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert isinstance(findings[0].details["idle_since_days"], int)


def test_signals_used_disclose_required_items():
    """spec 11.3: signals_used discloses compute type, states, age, and actual field name."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    f = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )[0]

    signals = " ".join(f.evidence.signals_used)
    assert "ComputeInstance" in signals
    assert "Succeeded" in signals
    assert "Running" in signals
    # Gap 2: actual field name, not just source label
    assert "lastOperation.operationTime" in signals


def test_signals_used_names_modified_on_field():
    """Gap 2: signals_used names 'modifiedOn' when that fallback is the signal source."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=None, modified_days=20)
    ml_client = _make_client(ws, [instance])

    f = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )[0]

    signals = " ".join(f.evidence.signals_used)
    assert "modifiedOn" in signals


def test_signals_not_checked_includes_blind_spots():
    """spec 11.3: signals_not_checked lists runtime blind spots."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    f = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )[0]

    combined = " ".join(f.evidence.signals_not_checked).lower()
    assert "jupyter" in combined
    assert "vs code" in combined
    assert "aml" in combined or "experiment" in combined


def test_summary_contains_instance_and_workspace():
    ws = _make_workspace(name="research-ws")
    instance = _make_instance(name="cv-model-dev", age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )

    assert "cv-model-dev" in findings[0].summary
    assert "research-ws" in findings[0].summary
    assert "Running" in findings[0].summary


# ---------------------------------------------------------------------------
# Multiple instances
# ---------------------------------------------------------------------------


def test_multiple_instances_mixed():
    """Only idle Running Succeeded ComputeInstance instances should be flagged."""
    ws = _make_workspace()
    instances = [
        _make_instance("idle-gpu", "Standard_NC6s_v3", age_days=31, last_op_time_days=20),
        _make_instance("active-cpu", "Standard_DS3_v2", age_days=31, last_op_time_days=3),
        _make_instance(
            "stopped-gpu", "Standard_NC12s_v3", state="Stopped", age_days=31, last_op_time_days=20
        ),
        _make_instance("idle-cpu", "Standard_D4s_v3", age_days=15, last_op_time_days=14),
        _make_instance(
            "failed-prov",
            "Standard_DS3_v2",
            provisioning_state="Failed",
            age_days=31,
            last_op_time_days=20,
        ),
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
    assert "failed-prov" not in names


# ---------------------------------------------------------------------------
# Exception handling (spec 12)
# ---------------------------------------------------------------------------


def test_workspace_list_auth_error_propagates_as_is():
    """spec 12: subscription-wide workspace inventory failures propagate unchanged."""

    class _ForbiddenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise Exception("AuthorizationFailed: insufficient permissions")

        machine_learning_compute = None

    with pytest.raises(Exception, match="AuthorizationFailed"):
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_ForbiddenClient()
        )


def test_workspace_list_403_error_propagates_as_is():
    """spec 12: 403 from workspace listing propagates unchanged (not converted)."""

    class _ForbiddenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise Exception("Forbidden (403) — access denied")

        machine_learning_compute = None

    with pytest.raises(Exception, match="403"):
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_ForbiddenClient()
        )


def test_unexpected_workspace_list_error_propagates():
    """spec 12: any workspace listing failure propagates."""

    class _BrokenClient:
        class workspaces:  # noqa: N801
            @staticmethod
            def list_by_subscription():
                raise RuntimeError("Unexpected SDK error")

        machine_learning_compute = None

    with pytest.raises(RuntimeError):
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=_BrokenClient()
        )


def test_compute_list_auth_error_skips_workspace():
    """spec 12: per-workspace compute listing failure (including auth) skips that workspace."""
    ws = _make_workspace()

    def _compute_list(rg, ws_name):
        raise Exception("AuthorizationFailed: missing computes/read permission")

    ml_client = SimpleNamespace(
        workspaces=SimpleNamespace(list_by_subscription=lambda: [ws]),
        machine_learning_compute=SimpleNamespace(list_by_workspace=_compute_list),
    )

    # Must not raise — workspace is skipped, returning empty findings
    findings = find_idle_aml_compute_instances(
        subscription_id="sub-123", credential=None, client=ml_client
    )
    assert findings == []


def test_compute_list_transient_error_skips_workspace_preserves_findings():
    """spec 12: transient error on compute listing skips that workspace, preserves others."""
    ws_good = _make_workspace(name="good-ws", rg="rg-good")
    ws_bad = _make_workspace(name="bad-ws", rg="rg-bad")
    good_instance = _make_instance(
        age_days=31, last_op_time_days=20, workspace="good-ws", rg="rg-good"
    )

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

    assert len(findings) == 1
    assert findings[0].details["workspace_name"] == "good-ws"
    assert call_count == 2


def test_missing_compute_id_skips():
    """spec 8.1: absent compute id -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.id = None
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_missing_compute_name_skips():
    """spec 8.2: absent compute name -> skip."""
    ws = _make_workspace()
    instance = _make_instance(age_days=31, last_op_time_days=20)
    instance.name = None
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


def test_missing_workspace_name_skips():
    """spec 8.3: absent workspace name -> skip."""
    ws = _make_workspace()
    ws.name = None
    instance = _make_instance(age_days=31, last_op_time_days=20)
    ml_client = _make_client(ws, [instance])

    assert (
        find_idle_aml_compute_instances(
            subscription_id="sub-123", credential=None, client=ml_client
        )
        == []
    )


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    assert RULE_METADATA["id"] == "azure.ml.compute_instance.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "machinelearning"
    assert RULE_METADATA["cost_impact"] == "high"
