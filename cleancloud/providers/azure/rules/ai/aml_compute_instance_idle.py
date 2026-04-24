"""
Rule: azure.ml.compute_instance.idle

Intent:
    Detect Azure Machine Learning compute instances that remain billable in Running
    state while showing no recent documented control-plane lifecycle activity over
    a conservative review window.

    This rule is deliberately precision-first. It is not a generic "inactive notebook"
    rule, not proof that a compute instance is safe to stop or delete, and not proof
    that no user is actively connected. It is a conservative review-candidate rule for
    compute instances that appear to have been left running without recent documented
    lifecycle actions.

Exclusions:
    - id absent or empty
    - name absent or empty
    - workspace.name absent or empty
    - outside optional region filter (compute resource location, exact lowercase match;
      spaces and hyphens preserved)
    - compute_type does not resolve to exactly "ComputeInstance" (SDK+nested,
      conflict -> skip)
    - provisioning_state does not resolve to exactly "Succeeded" (SDK+nested,
      conflict -> skip)
    - state does not resolve to exactly "Running" (SDK+nested, conflict -> skip)
    - location unresolvable or conflicting
    - created_at absent, invalid, in the future, or instance age < idle_days
    - lastOperation.operationTime present but unparsable -> skip
    - lastOperation.operationTime == created_at -> no proven post-create signal -> skip
    - modifiedOn fallback: only when lastOperation absent or has no operationTime;
      skip when modifiedOn absent, unparsable, <= created_at, or in the future
    - no lifecycle signal at all -> skip (no age-only fallback; no systemData fallback)
    - resolved lifecycle timestamp in the future -> skip
    - floored idle_since_days < effective idle_days -> skip

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)

APIs:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
"""

from datetime import datetime, timezone
from typing import Any, List, Optional

from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.ml.compute_instance.idle"
_RESOURCE_TYPE = "azure.ml.compute_instance"
_DEFAULT_IDLE_DAYS = 14

RULE_METADATA = {
    "id": _RULE_ID,
    "category": "ai",
    "service": "machinelearning",
    "cost_impact": "high",
}

# GPU VM size prefixes — exact case-sensitive prefix matching (spec 7, 9.5)
_GPU_VM_PREFIXES = ("Standard_NC", "Standard_ND", "Standard_NV")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _norm_location(s: str) -> str:
    """Lowercase only — exact lowercase match per spec 7 (spaces and hyphens preserved)."""
    return s.lower() if s else ""


def _extract_resource_group(resource_id: Optional[str]) -> Optional[str]:
    """Extract resource group name from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


def _extract_subscription_id(resource_id: Optional[str]) -> Optional[str]:
    """Extract subscription ID from Azure ARM resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "subscriptions")
        return parts[idx + 1]
    except (StopIteration, IndexError):
        return None


# ---------------------------------------------------------------------------
# State resolvers (spec 9.1)
# ---------------------------------------------------------------------------


def _resolve_str_field(obj, snake: str, camel: str) -> Optional[str]:
    """
    Resolve a string field from SDK snake_case then raw camelCase.
    Returns None on conflict or absent.
    """
    if obj is None:
        return None
    sdk_val = getattr(obj, snake, None)
    raw_val = getattr(obj, camel, None)
    if sdk_val is not None and raw_val is not None and sdk_val != raw_val:
        return None  # conflict -> skip
    val = sdk_val if sdk_val is not None else raw_val
    return val if isinstance(val, str) else None


def _resolve_compute_type(compute) -> Optional[str]:
    """
    Resolve compute_type from compute.properties (SDK+nested, spec 9.1).
    Only "ComputeInstance" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    return _resolve_str_field(outer, "compute_type", "computeType")


def _resolve_provisioning_state(compute) -> Optional[str]:
    """
    Resolve provisioning_state from compute.properties (SDK+nested, spec 9.1).
    Only "Succeeded" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    return _resolve_str_field(outer, "provisioning_state", "provisioningState")


def _resolve_state(compute) -> Optional[str]:
    """
    Resolve state from compute.properties.properties (SDK+nested, spec 9.1).
    Normalized by surrounding-whitespace trimming per spec 7 before comparison.
    Only "Running" is eligible; conflict or absent -> None.
    """
    outer = getattr(compute, "properties", None)
    inner = getattr(outer, "properties", None) if outer is not None else None
    raw = _resolve_str_field(inner, "state", "state")
    return raw.strip() if raw is not None else None


# ---------------------------------------------------------------------------
# Location contract (spec 9.2)
# ---------------------------------------------------------------------------


def _resolve_location(compute) -> Optional[str]:
    """
    Resolve compute resource location (spec 9.2) in priority order:
      1. top-level compute.location
      2. compute.properties.compute_location
      3. compute.properties.computeLocation

    Returns normalized (lowercase) or None if unresolvable or materially conflicting.
    """
    loc1_raw = getattr(compute, "location", None)
    outer = getattr(compute, "properties", None)
    loc2_raw = getattr(outer, "compute_location", None) if outer is not None else None
    if loc2_raw is None and outer is not None:
        loc2_raw = getattr(outer, "computeLocation", None)

    candidates = [loc for loc in (loc1_raw, loc2_raw) if isinstance(loc, str) and loc.strip()]
    if not candidates:
        return None
    normalized = [_norm_location(loc) for loc in candidates]
    if len(set(normalized)) > 1:
        return None  # material conflict -> skip
    return normalized[0]


# ---------------------------------------------------------------------------
# Timestamp parsing (spec 7, 9.3, 9.4)
# ---------------------------------------------------------------------------


def _parse_utc_timestamp(raw) -> Optional[datetime]:
    """
    Parse a raw timestamp to a UTC-normalized datetime (spec 9.4 contract).
    Naive datetimes are treated as UTC; aware non-UTC datetimes are converted to UTC.
    Returns None if absent, invalid type, or unparsable string.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw.astimezone(timezone.utc)
    if isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.rstrip("Z"))
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _resolve_created_at(compute) -> Optional[datetime]:
    """
    Resolve creation timestamp from compute.properties.created_on / createdOn (spec 7, 9.3).
    Returns UTC-aware datetime or None if absent or unparsable.
    """
    outer = getattr(compute, "properties", None)
    if outer is None:
        return None
    raw = getattr(outer, "created_on", None)
    if raw is None:
        raw = getattr(outer, "createdOn", None)
    return _parse_utc_timestamp(raw)


def _resolve_modified_at(compute) -> Optional[datetime]:
    """
    Resolve modifiedOn from compute.properties (spec 7, 9.4 fallback).
    Documented SDK surface: modified_on / modifiedOn.
    Returns UTC-aware datetime or None if absent or unparsable.
    """
    outer = getattr(compute, "properties", None)
    if outer is None:
        return None
    raw = getattr(outer, "modified_on", None)
    if raw is None:
        raw = getattr(outer, "modifiedOn", None)
    return _parse_utc_timestamp(raw)


# ---------------------------------------------------------------------------
# Risk and GPU classification (spec 7, 9.5)
# ---------------------------------------------------------------------------


def _is_gpu(vm_size: Optional[str]) -> bool:
    """
    GPU classification via exact case-sensitive prefix matching (spec 7, 9.5).
    null / absent vm_size is non-GPU.
    """
    if not vm_size:
        return False
    return any(vm_size.startswith(prefix) for prefix in _GPU_VM_PREFIXES)


# ---------------------------------------------------------------------------
# Main rule function
# ---------------------------------------------------------------------------


def find_idle_aml_compute_instances(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[Any] = None,
    idle_days: int = _DEFAULT_IDLE_DAYS,
) -> List[Finding]:
    """
    Find Azure ML Compute Instances in Running state with no recent documented
    control-plane lifecycle activity.

    Detection logic (spec 4, 8, 9):
    - compute_type resolves exactly to "ComputeInstance"
    - provisioning_state resolves exactly to "Succeeded"
    - state resolves exactly to "Running"
    - instance age >= effective idle_days
    - last documented lifecycle activity >= effective idle_days ago:
        Primary: lastOperation.operationTime
        Fallback: modifiedOn (only when lastOperation absent or has no operationTime,
                  and modifiedOn > created_at)
        No age fallback; no systemData.lastModifiedAt (spec 9.4.12-13)

    IAM permissions:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    effective_idle_days = max(idle_days, 1)  # spec 6.3

    ml_client = client or AzureMachineLearningWorkspaces(
        credential=credential, subscription_id=subscription_id
    )

    # Subscription-wide workspace inventory (spec 12: propagate if this fails)
    for workspace in ml_client.workspaces.list_by_subscription():
        # spec 8.3: workspace name guard
        ws_name = getattr(workspace, "name", None)
        if not ws_name:
            continue

        rg = _extract_resource_group(getattr(workspace, "id", None))
        if not rg:
            continue

        try:
            for compute in ml_client.machine_learning_compute.list_by_workspace(rg, ws_name):
                try:
                    # spec 8.1: id guard
                    compute_id = getattr(compute, "id", None)
                    if not compute_id:
                        continue

                    # spec 8.2: name guard
                    compute_name = getattr(compute, "name", None)
                    if not compute_name:
                        continue

                    # spec 8.5: compute_type must resolve to exactly "ComputeInstance"
                    if _resolve_compute_type(compute) != "ComputeInstance":
                        continue

                    # spec 8.6: provisioning_state must resolve to exactly "Succeeded"
                    if _resolve_provisioning_state(compute) != "Succeeded":
                        continue

                    # spec 8.7: state must resolve to exactly "Running"
                    if _resolve_state(compute) != "Running":
                        continue

                    # spec 8.8: location must resolve from compute resource (not workspace)
                    location = _resolve_location(compute)
                    if location is None:
                        continue

                    # spec 8.4: region filter — exact lowercase equality
                    if region_filter and location != _norm_location(region_filter):
                        continue

                    # spec 8.9 / 9.3: created_at required; future timestamps invalid
                    created_at = _resolve_created_at(compute)
                    if created_at is None:
                        continue
                    if created_at > now:
                        continue  # spec 9.3.2: future created_at -> skip
                    age_days_actual = (now - created_at).days
                    if age_days_actual < effective_idle_days:
                        continue  # spec 9.3.3: age gate

                    # spec 9.4: lifecycle-activity contract
                    outer = getattr(compute, "properties", None)
                    inner = getattr(outer, "properties", None) if outer is not None else None

                    last_op = getattr(inner, "last_operation", None)
                    if last_op is None:
                        last_op = getattr(inner, "lastOperation", None)

                    if last_op is not None:
                        # Each field: SDK snake_case first, then raw camelCase fallback
                        last_op_time_raw = getattr(last_op, "operation_time", None)
                        if last_op_time_raw is None:
                            last_op_time_raw = getattr(last_op, "operationTime", None)

                        last_op_name = getattr(last_op, "operation_name", None)
                        if last_op_name is None:
                            last_op_name = getattr(last_op, "operationName", None)

                        last_op_status = getattr(last_op, "operation_status", None)
                        if last_op_status is None:
                            last_op_status = getattr(last_op, "operationStatus", None)
                    else:
                        last_op_time_raw = None
                        last_op_name = None
                        last_op_status = None

                    # Resolve modified_at for fallback and detail reporting
                    modified_at = _resolve_modified_at(compute)

                    lifecycle_activity_at: Optional[datetime] = None
                    idle_signal_source: Optional[str] = None

                    if last_op_time_raw is not None:
                        # spec 9.4.3: lastOperation.operationTime present — must parse or skip
                        parsed_op_time = _parse_utc_timestamp(last_op_time_raw)
                        if parsed_op_time is None:
                            continue  # spec 9.4.4: present but unparsable -> skip
                        # spec 9.4.7: operationTime == created_at -> no proven post-create signal
                        if parsed_op_time == created_at:
                            continue
                        lifecycle_activity_at = parsed_op_time
                        idle_signal_source = "last_operation"
                    else:
                        # spec 9.4.8: lastOperation absent or has no operationTime -> try modifiedOn
                        if modified_at is None:
                            continue  # no lifecycle signal -> fail closed (spec 9.4.13)
                        # spec 9.4.8: only when modified_at > created_at (strict greater than)
                        if modified_at <= created_at:
                            continue  # spec 9.4.8/9: no proven post-create signal -> skip
                        # spec 9.4.10: modified_at selected but fails parsing already handled above
                        lifecycle_activity_at = modified_at
                        idle_signal_source = "modified_on"

                    # spec 8.11 / 9.4.11: future lifecycle timestamp -> skip (no clock-skew)
                    if lifecycle_activity_at > now:
                        continue

                    # spec 8.12 / 9.4.16-17: idle_since_days must be >= effective idle window
                    idle_since_days = int((now - lifecycle_activity_at).total_seconds() // 86400)
                    if idle_since_days < effective_idle_days:
                        continue

                    # --- Enrichment ---
                    vm_size = getattr(inner, "vm_size", None) if inner is not None else None
                    is_gpu_instance = _is_gpu(vm_size)
                    tags = getattr(compute, "tags", None) or {}  # spec 7: never None in output

                    # spec 9.5 / 11.2: Risk — HIGH for GPU, MEDIUM otherwise
                    risk = RiskLevel.HIGH if is_gpu_instance else RiskLevel.MEDIUM

                    # spec 9.5 / 11.2: Confidence — MEDIUM for last_operation, LOW for modified_on
                    confidence = (
                        ConfidenceLevel.MEDIUM
                        if idle_signal_source == "last_operation"
                        else ConfidenceLevel.LOW
                    )

                    # Resolve the lifecycle field label for evidence and detail reporting
                    lifecycle_field = (
                        "lastOperation.operationTime"
                        if idle_signal_source == "last_operation"
                        else "modifiedOn"
                    )

                    # spec 11.3: signals_used
                    signals_used = [
                        "Resource is exact compute type 'ComputeInstance'",
                        "Provisioning state is 'Succeeded'",
                        "Runtime state is 'Running'",
                        (
                            f"Instance age is {age_days_actual} days "
                            f"(>= configured idle window of {effective_idle_days} days)"
                        ),
                        (
                            f"Last documented control-plane lifecycle activity is "
                            f"{idle_since_days} days ago "
                            f"(field: {lifecycle_field}), "
                            f"older than the configured idle window"
                        ),
                    ]
                    if idle_signal_source == "last_operation" and last_op_name:
                        signals_used.append(f"Last operation name: {last_op_name}")

                    # last_operation_time detail: always the parsed operationTime when present;
                    # None when lastOperation was absent or had no operationTime (modified_on path)
                    last_operation_time_iso = (
                        lifecycle_activity_at.isoformat()
                        if idle_signal_source == "last_operation"
                        else None
                    )

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id=_RULE_ID,
                            resource_type=_RESOURCE_TYPE,
                            resource_id=compute_id,
                            region=location,
                            estimated_monthly_cost_usd=None,  # spec 10: always None
                            title=(
                                f"Idle Azure ML Compute Instance: {compute_name} "
                                f"({idle_since_days} days without control-plane activity)"
                            ),
                            summary=(
                                f"Azure ML Compute Instance '{compute_name}' in workspace "
                                f"'{ws_name}' has had no documented control-plane lifecycle "
                                f"activity for {idle_since_days} days but remains in Running "
                                f"state, continuing to incur compute-hour charges until stopped."
                            ),
                            reason=(
                                f"Compute instance remains Running with no documented "
                                f"lifecycle activity for {idle_since_days} days "
                                f"(signal: {idle_signal_source})"
                            ),
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=Evidence(
                                signals_used=signals_used,
                                signals_not_checked=[
                                    "Active Jupyter kernel sessions",
                                    "Active Jupyter terminal sessions",
                                    "Active AML runs or experiments",
                                    "Active VS Code connections",
                                    "Custom applications currently running on the compute",
                                    "Creator or business-owner intent",
                                    "Automatic schedules or shutdown behavior not visible from the rule's read path",
                                    "Exact pricing after discounts, reservations, or special commercial terms",
                                ],
                                time_window=f"{idle_since_days} days",
                            ),
                            details={
                                "instance_name": compute_name,
                                "workspace_name": ws_name,
                                "resource_group": rg,
                                "subscription_id": subscription_id,
                                "location": location,
                                "vm_size": vm_size,
                                "compute_type": "ComputeInstance",
                                "provisioning_state": "Succeeded",
                                "state": "Running",
                                "created_at": created_at.isoformat(),
                                "modified_at": (
                                    modified_at.isoformat() if modified_at is not None else None
                                ),
                                "last_operation_name": last_op_name,
                                "last_operation_time": last_operation_time_iso,
                                "last_operation_status": last_op_status,
                                "idle_since_days": idle_since_days,
                                "idle_days_threshold": effective_idle_days,
                                "idle_signal_source": idle_signal_source,
                                "tags": tags,
                            },
                        )
                    )

                except Exception:
                    continue  # malformed per-compute record -> skip (spec 12)

        except Exception:
            continue  # skip workspace on any error (spec 12); preserve findings so far

    return findings
