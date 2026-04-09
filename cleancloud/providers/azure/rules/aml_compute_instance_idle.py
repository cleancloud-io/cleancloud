from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "azure.ml.compute_instance.idle",
    "category": "ai",
    "service": "machinelearning",
    "cost_impact": "high",
}

# GPU VM size prefixes — significantly more expensive than CPU
_GPU_VM_PREFIXES = ("Standard_NC", "Standard_ND", "Standard_NV")

# Approximate monthly cost per instance (on-demand, East US, 730 h/month)
# Compute instances are single-VM dev environments — billed per hour while Running
_MONTHLY_COST_BY_SIZE = {
    # CPU — general purpose
    "Standard_DS2_v2": 130.0,
    "Standard_DS3_v2": 260.0,
    "Standard_DS4_v2": 519.0,
    "Standard_DS11_v2": 174.0,
    "Standard_DS12_v2": 349.0,
    "Standard_DS13_v2": 699.0,
    "Standard_D2s_v3": 96.0,
    "Standard_D4s_v3": 192.0,
    "Standard_D8s_v3": 384.0,
    "Standard_D16s_v3": 768.0,
    # GPU — NVIDIA V100 (NC v3 series)
    "Standard_NC6s_v3": 2_203.0,
    "Standard_NC12s_v3": 4_406.0,
    "Standard_NC24s_v3": 8_812.0,
    # GPU — NVIDIA K80 (NC series)
    "Standard_NC6": 648.0,
    "Standard_NC12": 1_296.0,
    "Standard_NC24": 2_592.0,
    # GPU — NVIDIA P40 (ND series)
    "Standard_ND6s": 2_203.0,
    "Standard_ND12s": 4_406.0,
    "Standard_ND24s": 8_812.0,
    "Standard_ND40rs_v2": 15_862.0,
    # GPU — NVIDIA M60 (NV series)
    "Standard_NV6": 1_094.0,
    "Standard_NV12": 2_189.0,
    "Standard_NV24": 4_378.0,
}
_DEFAULT_MONTHLY_COST = 200.0


def find_idle_aml_compute_instances(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[AzureMachineLearningWorkspaces] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Azure ML Compute Instances in Running state with no recent control-plane activity.

    Azure ML Compute Instances are single-VM interactive development environments
    (Jupyter, VS Code, RStudio) that bill continuously while Running — regardless of
    whether any notebooks or kernels are active. GPU instances (NC/ND/NV series) cost
    $600–$15K+/month. Data scientists frequently leave instances Running after a sprint
    ends, a project is deprioritised, or when a new instance is provisioned and the old
    one is forgotten.

    Detection logic:
    - Compute type is ComputeInstance
    - Instance state is Running (the only state that incurs compute charges)
    - No control-plane activity within the idle threshold:
        last_operation.operation_time older than idle_days (primary signal)
        system_data.last_modified_at used as fallback if last_operation unavailable

    Why last_operation / last_modified_at:
    Azure ML Compute Instances do not publish per-instance utilisation metrics to Azure
    Monitor by default. last_operation.operation_time is updated by the Azure ML control
    plane on Start, Stop, Restart, and Create operations. An instance with no recent
    last_operation has had no control-plane activity — the same approach AWS Cost
    Optimisation Hub uses for SageMaker Notebook LastModifiedTime.

    Confidence:
    - HIGH: idle_signal_source != age_fallback AND idle_since_days >= idle_days AND age >= idle_days
    - MEDIUM: idle_since_days >= 75% of idle_days AND age >= 75% of idle_days
      (age_fallback findings are capped at MEDIUM — age alone is not evidence of idleness)

    Risk:
    - CRITICAL: GPU instance AND idle_ratio >= 2.0 (e.g. 28+ days at default 14-day window)
    - HIGH: GPU instance (NC*, ND*, NV*)
    - MEDIUM: CPU instance

    IAM permissions:
    - Microsoft.MachineLearningServices/workspaces/read
    - Microsoft.MachineLearningServices/workspaces/computes/read
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    idle_days = max(idle_days, 1)

    ml_client = client or AzureMachineLearningWorkspaces(
        credential=credential,
        subscription_id=subscription_id,
    )

    def _norm(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "")

    try:
        for workspace in ml_client.workspaces.list_by_subscription():
            location_raw = workspace.location or ""
            if region_filter and _norm(location_raw) != _norm(region_filter):
                continue

            rg = _parse_resource_group(workspace.id)
            if not rg:
                continue

            try:
                for compute in ml_client.compute.list(rg, workspace.name):
                    compute_obj = compute.properties
                    if (
                        not compute_obj
                        or getattr(compute_obj, "compute_type", None) != "ComputeInstance"
                    ):
                        continue

                    # ComputeInstanceProperties lives under compute_obj.properties
                    ci_props = getattr(compute_obj, "properties", None)

                    # Only flag Running instances — Stopped instances do not incur charges
                    state = getattr(ci_props, "state", None)
                    if state != "Running":
                        continue

                    vm_size = getattr(ci_props, "vm_size", None)

                    # --- Age ---
                    age_days: Optional[int] = None
                    created_at = getattr(compute_obj, "created_on", None)
                    if created_at is not None:
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=timezone.utc)
                        age_days = (now - created_at).days
                        if age_days < max(idle_days // 2, 7):
                            continue

                    # --- Idle signal: last_operation.operation_time (primary) ---
                    idle_since_days: Optional[int] = None

                    last_op = getattr(ci_props, "last_operation", None)
                    op_time = getattr(last_op, "operation_time", None)
                    if op_time is not None:
                        if op_time.tzinfo is None:
                            op_time = op_time.replace(tzinfo=timezone.utc)
                        idle_since_days = (now - op_time).days

                    # Fallback: system_data.last_modified_at
                    if idle_since_days is None:
                        system_data = getattr(compute, "system_data", None)
                        last_modified = getattr(system_data, "last_modified_at", None)
                        if last_modified is not None:
                            if last_modified.tzinfo is None:
                                last_modified = last_modified.replace(tzinfo=timezone.utc)
                            idle_since_days = (now - last_modified).days

                    # Second fallback: treat age as idle proxy — caps confidence at MEDIUM
                    # (age alone is not evidence of idleness; the instance could be in active use)
                    using_age_fallback = idle_since_days is None
                    if idle_since_days is None:
                        idle_since_days = age_days if age_days is not None else idle_days

                    # Use effective age for confidence — fall back to idle_days (neutral) if unknown
                    effective_age = age_days if age_days is not None else idle_days

                    threshold_high = idle_days
                    threshold_medium = int(idle_days * 0.75)

                    if (
                        not using_age_fallback
                        and idle_since_days >= threshold_high
                        and effective_age >= threshold_high
                    ):
                        confidence = ConfidenceLevel.HIGH
                    elif idle_since_days >= threshold_medium and effective_age >= threshold_medium:
                        confidence = ConfidenceLevel.MEDIUM
                    else:
                        continue  # too borderline for a confident finding

                    vm_size_norm = (vm_size or "").lower()
                    is_gpu = any(vm_size_norm.startswith(p.lower()) for p in _GPU_VM_PREFIXES)

                    idle_ratio = round(idle_since_days / idle_days, 2) if idle_days > 0 else 0.0
                    if is_gpu and idle_ratio >= 2.0:
                        risk = RiskLevel.CRITICAL
                    elif is_gpu:
                        risk = RiskLevel.HIGH
                    else:
                        risk = RiskLevel.MEDIUM

                    vm_size_key = next(
                        (k for k in _MONTHLY_COST_BY_SIZE if k.lower() == vm_size_norm),
                        None,
                    )
                    monthly_cost = (
                        _MONTHLY_COST_BY_SIZE[vm_size_key] if vm_size_key else _DEFAULT_MONTHLY_COST
                    )

                    # Determine idle signal source for evidence + details
                    if last_op is not None and op_time is not None:
                        idle_signal_source = "last_operation"
                        idle_signal_desc = f"Last control-plane operation: {idle_since_days} days ago (last_operation.operation_time)"
                        op_name = getattr(last_op, "operation_name", None)
                        if op_name:
                            idle_signal_desc += f" — last op: {op_name}"
                    elif (
                        system_data is not None
                        and getattr(system_data, "last_modified_at", None) is not None
                    ):
                        idle_signal_source = "last_modified_at"
                        idle_signal_desc = f"Last control-plane activity: {idle_since_days} days ago (last_modified_at fallback)"
                    else:
                        idle_signal_source = "age_fallback"
                        idle_signal_desc = f"Last control-plane activity: {idle_since_days} days ago (age used as proxy — no operation or modified timestamp available)"

                    signals = [
                        "Instance state: Running",
                        f"Age: {effective_age} days",
                        idle_signal_desc,
                    ]
                    if vm_size:
                        signals.append(f"VM size: {vm_size}")
                    if is_gpu:
                        signals.append("GPU instance — high hourly cost")

                    evidence = Evidence(
                        signals_used=signals,
                        signals_not_checked=[
                            "Active Jupyter kernel or notebook sessions",
                            "VS Code / RStudio remote connections",
                            "Scheduled jobs running on this instance",
                            "Assigned user's planned future use",
                            "Resource tags (e.g. keep_alive=true) — use --ignore-tag or cleancloud.yaml exceptions to suppress intentional instances",
                        ],
                        time_window=f"{idle_since_days} days",
                    )

                    findings.append(
                        Finding(
                            provider="azure",
                            rule_id="azure.ml.compute_instance.idle",
                            resource_type="azure.ml.compute_instance",
                            resource_id=compute.id,
                            region=location_raw,
                            estimated_monthly_cost_usd=monthly_cost,
                            title=f"Idle Azure ML Compute Instance (No Activity for {idle_since_days} Days)",
                            summary=(
                                f"Azure ML Compute Instance '{compute.name}' in workspace "
                                f"'{workspace.name}' has had no control-plane activity for "
                                f"{idle_since_days} days but remains Running, incurring continuous "
                                f"charges (~${monthly_cost:,.0f}/month)."
                            ),
                            reason=(
                                f"Azure ML Compute Instance has had no control-plane activity "
                                f"for {idle_since_days} days"
                            ),
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=evidence,
                            details={
                                "instance_name": compute.name,
                                "workspace_name": workspace.name,
                                "resource_group": rg,
                                "vm_size": vm_size,
                                "state": state,
                                "is_gpu": is_gpu,
                                "age_days": effective_age,
                                "idle_since_days": idle_since_days,
                                "idle_days_threshold": idle_days,
                                "idle_ratio": idle_ratio,
                                "idle_signal_source": idle_signal_source,
                                "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                                "cost_source": f"approximate_{location_raw}",
                            },
                        )
                    )
            except Exception as ws_err:
                ws_msg = str(ws_err)
                if "AuthorizationFailed" in ws_msg or "Forbidden" in ws_msg or "403" in ws_msg:
                    raise PermissionError(
                        "Missing required permissions: "
                        "Microsoft.MachineLearningServices/workspaces/read, "
                        "Microsoft.MachineLearningServices/workspaces/computes/read"
                    ) from ws_err
                continue  # skip this workspace on transient error; preserve findings so far

    except Exception as e:
        msg = str(e)
        if "AuthorizationFailed" in msg or "Forbidden" in msg or "403" in msg:
            raise PermissionError(
                "Missing required permissions: "
                "Microsoft.MachineLearningServices/workspaces/read, "
                "Microsoft.MachineLearningServices/workspaces/computes/read"
            ) from e
        raise

    return findings


def _parse_resource_group(resource_id: Optional[str]) -> Optional[str]:
    """Extract the resource group name from an Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None
