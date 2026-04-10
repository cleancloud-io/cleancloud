from datetime import datetime, timezone
from typing import List, Optional

from google.auth.transport.requests import AuthorizedSession

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "gcp.vertex.workbench.idle",
    "category": "ai",
    "service": "notebooks",
    "cost_impact": "high",
}

# Accelerator types treated as GPU/high-cost
_GPU_ACCELERATORS = frozenset(
    {
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_P100",
        "NVIDIA_TESLA_K80",
        "NVIDIA_TESLA_A100",
        "NVIDIA_A100_80GB",
        "NVIDIA_L4",
        "NVIDIA_H100_80GB",
        "TPU_V2",
        "TPU_V3",
        "TPU_V4_POD",
    }
)

# Monthly cost per instance (on-demand, us-central1, 730 h/month)
_MACHINE_MONTHLY_COST = {
    "n1-standard-1": 35.0,
    "n1-standard-2": 69.0,
    "n1-standard-4": 138.0,
    "n1-standard-8": 277.0,
    "n1-standard-16": 554.0,
    "n1-highmem-2": 93.0,
    "n1-highmem-4": 187.0,
    "n1-highmem-8": 374.0,
    "n2-standard-2": 78.0,
    "n2-standard-4": 157.0,
    "n2-standard-8": 314.0,
    "n2-standard-16": 628.0,
    "c2-standard-4": 166.0,
    "c2-standard-8": 332.0,
    # a2-* and g2-* include GPU cost — no separate add-on
    "a2-highgpu-1g": 2_933.0,
    "a2-highgpu-2g": 5_866.0,
    "a2-highgpu-4g": 11_732.0,
    "a2-highgpu-8g": 23_464.0,
    "a2-ultragpu-1g": 5_103.0,
    "g2-standard-4": 706.0,
    "g2-standard-8": 1_060.0,
    "g2-standard-16": 2_120.0,
    "g2-standard-32": 4_241.0,
}
_DEFAULT_MACHINE_MONTHLY_COST = 150.0

# Additional monthly cost per GPU/TPU for n1-*/n2-* machines.
# a2-* and g2-* already include GPU cost above.
# TPU costs are approximate (v2 pod slice: ~$5.22/hr, v3: ~$8.00/hr, v4: ~$12.88/hr — 730h/month).
_GPU_MONTHLY_COST_EACH = {
    "NVIDIA_TESLA_T4": 311.0,
    "NVIDIA_TESLA_V100": 1_385.0,
    "NVIDIA_TESLA_P100": 1_022.0,
    "NVIDIA_TESLA_K80": 392.0,
    "NVIDIA_TESLA_A100": 2_933.0,
    "NVIDIA_A100_80GB": 5_103.0,
    "NVIDIA_L4": 680.0,
    "NVIDIA_H100_80GB": 8_000.0,
    "TPU_V2": 3_811.0,
    "TPU_V3": 5_840.0,
    "TPU_V4_POD": 9_402.0,
}

_DAYS_IDLE = 14


def find_idle_workbench_instances(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = _DAYS_IDLE,
) -> List[Finding]:
    """
    Find Vertex AI Workbench instances in ACTIVE state with no recent activity.

    Workbench instances incur continuous compute charges while ACTIVE, regardless
    of whether any notebooks or kernels are running. GPU-backed instances cost
    $300–$2,900+/month. Data scientists frequently leave instances running after
    a sprint ends, a project is deprioritised, or when they switch to a new instance.

    Detection logic:
    - Instance state is ACTIVE (only ACTIVE instances incur compute charges)
    - updateTime is older than idle_days — no configuration or lifecycle changes

    updateTime is updated by the Notebooks API when:
    - The instance is started, stopped, or restarted via the console or API
    - Instance configuration is modified (machine type, accelerators, etc.)
    - Scripts or scheduled operations modify instance metadata

    Instances with old updateTime have had no control-plane activity.
    This mirrors the signal used by SageMaker LastModifiedTime and
    Azure ML compute instance last_modified_at.

    Confidence:
    - HIGH: updateTime >= idle_days ago AND age >= idle_days
    - MEDIUM: updateTime >= 75% of idle_days AND age >= 75% of idle_days

    IAM permissions required:
    - notebooks.instances.list (roles/notebooks.viewer)
    """
    # Guard against caller passing 0
    idle_days = max(idle_days, 1)

    session = AuthorizedSession(credentials)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    instances = _list_instances(session, project_id)

    for raw in instances:
        inst = _normalize(raw)
        name = inst["name"]
        state = inst["state"]
        location = inst["location"]

        if region_filter and location.lower() != region_filter.lower():
            continue

        # Only ACTIVE instances incur compute charges
        if state != "ACTIVE":
            continue

        # Age calculation
        age_days: Optional[int] = None
        create_time_str = inst["create_time"]
        if create_time_str:
            try:
                created_at = datetime.fromisoformat(create_time_str.replace("Z", "+00:00"))
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                age_days = (now - created_at).days
            except ValueError:
                pass

        # Skip instances younger than half the idle threshold
        if age_days is not None and age_days < max(idle_days // 2, 7):
            continue

        # Idle signal: updateTime (control-plane last activity)
        idle_since_days: Optional[int] = None
        update_time_str = inst["update_time"]
        if update_time_str:
            try:
                updated_at = datetime.fromisoformat(update_time_str.replace("Z", "+00:00"))
                if updated_at.tzinfo is None:
                    updated_at = updated_at.replace(tzinfo=timezone.utc)
                idle_since_days = (now - updated_at).days
            except ValueError:
                pass

        # Fall back to age when updateTime is unavailable
        using_age_fallback = idle_since_days is None
        if idle_since_days is None:
            idle_since_days = age_days if age_days is not None else idle_days

        effective_age = age_days if age_days is not None else idle_since_days

        # Confidence thresholds
        threshold_high = idle_days
        threshold_medium = int(idle_days * 0.75)

        # Age-fallback findings are capped at MEDIUM — updateTime absence is not
        # evidence of idleness by itself.
        if (
            not using_age_fallback
            and idle_since_days >= threshold_high
            and effective_age >= threshold_high
        ):
            confidence = ConfidenceLevel.HIGH
        elif idle_since_days >= threshold_medium and effective_age >= threshold_medium:
            confidence = ConfidenceLevel.MEDIUM
        else:
            continue

        machine_type = inst["machine_type"]
        accel_type = inst["accel_type"]
        accel_count = inst["accel_count"]
        labels = inst["labels"]
        instance_id = name.split("/")[-1] if name else ""

        is_gpu = accel_type in _GPU_ACCELERATORS or (machine_type or "").startswith(
            ("a2-", "g2-")
        )

        monthly_cost = _estimate_cost(machine_type, accel_type, accel_count)

        idle_ratio = round(idle_since_days / idle_days, 2) if idle_days > 0 else 0.0
        if is_gpu and idle_ratio >= 2.0:
            risk = RiskLevel.CRITICAL
        elif is_gpu:
            risk = RiskLevel.HIGH
        else:
            risk = RiskLevel.MEDIUM

        idle_signal_source = "age_fallback" if using_age_fallback else "update_time"
        activity_source = "age (fallback)" if using_age_fallback else "updateTime"

        signals = [
            f"Instance state: ACTIVE",
            f"Last control-plane activity: {idle_since_days} days ago ({activity_source})",
        ]
        if age_days is not None:
            signals.append(f"Instance age: {age_days} days")
        if machine_type:
            signals.append(f"Machine type: {machine_type}")
        if is_gpu and accel_type:
            signals.append(f"Accelerator: {accel_type} x {accel_count}")
        if is_gpu:
            accel_label = "TPU-backed" if (accel_type or "").startswith("TPU_") else "GPU-backed"
            signals.append(f"{accel_label} instance — high continuous cost (~${monthly_cost:,.0f}/month)")
        if using_age_fallback:
            signals.append(
                "updateTime unavailable — age used as fallback signal; "
                "confidence capped at MEDIUM"
            )

        not_checked = [
            f"Active kernel sessions not captured by updateTime (requires Cloud Monitoring agent)",
            f"Scheduled notebook runs via Cloud Scheduler or Vertex AI Pipelines",
            "Planned future use by the assigned user",
            f"Idle shutdown policy configured on the instance — may auto-stop before {idle_days} days",
        ]

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=not_checked,
            time_window=f"{idle_since_days} days",
        )

        is_tpu = (accel_type or "").startswith("TPU_")
        if is_gpu:
            accel_kind = "TPU" if is_tpu else "GPU"
            title = (
                f"Idle {accel_kind}-Backed Workbench Instance "
                f"(>{idle_days} Days Idle, {idle_since_days} Days Since Activity)"
            )
        else:
            title = (
                f"Idle Vertex AI Workbench Instance "
                f"(>{idle_days} Days Idle, {idle_since_days} Days Since Activity)"
            )

        if is_gpu:
            accel_prefix = "TPU-backed " if is_tpu else "GPU-backed "
        else:
            accel_prefix = ""
        summary = (
            f"{accel_prefix}Vertex AI Workbench instance '{instance_id}' "
            f"in '{location}' has had no control-plane activity for {idle_since_days} days "
            f"but remains ACTIVE, incurring continuous charges "
            f"(~${monthly_cost:,.0f}/month)."
        )

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.workbench.idle",
                resource_type="gcp.vertex.workbench.instance",
                resource_id=name,
                region=location,
                estimated_monthly_cost_usd=monthly_cost,
                title=title,
                summary=summary,
                reason=(
                    f"Workbench instance has had no control-plane activity "
                    f"for {idle_since_days} days while ACTIVE"
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                details={
                    "instance_id": instance_id,
                    "location": location,
                    "machine_type": machine_type,
                    "accelerator_type": accel_type or None,
                    "accelerator_count": accel_count,
                    "is_gpu": is_gpu,
                    "age_days": age_days if age_days is not None else "unknown",
                    "idle_since_days": idle_since_days,
                    "idle_days_threshold": idle_days,
                    "idle_ratio": idle_ratio,
                    "idle_signal_source": idle_signal_source,
                    "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                    "cost_basis": "us-central1 baseline estimate",
                    "labels": labels,
                    "api_version": "v2",
                },
            )
        )

    return findings


find_idle_workbench_instances.RULE_ID = "gcp.vertex.workbench.idle"


def _list_instances(session: AuthorizedSession, project_id: str) -> list:
    """
    List all Vertex AI Workbench instances across all locations using the v2 API.

    Uses the locations/- wildcard for a single paginated call covering all regions.

    Raises PermissionError on 403. Returns [] on 404 (API not enabled).
    """
    results = []
    url = f"https://notebooks.googleapis.com/v2/projects/{project_id}/locations/-/instances"
    params: dict = {"pageSize": 100}

    while True:
        try:
            resp = session.get(url, params=params)
        except Exception:
            break  # network error — skip, don't abort project scan
        if resp.status_code == 403:
            raise PermissionError(
                "notebooks.instances.list permission required (roles/notebooks.viewer)"
            )
        if resp.status_code in (404, 400):
            return []  # API not enabled for this project
        if resp.status_code >= 500:
            break  # transient server error — skip rather than abort scan
        resp.raise_for_status()
        data = resp.json()
        for inst in data.get("instances", []):
            inst["_api_version"] = "v2"
            results.append(inst)
        next_token = data.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token

    return results


def _normalize(instance: dict) -> dict:
    """
    Normalize a v2 Workbench instance dict to a common schema.

    machineType lives under gceSetup.machineType (short name).
    Accelerators under gceSetup.acceleratorConfigs (list).
    """
    name = instance.get("name", "")

    # Extract location from resource name:
    # projects/{proj}/locations/{loc}/instances/{id}
    parts = name.split("/")
    location = parts[3] if len(parts) > 3 else ""

    gce = instance.get("gceSetup", {})
    machine_type = gce.get("machineType", "")
    accels = gce.get("acceleratorConfigs", [])
    accel_type = accels[0].get("type", "") if accels else ""
    accel_count = int(accels[0].get("coreCount", 0) or 0) if accels else 0

    if accel_type == "ACCELERATOR_TYPE_UNSPECIFIED":
        accel_type = ""

    return {
        "name": name,
        "location": location,
        "state": instance.get("state", ""),
        "create_time": instance.get("createTime", ""),
        "update_time": instance.get("updateTime", ""),
        "machine_type": machine_type,
        "accel_type": accel_type,
        "accel_count": accel_count,
        "labels": instance.get("labels", {}),
    }


def _estimate_cost(
    machine_type: Optional[str],
    accel_type: Optional[str],
    accel_count: int,
) -> float:
    """
    Estimate monthly cost for one always-on Workbench instance.

    a2-* and g2-* machine types bundle GPU cost — no separate add-on.
    n1-*/n2-* machines add GPU cost separately.
    """
    machine_cost = _MACHINE_MONTHLY_COST.get(machine_type or "", _DEFAULT_MACHINE_MONTHLY_COST)

    gpu_addon = 0.0
    if accel_type and accel_type in _GPU_MONTHLY_COST_EACH:
        is_gpu_machine = (machine_type or "").startswith(("a2-", "g2-"))
        if not is_gpu_machine:
            gpu_addon = _GPU_MONTHLY_COST_EACH[accel_type] * max(accel_count, 1)

    return machine_cost + gpu_addon
