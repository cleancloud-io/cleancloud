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

# Locations where Vertex AI Workbench is available
_NOTEBOOK_LOCATIONS = [
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west2",
    "us-west4",
    "northamerica-northeast1",
    "southamerica-east1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-north1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast3",
    "asia-south1",
    "asia-southeast1",
    "australia-southeast1",
    "me-west1",
]


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

    Covers both generations:
    - Vertex AI Workbench (v2): current managed notebook experience
    - User-Managed Notebooks (v1): older generation, deprecated Sept 2024

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
        api_version = inst["api_version"]

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
        if is_gpu and accel_type and accel_type != "ACCELERATOR_TYPE_UNSPECIFIED":
            accel_label = "TPU-backed" if accel_type.startswith("TPU_") else "GPU-backed"
            signals.append(f"Accelerator: {accel_type} x {accel_count}")
        if is_gpu:
            accel_label = "TPU-backed" if (accel_type or "").startswith("TPU_") else "GPU-backed"
            signals.append(f"{accel_label} instance — high continuous cost (~${monthly_cost:,.0f}/month)")
        if using_age_fallback:
            signals.append(
                "updateTime unavailable — age used as fallback signal; "
                "confidence capped at MEDIUM"
            )
        if api_version == "v1":
            signals.append(
                "User-Managed Notebook (v1 API) — deprecated Sept 2024; "
                "consider migrating to Vertex AI Workbench"
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
                    "api_version": api_version,
                },
            )
        )

    return findings


find_idle_workbench_instances.RULE_ID = "gcp.vertex.workbench.idle"


def _list_instances(session: AuthorizedSession, project_id: str) -> list:
    """
    List all ACTIVE Vertex AI Workbench instances across all locations.

    Queries both v2 (Vertex AI Workbench, current) and v1 (User-Managed Notebooks,
    deprecated Sept 2024) APIs to give full coverage across generations.

    v2 uses the locations/- wildcard for a single paginated call.
    v1 queries each known location individually.

    Raises PermissionError on 403. Returns [] on 404 (API not enabled).
    """
    results = []
    seen_names: set = set()

    # --- v2: Vertex AI Workbench (current generation) ---
    v2_base = f"https://notebooks.googleapis.com/v2/projects/{project_id}/locations"

    def _paginate_v2(url: str) -> Optional[list]:
        out = []
        params: dict = {"pageSize": 100}
        while True:
            try:
                resp = session.get(url, params=params)
            except Exception:
                break  # network error — skip this URL, don't abort project scan
            if resp.status_code == 403:
                raise PermissionError(
                    "notebooks.instances.list permission required (roles/notebooks.viewer)"
                )
            if resp.status_code == 404:
                return []
            if resp.status_code == 400:
                return None  # wildcard not supported — signal caller to try per-location
            if resp.status_code >= 500:
                break  # transient server error — skip rather than abort scan
            resp.raise_for_status()
            data = resp.json()
            for inst in data.get("instances", []):
                inst["_api_version"] = "v2"
                out.append(inst)
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        return out

    v2_result = _paginate_v2(f"{v2_base}/-/instances")
    if v2_result is None:
        # Wildcard not supported — query per location
        for loc in _NOTEBOOK_LOCATIONS:
            loc_result = _paginate_v2(f"{v2_base}/{loc}/instances")
            if loc_result is None:
                continue
            for inst in loc_result:
                n = inst.get("name", "")
                if n and n not in seen_names:
                    seen_names.add(n)
                    results.append(inst)
    else:
        for inst in v2_result:
            n = inst.get("name", "")
            if n:
                seen_names.add(n)
                results.append(inst)

    # --- v1: User-Managed Notebooks (deprecated, but still widely deployed) ---
    v1_base = f"https://notebooks.googleapis.com/v1/projects/{project_id}/locations"

    for loc in _NOTEBOOK_LOCATIONS:
        params: dict = {"pageSize": 100}
        while True:
            try:
                resp = session.get(f"{v1_base}/{loc}/instances", params=params)
            except Exception:
                break  # network error — skip location, don't abort project scan
            if resp.status_code == 403:
                raise PermissionError(
                    "notebooks.instances.list permission required (roles/notebooks.viewer)"
                )
            if resp.status_code in (404, 400):
                break  # location not available or API not enabled
            if resp.status_code >= 500:
                break  # transient server error — skip location rather than abort scan
            resp.raise_for_status()
            data = resp.json()
            for inst in data.get("instances", []):
                n = inst.get("name", "")
                if n and n not in seen_names:
                    # v1 instances have a different name path prefix
                    inst["_api_version"] = "v1"
                    seen_names.add(n)
                    results.append(inst)
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token

    return results


def _normalize(instance: dict) -> dict:
    """
    Normalize a v1 or v2 Workbench instance dict to a common schema.

    v2 (Vertex AI Workbench):
      machineType lives under gceSetup.machineType (already short name)
      accelerators under gceSetup.acceleratorConfigs (list)

    v1 (User-Managed Notebooks):
      machineType is a zone-qualified path: zones/{zone}/machineTypes/{type}
      accelerator under acceleratorConfig (singular dict)
    """
    api_version = instance.get("_api_version", "v2")
    name = instance.get("name", "")

    # Extract location from resource name:
    # projects/{proj}/locations/{loc}/instances/{id}
    parts = name.split("/")
    location = parts[3] if len(parts) > 3 else ""

    if api_version == "v2":
        gce = instance.get("gceSetup", {})
        machine_type = gce.get("machineType", "")
        accels = gce.get("acceleratorConfigs", [])
        accel_type = accels[0].get("type", "") if accels else ""
        accel_count = int(accels[0].get("coreCount", 0) or 0) if accels else 0
    else:
        mt_raw = instance.get("machineType", "")
        machine_type = mt_raw.split("/")[-1] if "/" in mt_raw else mt_raw
        accel = instance.get("acceleratorConfig", {}) or {}
        accel_type = accel.get("type", "")
        accel_count = int(accel.get("coreCount", 0) or 0)

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
        "api_version": api_version,
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
