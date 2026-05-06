"""
Rule: gcp.vertex.training_job.long_running

    (spec -- docs/specs/gcp/ai/vertex_training_job_long_running.md)

Intent:
    Detect Vertex AI training resources (CustomJob and TrainingPipeline) that are
    provably still in an exact documented running state and whose documented startTime
    shows they have been running for at least a conservative review threshold.

    This rule is deliberately precision-first. It is a review-candidate rule only.
    It is not proof that a job is hung, not proof that no useful progress is occurring,
    not proof that the resource is safe to cancel, and not proof of a specific saving.

Covered resource types (spec 3.1, 3.2):
    - Vertex AI CustomJob  (state == JOB_STATE_RUNNING)
    - Vertex AI TrainingPipeline  (state == PIPELINE_STATE_RUNNING)

Runtime anchor (spec 7, 9.4):
    - Canonical anchor: startTime (when the job first entered running state)
    - createTime is NOT a fallback -- missing startTime must skip (spec 9.4)
    - Future startTime values must skip (spec 7)

Exclusions:
    - resource name absent or not exactly matching the documented pattern (spec 7, 11)
    - state not exactly equal to the documented running enum (spec 3.3, 9.1)
    - startTime absent, non-RFC3339, unparsable, or future (spec 7, 9.1)
    - elapsed runtime < long_running_hours_threshold (spec 9.1)
    - location filter set and parsed location does not exactly match (spec 7)

Detection (all must be true to emit):
    1. resource is CustomJob or TrainingPipeline
    2. state is exactly JOB_STATE_RUNNING or PIPELINE_STATE_RUNNING
    3. startTime is valid and not future
    4. elapsed_runtime_seconds >= long_running_hours_threshold * 3600

Confidence / Risk (spec 9.2, 9.3):
    HIGH confidence:   elapsed >= 3 * threshold  (clearly runaway)
    MEDIUM confidence: threshold <= elapsed < 3 * threshold
    CRITICAL risk:     HIGH confidence + provably accelerator-backed
    HIGH risk:         HIGH confidence + hardware not proven accelerated
    MEDIUM risk:       all MEDIUM confidence findings

Cost model (spec 10.1, 10.2):
    estimated_monthly_cost_usd = None
    Training jobs are transient, not recurring monthly resources.
    Static pricing tables are out of scope for the canonical rule.

APIs:
    - aiplatform.googleapis.com/v1: projects/{project}/locations/-/customJobs
    - aiplatform.googleapis.com/v1: projects/{project}/locations/-/trainingPipelines
"""

import json
import re
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from google.auth.transport.requests import AuthorizedSession

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "gcp.vertex.training_job.long_running",
    "category": "ai",
    "service": "aiplatform",
    "cost_impact": "high",
}

# Machine type prefixes whose GPU/accelerator cost is bundled (no separate add-on charge).
# Covers NVIDIA GPU families (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*).
_BUNDLED_GPU_PREFIXES = ("a2-", "a3-", "a4-", "a4x-", "g2-", "g4-")

# Machine type prefixes for Cloud TPU nodes (Vertex AI TPU training).
# ct4- uses a trailing dash (exact family anchor); ct5/ct6/ct7 match all sub-variants.
# "tpu" covers tpu7x-* and any future tpu-prefixed names.
# Use _is_tpu_machine() rather than calling .startswith() with this tuple directly.
_TPU_MACHINE_PREFIXES = ("ct4-", "ct5", "ct6", "ct7", "tpu")

# Accelerator types for hardware classification (spec 8.1).
# A job is accelerator-backed when any worker pool uses one of these types
# with a nonzero count, or when the machine type is in a bundled GPU/TPU family.
_ACCELERATOR_TYPES = frozenset(
    {
        # Volta / Turing / Ampere
        "NVIDIA_TESLA_K80",
        "NVIDIA_TESLA_P4",
        "NVIDIA_TESLA_P100",
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_A100",
        "NVIDIA_A100_80GB",
        # Ada / Hopper / Blackwell
        "NVIDIA_L4",
        "NVIDIA_H100_80GB",
        "NVIDIA_H100_MEGA_80GB",
        "NVIDIA_H200_141GB",
        "NVIDIA_B200",
        "NVIDIA_GB200",
        "NVIDIA_RTX_PRO_6000",
        # TPU
        "TPU_V2",
        "TPU_V3",
        "TPU_V4_POD",
        "TPU_V5_LITEPOD",
    }
)

# Chips per physical host for known Cloud TPU machine types.
# Used by _tpu_topology_host_count to derive actual host count from tpuTopology,
# since Vertex AI always reports replicaCount=1 for TPU pods regardless of scale.
# Hardware classification only -- not used for cost estimation.
_BUNDLED_ACCELERATOR_COUNT: dict[str, int] = {
    # a2-* (A100 40GB)
    "a2-highgpu-1g": 1,
    "a2-highgpu-2g": 2,
    "a2-highgpu-4g": 4,
    "a2-highgpu-8g": 8,
    "a2-megagpu-16g": 16,
    # a2-ultragpu-* (A100 80GB)
    "a2-ultragpu-1g": 1,
    "a2-ultragpu-2g": 2,
    "a2-ultragpu-4g": 4,
    "a2-ultragpu-8g": 8,
    # a3-* (H100 SXM5)
    "a3-highgpu-1g": 1,
    "a3-highgpu-2g": 2,
    "a3-highgpu-4g": 4,
    "a3-highgpu-8g": 8,
    "a3-megagpu-8g": 8,
    "a3-ultragpu-8g": 8,
    # a4-* (B200)
    "a4-highgpu-8g": 8,
    # a4x-* (GB200 NVLink)
    "a4x-highgpu-4g": 4,
    # g2-* (L4)
    "g2-standard-4": 1,
    "g2-standard-8": 1,
    "g2-standard-12": 1,
    "g2-standard-16": 1,
    "g2-standard-24": 2,
    "g2-standard-48": 4,
    "g2-standard-96": 8,
    # g4-* (RTX Pro 6000 Ada) — 48=1 GPU, 96=2, 192=4, 384=8
    "g4-standard-48": 1,
    "g4-standard-96": 2,
    "g4-standard-192": 4,
    "g4-standard-384": 8,
    # Cloud TPU machine types
    "ct5lp-hightpu-1t": 1,
    "ct5lp-hightpu-4t": 4,
    "ct5lp-hightpu-8t": 8,
    "ct5p-hightpu-4t": 4,
    "ct5p-hightpu-8t": 8,
    "ct6e-standard-1t": 1,
    "ct6e-standard-4t": 4,
    "ct6e-standard-8t": 8,
    "tpu7x-standard-4t": 4,
}

# Duration multiplier beyond which a job is confidently runaway (spec 9.2).
_RUNAWAY_MULTIPLIER = 3

# Default threshold hours (spec 6.3).
_DEFAULT_LONG_RUNNING_HOURS = 24

# (project_id, resource) pairs where locations/- wildcard returned 400 -- fall back
# to per-region calls for that specific combination.
# Keyed per (project_id, resource) so customJobs and trainingPipelines are independent.
_wildcard_unsupported: set[tuple[str, str]] = set()

# Known Vertex AI locations for fallback when the wildcard is not supported.
# Last reviewed: 2026-04-17. Source: https://cloud.google.com/vertex-ai/docs/general/locations
_VERTEX_LOCATIONS = [
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
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


# Strict RFC3339 validation pattern (spec 7).
# Accepts: YYYY-MM-DDTHH:MM:SS[.fractional](Z | +HH:MM | -HH:MM)
# Rejects: date-only, space separator, missing timezone.
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

# Maps internal job_type strings to the expected URL/name path segment.
_RESOURCE_TYPE_SEGMENT: dict[str, str] = {
    "customJob": "customJobs",
    "trainingPipeline": "trainingPipelines",
}

# Maps job_type to the exact running-state enum the resource must expose (spec 3.3, 9.1).
_EXPECTED_STATE: dict[str, str] = {
    "customJob": "JOB_STATE_RUNNING",
    "trainingPipeline": "PIPELINE_STATE_RUNNING",
}


def _validate_resource_name(name: str, job_type: str) -> bool:
    """
    Return True only when name exactly matches the documented Vertex AI resource-name
    pattern for the given job type (spec 7):
        projects/{project}/locations/{location}/customJobs/{id}
        projects/{project}/locations/{location}/trainingPipelines/{id}

    All six slash-delimited segments must be present and non-empty.  Any extra
    or missing path segments, or a wrong resource-type segment, returns False.
    """
    parts = name.split("/")
    return (
        len(parts) == 6
        and parts[0] == "projects"
        and parts[2] == "locations"
        and parts[4] == _RESOURCE_TYPE_SEGMENT[job_type]
        and bool(parts[1])  # project id
        and bool(parts[3])  # location
        and bool(parts[5])  # resource id
    )


def find_long_running_vertex_training_jobs(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    long_running_hours_threshold: int = _DEFAULT_LONG_RUNNING_HOURS,
) -> List[Finding]:
    """
    Find Vertex AI CustomJobs and TrainingPipelines running beyond the threshold.

    Emits a finding only when all of the following are true (spec 9):
        1. resource is CustomJob or TrainingPipeline in the exact running state
        2. startTime is valid and not future (createTime is NOT a fallback; spec 9.4)
        3. elapsed_runtime_seconds >= long_running_hours_threshold * 3600

    Confidence (spec 9.2):
        HIGH:   elapsed >= 3 * threshold  (clearly runaway)
        MEDIUM: threshold <= elapsed < 3 * threshold

    Risk (spec 9.3):
        CRITICAL: HIGH confidence + provably accelerator-backed
        HIGH:     HIGH confidence + hardware not proven accelerated
        MEDIUM:   all MEDIUM confidence findings

    No sub-threshold early warnings are emitted (spec 9.4).
    No hardcoded pricing tables are used (spec 10.2).

    IAM permissions required:
        aiplatform.customJobs.list         (roles/aiplatform.viewer)
        aiplatform.trainingPipelines.list  (roles/aiplatform.viewer)
    """
    if long_running_hours_threshold < 1:
        raise ValueError(
            f"long_running_hours_threshold must be >= 1, " f"got {long_running_hours_threshold!r}"
        )

    threshold_seconds = long_running_hours_threshold * 3600
    session = AuthorizedSession(credentials)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []
    skipped_jobs: int = 0

    # Query both resource types in parallel; failures on one surface do not block the other.
    # PermissionError propagates immediately (missing IAM is user-actionable).
    custom_jobs: list = []
    training_pipelines: list = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        fut_custom = executor.submit(
            _list_jobs, session, project_id, "customJobs", 'state="JOB_STATE_RUNNING"'
        )
        fut_pipeline = executor.submit(
            _list_jobs,
            session,
            project_id,
            "trainingPipelines",
            'state="PIPELINE_STATE_RUNNING"',
        )
        try:
            custom_jobs = fut_custom.result()
        except PermissionError:
            raise
        except Exception as e:
            warnings.warn(
                f"gcp.vertex.training_job.long_running: customJobs fetch failed "
                f"({type(e).__name__}: {e}) — findings may be incomplete",
                stacklevel=2,
            )
        try:
            training_pipelines = fut_pipeline.result()
        except PermissionError:
            raise
        except Exception as e:
            warnings.warn(
                f"gcp.vertex.training_job.long_running: trainingPipelines fetch failed "
                f"({type(e).__name__}: {e}) — findings may be incomplete",
                stacklevel=2,
            )

    for job, job_type in [(j, "customJob") for j in custom_jobs] + [
        (p, "trainingPipeline") for p in training_pipelines
    ]:
        # --- Identity: exact resource-name pattern (spec 7, 11) ---
        name = (job.get("name") or "").strip()
        if not name or not _validate_resource_name(name, job_type):
            # Empty name or doesn't match expected pattern → skip (spec 7, 11)
            skipped_jobs += 1
            continue

        location = name.split("/")[3]  # guaranteed by _validate_resource_name

        # Region filter: exact string equality, no case folding (spec 7)
        if region_filter and location != region_filter:
            continue

        # --- State validation: exact documented running enum (spec 3.3, 9.1) ---
        expected_state = _EXPECTED_STATE[job_type]
        actual_state = (job.get("state") or "").strip()
        if actual_state != expected_state:
            skipped_jobs += 1
            continue

        # --- Runtime anchor: startTime only (spec 7, 9.4) ---
        # createTime is NOT a fallback. Missing startTime must skip unconditionally.
        start_str = (job.get("startTime") or "").strip()
        if not start_str:
            skipped_jobs += 1
            continue

        # Strict RFC3339 validation (spec 7): reject space separators, date-only, no-tz values.
        if not _RFC3339_RE.match(start_str):
            skipped_jobs += 1
            continue

        try:
            start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:  # defensive; RFC3339 regex guarantees tz
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            skipped_jobs += 1
            continue

        # Future startTime is unusable (spec 7)
        if start_dt > now:
            skipped_jobs += 1
            continue

        # --- Duration check (spec 9.1) ---
        elapsed_seconds = (now - start_dt).total_seconds()
        if elapsed_seconds < threshold_seconds:
            continue  # not yet long-running; no sub-threshold early warning (spec 9.4)

        duration_hours = elapsed_seconds / 3600
        duration_display = round(duration_hours, 1)
        display_name = (job.get("displayName") or "").strip()

        # --- Hardware classification (spec 8) ---
        if job_type == "customJob":
            raw_worker_specs = job.get("jobSpec", {}).get("workerPoolSpecs", [])
            pools = _parse_worker_pools(raw_worker_specs)
            # spec 8.1: missing, empty, or all-malformed workerPoolSpecs → hardware_unknown
            hardware_unknown = not pools
        else:
            task_inputs = job.get("trainingTaskInputs") or {}
            if isinstance(task_inputs, str):
                try:
                    task_inputs = json.loads(task_inputs)
                except (ValueError, TypeError):
                    task_inputs = {}
            tp_specs = (
                task_inputs.get("workerPoolSpecs", []) if isinstance(task_inputs, dict) else []
            )
            raw_worker_specs = tp_specs
            pools = _parse_worker_pools(raw_worker_specs)
            hardware_unknown = not pools

        is_accelerator = _has_accelerator_hardware(pools)

        # --- Confidence (spec 9.2) ---
        if elapsed_seconds >= _RUNAWAY_MULTIPLIER * threshold_seconds:
            confidence = ConfidenceLevel.HIGH
        else:
            confidence = ConfidenceLevel.MEDIUM

        # --- Risk (spec 9.3) ---
        if confidence == ConfidenceLevel.HIGH:
            risk = RiskLevel.CRITICAL if is_accelerator else RiskLevel.HIGH
        else:
            risk = RiskLevel.MEDIUM

        # --- Finding construction ---
        job_id = name.rsplit("/", 1)[-1] if name else ""
        label = display_name or job_id

        if pools:
            total_replicas = sum(pool[3] for pool in pools)  # each pool[3] >= 1
            primary_machine = pools[0][0]
            primary_accel = pools[0][1]
            primary_accel_count = pools[0][2]
            primary_tpu_topology: Optional[str] = pools[0][4]  # stored during parsing
        else:
            total_replicas = 1
            primary_machine = None
            primary_accel = None
            primary_accel_count = 0
            primary_tpu_topology = None

        hardware_label = _hardware_label(
            primary_machine,
            primary_accel,
            primary_accel_count,
            total_replicas,
            tpu_topology=primary_tpu_topology,
        )

        state = actual_state  # already validated == expected enum for this job_type
        overrun_hours = max(0.0, duration_hours - long_running_hours_threshold)
        threshold_detail = (
            f"exceeded by {int(overrun_hours)}h"
            if overrun_hours > 0
            else f"{round(long_running_hours_threshold - duration_hours, 1)}h below threshold"
        )

        title = (
            f"Long-Running Vertex Training Job ({duration_display}h"
            + (f", {hardware_label}" if hardware_label else "")
            + ")"
        )

        signals = [
            f"Job status: {state} for {duration_display}h "
            f"(threshold: {long_running_hours_threshold}h, {threshold_detail})",
        ]
        if hardware_label:
            signals.append(f"Hardware: {hardware_label}")
        if total_replicas > 1:
            signals.append(
                f"Distributed training ({total_replicas} workers) — "
                "long durations may be expected for large-scale jobs"
            )
        if hardware_unknown:
            signals.append("Hardware spec not structurally exposed in API response")

        not_checked = [
            "Intentional long-running distributed training (LLM pre-training, large fine-tunes)",
            "Checkpoint saving — job may be making progress without visible status updates",
            "Committed use discounts — actual cost may be significantly lower than on-demand",
            "Preemptible/Spot workers — cost and interruption semantics differ",
        ]

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.training_job.long_running",
                resource_type="gcp.vertex.training_job",
                resource_id=name,
                region=location,
                title=title,
                summary=(
                    f"Vertex AI {job_type} '{label}' has been {state} for {duration_display}h"
                    + (f" ({hardware_label})" if hardware_label else "")
                    + f". Most training jobs complete well under "
                    f"{long_running_hours_threshold}h unless intentionally long-running."
                ),
                reason=(
                    f"Job has been {state} for {duration_display}h "
                    f"(threshold: {long_running_hours_threshold}h)"
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals,
                    signals_not_checked=not_checked,
                    time_window=f"{duration_display}h",
                ),
                estimated_monthly_cost_usd=None,  # spec 10.1: transient resource
                details={
                    "job_name": name,
                    "display_name": display_name or None,
                    "job_type": job_type,
                    "state": state,
                    "location": location,
                    "start_time": start_str,
                    "duration_hours": round(duration_hours, 2),
                    "long_running_hours_threshold": long_running_hours_threshold,
                    "machine_type": primary_machine or None,
                    "accelerator_type": primary_accel or None,
                    "accelerator_count": (primary_accel_count if primary_accel_count else None),
                    "tpu_topology": primary_tpu_topology,
                    "total_workers": total_replicas,
                    "is_accelerator": is_accelerator,
                    "hardware_unknown": hardware_unknown,
                },
            )
        )

    if skipped_jobs > 0:
        warnings.warn(
            f"gcp.vertex.training_job.long_running: {skipped_jobs} job(s) skipped "
            "due to malformed resource name, unexpected state, or unusable startTime "
            "— findings may be incomplete",
            stacklevel=2,
        )

    return findings


find_long_running_vertex_training_jobs.RULE_ID = "gcp.vertex.training_job.long_running"


def _list_jobs(
    session: AuthorizedSession,
    project_id: str,
    resource: str,
    state_filter: str,
) -> list:
    """
    List running Vertex AI jobs (customJobs or trainingPipelines) across all locations.

    Attempts the locations/- wildcard first. Falls back to per-location queries
    when the wildcard returns 400.

    Raises PermissionError on 403. Returns [] on 404 (API not enabled).
    """
    base_url = f"https://aiplatform.googleapis.com/v1/projects/{project_id}/locations"

    def _paginate(url: str) -> Optional[list]:
        results = []
        params: dict = {"pageSize": 100, "filter": state_filter}
        while True:
            resp = session.get(url, params=params)
            if resp.status_code == 403:
                raise PermissionError(
                    f"aiplatform.{resource}.list permission required " f"(roles/aiplatform.viewer)"
                )
            if not resp.ok:
                if results:
                    # Later-page failure: keep earlier pages, warn (spec 11.3).
                    # Treat identically to a non-permission surface failure so the
                    # caller can decide whether to continue with the other surface.
                    warnings.warn(
                        f"gcp.vertex.training_job.long_running: {resource} pagination "
                        f"failed mid-scan (HTTP {resp.status_code}) — "
                        "partial page results kept; findings may be incomplete",
                        stacklevel=4,
                    )
                    return results
                # First-page failures:
                if resp.status_code == 404:
                    return []  # API not enabled — not an error
                if resp.status_code == 400:
                    return None  # wildcard unsupported — signal caller for fallback
                resp.raise_for_status()  # propagate other first-page errors
            data = resp.json()
            results.extend(data.get(resource, []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        return results

    cache_key = (project_id, resource)
    if cache_key not in _wildcard_unsupported:
        result = _paginate(f"{base_url}/-/{resource}")
        if result is not None:
            return result
        _wildcard_unsupported.add(cache_key)

    all_jobs: list = []
    seen: set = set()
    for location in _VERTEX_LOCATIONS:
        loc_result = _paginate(f"{base_url}/{location}/{resource}")
        if loc_result is None:
            continue
        for job in loc_result:
            n = job.get("name", "")
            if n and n not in seen:
                seen.add(n)
                all_jobs.append(job)
    return all_jobs


def _tpu_topology_host_count(machine_type: str, topology: str) -> int:
    """
    Compute the number of physical TPU hosts implied by tpuTopology.

    Vertex AI TPU jobs use replicaCount=1 regardless of scale; the actual number
    of physical hosts is encoded in tpuTopology (e.g. "2x4" = 8 total chips).

    Calculation:
        total_chips = product of all dimensions  ("2x4" → 8, "4x4" → 16, "2" → 2)
        chips_per_host = _BUNDLED_ACCELERATOR_COUNT[machine_type]
        hosts = max(1, total_chips // chips_per_host)

    Returns 0 when topology is empty or unparseable -- callers fall back to replicaCount.
    """
    if not topology:
        return 0
    try:
        total_chips = 1
        for dim in topology.lower().split("x"):
            total_chips *= int(dim.strip())
    except (ValueError, AttributeError):
        warnings.warn(
            f"gcp.vertex.training_job.long_running: could not parse tpuTopology "
            f"{topology!r} for machine {machine_type!r} — host count defaults to replicaCount",
            stacklevel=3,
        )
        return 0
    chips_per_host = _BUNDLED_ACCELERATOR_COUNT.get(machine_type, 0)
    if chips_per_host <= 0:
        # Fallback: parse the -Nt suffix common to all Cloud TPU machine names.
        # e.g. "tpu7x-standard-4t" → suffix "4t" → 4 chips/host.
        suffix = (machine_type or "").rsplit("-", 1)[-1]
        if suffix.endswith("t") and suffix[:-1].isdigit():
            chips_per_host = int(suffix[:-1])
    if chips_per_host <= 0:
        warnings.warn(
            f"gcp.vertex.training_job.long_running: unknown chips-per-host for machine "
            f"{machine_type!r} — host count defaults to replicaCount",
            stacklevel=3,
        )
        return 0
    return max(1, total_chips // chips_per_host)


def _parse_worker_pools(
    worker_pool_specs: list,
) -> List[Tuple[Optional[str], Optional[str], int, int, Optional[str]]]:
    """
    Parse per-pool hardware specs from a CustomJob or TrainingPipeline.

    Returns a list of (machine_type, accel_type, accel_count, replica_count, tpu_topology)
    tuples, one per pool. The first element is the primary (chief) pool.

    Returns [] when no specs are provided, or when all entries are malformed.

    Per spec 8.1 and 8.2: `machineType` is required in a pool entry for it to be
    structurally valid.  Entries missing `machineType`, or entries that cannot be
    parsed due to type errors, are silently skipped rather than making the whole
    resource ineligible.

    TPU topology: for TPU machine types (ct5lp-*, ct6e-*, tpu7x-*, etc.), replicaCount
    is always 1 in the API even for multi-host pods. tpuTopology encodes the actual
    chip grid; this function replaces replicaCount with the derived host count.
    tpu_topology is stored in the tuple so callers never need to re-index into the
    original raw specs list (which may have different indices after malformed entries
    are filtered).
    """
    pools = []
    for pool in worker_pool_specs:
        try:
            if not isinstance(pool, dict):
                continue
            machine_spec = pool.get("machineSpec") or {}
            if not isinstance(machine_spec, dict):
                continue
            # machineType is required for a structurally valid pool (spec 8.1, 8.2)
            machine = (machine_spec.get("machineType") or "").strip() or None
            if not machine:
                continue
            replicas = max(1, int(pool.get("replicaCount") or 1))
            accel = (machine_spec.get("acceleratorType") or "").strip() or None
            count = int(machine_spec.get("acceleratorCount") or 0)

            tpu_topo: Optional[str] = None
            if _is_tpu_machine(machine):
                tpu_topo = (machine_spec.get("tpuTopology") or "").strip() or None
                if tpu_topo:
                    host_count = _tpu_topology_host_count(machine, tpu_topo)
                    if host_count > 0:
                        replicas = host_count

            pools.append((machine, accel, count, replicas, tpu_topo))
        except (TypeError, ValueError):
            # Malformed pool entry: skip for hardware classification (spec 8.1, 8.2)
            continue
    return pools


def _is_tpu_machine(machine_type: Optional[str]) -> bool:
    """
    Return True if the machine type is a Cloud TPU node (Vertex AI TPU training).

    TPU machines use machineType + tpuTopology rather than acceleratorType.
    Per-family anchor rules:
      ct4-  exact dash anchor (avoids hypothetical ct40-* collision)
      ct5*  covers ct5l-/ct5lp-/ct5p- and future ct5 sub-families
      ct6*  covers ct6e-/ct6a- and future ct6 sub-families
      ct7*  forward-compat for TPU v7 machines
      tpu*  legacy tpu7x-* and any future tpu-prefixed names
    """
    m = machine_type or ""
    return m.startswith(_TPU_MACHINE_PREFIXES)


def _is_bundled_machine(machine_type: Optional[str]) -> bool:
    """
    Return True if the machine type has accelerator cost bundled (no separate add-on).

    Covers GPU machine families (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*) and
    Cloud TPU machine types that expose TPU via machineType + tpuTopology.
    """
    m = machine_type or ""
    return m.startswith(_BUNDLED_GPU_PREFIXES) or _is_tpu_machine(machine_type)


def _has_accelerator_hardware(
    pools: List[Tuple[Optional[str], Optional[str], int, int, Optional[str]]],
) -> bool:
    """
    Return True if any worker pool uses GPU or TPU accelerator hardware.

    Two independent detection paths (spec 8.1):
    - Explicit path: acceleratorType is a recognized enum AND acceleratorCount > 0
    - Bundled path: machine type is in a GPU or TPU family (_is_bundled_machine)

    acceleratorType alone with count == 0 does NOT classify a pool as accelerated.
    Empty pools → False. Unknown hardware does NOT imply accelerated workload.
    """
    return any(
        ((a or "").upper() in _ACCELERATOR_TYPES and c > 0) or _is_bundled_machine(m)
        for m, a, c, r, *_ in pools
    )


def _hardware_label(
    machine_type: Optional[str],
    accel_type: Optional[str],
    accel_count: int,
    total_replicas: int,
    tpu_topology: Optional[str] = None,
) -> str:
    """Build a compact hardware label for title/summary."""
    parts = []
    if machine_type:
        label = machine_type
        if tpu_topology and _is_tpu_machine(machine_type):
            label = f"{machine_type} [{tpu_topology}]"
        parts.append(label)
    if accel_type and accel_type != "ACCELERATOR_TYPE_UNSPECIFIED" and accel_count > 0:
        count_str = f"{accel_count}×" if accel_count > 1 else ""
        parts.append(f"{count_str}{accel_type}")
    if total_replicas > 1:
        parts.append(f"×{total_replicas} hosts" if tpu_topology else f"×{total_replicas} workers")
    return ", ".join(parts)
