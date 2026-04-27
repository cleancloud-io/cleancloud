import json
import math
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
# Use _is_tpu_machine() rather than calling .startswith() with this tuple directly —
# that function enforces the correct per-family anchor rules.
_TPU_MACHINE_PREFIXES = ("ct4-", "ct5", "ct6", "ct7", "tpu")

# High-cost accelerator types: GPU families and TPU pods.
# Named _ACCELERATOR_TYPES (not _GPU_ACCELERATORS) because TPU variants are included.
# Keep in sync with MachineSpec.AcceleratorType in the Vertex AI REST reference.
# Entries marked [est] have no published GCP Vertex AI pricing; costs are estimates.
_ACCELERATOR_TYPES = frozenset(
    {
        # Volta / Turing / Ampere
        "NVIDIA_TESLA_K80",
        "NVIDIA_TESLA_P4",
        "NVIDIA_TESLA_P100",
        "NVIDIA_TESLA_T4",
        "NVIDIA_TESLA_V100",
        "NVIDIA_TESLA_A100",  # A100 40GB (add-on; a2-* bundles it)
        "NVIDIA_A100_80GB",  # A100 80GB (add-on; a2-ultragpu-* bundles it)
        # Ada / Hopper / Blackwell
        "NVIDIA_L4",
        "NVIDIA_H100_80GB",
        "NVIDIA_H100_MEGA_80GB",
        "NVIDIA_H200_141GB",  # [est] H200 141GB
        "NVIDIA_B200",  # [est] Blackwell B200 — pre-GA
        "NVIDIA_GB200",  # [est] Grace Blackwell NVL — pre-GA
        "NVIDIA_RTX_PRO_6000",  # [est] RTX Pro 6000 Ada
        # TPU
        "TPU_V2",
        "TPU_V3",
        "TPU_V4_POD",
        "TPU_V5_LITEPOD",  # [est] v5e litepod
    }
)

# Monthly cost per machine type (on-demand, us-central1, 730 h/month).
# Bundled GPU families (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*) include accelerator cost.
# TPU machine types (ct5lp-*, ct6e-*, tpu7x-*, …) include TPU chip cost.
_MACHINE_MONTHLY_COST = {
    "n1-standard-1": 35.0,
    "n1-standard-2": 69.0,
    "n1-standard-4": 138.0,
    "n1-standard-8": 277.0,
    "n1-standard-16": 554.0,
    "n1-standard-32": 1_107.0,
    "n1-standard-64": 2_214.0,
    "n1-standard-96": 3_321.0,
    "n1-highmem-2": 93.0,
    "n1-highmem-4": 187.0,
    "n1-highmem-8": 374.0,
    "n1-highmem-16": 748.0,
    "n1-highmem-32": 1_496.0,
    "n1-highmem-64": 2_991.0,
    "n1-highmem-96": 4_487.0,
    "n2-standard-2": 78.0,
    "n2-standard-4": 157.0,
    "n2-standard-8": 314.0,
    "n2-standard-16": 628.0,
    "n2-standard-32": 1_255.0,
    "c2-standard-4": 166.0,
    "c2-standard-8": 332.0,
    "c2-standard-16": 664.0,
    "c2-standard-30": 1_245.0,
    "c2-standard-60": 2_490.0,
    # a2-* (A100 40GB bundled)
    "a2-highgpu-1g": 2_933.0,
    "a2-highgpu-2g": 5_866.0,
    "a2-highgpu-4g": 11_732.0,
    "a2-highgpu-8g": 23_464.0,
    "a2-megagpu-16g": 46_927.0,
    # a2-ultragpu-* (A100 80GB bundled)
    "a2-ultragpu-1g": 5_103.0,
    "a2-ultragpu-2g": 10_206.0,
    "a2-ultragpu-4g": 20_412.0,
    "a2-ultragpu-8g": 40_824.0,
    # a3-* (H100 SXM5 bundled) — 1g/2g/4g priced proportionally to published 8g rate
    "a3-highgpu-1g": 7_299.0,  # [est] 1/8 of 8g
    "a3-highgpu-2g": 14_598.0,  # [est] 2/8 of 8g
    "a3-highgpu-4g": 29_197.0,  # [est] 4/8 of 8g
    "a3-highgpu-8g": 58_393.0,  # published GCP rate
    "a3-megagpu-8g": 65_000.0,  # [est] 8× H100, high-mem NVLink config
    "a3-ultragpu-8g": 80_000.0,  # [est] 8× H200 141GB
    # a4-* (B200 bundled) — [est] no published GCP rate
    "a4-highgpu-8g": 100_000.0,  # [est] 8× B200 next-gen flagship
    # a4x-* (GB200 NVL bundled) — [est]
    "a4x-highgpu-4g": 60_000.0,  # [est] 4× GB200 NVLink
    # g2-* (L4 bundled)
    "g2-standard-4": 706.0,
    "g2-standard-8": 1_060.0,
    "g2-standard-12": 1_590.0,
    "g2-standard-16": 2_120.0,
    "g2-standard-24": 3_180.0,
    "g2-standard-32": 4_241.0,
    "g2-standard-48": 6_361.0,
    "g2-standard-96": 12_722.0,
    # g4-* (RTX Pro 6000 Ada bundled) — documented sizes per Vertex AI training docs:
    # 48=1 GPU, 96=2 GPUs, 192=4 GPUs, 384=8 GPUs
    # Pricing [est]: no published GCP rate; ~$2,800/GPU/mo (RTX Pro 6000 + host vCPU share)
    "g4-standard-48": 2_800.0,  # [est] 1 GPU
    "g4-standard-96": 5_600.0,  # [est] 2 GPUs
    "g4-standard-192": 11_200.0,  # [est] 4 GPUs
    "g4-standard-384": 22_400.0,  # [est] 8 GPUs
    # Cloud TPU machine types — cost is the TPU chip(s) + host VM bundled
    # TPU v5e (ct5lp-hightpu-*): ~$1.20/chip-hr (published)
    "ct5lp-hightpu-1t": 876.0,
    "ct5lp-hightpu-4t": 3_504.0,
    "ct5lp-hightpu-8t": 7_008.0,
    # TPU v5p (ct5p-hightpu-*): ~$1.80/chip-hr [est]
    "ct5p-hightpu-4t": 5_256.0,  # [est]
    "ct5p-hightpu-8t": 10_512.0,  # [est]
    # TPU v6e (ct6e-standard-*): ~$1.80/chip-hr [est]
    "ct6e-standard-1t": 1_314.0,  # [est] 1 chip
    "ct6e-standard-4t": 5_256.0,  # [est] 4 chips
    "ct6e-standard-8t": 10_512.0,  # [est] 8 chips
}
_DEFAULT_MACHINE_MONTHLY_COST = 150.0
# Fallback for unrecognized TPU machine types — avoids the $0.21/hr generic default
# massively underestimating a 4-chip-equivalent TPU job.
_DEFAULT_TPU_MONTHLY_COST = 10_000.0  # ~$13.70/hr, conservative multi-host TPU estimate

# Duration-tiered fallback costs for TrainingPipelines when workerPoolSpecs cannot be parsed.
# Longer-running pipelines are statistically more likely to be GPU-backed workloads.
# Three tiers (inlined in find_long_running_vertex_training_jobs):
#   >24h → $20/hr (probable multi-GPU), 6–24h → $5/hr (ambiguous), else → $1/hr.
# These are not exact — large GPU pipelines cost $50–$500+/hr; these are indicative minimums.

# Additional monthly cost per accelerator unit for n1-*/n2-*/c2-* machines (add-on pricing).
# Bundled families (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*, ct*/tpu7x-*) already include
# accelerator cost in _MACHINE_MONTHLY_COST — no add-on needed for those.
# All costs: us-central1 on-demand, 730 h/month.
# Entries marked [est] use conservative estimates — no published GCP Vertex AI rate.
_ACCELERATOR_MONTHLY_COST_EACH = {
    # Volta / Turing / Ampere (published GCP rates)
    "NVIDIA_TESLA_K80": 392.0,
    "NVIDIA_TESLA_P4": 438.0,  # ~$0.60/hr
    "NVIDIA_TESLA_P100": 1_022.0,
    "NVIDIA_TESLA_T4": 311.0,
    "NVIDIA_TESLA_V100": 1_385.0,
    "NVIDIA_TESLA_A100": 2_933.0,  # A100 40GB add-on (n1-* only; a2-* bundles)
    "NVIDIA_A100_80GB": 5_103.0,  # A100 80GB add-on
    # Ada / Hopper (published GCP rates)
    "NVIDIA_L4": 680.0,
    "NVIDIA_H100_80GB": 8_000.0,
    "NVIDIA_H100_MEGA_80GB": 10_000.0,
    # Newer accelerators — [est] conservative estimates; update when GCP publishes rates
    "NVIDIA_H200_141GB": 11_000.0,  # [est] ~1.4× H100 80GB
    "NVIDIA_B200": 18_000.0,  # [est] Blackwell B200 — pre-GA
    "NVIDIA_GB200": 22_000.0,  # [est] Grace Blackwell NVL — pre-GA
    "NVIDIA_RTX_PRO_6000": 2_200.0,  # [est] RTX Pro 6000 Ada workstation
    # TPU (published GCP rates)
    "TPU_V2": 3_811.0,
    "TPU_V3": 5_840.0,
    "TPU_V4_POD": 9_402.0,
    "TPU_V5_LITEPOD": 3_500.0,  # [est] v5e litepod per unit
}

_HOURS_PER_MONTH = 730.0

# Machine type prefixes and accelerator types whose pricing is estimated (no published GCP rate).
# Used to tag findings with pricing_confidence="partial_estimate" vs "published".
_PRICING_ESTIMATED_MACHINE_PREFIXES = (
    "a3-megagpu",
    "a3-ultragpu",  # H200/future a3 variants
    "a4-",  # B200
    "a4x-",  # GB200 NVLink
    "g4-",  # RTX Pro 6000 Ada
    "ct5p-",  # TPU v5p
    "ct6e-",  # TPU v6e
    "tpu7x-",  # TPU v7 (pre-GA)
)
_PRICING_ESTIMATED_ACCEL_TYPES = frozenset(
    {
        "NVIDIA_H200_141GB",
        "NVIDIA_B200",
        "NVIDIA_GB200",
        "NVIDIA_RTX_PRO_6000",
        "TPU_V5_LITEPOD",
    }
)

# Full accelerator count per bundled machine type — used for co-scheduling cost correction.
# Vertex AI may co-schedule floor(N/accel_count) replicas onto one VM when accel_count <= N//2,
# so each replica pays only 1/replicas_per_vm of the machine cost.
# g2-standard-32 is omitted: its GPU count is ambiguous in GCP docs (co-scheduling impact is low
# for single-GPU machines anyway).
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
    # g4-* (RTX Pro 6000 Ada) — 48=1 GPU, 96=2 GPUs, 192=4 GPUs, 384=8 GPUs
    "g4-standard-48": 1,
    "g4-standard-96": 2,
    "g4-standard-192": 4,
    "g4-standard-384": 8,
    # Cloud TPU machines — chip count encoded in machine name suffix (e.g. -4t = 4 chips)
    "ct5lp-hightpu-1t": 1,
    "ct5lp-hightpu-4t": 4,
    "ct5lp-hightpu-8t": 8,
    "ct5p-hightpu-4t": 4,
    "ct5p-hightpu-8t": 8,
    "ct6e-standard-1t": 1,
    "ct6e-standard-4t": 4,
    "ct6e-standard-8t": 8,
    "tpu7x-standard-4t": 4,  # TPU v7 — 4 chips/host (pre-GA)
}

# Jobs running longer than this multiple of the threshold are almost certainly runaway
_RUNAWAY_MULTIPLIER = 3

# Default threshold
_DEFAULT_LONG_RUNNING_HOURS = 24

# Fraction of threshold at which GPU early-warning fires (before crossing threshold).
# 90% reduces noise vs 75%: a 21.6h GPU job (at 24h threshold) is genuinely unusual;
# an 18h job is still plausible for legitimate large-scale training.
_EARLY_WARNING_FRACTION = 0.9

# (project_id, resource) pairs where locations/- wildcard returned 400 — fall back
# to per-region calls for that specific combination.
# Keyed per (project_id, resource) so:
#   - customJobs and trainingPipelines are tracked independently (one may support wildcard)
#   - project A's failure does not suppress the wildcard attempt for project B
# Written lazily on first 400; read on subsequent scans in the same process.
# A race between parallel calls is benign: at worst both try the wildcard once and
# both add the same key — set.add is GIL-protected and idempotent.
_wildcard_unsupported: set[tuple[str, str]] = set()

# Known Vertex AI locations for fallback when the wildcard is not supported.
# GCP adds new regions over time — this list may miss recently-announced locations.
# To ensure full coverage: grant locations/- wildcard support (roles/aiplatform.viewer
# is sufficient for most projects), or extend this list when new regions are confirmed.
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


def find_long_running_vertex_training_jobs(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    long_running_hours: int = _DEFAULT_LONG_RUNNING_HOURS,
    early_warning_fraction: float = _EARLY_WARNING_FRACTION,
    runaway_multiplier: int = _RUNAWAY_MULTIPLIER,
    expensive_hourly_threshold: float = 20.0,
) -> List[Finding]:
    """
    Find Vertex AI CustomJobs and TrainingPipelines that have been running
    longer than expected.

    Most training jobs complete within a few hours. A job still running after
    24 hours is unusual — it may be hung, deadlocked in distributed training,
    caught in an OOM loop, or simply forgotten after a project was cancelled.

    GPU-backed training is especially costly: an A100 40GB node (a2-highgpu-1g)
    runs at ~$4/hr; an a3-highgpu-8g (8 × H100) runs at ~$80/hr. Multi-worker
    jobs multiply cost linearly.

    Detection logic:
    - Queries both CustomJobs (state="JOB_STATE_RUNNING") and TrainingPipelines
      (state="PIPELINE_STATE_RUNNING") via the Vertex AI REST API, in parallel
    - Duration is computed from startTime (when compute began billing); falls
      back to createTime if startTime is absent (jobs stuck in pre-run phases)
    - Hardware: CustomJobs expose workerPoolSpecs directly; TrainingPipelines
      attempt to parse workerPoolSpecs from trainingTaskInputs (handling both
      dict and JSON-string encoding) before falling back to a neutral hourly
      estimate (~$3/hr). Unknown hardware does NOT set is_accelerator=True — is_accelerator
      is derived strictly from parsed pool data.

    Cost aggregation:
    - Each pool's cost = _estimate_hourly_rate_per_replica × effective_replicas
    - For GPU/CPU pools: effective_replicas = replicaCount from API
    - For TPU pools: effective_replicas = physical host count derived from tpuTopology
      (Vertex always reports replicaCount=1 for TPU regardless of pod size)
    - Total burn rate = sum across ALL pools (not primary pool × total_replicas)
    - This correctly handles heterogeneous jobs (e.g., a2-highgpu chief + n1 workers)

    Confidence:
    - HIGH: duration >= long_running_hours × 3 — clearly runaway
    - MEDIUM: duration >= long_running_hours — worth reviewing
    - MEDIUM (early warning): accelerator job or expensive CPU cluster
      (hourly_rate_total > expensive_hourly_threshold) at 90–100% of threshold

    Risk:
    - CRITICAL: HIGH confidence + GPU/accelerator hardware
    - HIGH:     HIGH confidence, CPU-only
    - MEDIUM:   all MEDIUM-confidence findings (GPU or CPU alike)

    Cost reported:
    - Accrued cost so far: duration_hours × hourly_burn_rate (all worker pools)
    - estimated_monthly_cost_usd is intentionally None — training jobs are
      transient, not recurring monthly expenses
    - Pricing is a static estimate (us-central1, on-demand); actual cost varies
      by region and committed use discounts

    IAM permissions required:
    - aiplatform.customJobs.list  (roles/aiplatform.viewer)
    - aiplatform.trainingPipelines.list  (roles/aiplatform.viewer)
    """
    long_running_hours = max(long_running_hours, 1)
    early_warning_fraction = max(0.0, min(early_warning_fraction, 1.0))
    runaway_multiplier = max(1, runaway_multiplier)
    expensive_hourly_threshold = max(0.0, expensive_hourly_threshold)

    session = AuthorizedSession(credentials)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []
    skipped_jobs: int = 0

    # Query both resource types in parallel — each may independently need the
    # per-region fallback if the locations/- wildcard returns 400.
    # Results are collected independently: a transient failure on one resource type
    # still yields findings from the other. PermissionError propagates immediately
    # (missing IAM is user-actionable and should not be silently swallowed).
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
        name = job.get("name", "")
        display_name = job.get("displayName", "")
        location = _parse_location(name) or "unknown"

        if region_filter and location.lower() != region_filter.lower():
            continue

        # Duration: prefer startTime (actual compute start); fall back to createTime
        start_str = job.get("startTime") or job.get("createTime", "")
        if not start_str:
            skipped_jobs += 1
            continue
        try:
            start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            skipped_jobs += 1
            continue

        duration_hours = (now - start_dt).total_seconds() / 3600

        # Hardware: parse per-pool specs for accurate cost aggregation.
        # Done before the duration filter so expensive_hourly_threshold can be evaluated.
        # CustomJob exposes workerPoolSpecs directly. TrainingPipeline may embed
        # them in trainingTaskInputs (works for custom-training pipelines) or may
        # not expose them at all (AutoML, managed job types).
        if job_type == "customJob":
            raw_worker_specs = job.get("jobSpec", {}).get("workerPoolSpecs", [])
            pools = _parse_worker_pools(raw_worker_specs)
            hardware_unknown = False
        else:
            task_inputs = job.get("trainingTaskInputs") or {}
            # The field is occasionally returned as a JSON string rather than a parsed dict
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

        # Accelerator detection: derived from actual hardware data only.
        # hardware_unknown does not imply GPU — it only triggers duration-tiered fallback
        # cost, keeping risk conservatively MEDIUM.
        is_accelerator = _has_accelerator_hardware(pools)

        # Cost: sum per-pool cost × replica_count across ALL pools.
        # This correctly handles heterogeneous clusters (different machine types per pool).
        # For TPU jobs: each "replica" in the pool tuple is a physical host (derived from
        # tpuTopology), so _total_hourly_rate correctly prices host_count × per-host cost.
        if pools:
            total_replicas = sum(r for _, _, _, r in pools) or 1
            primary_machine = pools[0][0]
            primary_accel = pools[0][1]
            primary_accel_count = pools[0][2]
            hourly_rate_total = _total_hourly_rate(pools)
            # Capture TPU topology for label — present in raw spec but not in pool tuple
            primary_tpu_topology: Optional[str] = None
            if raw_worker_specs and primary_machine and _is_tpu_machine(primary_machine):
                primary_tpu_topology = (
                    raw_worker_specs[0].get("machineSpec", {}).get("tpuTopology") or None
                )
        else:
            total_replicas = 1
            primary_machine = None
            primary_accel = None
            primary_accel_count = 0
            primary_tpu_topology = None
            # Duration-scaled fallback: longer jobs are more likely to be GPU-class pipelines.
            # Tiers: >24h → $20/hr (probable multi-GPU), >6h → $5/hr (ambiguous), else → $1/hr.
            # Still conservative — large GPU pipelines can cost $50–$500+/hr.
            if duration_hours > 24:
                hourly_rate_total = 20.0
            elif duration_hours > 6:
                hourly_rate_total = 5.0
            else:
                hourly_rate_total = 1.0

        # Early-exit: skip all jobs below early_warning_fraction of the threshold.
        # The early-warning band (fraction–100%) is evaluated in the confidence block below.
        if duration_hours < long_running_hours * early_warning_fraction:
            continue

        # Raw values — no intermediate rounding; format inline, round once for storage.
        # accrued_raw is the true computed cost and is stored in details unchanged.
        # accrued_display is capped at $1M to avoid distorting summaries with stale-table
        # outliers, but the raw value is always preserved for analysis.
        duration_display = round(duration_hours, 1)
        accrued_raw = hourly_rate_total * duration_hours
        if accrued_raw > 1_000_000:
            warnings.warn(
                f"gcp.vertex.training_job.long_running: accrued cost estimate "
                f"${accrued_raw:,.0f} exceeds $1M — cost table may be stale or topology "
                f"unusually large; capping display at $1,000,000",
                stacklevel=2,
            )
        accrued_display = min(accrued_raw, 1_000_000.0)
        overrun_hours = max(0.0, duration_hours - long_running_hours)

        # Confidence
        if duration_hours >= long_running_hours * runaway_multiplier:
            confidence = ConfidenceLevel.HIGH
        elif duration_hours >= long_running_hours:
            confidence = ConfidenceLevel.MEDIUM
        else:
            # early_warning_fraction–100% of threshold: fire early for accelerators or
            # expensive CPU clusters. The replica cap (≤50) suppresses early warnings for
            # very large CPU-only clusters that are likely intentional distributed workloads
            # (e.g. 200-node Spark/Beam jobs); accelerators are never gated by replica count.
            expensive_cpu = hourly_rate_total > expensive_hourly_threshold and total_replicas <= 50
            if is_accelerator or expensive_cpu:
                confidence = ConfidenceLevel.MEDIUM
            else:
                continue

        # Risk model:
        #   HIGH confidence + accelerator (GPU/TPU) → CRITICAL
        #   HIGH confidence + CPU or unknown hw     → HIGH
        #     (unknown hardware + runaway lands here via is_accelerator=False — suspicious enough
        #      to warrant HIGH without an actual accelerator spec; avoids false CRITICAL)
        #   MEDIUM confidence                       → MEDIUM
        if confidence == ConfidenceLevel.HIGH:
            risk = RiskLevel.CRITICAL if is_accelerator else RiskLevel.HIGH
        else:
            risk = RiskLevel.MEDIUM

        # Human-readable job label
        job_id = name.rsplit("/", 1)[-1] if name else ""
        label = display_name or job_id

        hardware_label = _hardware_label(
            primary_machine,
            primary_accel,
            primary_accel_count,
            total_replicas,
            tpu_topology=primary_tpu_topology,
        )

        threshold_detail = (
            f"exceeded by {math.floor(overrun_hours)}h"
            if overrun_hours > 0
            else f"{round(long_running_hours - duration_hours, 1)}h below threshold (early warning)"
        )

        title = (
            f"Long-Running Vertex Training Job ({duration_display}h"
            + (f", {hardware_label}" if hardware_label else "")
            + ")"
        )

        primary_bundled = _is_bundled_machine(primary_machine)
        signals = [
            f"Job status: RUNNING for {duration_display}h "
            f"(threshold: {long_running_hours}h, {threshold_detail})",
            (
                f"Burn rate: ~${hourly_rate_total:.2f}/hr across {total_replicas} workers"
                if total_replicas > 1
                else f"Burn rate: ~${hourly_rate_total:.2f}/hr"
            ),
        ]
        if hardware_label:
            signals.append(
                f"Hardware: {hardware_label}"
                + (" (GPU/accelerator)" if is_accelerator and not primary_bundled else "")
            )
        if total_replicas > 1:
            signals.append(
                f"Distributed training ({total_replicas} workers) — "
                f"long durations may be expected for large-scale jobs"
            )
        signals.append(
            f"Accrued cost: ~${accrued_display:,.2f} "
            f"(${hourly_rate_total:.2f}/hr × {duration_display}h elapsed, "
            f"us-central1 on-demand — actual cost varies by region and committed use discounts)"
        )
        if hardware_unknown:
            signals.append(
                f"TrainingPipeline: hardware spec not exposed in API response — "
                f"cost estimate uses duration-scaled placeholder (~${hourly_rate_total:.2f}/hr); "
                "actual cost varies widely: ~$0.20–$1/hr for small CPU pipelines, "
                "$50–$100+/hr for large accelerator jobs"
            )

        not_checked = [
            "Intentional long-running distributed training (LLM pre-training, large fine-tunes)",
            "Checkpoint saving — job may be making progress without visible status updates",
            "Committed use discounts — actual cost may be significantly lower than on-demand estimate",
            "Preemptible/Spot workers — cost and interruption semantics differ",
        ]

        evidence = Evidence(
            signals_used=signals,
            signals_not_checked=not_checked,
            time_window=f"{duration_display}h",
        )

        findings.append(
            Finding(
                provider="gcp",
                rule_id="gcp.vertex.training_job.long_running",
                resource_type="gcp.vertex.training_job",
                resource_id=name or job_id,
                region=location,
                title=title,
                summary=(
                    f"Vertex AI {job_type} '{label}' has been RUNNING for {duration_display}h"
                    + (f" ({hardware_label})" if hardware_label else "")
                    + f", accruing ~${accrued_display:,.2f} so far."
                    + f" Most training jobs complete well under {long_running_hours} hours unless intentionally long-running."
                ),
                reason=(
                    f"Job has been RUNNING for {duration_display}h "
                    f"(threshold: {long_running_hours}h)"
                ),
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                # Training jobs are transient — setting estimated_monthly_cost_usd would
                # corrupt monthly savings totals. Accrued cost lives in details only.
                estimated_monthly_cost_usd=None,
                details={
                    "job_name": name,
                    "display_name": display_name or None,
                    "job_type": job_type,
                    "location": location,
                    "machine_type": primary_machine or None,
                    "accelerator_type": primary_accel or None,
                    "accelerator_count": (primary_accel_count if primary_accel_count else None),
                    "tpu_topology": primary_tpu_topology,
                    "total_workers": total_replicas,
                    "is_accelerator": is_accelerator,
                    "hardware_unknown": hardware_unknown,
                    "duration_hours": round(duration_hours, 2),
                    "long_running_hours_threshold": long_running_hours,
                    "burn_rate_per_hour": hourly_rate_total,
                    "overrun_hours": overrun_hours,
                    "accrued_cost_usd": accrued_raw,
                    "cost_type": "accrued_to_date",
                    "pricing_source": (
                        "conservative_pipeline_default"
                        if hardware_unknown
                        else "static_estimate_us_central1"
                    ),
                    "pricing_confidence": (
                        "pipeline_default" if hardware_unknown else _pricing_confidence(pools)
                    ),
                    "pricing_scope": "us-central1_reference",
                    "pricing_note": (
                        f"Cost estimated using us-central1 on-demand baseline; "
                        f"actual job is in {location}"
                        + (
                            " — pricing is likely similar"
                            if location.startswith("us-")
                            else " — regional pricing may differ significantly"
                        )
                    ),
                },
            )
        )

    if skipped_jobs > 0:
        warnings.warn(
            f"gcp.vertex.training_job.long_running: {skipped_jobs} job(s) skipped "
            f"due to missing or unparseable timestamps — findings may be incomplete",
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
            if resp.status_code == 404:
                return []
            if resp.status_code == 400:
                return None  # signal caller to try fallback
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get(resource, []))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        return results

    # Fast path: wildcard covers all regions in one paginated sequence.
    # Skip if we already know this project+resource combination doesn't support it.
    cache_key = (project_id, resource)
    if cache_key not in _wildcard_unsupported:
        result = _paginate(f"{base_url}/-/{resource}")
        if result is not None:
            return result
        _wildcard_unsupported.add(cache_key)

    # Fallback: per-location queries
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


def _parse_location(name: str) -> str:
    """Extract location from resource name: projects/{p}/locations/{loc}/.../{id}"""
    parts = name.split("/")
    try:
        idx = parts.index("locations")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


def _tpu_topology_host_count(machine_type: str, topology: str) -> int:
    """
    Compute the number of physical TPU hosts implied by tpuTopology.

    Vertex AI TPU jobs use replicaCount=1 regardless of scale; the actual number
    of physical hosts is encoded in tpuTopology (e.g. "2x4" = 8 total chips).

    Calculation:
        total_chips = product of all dimensions  ("2x4" → 8, "4x4" → 16, "2" → 2)
        chips_per_host = _BUNDLED_ACCELERATOR_COUNT[machine_type]
        hosts = max(1, total_chips // chips_per_host)

    Returns 0 when topology is empty or unparseable — callers fall back to replicaCount.
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
        # This handles future variants automatically without requiring a table entry.
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
) -> List[Tuple[Optional[str], Optional[str], int, int]]:
    """
    Parse per-pool hardware specs from a CustomJob or TrainingPipeline.

    Returns a list of (machine_type, accel_type, accel_count, replica_count) tuples,
    one per pool. The first element is the primary (chief) pool.

    Returns [] when no specs are provided; callers should apply defaults in that case.
    Cost must be summed across all pools — do not use primary pool × total_replicas,
    as secondary pools often have different (and more expensive) machine types.

    TPU topology: for TPU machine types (ct5lp-*, ct6e-*, tpu7x-*, etc.), replicaCount
    is always 1 in the API even for multi-host pods. tpuTopology encodes the actual
    chip grid; this function replaces replicaCount with the derived host count so that
    _total_hourly_rate() correctly prices the whole pod.
    """
    pools = []
    for pool in worker_pool_specs:
        machine_spec = pool.get("machineSpec", {})
        replicas = max(1, int(pool.get("replicaCount", 1)))
        machine = machine_spec.get("machineType") or None
        accel = machine_spec.get("acceleratorType") or None
        count = int(machine_spec.get("acceleratorCount", 0))

        # For TPU machines replicaCount is always 1; derive real host count from topology.
        if machine and _is_tpu_machine(machine):
            topology = machine_spec.get("tpuTopology") or ""
            host_count = _tpu_topology_host_count(machine, topology)
            if host_count > 0:
                replicas = host_count

        pools.append((machine, accel, count, replicas))
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
    Cloud TPU machine types (ct5lp-*, ct5p-*, ct6e-*, etc.) that expose TPU
    via machineType + tpuTopology rather than acceleratorType.
    """
    m = machine_type or ""
    return m.startswith(_BUNDLED_GPU_PREFIXES) or _is_tpu_machine(machine_type)


def _has_accelerator_hardware(
    pools: List[Tuple[Optional[str], Optional[str], int, int]],
) -> bool:
    """
    Return True if any worker pool uses GPU or TPU accelerator hardware.

    Detects accelerators via two structured paths:
    - Explicit accelerator type in _ACCELERATOR_TYPES (GPU families and TPU pods via add-on)
    - _is_bundled_machine(m): covers _BUNDLED_GPU_PREFIXES (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*)
      and _is_tpu_machine() (ct4-*/ct5*/ct6*/ct7*/tpu*)

    Empty pools → False. Unknown hardware does NOT imply accelerated workload.
    Relies on structured prefix lists only — no substring matching.
    """
    return any(
        (a or "").upper() in _ACCELERATOR_TYPES or _is_bundled_machine(m) for m, a, c, r in pools
    )


def _estimate_hourly_rate_per_replica(
    machine_type: Optional[str],
    accel_type: Optional[str],
    accel_count: int,
) -> float:
    """
    Estimate hourly cost for a single replica (one worker node).

    Bundled families (a2-*, a3-*, a4-*, a4x-*, g2-*, g4-*, ct*/tpu7x-*) include accelerator
    cost in the machine price. n1-*/n2-*/c2-* add accelerator cost separately.

    Co-scheduling (bundled machines only): when accel_count <= N//2 (where N is the machine's
    full accelerator count from _BUNDLED_ACCELERATOR_COUNT), Vertex AI may place
    floor(N/accel_count) replicas onto one VM. In that case each replica shares the machine
    cost proportionally — machine_hourly is divided by replicas_per_vm. When accel_count is 0
    or unknown, the full machine price is charged conservatively.
    """
    # For unrecognized TPU machine types use the TPU-specific default to avoid the
    # generic $150/mo fallback massively underestimating a real TPU job.
    _mt = machine_type or ""
    if _mt in _MACHINE_MONTHLY_COST:
        machine_monthly = _MACHINE_MONTHLY_COST[_mt]
    elif _is_tpu_machine(_mt) or "tpu" in _mt.lower():
        # Second condition is a defensive catch for future TPU naming patterns that
        # _is_tpu_machine() might miss — avoids silent 70× underestimate vs generic $150/mo.
        machine_monthly = _DEFAULT_TPU_MONTHLY_COST
    else:
        machine_monthly = _DEFAULT_MACHINE_MONTHLY_COST
    machine_hourly = machine_monthly / _HOURS_PER_MONTH

    # Co-scheduling correction for bundled machines.
    # Only applies when accel_count divides machine_gpu_count evenly (clean partition)
    # and accel_count <= machine_gpu_count (requesting more GPUs than exist is invalid).
    if _is_bundled_machine(machine_type) and accel_count >= 1:
        machine_gpu_count = _BUNDLED_ACCELERATOR_COUNT.get(machine_type or "", 0)
        if (
            machine_gpu_count > 0
            and accel_count <= machine_gpu_count
            and machine_gpu_count % accel_count == 0
        ):
            replicas_per_vm = max(1, machine_gpu_count // accel_count)
            machine_hourly = machine_hourly / replicas_per_vm

    accelerator_hourly = 0.0
    if accel_type and accel_type in _ACCELERATOR_MONTHLY_COST_EACH:
        if not _is_bundled_machine(machine_type):
            accelerator_hourly = (
                _ACCELERATOR_MONTHLY_COST_EACH[accel_type] / _HOURS_PER_MONTH
            ) * max(accel_count, 1)

    return machine_hourly + accelerator_hourly


def _pricing_confidence(
    pools: List[Tuple[Optional[str], Optional[str], int, int]],
) -> str:
    """
    Return "published" if all machine types and accelerators in the pool list have
    published GCP pricing, otherwise "partial_estimate".
    """
    for m, a, _c, _r in pools:
        mt = m or ""
        if mt.startswith(_PRICING_ESTIMATED_MACHINE_PREFIXES):
            return "partial_estimate"
        if (a or "").upper() in _PRICING_ESTIMATED_ACCEL_TYPES:
            return "partial_estimate"
    return "published"


def _total_hourly_rate(
    pools: List[Tuple[Optional[str], Optional[str], int, int]],
) -> float:
    """
    Sum hourly burn rate across all worker pools.

    Each pool contributes _estimate_hourly_rate_per_replica × replica_count.
    Correctly handles heterogeneous jobs (different machine types per pool).
    """
    return sum(_estimate_hourly_rate_per_replica(m, a, c) * r for m, a, c, r in pools)


def _hardware_label(
    machine_type: Optional[str],
    accel_type: Optional[str],
    accel_count: int,
    total_replicas: int,
    tpu_topology: Optional[str] = None,
) -> str:
    """Build a compact hardware label for title/summary.

    For TPU machines, tpu_topology (e.g. "2x4") is appended when non-empty
    because the machine name alone (e.g. "ct5lp-hightpu-8t") does not convey
    the full chip grid or host count.
    """
    parts = []
    if machine_type:
        label = machine_type
        if tpu_topology and _is_tpu_machine(machine_type):
            label = f"{machine_type} [{tpu_topology}]"
        parts.append(label)
    if accel_type and accel_type != "ACCELERATOR_TYPE_UNSPECIFIED":
        count_str = f"{accel_count}×" if accel_count > 1 else ""
        parts.append(f"{count_str}{accel_type}")
    if total_replicas > 1:
        parts.append(f"×{total_replicas} hosts" if tpu_topology else f"×{total_replicas} workers")
    return ", ".join(parts)
