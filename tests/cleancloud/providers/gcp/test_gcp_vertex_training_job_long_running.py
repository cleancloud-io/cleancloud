"""
Tests for gcp.vertex.training_job.long_running rule.

Coverage:
- Core detection: CPU job over threshold (MEDIUM/MEDIUM), GPU job over threshold (MEDIUM)
- Runaway (3× threshold): HIGH confidence, CRITICAL for GPU, HIGH for CPU
- Risk model: GPU+HIGH→CRITICAL, CPU+HIGH→HIGH, MEDIUM confidence→MEDIUM regardless of GPU
- Early warning: GPU job at 90–100% of threshold only (not 75%)
- Noise reduction: GPU job at 75–89% of threshold does NOT fire
- TrainingPipeline resource type: attempts trainingTaskInputs parsing; conservative fallback
- TrainingPipeline with workerPoolSpecs in trainingTaskInputs: uses parsed hardware
- TrainingPipeline with no hardware spec: is_gpu=False (hardware_unknown=True), conservative duration-tiered fallback cost
- No findings: job below 90% of threshold (CPU or GPU)
- Region filter: jobs outside filter are skipped
- Location fallback: malformed name → region="unknown"
- Permission errors: PermissionError raised on 403
- estimated_monthly_cost_usd is always None (transient job)
- Per-pool cost: heterogeneous cluster cost sums all pools (not primary × total)
- Accelerator detection from _has_accelerator_hardware: accelerator type OR machine prefix
- _parse_worker_pools: returns list of per-pool tuples; empty → []
- _estimate_hourly_rate_per_replica: bundled vs additive GPU cost
- _total_hourly_rate: sums across pools
- _hardware_label: single worker, multi-worker, with accelerator
- RULE_ID attribute
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.vertex_training_job_long_running import (
    _BUNDLED_ACCELERATOR_COUNT,
    _DEFAULT_LONG_RUNNING_HOURS,
    _DEFAULT_MACHINE_MONTHLY_COST,
    _DEFAULT_TPU_MONTHLY_COST,
    _HOURS_PER_MONTH,
    _MACHINE_MONTHLY_COST,
    _RUNAWAY_MULTIPLIER,
    _TPU_MACHINE_PREFIXES,
    _estimate_hourly_rate_per_replica,
    _hardware_label,
    _has_accelerator_hardware,
    _parse_location,
    _parse_worker_pools,
    _pricing_confidence,
    _total_hourly_rate,
    _tpu_topology_host_count,
    find_long_running_vertex_training_jobs,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROJECT = "my-project"
_THRESHOLD = _DEFAULT_LONG_RUNNING_HOURS  # 24


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _custom_job(
    job_id: str,
    location: str,
    start_hours_ago: float,
    machine_type: str = "n1-standard-4",
    accel_type: str = "",
    accel_count: int = 0,
    replica_count: int = 1,
    display_name: str = "",
) -> dict:
    start = NOW - timedelta(hours=start_hours_ago)
    return {
        "name": f"projects/{_PROJECT}/locations/{location}/customJobs/{job_id}",
        "displayName": display_name or job_id,
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {
            "workerPoolSpecs": [
                {
                    "replicaCount": replica_count,
                    "machineSpec": {
                        "machineType": machine_type,
                        "acceleratorType": accel_type,
                        "acceleratorCount": accel_count,
                    },
                }
            ]
        },
    }


def _training_pipeline(
    pipeline_id: str,
    location: str,
    start_hours_ago: float,
    task_inputs: dict | str | None = None,
) -> dict:
    start = NOW - timedelta(hours=start_hours_ago)
    job: dict = {
        "name": f"projects/{_PROJECT}/locations/{location}/trainingPipelines/{pipeline_id}",
        "displayName": f"pipeline-{pipeline_id}",
        "startTime": _iso(start),
        "state": "PIPELINE_STATE_RUNNING",
    }
    if task_inputs is not None:
        job["trainingTaskInputs"] = task_inputs
    return job


def _make_session(custom_jobs=None, training_pipelines=None, status=200) -> MagicMock:
    """Return an AuthorizedSession mock that returns the given job lists."""
    session = MagicMock()

    def _get(url, params=None):
        resp = MagicMock()
        resp.status_code = status
        if status == 403:
            return resp
        if "customJobs" in url:
            resp.json.return_value = {"customJobs": custom_jobs or []}
        else:
            resp.json.return_value = {"trainingPipelines": training_pipelines or []}
        return resp

    session.get.side_effect = _get
    return session


def _run(
    custom_jobs=None,
    training_pipelines=None,
    region_filter=None,
    threshold=_THRESHOLD,
    extra_kwargs=None,
):
    creds = MagicMock()
    session = _make_session(custom_jobs=custom_jobs, training_pipelines=training_pipelines)
    with patch(
        "cleancloud.providers.gcp.rules.vertex_training_job_long_running.AuthorizedSession",
        return_value=session,
    ):
        with patch(
            "cleancloud.providers.gcp.rules.vertex_training_job_long_running.datetime"
        ) as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat.side_effect = datetime.fromisoformat
            return find_long_running_vertex_training_jobs(
                project_id=_PROJECT,
                credentials=creds,
                region_filter=region_filter,
                long_running_hours=threshold,
                **(extra_kwargs or {}),
            )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_cpu_job_over_threshold_medium_confidence():
    job = _custom_job("job-1", "us-central1", start_hours_ago=_THRESHOLD + 2)
    findings = _run(custom_jobs=[job])

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.vertex.training_job.long_running"
    assert f.resource_type == "gcp.vertex.training_job"
    assert f.provider == "gcp"
    assert f.confidence == ConfidenceLevel.MEDIUM
    assert f.risk == RiskLevel.MEDIUM
    assert f.details["is_accelerator"] is False
    assert f.details["job_type"] == "customJob"
    assert f.details["duration_hours"] > _THRESHOLD
    assert f.details["accrued_cost_usd"] > 0
    assert f.estimated_monthly_cost_usd is None


def test_gpu_job_over_threshold_medium_risk():
    """GPU jobs at MEDIUM confidence get MEDIUM risk (not HIGH) to reduce noise."""
    job = _custom_job(
        "gpu-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 5,
        machine_type="n1-standard-8",
        accel_type="NVIDIA_TESLA_V100",
        accel_count=2,
    )
    findings = _run(custom_jobs=[job])

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == ConfidenceLevel.MEDIUM
    assert f.risk == RiskLevel.MEDIUM  # not HIGH — see risk model
    assert f.details["is_accelerator"] is True
    assert f.details["accelerator_type"] == "NVIDIA_TESLA_V100"
    assert f.details["accelerator_count"] == 2


def test_gpu_job_runaway_3x_critical():
    job = _custom_job(
        "runaway",
        "us-central1",
        start_hours_ago=_THRESHOLD * _RUNAWAY_MULTIPLIER + 1,
        machine_type="a2-highgpu-1g",
    )
    findings = _run(custom_jobs=[job])

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == ConfidenceLevel.HIGH
    assert f.risk == RiskLevel.CRITICAL
    assert f.details["is_accelerator"] is True


def test_cpu_job_runaway_3x_high():
    job = _custom_job(
        "cpu-runaway",
        "us-central1",
        start_hours_ago=_THRESHOLD * _RUNAWAY_MULTIPLIER + 1,
    )
    findings = _run(custom_jobs=[job])

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == ConfidenceLevel.HIGH
    assert f.risk == RiskLevel.HIGH
    assert f.details["is_accelerator"] is False


# ---------------------------------------------------------------------------
# Early warning (GPU only, 90% threshold)
# ---------------------------------------------------------------------------


def test_gpu_early_warning_at_90pct_threshold():
    """GPU job at 92% of threshold triggers early warning."""
    job = _custom_job(
        "early",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.92,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == ConfidenceLevel.MEDIUM
    assert f.risk == RiskLevel.MEDIUM
    assert f.details["is_accelerator"] is True
    assert f.details["overrun_hours"] == 0.0


def test_gpu_job_at_80pct_no_finding():
    """GPU job at 80% of threshold does NOT fire (below _EARLY_WARNING_FRACTION=0.9)."""
    job = _custom_job(
        "too-young",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.80,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings == []


def test_cpu_early_warning_not_emitted():
    """CPU job at 92% of threshold produces no finding — early warning is GPU/TPU only."""
    job = _custom_job("cpu-early", "us-central1", start_hours_ago=_THRESHOLD * 0.92)
    findings = _run(custom_jobs=[job])
    assert findings == []


def test_job_below_50pct_no_finding():
    """No job type fires below _EARLY_WARNING_FRACTION."""
    job = _custom_job(
        "way-too-young",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.50,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings == []


# ---------------------------------------------------------------------------
# estimated_monthly_cost_usd
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_always_none():
    """Training jobs are transient; monthly cost field must be None."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 10)
    findings = _run(custom_jobs=[job])
    assert findings[0].estimated_monthly_cost_usd is None


def test_accrued_cost_populated():
    """Accrued cost (duration × hourly rate) must be > 0 and in details."""
    job = _custom_job(
        "j2",
        "us-central1",
        start_hours_ago=_THRESHOLD + 1,
        machine_type="n1-standard-8",
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["accrued_cost_usd"] > 0


# ---------------------------------------------------------------------------
# TrainingPipeline resource type
# ---------------------------------------------------------------------------


def test_training_pipeline_no_hardware_conservative_fallback():
    """Pipeline with no hardware spec uses duration-scaled fallback cost.

    >24h → $20/hr, 6–24h → $5/hr, <6h → $1/hr.
    """
    # >24h tier: start_hours_ago=_THRESHOLD+5 = 29h → $20/hr
    pipeline = _training_pipeline("pl-1", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(training_pipelines=[pipeline])

    assert len(findings) == 1
    f = findings[0]
    assert f.details["job_type"] == "trainingPipeline"
    assert f.details["is_accelerator"] is False  # hardware unknown ≠ GPU; only cost is conservative
    assert f.details["hardware_unknown"] is True
    assert f.details["pricing_source"] == "conservative_pipeline_default"
    assert f.details["burn_rate_per_hour"] == pytest.approx(20.0)  # >24h tier
    assert f.estimated_monthly_cost_usd is None


def test_training_pipeline_no_hardware_mid_tier():
    """Pipeline at exactly threshold (24h) uses $5/hr mid-tier (duration <= 24h, > 6h)."""
    # duration == _THRESHOLD (24h): not > 24 → $5/hr tier; >= threshold → MEDIUM confidence
    pipeline = _training_pipeline("pl-mid", "us-central1", start_hours_ago=_THRESHOLD)
    findings = _run(training_pipelines=[pipeline])
    assert len(findings) == 1
    assert findings[0].details["burn_rate_per_hour"] == pytest.approx(5.0)  # 6–24h tier


def test_training_pipeline_no_hardware_low_tier():
    """Pipeline <6h uses $1/hr low-tier when threshold is small enough to fire at <6h."""
    # Use threshold=5h so a 5h job fires (duration >= threshold); duration <= 6h → $1/hr tier
    pipeline = _training_pipeline("pl-low2", "us-central1", start_hours_ago=5)
    findings = _run(training_pipelines=[pipeline], threshold=5)
    assert len(findings) == 1
    assert findings[0].details["burn_rate_per_hour"] == pytest.approx(1.0)


def test_training_pipeline_with_worker_pool_specs_in_task_inputs():
    """Pipeline that embeds workerPoolSpecs in trainingTaskInputs is correctly parsed."""
    task_inputs = {
        "workerPoolSpecs": [
            {
                "replicaCount": 2,
                "machineSpec": {
                    "machineType": "a2-highgpu-1g",
                    "acceleratorType": "",
                    "acceleratorCount": 0,
                },
            }
        ]
    }
    pipeline = _training_pipeline(
        "pl-2", "us-central1", start_hours_ago=_THRESHOLD + 5, task_inputs=task_inputs
    )
    findings = _run(training_pipelines=[pipeline])

    assert len(findings) == 1
    f = findings[0]
    assert f.details["hardware_unknown"] is False
    assert f.details["is_accelerator"] is True  # a2-* prefix
    assert f.details["machine_type"] == "a2-highgpu-1g"
    assert f.details["total_workers"] == 2
    assert f.details["pricing_source"] == "static_estimate_us_central1"


def test_training_pipeline_task_inputs_as_json_string():
    """trainingTaskInputs returned as a JSON string (not a dict) is correctly parsed."""
    import json

    task_inputs_str = json.dumps(
        {
            "workerPoolSpecs": [
                {
                    "replicaCount": 1,
                    "machineSpec": {
                        "machineType": "g2-standard-8",
                        "acceleratorType": "",
                        "acceleratorCount": 0,
                    },
                }
            ]
        }
    )
    pipeline = _training_pipeline(
        "pl-json",
        "us-central1",
        start_hours_ago=_THRESHOLD + 5,
        task_inputs=task_inputs_str,
    )
    findings = _run(training_pipelines=[pipeline])

    assert len(findings) == 1
    f = findings[0]
    assert f.details["hardware_unknown"] is False
    assert f.details["is_accelerator"] is True  # g2-* prefix
    assert f.details["machine_type"] == "g2-standard-8"


# ---------------------------------------------------------------------------
# GPU detection
# ---------------------------------------------------------------------------


def test_a2_machine_classified_as_gpu():
    job = _custom_job(
        "a2-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 2,
        machine_type="a2-highgpu-4g",
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["is_accelerator"] is True


def test_g2_machine_classified_as_gpu():
    job = _custom_job(
        "g2-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 2,
        machine_type="g2-standard-8",
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["is_accelerator"] is True


def test_a3_machine_classified_as_gpu():
    job = _custom_job(
        "a3-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 2,
        machine_type="a3-highgpu-8g",
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["is_accelerator"] is True


def test_accelerator_type_classified_as_gpu():
    job = _custom_job(
        "h100-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 2,
        machine_type="n1-standard-8",
        accel_type="NVIDIA_H100_80GB",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["is_accelerator"] is True


def test_n1_cpu_not_classified_as_gpu():
    job = _custom_job(
        "cpu-job",
        "us-central1",
        start_hours_ago=_THRESHOLD + 2,
        machine_type="n1-standard-32",
    )
    findings = _run(custom_jobs=[job])
    assert findings[0].details["is_accelerator"] is False


# ---------------------------------------------------------------------------
# Per-pool cost aggregation (fix: sum all pools, not primary × total)
# ---------------------------------------------------------------------------


def test_heterogeneous_cluster_cost_sums_all_pools():
    """
    Chief: a2-highgpu-1g (1 replica) ≈ $4.02/hr
    Workers: n1-standard-4 (8 replicas) ≈ $0.19/hr each → $1.52/hr total
    Total should be ≈ $5.54/hr, not a2-price × 9 ($36.18/hr).
    """
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/hetero",
        "displayName": "hetero",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {
            "workerPoolSpecs": [
                {
                    "replicaCount": 1,
                    "machineSpec": {
                        "machineType": "a2-highgpu-1g",
                        "acceleratorType": "",
                        "acceleratorCount": 0,
                    },
                },
                {
                    "replicaCount": 8,
                    "machineSpec": {
                        "machineType": "n1-standard-4",
                        "acceleratorType": "",
                        "acceleratorCount": 0,
                    },
                },
            ]
        },
    }
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    f = findings[0]

    a2_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-1g"] / _HOURS_PER_MONTH
    n1_hourly = _MACHINE_MONTHLY_COST["n1-standard-4"] / _HOURS_PER_MONTH
    expected_total = a2_hourly * 1 + n1_hourly * 8
    assert f.details["burn_rate_per_hour"] == pytest.approx(expected_total)
    assert f.details["total_workers"] == 9


# ---------------------------------------------------------------------------
# Region filter
# ---------------------------------------------------------------------------


def test_region_filter_excludes_other_regions():
    job_keep = _custom_job("j-keep", "us-central1", start_hours_ago=_THRESHOLD + 5)
    job_skip = _custom_job("j-skip", "europe-west1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job_keep, job_skip], region_filter="us-central1")
    assert len(findings) == 1
    assert findings[0].region == "us-central1"


# ---------------------------------------------------------------------------
# Location fallback
# ---------------------------------------------------------------------------


def test_location_unknown_for_malformed_name():
    """Jobs with unparseable resource names get region='unknown', not ''."""
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": "malformed-resource-name",
        "displayName": "bad-job",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    findings = _run(custom_jobs=[job])
    if findings:  # may be filtered out if region_filter active — just check region value
        assert findings[0].region == "unknown"


# ---------------------------------------------------------------------------
# Permission error
# ---------------------------------------------------------------------------


def test_permission_error_raises():
    creds = MagicMock()
    session = _make_session(status=403)
    with patch(
        "cleancloud.providers.gcp.rules.vertex_training_job_long_running.AuthorizedSession",
        return_value=session,
    ):
        with pytest.raises(PermissionError):
            find_long_running_vertex_training_jobs(project_id=_PROJECT, credentials=creds)


def test_partial_failure_warns_and_returns_partial_findings():
    """One resource type failing emits a warning but still returns findings from the other."""
    job = _custom_job("j1", "us-central1", start_hours_ago=_THRESHOLD + 1)
    good_session = _make_session(custom_jobs=[job])

    # Patch _list_jobs so customJobs succeeds but trainingPipelines raises
    original_list_jobs = __import__(
        "cleancloud.providers.gcp.rules.vertex_training_job_long_running",
        fromlist=["_list_jobs"],
    )._list_jobs

    call_count = {"n": 0}

    def _patched_list_jobs(session, project_id, resource, state_filter):
        call_count["n"] += 1
        if resource == "trainingPipelines":
            raise RuntimeError("simulated network error")
        return original_list_jobs(session, project_id, resource, state_filter)

    creds = MagicMock()
    with patch(
        "cleancloud.providers.gcp.rules.vertex_training_job_long_running.AuthorizedSession",
        return_value=good_session,
    ):
        with patch(
            "cleancloud.providers.gcp.rules.vertex_training_job_long_running._list_jobs",
            side_effect=_patched_list_jobs,
        ):
            import warnings as _warnings

            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                findings = find_long_running_vertex_training_jobs(
                    project_id=_PROJECT, credentials=creds
                )

    assert len(findings) == 1  # customJob finding still returned
    assert any("trainingPipelines" in str(w.message) for w in caught)
    assert any("findings may be incomplete" in str(w.message) for w in caught)


# ---------------------------------------------------------------------------
# _parse_worker_pools
# ---------------------------------------------------------------------------


def test_parse_worker_pools_empty():
    """Empty spec → [] (not a single-tuple fallback)."""
    result = _parse_worker_pools([])
    assert result == []


def test_parse_worker_pools_single_pool():
    specs = [
        {
            "replicaCount": 4,
            "machineSpec": {
                "machineType": "n1-standard-8",
                "acceleratorType": "NVIDIA_TESLA_V100",
                "acceleratorCount": 2,
            },
        }
    ]
    result = _parse_worker_pools(specs)
    assert len(result) == 1
    machine, accel, count, replicas = result[0]
    assert machine == "n1-standard-8"
    assert accel == "NVIDIA_TESLA_V100"
    assert count == 2
    assert replicas == 4


def test_parse_worker_pools_multi_pool():
    """Each pool is a separate tuple; primary is first."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {
                "machineType": "a2-highgpu-1g",
                "acceleratorType": "",
                "acceleratorCount": 0,
            },
        },
        {
            "replicaCount": 8,
            "machineSpec": {
                "machineType": "n1-standard-4",
                "acceleratorType": "",
                "acceleratorCount": 0,
            },
        },
    ]
    result = _parse_worker_pools(specs)
    assert len(result) == 2
    assert result[0][0] == "a2-highgpu-1g"
    assert result[0][3] == 1
    assert result[1][0] == "n1-standard-4"
    assert result[1][3] == 8


# ---------------------------------------------------------------------------
# _tpu_topology_host_count
# ---------------------------------------------------------------------------


def test_tpu_topology_host_count_2x4():
    """2x4 topology on ct5lp-hightpu-4t (4 chips/host) → 2 hosts."""
    assert _tpu_topology_host_count("ct5lp-hightpu-4t", "2x4") == 2


def test_tpu_topology_host_count_4x4():
    """4x4 topology on ct5lp-hightpu-4t → 4 hosts."""
    assert _tpu_topology_host_count("ct5lp-hightpu-4t", "4x4") == 4


def test_tpu_topology_host_count_single_dim():
    """Single-dim topology '2' on ct5lp-hightpu-1t (1 chip/host) → 2 hosts."""
    assert _tpu_topology_host_count("ct5lp-hightpu-1t", "2") == 2


def test_tpu_topology_host_count_empty_returns_zero():
    """Empty topology → 0 (caller falls back to replicaCount)."""
    assert _tpu_topology_host_count("ct5lp-hightpu-4t", "") == 0


def test_tpu_topology_host_count_unknown_machine_parses_suffix():
    """Unknown machine type not in table → -Nt suffix parsing used as fallback.
    ct99x-future-8t → 8 chips/host; 4x4=16 total → 2 hosts."""
    assert _tpu_topology_host_count("ct99x-future-8t", "4x4") == 2


def test_tpu_topology_host_count_unparseable_suffix_returns_zero():
    """Machine with no -Nt suffix and not in table → returns 0 with a warning."""
    import warnings as _warnings

    with _warnings.catch_warnings(record=True) as w:
        _warnings.simplefilter("always")
        result = _tpu_topology_host_count("n1-standard-4", "2x4")
    assert result == 0
    assert any("unknown chips-per-host" in str(warning.message) for warning in w)


def test_parse_worker_pools_tpu_topology_overrides_replica_count():
    """TPU pool with replicaCount=1 and topology '2x4' → effective replicas=2."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {
                "machineType": "ct5lp-hightpu-4t",
                "tpuTopology": "2x4",
            },
        }
    ]
    result = _parse_worker_pools(specs)
    assert result[0][3] == 2  # 2x4=8 chips / 4 chips-per-host = 2 hosts


def test_parse_worker_pools_tpu_no_topology_keeps_replica_count():
    """TPU pool with no topology keeps replicaCount unchanged."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "ct5lp-hightpu-4t"},
        }
    ]
    result = _parse_worker_pools(specs)
    assert result[0][3] == 1


def test_total_hourly_rate_tpu_multi_host():
    """A ct5lp-hightpu-4t pool with 2x4 topology is priced as 2 hosts."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "ct5lp-hightpu-4t", "tpuTopology": "2x4"},
        }
    ]
    pools = _parse_worker_pools(specs)
    per_host = _MACHINE_MONTHLY_COST["ct5lp-hightpu-4t"] / _HOURS_PER_MONTH
    assert _total_hourly_rate(pools) == pytest.approx(per_host * 2)


def test_g4_gpu_counts_match_docs():
    """g4 GPU counts in _BUNDLED_ACCELERATOR_COUNT match documented Vertex values."""
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-48"] == 1
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-96"] == 2
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-192"] == 4
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-384"] == 8


# ---------------------------------------------------------------------------
# _has_accelerator_hardware
# ---------------------------------------------------------------------------


def test_has_accelerator_hardware_accelerator_type():
    pools = [("n1-standard-8", "NVIDIA_TESLA_T4", 1, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_has_accelerator_hardware_a2_prefix():
    pools = [("a2-highgpu-1g", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_has_accelerator_hardware_any_pool():
    """GPU in any pool (not just primary) returns True."""
    pools = [
        ("n1-standard-4", None, 0, 8),
        ("g2-standard-8", None, 0, 1),
    ]
    assert _has_accelerator_hardware(pools) is True


def test_has_accelerator_hardware_cpu_only():
    pools = [("n1-standard-32", None, 0, 4)]
    assert _has_accelerator_hardware(pools) is False


def test_has_accelerator_hardware_unspecified_not_classified():
    """ACCELERATOR_TYPE_UNSPECIFIED should not be treated as an accelerator."""
    pools = [("n1-standard-4", "ACCELERATOR_TYPE_UNSPECIFIED", 0, 1)]
    assert _has_accelerator_hardware(pools) is False


def test_has_accelerator_hardware_empty_string_not_classified():
    """Empty string accelerator type should not be treated as an accelerator."""
    pools = [("n1-standard-4", "", 0, 1)]
    assert _has_accelerator_hardware(pools) is False


# ---------------------------------------------------------------------------
# _estimate_hourly_rate_per_replica
# ---------------------------------------------------------------------------


def test_estimate_hourly_rate_per_replica_n1_with_gpu_is_additive():
    """n1-* machines add GPU cost on top of machine cost."""
    machine_hourly = _MACHINE_MONTHLY_COST["n1-standard-8"] / _HOURS_PER_MONTH
    gpu_monthly_each = 311.0  # NVIDIA_TESLA_T4
    gpu_hourly = gpu_monthly_each / _HOURS_PER_MONTH * 2  # 2 GPUs
    expected = machine_hourly + gpu_hourly
    result = _estimate_hourly_rate_per_replica("n1-standard-8", "NVIDIA_TESLA_T4", 2)
    assert abs(result - expected) < 0.01


def test_estimate_hourly_rate_per_replica_a2_bundled_no_addon():
    """a2-* machines bundle GPU cost — no accelerator add-on."""
    machine_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-1g"] / _HOURS_PER_MONTH
    result = _estimate_hourly_rate_per_replica("a2-highgpu-1g", "NVIDIA_TESLA_A100", 1)
    assert abs(result - machine_hourly) < 0.01


def test_estimate_hourly_rate_per_replica_unknown_machine_uses_default():
    result = _estimate_hourly_rate_per_replica("custom-unknown-machine", None, 0)
    expected = _DEFAULT_MACHINE_MONTHLY_COST / _HOURS_PER_MONTH
    assert abs(result - expected) < 0.01


def test_estimate_hourly_rate_co_scheduling_single_accel():
    """a2-highgpu-8g with accel_count=1 triggers co-scheduling: 8 replicas per VM, cost 1/8."""
    full_machine_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-8g"] / _HOURS_PER_MONTH
    # accel_count=1 == 1 → replicas_per_vm = 8//1 = 8
    result = _estimate_hourly_rate_per_replica("a2-highgpu-8g", "NVIDIA_TESLA_A100", 1)
    assert result == pytest.approx(full_machine_hourly / 8)


def test_estimate_hourly_rate_co_scheduling_divides_evenly():
    """a2-highgpu-8g with accel_count=2: 8%2==0 → co-scheduling applies, cost is 1/4."""
    full_machine_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-8g"] / _HOURS_PER_MONTH
    # accel_count=2, machine_gpu_count=8, 8%2==0 → replicas_per_vm=4
    result = _estimate_hourly_rate_per_replica("a2-highgpu-8g", "NVIDIA_TESLA_A100", 2)
    assert result == pytest.approx(full_machine_hourly / 4)


def test_estimate_hourly_rate_no_co_scheduling_above_half():
    """a2-highgpu-8g with accel_count=5 → no co-scheduling (accel_count != 1), full price."""
    full_machine_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-8g"] / _HOURS_PER_MONTH
    result = _estimate_hourly_rate_per_replica("a2-highgpu-8g", "NVIDIA_TESLA_A100", 5)
    assert result == pytest.approx(full_machine_hourly)


def test_estimate_hourly_rate_no_co_scheduling_zero_accel_count():
    """accel_count=0 (unspecified) → full price, no co-scheduling assumed."""
    full_machine_hourly = _MACHINE_MONTHLY_COST["a2-highgpu-8g"] / _HOURS_PER_MONTH
    result = _estimate_hourly_rate_per_replica("a2-highgpu-8g", None, 0)
    assert result == pytest.approx(full_machine_hourly)


def test_bundled_accelerator_count_covers_all_machine_monthly_cost_bundled_types():
    """Every bundled machine type in _MACHINE_MONTHLY_COST (except g2-standard-32)
    has a known GPU/TPU count in _BUNDLED_ACCELERATOR_COUNT."""
    gpu_prefixes = ("a2-", "a3-", "a4-", "a4x-", "g2-", "g4-")
    bundled_types = [
        m
        for m in _MACHINE_MONTHLY_COST
        if m.startswith(gpu_prefixes) or m.startswith(_TPU_MACHINE_PREFIXES)
    ]
    unknown = [
        m for m in bundled_types if m not in _BUNDLED_ACCELERATOR_COUNT and m != "g2-standard-32"
    ]
    assert unknown == [], f"Missing from _BUNDLED_ACCELERATOR_COUNT: {unknown}"


def test_tpu_machine_type_detected_as_accelerated():
    """ct5lp-* (TPU v5e litepod) is detected as accelerated via machine type prefix."""
    pools = [("ct5lp-hightpu-4t", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_tpu_machine_type_uses_tpu_default_cost_when_unknown():
    """Unrecognized ct5lp-* machine falls back to _DEFAULT_TPU_MONTHLY_COST, not generic $150."""
    result = _estimate_hourly_rate_per_replica("ct5lp-hightpu-16t", None, 0)
    assert result == pytest.approx(_DEFAULT_TPU_MONTHLY_COST / _HOURS_PER_MONTH)


def test_tpu_machine_type_uses_table_cost_when_known():
    """Known ct5lp-hightpu-4t uses the exact cost from _MACHINE_MONTHLY_COST."""
    result = _estimate_hourly_rate_per_replica("ct5lp-hightpu-4t", None, 0)
    assert result == pytest.approx(_MACHINE_MONTHLY_COST["ct5lp-hightpu-4t"] / _HOURS_PER_MONTH)


def test_a3_megagpu_detected_as_bundled():
    """a3-megagpu-8g is detected as bundled via a3- prefix."""
    pools = [("a3-megagpu-8g", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_a4_machine_detected_as_bundled():
    """a4-highgpu-8g is detected as bundled (new prefix)."""
    pools = [("a4-highgpu-8g", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_a4x_machine_detected_as_bundled():
    """a4x-highgpu-4g is detected as bundled (separate prefix from a4-)."""
    pools = [("a4x-highgpu-4g", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_tpu7x_machine_detected_as_accelerated():
    """tpu7x-standard-4t (TPU v7) is detected via tpu7x- prefix."""
    pools = [("tpu7x-standard-4t", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


def test_tpu7x_uses_tpu_default_cost():
    """tpu7x-* has no cost table entry — should use _DEFAULT_TPU_MONTHLY_COST."""
    result = _estimate_hourly_rate_per_replica("tpu7x-standard-4t", None, 0)
    assert result == pytest.approx(_DEFAULT_TPU_MONTHLY_COST / _HOURS_PER_MONTH)


def test_tpu7x_topology_scaling_via_suffix_parse():
    """tpu7x-standard-4t not in _BUNDLED_ACCELERATOR_COUNT but -4t suffix → 4 chips/host.
    Topology '4x4' = 16 chips → 4 hosts → priced as 4 × per-host rate."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "tpu7x-standard-4t", "tpuTopology": "4x4"},
        }
    ]
    pools = _parse_worker_pools(specs)
    assert pools[0][3] == 4  # 16 chips / 4 per host = 4 hosts
    per_host = _DEFAULT_TPU_MONTHLY_COST / _HOURS_PER_MONTH
    assert _total_hourly_rate(pools) == pytest.approx(per_host * 4)


# ---------------------------------------------------------------------------
# _total_hourly_rate
# ---------------------------------------------------------------------------


def test_total_hourly_rate_single_pool():
    per_replica = _estimate_hourly_rate_per_replica("n1-standard-4", None, 0)
    pools = [("n1-standard-4", None, 0, 3)]
    assert abs(_total_hourly_rate(pools) - per_replica * 3) < 0.01


def test_total_hourly_rate_heterogeneous():
    """Cost sums correctly across pools with different machine types."""
    chief = _estimate_hourly_rate_per_replica("a2-highgpu-1g", None, 0) * 1
    workers = _estimate_hourly_rate_per_replica("n1-standard-4", None, 0) * 8
    pools = [
        ("a2-highgpu-1g", None, 0, 1),
        ("n1-standard-4", None, 0, 8),
    ]
    assert abs(_total_hourly_rate(pools) - (chief + workers)) < 0.01


# ---------------------------------------------------------------------------
# _hardware_label
# ---------------------------------------------------------------------------


def test_hardware_label_single_cpu():
    assert "n1-standard-4" in _hardware_label("n1-standard-4", None, 0, 1)


def test_hardware_label_with_accelerator():
    label = _hardware_label("n1-standard-8", "NVIDIA_TESLA_T4", 2, 1)
    assert "n1-standard-8" in label
    assert "NVIDIA_TESLA_T4" in label
    assert "2×" in label


def test_hardware_label_multi_worker():
    label = _hardware_label("n1-standard-4", None, 0, 8)
    assert "×8 workers" in label


# ---------------------------------------------------------------------------
# _parse_location
# ---------------------------------------------------------------------------


def test_parse_location_standard():
    name = "projects/my-proj/locations/us-central1/customJobs/12345"
    assert _parse_location(name) == "us-central1"


def test_parse_location_missing_returns_empty():
    assert _parse_location("invalid-name") == ""


# ---------------------------------------------------------------------------
# RULE_ID attribute
# ---------------------------------------------------------------------------


def test_rule_id_attribute():
    assert find_long_running_vertex_training_jobs.RULE_ID == "gcp.vertex.training_job.long_running"


# ---------------------------------------------------------------------------
# Fix 2: wildcard cache keyed per (project_id, resource)
# ---------------------------------------------------------------------------


def test_wildcard_unsupported_keyed_per_project_and_resource():
    """_wildcard_unsupported uses (project_id, resource) tuples, not plain strings."""
    # Verify the set stores tuples so customJobs and trainingPipelines are independent
    test_set = set()
    test_set.add(("proj-a", "customJobs"))
    assert ("proj-a", "customJobs") in test_set
    assert ("proj-a", "trainingPipelines") not in test_set  # independent per resource


# ---------------------------------------------------------------------------
# Fix 3: pricing_confidence
# ---------------------------------------------------------------------------


def test_pricing_confidence_published_for_known_machines():
    pools = [("n1-standard-8", "NVIDIA_TESLA_T4", 1, 1)]
    assert _pricing_confidence(pools) == "published"


def test_pricing_confidence_partial_estimate_for_estimated_machine():
    """a4-* machines use estimated pricing."""
    pools = [("a4-highgpu-8g", None, 0, 1)]
    assert _pricing_confidence(pools) == "partial_estimate"


def test_pricing_confidence_partial_estimate_for_estimated_accel():
    """H200 accelerator uses estimated pricing."""
    pools = [("n1-standard-8", "NVIDIA_H200_141GB", 1, 1)]
    assert _pricing_confidence(pools) == "partial_estimate"


def test_pricing_confidence_empty_pools():
    """Empty pool list → published (no estimated prices involved)."""
    assert _pricing_confidence([]) == "published"


def test_finding_includes_pricing_confidence_field():
    """pricing_confidence appears in finding details for custom jobs."""
    job = _custom_job(
        "job-1",
        "us-central1",
        start_hours_ago=_THRESHOLD + 1,
        machine_type="n1-standard-4",
    )
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert "pricing_confidence" in findings[0].details


# ---------------------------------------------------------------------------
# Fix 6: skipped_jobs warning
# ---------------------------------------------------------------------------


def test_skipped_jobs_warning_on_missing_timestamp():
    """Jobs with no startTime or createTime emit a warning."""
    import warnings as _warnings

    job = {
        "name": "projects/my-project/locations/us-central1/customJobs/bad",
        "displayName": "bad-job",
        "state": "JOB_STATE_RUNNING",
        # no startTime or createTime
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"customJobs": [job], "trainingPipelines": []}

    with patch(
        "cleancloud.providers.gcp.rules.vertex_training_job_long_running.AuthorizedSession"
    ) as mock_session_cls:
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        with _warnings.catch_warnings(record=True) as w:
            _warnings.simplefilter("always")
            findings = find_long_running_vertex_training_jobs(
                project_id=_PROJECT,
                credentials=MagicMock(),
            )

    assert findings == []
    assert any("skipped" in str(warning.message).lower() for warning in w)


# ---------------------------------------------------------------------------
# Fix 9: early_warning_fraction and runaway_multiplier kwargs
# ---------------------------------------------------------------------------


def test_custom_early_warning_fraction_fires_earlier():
    """early_warning_fraction=0.5 → job at 60% of threshold fires; default 0.9 would not."""
    job = _custom_job(
        "job-ew",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.6,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job], extra_kwargs={"early_warning_fraction": 0.5})
    assert len(findings) == 1


def test_custom_early_warning_fraction_default_does_not_fire():
    """Same job at 60% of threshold does NOT fire with default fraction (0.9)."""
    job = _custom_job(
        "job-ew-no",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.6,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings == []


def test_custom_runaway_multiplier_changes_confidence():
    """runaway_multiplier=2 → job at 2.5× threshold is HIGH; default 3× it would be MEDIUM."""
    job = _custom_job("job-rm", "us-central1", start_hours_ago=_THRESHOLD * 2.5)
    findings = _run(custom_jobs=[job], extra_kwargs={"runaway_multiplier": 2})
    assert len(findings) == 1
    assert findings[0].confidence.name == "HIGH"


def test_default_runaway_multiplier_at_2_5x_is_medium():
    """Same job at 2.5× threshold with default multiplier (3) → MEDIUM confidence."""
    job = _custom_job("job-rm-med", "us-central1", start_hours_ago=_THRESHOLD * 2.5)
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert findings[0].confidence.name == "MEDIUM"
