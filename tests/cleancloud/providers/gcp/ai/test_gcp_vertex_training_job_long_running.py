"""
Tests for gcp.vertex.training_job.long_running rule.

Coverage:
- Core detection: CPU job over threshold (MEDIUM/MEDIUM), GPU job over threshold (MEDIUM)
- Runaway (3× threshold): HIGH confidence, CRITICAL for GPU, HIGH for CPU
- Risk model: GPU+HIGH→CRITICAL, CPU+HIGH→HIGH, MEDIUM confidence→MEDIUM regardless of GPU
- Below-threshold jobs: no finding emitted (spec 9.4 — no sub-threshold early warnings)
- TrainingPipeline resource type: parses trainingTaskInputs; hardware_unknown when absent
- TrainingPipeline with workerPoolSpecs in trainingTaskInputs: uses parsed hardware
- TrainingPipeline with no hardware spec: hardware_unknown=True, is_accelerator=False
- No findings: job below threshold (CPU or GPU)
- Region filter: exact string equality (spec 7) — no case folding
- Invalid threshold (< 1): fail-fast with ValueError (spec 9.1)
- startTime absence skips job; createTime NOT used as fallback (spec 9.4)
- Future startTime skips job (spec 7)
- Malformed name skips job (spec 7, 11)
- Permission errors: PermissionError raised on 403
- estimated_monthly_cost_usd is always None (transient job, spec 10.1)
- No cost fields in details (accrued_cost_usd, burn_rate_per_hour, pricing_source, etc.)
- Details: state field (exact running enum), start_time field (RFC3339 string)
- Accelerator detection from _has_accelerator_hardware: accelerator type OR machine prefix
- _parse_worker_pools: returns list of per-pool tuples; empty → []
- _hardware_label: single worker, multi-worker, with accelerator
- RULE_ID attribute
- Exact resource-name pattern enforcement (spec 7): extra segments, wrong type segment, skipped
- State validation: exact enum from resource, not synthesised; wrong/missing state → skip
- CustomJob hardware_unknown=True when workerPoolSpecs is empty or all entries malformed
- _parse_worker_pools: entries without machineType are skipped (spec 8.1, 8.2)
- _parse_worker_pools: malformed (non-dict, bad replicaCount/acceleratorCount) entries skipped
- RFC3339 strictness: space separator, date-only, no-tz values all rejected
- Partial pagination: later-page failure keeps accumulated pages and warns (spec 11.3)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running import (
    _BUNDLED_ACCELERATOR_COUNT,
    _DEFAULT_LONG_RUNNING_HOURS,
    _EXPECTED_STATE,
    _RUNAWAY_MULTIPLIER,
    _hardware_label,
    _has_accelerator_hardware,
    _parse_worker_pools,
    _tpu_topology_host_count,
    _validate_resource_name,
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
):
    creds = MagicMock()
    session = _make_session(custom_jobs=custom_jobs, training_pipelines=training_pipelines)
    with patch(
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.AuthorizedSession",
        return_value=session,
    ):
        with patch(
            "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.datetime"
        ) as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat.side_effect = datetime.fromisoformat
            return find_long_running_vertex_training_jobs(
                project_id=_PROJECT,
                credentials=creds,
                region_filter=region_filter,
                long_running_hours_threshold=threshold,
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
    assert f.risk == RiskLevel.MEDIUM  # not HIGH — see risk model (spec 9.3)
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
# Threshold behavior (spec 9.4: no sub-threshold early warnings)
# ---------------------------------------------------------------------------


def test_job_below_threshold_no_finding():
    """No job type fires below the threshold (spec 9.4)."""
    job = _custom_job("too-young", "us-central1", start_hours_ago=_THRESHOLD * 0.99)
    findings = _run(custom_jobs=[job])
    assert findings == []


def test_gpu_job_below_threshold_no_finding():
    """GPU job below threshold does NOT fire — no sub-threshold early warnings (spec 9.4)."""
    job = _custom_job(
        "gpu-too-young",
        "us-central1",
        start_hours_ago=_THRESHOLD * 0.80,
        accel_type="NVIDIA_TESLA_T4",
        accel_count=1,
    )
    findings = _run(custom_jobs=[job])
    assert findings == []


def test_job_at_exactly_threshold_fires():
    """Job at exactly the threshold is in scope."""
    job = _custom_job("exactly", "us-central1", start_hours_ago=_THRESHOLD)
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# estimated_monthly_cost_usd and cost fields
# ---------------------------------------------------------------------------


def test_estimated_monthly_cost_always_none():
    """Training jobs are transient; monthly cost field must be None (spec 10.1)."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 10)
    findings = _run(custom_jobs=[job])
    assert findings[0].estimated_monthly_cost_usd is None


def test_no_accrued_cost_in_details():
    """Removed pricing fields must not appear in finding details (spec 10.2)."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    details = findings[0].details
    assert "accrued_cost_usd" not in details
    assert "burn_rate_per_hour" not in details
    assert "pricing_source" not in details
    assert "pricing_confidence" not in details
    assert "cost_type" not in details
    assert "overrun_hours" not in details


# ---------------------------------------------------------------------------
# Spec-compliance: threshold validation, startTime, region filter
# ---------------------------------------------------------------------------


def test_threshold_less_than_1_raises_value_error():
    """Invalid threshold (< 1) must fail fast with ValueError (spec 9.1)."""
    creds = MagicMock()
    with pytest.raises(ValueError, match="long_running_hours_threshold"):
        find_long_running_vertex_training_jobs(
            project_id=_PROJECT,
            credentials=creds,
            long_running_hours_threshold=0,
        )


def test_threshold_of_zero_raises_value_error():
    creds = MagicMock()
    with pytest.raises(ValueError):
        find_long_running_vertex_training_jobs(
            project_id=_PROJECT,
            credentials=creds,
            long_running_hours_threshold=-1,
        )


def test_create_time_not_used_as_fallback():
    """Jobs with createTime but no startTime are skipped — createTime is NOT a fallback (spec 9.4)."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/no-start",
        "displayName": "no-start-job",
        "createTime": _iso(start),  # present but must NOT be used
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_future_start_time_skips_job():
    """Jobs with future startTime are skipped (spec 7)."""
    import warnings as _warnings

    future = NOW + timedelta(hours=5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/future",
        "displayName": "future-job",
        "startTime": _iso(future),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_malformed_name_skips_job():
    """Jobs with malformed resource names (location not resolvable) are skipped (spec 7, 11)."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": "malformed-resource-name",
        "displayName": "bad-job",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_region_filter_exact_match_required():
    """Region filter is exact string equality; prefix match must not pass (spec 7)."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job], region_filter="us-central")
    assert findings == []


# ---------------------------------------------------------------------------
# Details fields
# ---------------------------------------------------------------------------


def test_details_state_field_present():
    """Finding details include 'state' with the exact running enum value."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert findings[0].details["state"] == "JOB_STATE_RUNNING"


def test_details_state_field_training_pipeline():
    """TrainingPipeline finding uses PIPELINE_STATE_RUNNING."""
    pipeline = _training_pipeline("pl", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(training_pipelines=[pipeline])
    assert len(findings) == 1
    assert findings[0].details["state"] == "PIPELINE_STATE_RUNNING"


def test_details_start_time_field_present():
    """Finding details include 'start_time' as an RFC3339 string."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert "start_time" in findings[0].details
    assert isinstance(findings[0].details["start_time"], str)
    assert findings[0].details["start_time"].endswith("Z")


def test_details_long_running_hours_threshold_present():
    """Finding details include 'long_running_hours_threshold'."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(custom_jobs=[job])
    assert findings[0].details["long_running_hours_threshold"] == _THRESHOLD


# ---------------------------------------------------------------------------
# TrainingPipeline resource type
# ---------------------------------------------------------------------------


def test_training_pipeline_no_hardware_spec():
    """Pipeline with no hardware spec: hardware_unknown=True, is_accelerator=False."""
    pipeline = _training_pipeline("pl-1", "us-central1", start_hours_ago=_THRESHOLD + 5)
    findings = _run(training_pipelines=[pipeline])

    assert len(findings) == 1
    f = findings[0]
    assert f.details["job_type"] == "trainingPipeline"
    assert f.details["is_accelerator"] is False
    assert f.details["hardware_unknown"] is True
    assert f.estimated_monthly_cost_usd is None


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
# Heterogeneous cluster: total_workers
# ---------------------------------------------------------------------------


def test_heterogeneous_cluster_total_workers():
    """Chief (1 replica) + 8 workers = total_workers 9."""
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
    assert findings[0].details["total_workers"] == 9


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
# Permission error
# ---------------------------------------------------------------------------


def test_permission_error_raises():
    creds = MagicMock()
    session = _make_session(status=403)
    with patch(
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.AuthorizedSession",
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
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running",
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
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.AuthorizedSession",
        return_value=good_session,
    ):
        with patch(
            "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running._list_jobs",
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
    machine, accel, count, replicas, tpu_topology = result[0]
    assert machine == "n1-standard-8"
    assert accel == "NVIDIA_TESLA_V100"
    assert count == 2
    assert replicas == 4
    assert tpu_topology is None  # non-TPU machine


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


def test_parse_worker_pools_tpu_topology_stored_in_tuple():
    """tpu_topology (index 4) is stored in the pool tuple to avoid raw-spec index mismatch."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "ct5lp-hightpu-4t", "tpuTopology": "2x4"},
        }
    ]
    result = _parse_worker_pools(specs)
    assert result[0][4] == "2x4"


def test_parse_worker_pools_tpu_topology_correct_after_malformed_first_entry():
    """When the first raw entry is malformed and skipped, pools[0][4] gives the correct
    topology for the valid pool -- not the topology from the skipped first raw entry."""
    specs = [
        # Entry 0: malformed (no machineType) -- must be skipped
        {"replicaCount": 1, "machineSpec": {"tpuTopology": "wrong-topology"}},
        # Entry 1: valid TPU pool -- should become pools[0]
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "ct5lp-hightpu-4t", "tpuTopology": "2x4"},
        },
    ]
    result = _parse_worker_pools(specs)
    assert len(result) == 1
    assert result[0][0] == "ct5lp-hightpu-4t"
    assert result[0][4] == "2x4"  # correct topology, not "wrong-topology"


def test_g4_gpu_counts_match_docs():
    """g4 GPU counts in _BUNDLED_ACCELERATOR_COUNT match documented Vertex values."""
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-48"] == 1
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-96"] == 2
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-192"] == 4
    assert _BUNDLED_ACCELERATOR_COUNT["g4-standard-384"] == 8


def test_tpu7x_topology_scaling_via_suffix_parse():
    """tpu7x-standard-4t not in _BUNDLED_ACCELERATOR_COUNT but -4t suffix → 4 chips/host.
    Topology '4x4' = 16 chips → 4 hosts."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {"machineType": "tpu7x-standard-4t", "tpuTopology": "4x4"},
        }
    ]
    pools = _parse_worker_pools(specs)
    assert pools[0][3] == 4  # 16 chips / 4 per host = 4 hosts


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


def test_has_accelerator_hardware_recognized_type_zero_count_not_accelerated():
    """Recognized acceleratorType with acceleratorCount=0 is NOT accelerated (spec 8.1).

    acceleratorCount=0 means no accelerator is attached even if the type field is set.
    The explicit path requires both a recognized type AND count > 0.
    """
    pools = [("n1-standard-8", "NVIDIA_TESLA_T4", 0, 1)]
    assert _has_accelerator_hardware(pools) is False


def test_tpu_machine_type_detected_as_accelerated():
    """ct5lp-* (TPU v5e litepod) is detected as accelerated via machine type prefix."""
    pools = [("ct5lp-hightpu-4t", None, 0, 1)]
    assert _has_accelerator_hardware(pools) is True


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


def test_hardware_label_zero_accel_count_omits_type():
    """acceleratorType is omitted from the label when acceleratorCount == 0."""
    label = _hardware_label("n1-standard-8", "NVIDIA_TESLA_T4", 0, 1)
    assert "NVIDIA_TESLA_T4" not in label
    assert "n1-standard-8" in label


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
    test_set = set()
    test_set.add(("proj-a", "customJobs"))
    assert ("proj-a", "customJobs") in test_set
    assert ("proj-a", "trainingPipelines") not in test_set  # independent per resource


# ---------------------------------------------------------------------------
# Fix 6: skipped_jobs warning
# ---------------------------------------------------------------------------


def test_skipped_jobs_warning_on_missing_timestamp():
    """Jobs with no startTime emit a warning and are skipped."""
    import warnings as _warnings

    job = {
        "name": "projects/my-project/locations/us-central1/customJobs/bad",
        "displayName": "bad-job",
        "state": "JOB_STATE_RUNNING",
        # no startTime
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"customJobs": [job], "trainingPipelines": []}

    with patch(
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.AuthorizedSession"
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
# Resource-name pattern enforcement (spec 7)
# ---------------------------------------------------------------------------


def test_validate_resource_name_valid_customjob():
    assert (
        _validate_resource_name(
            "projects/my-proj/locations/us-central1/customJobs/123", "customJob"
        )
        is True
    )


def test_validate_resource_name_valid_pipeline():
    assert (
        _validate_resource_name(
            "projects/my-proj/locations/us-central1/trainingPipelines/456", "trainingPipeline"
        )
        is True
    )


def test_validate_resource_name_too_many_parts():
    """Extra path segment (7 parts instead of 6) → invalid."""
    assert (
        _validate_resource_name(
            "projects/p/locations/us-central1/customJobs/123/extra", "customJob"
        )
        is False
    )


def test_validate_resource_name_too_few_parts():
    assert _validate_resource_name("projects/p/locations/customJobs/123", "customJob") is False


def test_validate_resource_name_wrong_type_segment():
    """customJobs name treated as trainingPipeline → invalid."""
    assert (
        _validate_resource_name(
            "projects/p/locations/us-central1/customJobs/123", "trainingPipeline"
        )
        is False
    )


def test_validate_resource_name_empty_location():
    """Empty location segment → invalid."""
    assert _validate_resource_name("projects/p/locations//customJobs/123", "customJob") is False


def test_resource_name_extra_segments_skipped():
    """A name with extra path segments is not emitted as a finding."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/123/extra",
        "displayName": "extra-path",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_resource_name_location_bearing_but_wrong_type_skipped():
    """Name has valid location segment but wrong resource-type keyword → skip."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/models/123",
        "displayName": "wrong-type",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


# ---------------------------------------------------------------------------
# State validation (spec 3.3, 9.1)
# ---------------------------------------------------------------------------


def test_expected_state_constants():
    """_EXPECTED_STATE maps job types to exact documented running-state enums."""
    assert _EXPECTED_STATE["customJob"] == "JOB_STATE_RUNNING"
    assert _EXPECTED_STATE["trainingPipeline"] == "PIPELINE_STATE_RUNNING"


def test_wrong_state_custom_job_skipped():
    """CustomJob not in JOB_STATE_RUNNING is skipped even if it passes other checks."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j1",
        "displayName": "pending-job",
        "startTime": _iso(start),
        "state": "JOB_STATE_PENDING",  # not running
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_missing_state_custom_job_skipped():
    """CustomJob with absent state field is skipped."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j2",
        "displayName": "no-state",
        "startTime": _iso(start),
        # no 'state' key
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_state_is_read_from_resource_not_synthesised():
    """The 'state' in finding details reflects the actual resource state, not a synthesised value."""
    job = _custom_job("j", "us-central1", start_hours_ago=_THRESHOLD + 5)
    # Confirm the fixture sets state to JOB_STATE_RUNNING
    assert job["state"] == "JOB_STATE_RUNNING"
    findings = _run(custom_jobs=[job])
    assert findings[0].details["state"] == "JOB_STATE_RUNNING"


# ---------------------------------------------------------------------------
# CustomJob hardware_unknown when workerPoolSpecs absent/empty (spec 8.1)
# ---------------------------------------------------------------------------


def test_custom_job_empty_worker_specs_hardware_unknown():
    """CustomJob with empty workerPoolSpecs must have hardware_unknown=True (spec 8.1)."""
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-no-specs",
        "displayName": "no-specs",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        "jobSpec": {"workerPoolSpecs": []},
    }
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert findings[0].details["hardware_unknown"] is True
    assert findings[0].details["is_accelerator"] is False


def test_custom_job_absent_job_spec_hardware_unknown():
    """CustomJob with no jobSpec at all is still eligible; hardware_unknown=True."""
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-no-spec",
        "displayName": "no-job-spec",
        "startTime": _iso(start),
        "state": "JOB_STATE_RUNNING",
        # no 'jobSpec' key
    }
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1
    assert findings[0].details["hardware_unknown"] is True


# ---------------------------------------------------------------------------
# _parse_worker_pools: malformed entries and missing machineType (spec 8.1, 8.2)
# ---------------------------------------------------------------------------


def test_parse_worker_pools_missing_machine_type_skipped():
    """Pool entries without machineType are skipped (spec 8.1, 8.2)."""
    specs = [
        {
            "replicaCount": 1,
            "machineSpec": {
                # no machineType
                "acceleratorType": "NVIDIA_TESLA_T4",
                "acceleratorCount": 1,
            },
        }
    ]
    assert _parse_worker_pools(specs) == []


def test_parse_worker_pools_empty_machine_type_skipped():
    """Pool entry with empty machineType string is treated as missing → skipped."""
    specs = [{"replicaCount": 1, "machineSpec": {"machineType": ""}}]
    assert _parse_worker_pools(specs) == []


def test_parse_worker_pools_non_dict_entry_skipped():
    """Non-dict entries in workerPoolSpecs are silently skipped."""
    specs = ["not-a-dict", None, 42]
    assert _parse_worker_pools(specs) == []


def test_parse_worker_pools_bad_replica_count_skipped():
    """Pool with non-numeric replicaCount is treated as malformed → skipped."""
    specs = [
        {
            "replicaCount": "bad-value",
            "machineSpec": {"machineType": "n1-standard-4"},
        }
    ]
    assert _parse_worker_pools(specs) == []


def test_parse_worker_pools_mixed_valid_invalid():
    """Valid pool entries are kept; malformed entries are silently dropped."""
    specs = [
        {"replicaCount": "bad", "machineSpec": {"machineType": "n1-standard-4"}},
        {
            "replicaCount": 2,
            "machineSpec": {"machineType": "a2-highgpu-1g"},
        },
        {"replicaCount": 1, "machineSpec": {}},  # no machineType
    ]
    result = _parse_worker_pools(specs)
    assert len(result) == 1
    assert result[0][0] == "a2-highgpu-1g"
    assert result[0][3] == 2


def test_training_pipeline_pools_without_machine_type_hardware_unknown():
    """TrainingPipeline whose exposed workerPoolSpecs entries all lack machineType → hardware_unknown."""
    task_inputs = {
        "workerPoolSpecs": [
            {
                "replicaCount": 1,
                "machineSpec": {
                    # machineType absent
                    "acceleratorType": "NVIDIA_TESLA_T4",
                    "acceleratorCount": 1,
                },
            }
        ]
    }
    pipeline = _training_pipeline(
        "pl-no-mt", "us-central1", start_hours_ago=_THRESHOLD + 5, task_inputs=task_inputs
    )
    findings = _run(training_pipelines=[pipeline])
    assert len(findings) == 1
    assert findings[0].details["hardware_unknown"] is True
    assert findings[0].details["is_accelerator"] is False


# ---------------------------------------------------------------------------
# RFC3339 startTime strictness (spec 7)
# ---------------------------------------------------------------------------


def test_start_time_space_separator_rejected():
    """startTime with space separator (not T) is not valid RFC3339 and must be skipped."""
    import warnings as _warnings

    start = NOW - timedelta(hours=_THRESHOLD + 5)
    iso_space = start.isoformat().replace("T", " ")  # e.g. "2025-05-31 06:00:00+00:00"
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-space",
        "state": "JOB_STATE_RUNNING",
        "startTime": iso_space,
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_start_time_date_only_rejected():
    """Date-only startTime (no time component) is not valid RFC3339 and must be skipped."""
    import warnings as _warnings

    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-date",
        "state": "JOB_STATE_RUNNING",
        "startTime": "2025-05-01",
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_start_time_no_timezone_rejected():
    """startTime without timezone offset is not valid RFC3339 and must be skipped."""
    import warnings as _warnings

    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-notz",
        "state": "JOB_STATE_RUNNING",
        "startTime": "2025-05-01T06:00:00",  # no Z or offset
        "jobSpec": {"workerPoolSpecs": []},
    }
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        findings = _run(custom_jobs=[job])
    assert findings == []


def test_start_time_fractional_seconds_accepted():
    """startTime with fractional seconds and Z is valid RFC3339 and must be accepted."""
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    frac_str = start.strftime("%Y-%m-%dT%H:%M:%S.123456Z")
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-frac",
        "state": "JOB_STATE_RUNNING",
        "startTime": frac_str,
        "jobSpec": {
            "workerPoolSpecs": [
                {"replicaCount": 1, "machineSpec": {"machineType": "n1-standard-4"}}
            ]
        },
    }
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1


def test_start_time_explicit_offset_accepted():
    """startTime with explicit +00:00 offset is valid RFC3339 and must be accepted."""
    start = NOW - timedelta(hours=_THRESHOLD + 5)
    offset_str = start.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    job = {
        "name": f"projects/{_PROJECT}/locations/us-central1/customJobs/j-offset",
        "state": "JOB_STATE_RUNNING",
        "startTime": offset_str,
        "jobSpec": {
            "workerPoolSpecs": [
                {"replicaCount": 1, "machineSpec": {"machineType": "n1-standard-4"}}
            ]
        },
    }
    findings = _run(custom_jobs=[job])
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Partial pagination: later-page failure keeps earlier pages (spec 11.3)
# ---------------------------------------------------------------------------


def test_pagination_later_page_failure_keeps_partial_results():
    """A non-403 failure on a later page returns earlier accumulated pages and warns."""
    import warnings as _warnings

    job = _custom_job("j-page1", "us-central1", start_hours_ago=_THRESHOLD + 5)

    page1_resp = MagicMock()
    page1_resp.status_code = 200
    page1_resp.ok = True
    page1_resp.json.return_value = {
        "customJobs": [job],
        "nextPageToken": "token-abc",  # signals a second page
    }

    page2_resp = MagicMock()
    page2_resp.status_code = 503
    page2_resp.ok = False

    empty_pipeline_resp = MagicMock()
    empty_pipeline_resp.status_code = 200
    empty_pipeline_resp.ok = True
    empty_pipeline_resp.json.return_value = {"trainingPipelines": []}

    responses = {"customJobs": [page1_resp, page2_resp], "trainingPipelines": [empty_pipeline_resp]}
    counters = {"customJobs": 0, "trainingPipelines": 0}

    def _get(url, params=None):
        if "customJobs" in url:
            idx = counters["customJobs"]
            counters["customJobs"] += 1
            return responses["customJobs"][min(idx, len(responses["customJobs"]) - 1)]
        else:
            idx = counters["trainingPipelines"]
            counters["trainingPipelines"] += 1
            return responses["trainingPipelines"][min(idx, len(responses["trainingPipelines"]) - 1)]

    creds = MagicMock()
    mock_session = MagicMock()
    mock_session.get.side_effect = _get

    with patch(
        "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.AuthorizedSession",
        return_value=mock_session,
    ):
        with patch(
            "cleancloud.providers.gcp.rules.ai.vertex_training_job_long_running.datetime"
        ) as mock_dt:
            mock_dt.now.return_value = NOW
            mock_dt.fromisoformat.side_effect = datetime.fromisoformat
            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                findings = find_long_running_vertex_training_jobs(
                    project_id=_PROJECT,
                    credentials=creds,
                    long_running_hours_threshold=_THRESHOLD,
                )

    # Page 1 job must still appear even though page 2 failed
    assert len(findings) == 1
    assert findings[0].details["job_name"].endswith("j-page1")
    # A warning about the partial read must have been emitted
    assert any("partial" in str(w.message).lower() for w in caught)
