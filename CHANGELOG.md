# Changelog

All notable changes to CleanCloud are documented here.

## [1.15.0] — 2026-04-11

### Added
- `aws.ec2.gpu.idle` — Idle EC2 GPU/accelerator instance detection across 20 families (p2/p3/p4/p5, g4/g5/g6/g6e/gr6, trn1/trn2, inf1/inf2, dl1/dl2q). Two-tier detection: GPU utilisation via NVIDIA CloudWatch agent (HIGH confidence) or CPU fallback (MEDIUM). Neuron instances (Trainium/Inferentia) handled correctly — always CPU fallback by design. Parameters: `idle_days` (default 7), `gpu_threshold` (5%), `cpu_threshold` (10%).
- `gcp.vertex.workbench.idle` — Idle Vertex AI Workbench instances via v2 API. Uses `updateTime` as idle signal; GPU/TPU-aware; age-fallback capped at MEDIUM confidence.
- `schemas/output-v1.3.0.json` — JSON output schema update: added `critical` to risk enum, `suppressed` array, `rules_evaluated` summary field.
- Optional provider extras: `pip install 'cleancloud[aws]'`, `'cleancloud[azure]'`, `'cleancloud[gcp]'`, `'cleancloud[all]'`. Cloud SDKs are no longer hard dependencies.
- Docker `CLEANCLOUD_EXTRAS` build arg for slim provider-specific images.
- Graceful error messages with install hints when a provider SDK is not installed.

### Changed
- Cross-cloud AI baseline complete: 7 rules across AWS (3), Azure (2), GCP (2).
- README Quick Start consolidated to a single clear two-step flow (demo → install provider → scan).
- `azure/rules/ebs_snapshots_old.py` renamed to `disk_snapshots_old.py` (AWS terminology removed).
- `scan/command.py` EnvironmentError handler now uses `f"--provider {provider}"` (was hardcoded to `azure`).
- Lint is now blocking on main branch (was non-blocking with `|| echo` fallback).
- `output/feedback.py` no longer includes a personal email address.
- `except Exception: pass` blocks narrowed to specific exception types.

### Fixed
- `security/aws/hygiene-readonly.json` — added missing `cloudwatch:GetMetricStatistics` permission.

---

## [1.14.1] — 2026-04-09

### Fixed
- `aws/rules/untagged_resources.py` — `s3.exceptions.ClientError` crash fixed; now catches `botocore.exceptions.ClientError` with `NoSuchTagSet` check.
- `aws/rules/rds_idle.py` — hardcoded `"connections_14d"` key fixed; CloudWatch `AccessDenied` now surfaces as `PermissionError`.
- `aws/rules/elb_idle.py`, `nat_gateway_idle.py` — same CloudWatch `AccessDenied` fix.
- `azure/rules/app_service_plan_empty.py` — `plan.location.lower()` crash on `None`.
- `azure/rules/vm_stopped_not_deallocated.py` — `instance_view()` wrapped in try/except; no longer aborts subscription scan on one bad VM.
- `azure/rules/sql_database_idle.py` — hardcoded idle day strings fixed; per-server error handling added.
- `azure/rules/ebs_snapshots_old.py` — dead branch fixed; case-sensitive region filter fixed.
- `azure/rules/untagged_resources.py` — case-sensitive region filter fixed for disks and snapshots.
- `gcp/rules/sql_instance_idle.py` — hardcoded `"7-day window"` fixed to use `idle_days`.
- `gcp/rules/vertex_endpoint_idle.py` — unreachable dead branch removed.

---

## [1.14.0] — 2026-04-09

### Added
- `azure.aml.compute.idle` — Idle Azure ML Compute Clusters (Azure Monitor metrics + age fallback).
- `azure.ml.compute_instance.idle` — Idle Azure ML Compute Instances (last_operation + last_modified_at + age fallback).
- `rules_evaluated` field in JSON scan summary — map of rule_id to finding count.

### Changed
- Unified Azure subscription display (removed duplicate subscription output).
- Age-fallback confidence capped at MEDIUM for compute instance rule.
- All-None Azure Monitor maximums treated as unknown (not idle).
- Unicode arrow chars (`→`) removed from all Python source files.
