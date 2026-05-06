# aws.ec2.gpu.idle -- Canonical Rule Specification

## 1. Intent

Detect raw Amazon EC2 accelerated-computing instances that are still `running`, old enough to
evaluate, and show persistently low accelerator-related utilization over the configured evaluation
window.

This is a **CleanCloud-derived review-candidate heuristic**, not an AWS-native idle-state signal.
It is intentionally conservative and read-only. It is **not** proof that an instance is safe to
stop, **not** proof that no scheduled or intermittent workload exists, and **not** proof that no
future use is planned.

Two signal tiers are used:

1. **HIGH confidence** when an NVIDIA CloudWatch agent GPU metric is available and stays below
   threshold.
2. **MEDIUM confidence** CPU fallback when no qualifying per-instance NVIDIA GPU metric is
   available.

---

## 2. AWS API Grounding

Based on current AWS EC2 and CloudWatch documentation.

### Key facts

1. `DescribeInstances` supports filtering by `instance-state-name`.
2. EC2 instance state names include `running`, `pending`, `stopping`, `stopped`, and others.
3. `DescribeInstances` returns core fields needed by this rule, including `InstanceId`,
   `InstanceType`, `LaunchTime`, `Tags`, `State`, and `InstanceLifecycle`.
4. The EC2 CloudWatch metrics reference documents `CPUUtilization` in namespace `AWS/EC2`,
   with meaningful statistics including `Average`, `Minimum`, and `Maximum`.
5. AWS documents `GPUPowerUtilization` in namespace `AWS/EC2` for only a subset of accelerated
   instance types.
6. `ListMetrics` lists metrics by namespace, metric name, and dimensions, returns up to 500
   results per call, and does not return metrics that have not published data in the past two
   weeks.
7. `GetMetricStatistics` retrieves CloudWatch datapoints for a metric and requires exact
   dimensions that match the published metric.
8. `GetMetricStatistics` retains 1-hour metric resolution for 455 days, and when the start time
   is greater than 63 days ago, 3600-second periods are valid.
9. AWS documents NVIDIA GPU metrics collected by the CloudWatch agent, including
   `nvidia_smi_utilization_gpu`, which represents the percentage of time over the sample period
   during which one or more kernels on the GPU was running.
10. AWS documents CloudWatch agent metric dimensions for NVIDIA GPU metrics as GPU-level
    dimensions such as `index`, `name`, and `arch`.
11. AWS also documents CloudWatch agent `append_dimensions`, including `InstanceId`, when the
    agent is configured to append EC2 dimensions to collected metrics.
12. AWS accelerated-computing instance documentation includes GPU and AI-accelerator families such
    as P, G, Trn, Inf, and DL families, plus non-AI families such as F and VT.
13. AWS pricing docs exist, but fixed monthly USD estimates used by CleanCloud are implementation
    context, not canonical AWS API outputs.

### Implications

- `DescribeInstances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])` is the
  canonical inventory API for this rule.
- Only `running` instances are in scope because they incur live compute charges.
- `LaunchTime` is the canonical age gate for suppressing newly launched instances.
- `CPUUtilization` is a documented EC2 metric and can support a fallback heuristic.
- `GPUPowerUtilization` is excluded due to inconsistent emission and non-idle semantics across
  instance families.
- `nvidia_smi_utilization_gpu` is the strongest available GPU activity signal used by this rule,
  but it is **agent-dependent**, not AWS-native by default.
- The current implementation's high-confidence GPU path depends on the CloudWatch agent publishing
  GPU metrics that are discoverable per instance under the exact dimension pattern the rule probes.
  In practice, this often requires agent `append_dimensions` such as `InstanceId`, but AWS does not
  guarantee that GPU metrics include that dimension by default.
- Because `ListMetrics` does not return metrics with no datapoints in the past two weeks, GPU
  metric discovery is inherently recency-limited even though `GetMetricStatistics` can query older
  datapoints at coarser resolution. In quiet, low-noise, or intermittently reporting fleets, this
  can systematically under-detect GPU metrics, suppress the GPU path entirely, and bias
  classification toward CPU fallback findings rather than GPU-based findings.
- Absence of `nvidia_smi_utilization_gpu` is **not** proof that the instance is idle; it may mean
  the CloudWatch agent is absent, misconfigured, or not appending the dimensions the rule probes.
- Trainium, Inferentia, and other non-NVIDIA accelerator families do not expose
  `nvidia_smi_utilization_gpu`; those families necessarily fall back to CPU in the current rule,
  and AWS does not document a standard EC2-native GPU-equivalent utilization metric for them that
  this rule can use as a direct substitute.
- In many real fleets, the CWAgent GPU metric path will be unavailable more often than available,
  so CPU fallback may dominate in practice.

---

## 3. Scope and Terminology

- **EC2 accelerated instance** - an EC2 instance whose type belongs to the rule's targeted
  AI/accelerator family allowlist.
- **Running instance** - an EC2 instance whose `State.Name` is exactly `running`.
- **Age gate** - `LaunchTime` is at least `effective_idle_days` old.
- **GPU metric path** - NVIDIA CloudWatch agent metric `CWAgent / nvidia_smi_utilization_gpu`
  exists for the instance and remains below threshold over the evaluation window.
- **CPU fallback path** - no qualifying GPU metric is available, so `AWS/EC2 / CPUUtilization`
  is used as a weaker heuristic.
- **effective_idle_days** - `max(idle_days, 1)`.
- **age_days** - `floor((now_utc - launch_time_utc) / 86400 seconds)`.
- **idle_ratio** - `age_days / effective_idle_days`.
- **evaluation_window_end_utc** - `now_utc`
- **evaluation_window_start_utc** - `evaluation_window_end_utc - effective_idle_days x 86400 seconds`
- **GPU metric available** - at least one matching `nvidia_smi_utilization_gpu` metric was
  discoverable for the instance.

### 3.1 Explicit scope boundary

This rule applies only to **raw EC2 accelerated-computing instances**, not managed ML resources.

Out of scope:

- SageMaker endpoints, notebooks, Studio apps, or training jobs
- stopped, stopping, pending, shutting-down, or terminated EC2 instances
- FPGA-only and video-transcode families not targeted by this rule
- storage-only cost after instance stop
- workload-semantic reconstruction from application logs

### 3.2 Current family allowlist

The current rule targets these instance-type prefixes:

- `p2.`, `p3.`, `p3dn.`, `p4d.`, `p4de.`, `p5.`, `p5en.`, `p6.`
- `g4dn.`, `g4ad.`, `g5.`, `g5g.`, `g6.`, `g6e.`, `gr6.`
- `trn1.`, `trn1n.`, `trn2.`
- `inf1.`, `inf2.`
- `dl1.`, `dl2q.`

Notes:

- This is a **rule allowlist**, not a complete inventory of every accelerated EC2 family AWS may
  document.
- Non-AI accelerated families such as `f1`, `f2`, and `vt1` are intentionally out of scope.
- Future AWS family-name additions may require allowlist updates even when they are documented in
  the latest accelerated-computing pages.

---

## 4. Canonical Rule Statement

An EC2 instance is eligible only when **all** of the following are true:

1. `State.Name == "running"`
2. `InstanceType` matches the rule allowlist
3. `LaunchTime` is valid and `age_days >= effective_idle_days`
4. one of the utilization branches below is satisfied:
   - **GPU path:** maximum observed `nvidia_smi_utilization_gpu` over the evaluation window is below
      `gpu_threshold`
   - **CPU fallback path:** no qualifying GPU metric is available and maximum observed daily
     `CPUUtilization` over the evaluation window is below `cpu_threshold`

No finding may be emitted from age alone, from instance family alone, or from missing GPU metrics
alone.

---

## 5. Normalization Contract

All logic must operate on normalized fields only.

| Canonical field | Source field | Absent / invalid |
|---|---|---|
| `resource_id` | `InstanceId` | skip item |
| `instance_id` | `InstanceId` | skip item |
| `instance_type` | `InstanceType` | skip item |
| `normalized_state` | `State.Name` | skip item |
| `launch_time_utc` | `LaunchTime` (tz-aware UTC) | skip item |
| `age_days` | floor((now - launch_time_utc) / 86400) | skip item |
| `name_tag` | tag `Name` | fall back to `instance_id` |
| `purchasing_model` | `InstanceLifecycle` | `"on-demand"` when absent |
| `tags` | `Tags` | `{}` |

Normalization requirements:

- `InstanceId` and `InstanceType` must be non-empty strings.
- `State.Name` must be a non-empty string.
- `LaunchTime` must be timezone-aware UTC before use.
- future `LaunchTime` must skip the item.
- `effective_idle_days = max(idle_days, 1)`.

---

## 6. Signal Contract

This rule uses a two-tier utilization model.

### 6.1 HIGH-confidence GPU path

The preferred signal is:

- namespace: `CWAgent`
- metric: `nvidia_smi_utilization_gpu`

Signal interpretation:

- AWS documents this metric as the percentage of time over the sample period during which one or
  more GPU kernels were running.
- The rule first probes metric presence with `ListMetrics`.
- When GPU metrics are present, the rule queries `GetMetricStatistics` using `Statistics=["Maximum"]`
  and `Period=3600`.
- For multi-GPU instances, the rule takes the **maximum** observed utilization across all returned
  GPU-index metrics in the evaluation window.
- If the GPU metric has not published in the last two weeks, `ListMetrics` may not return it even
  if older datapoints still exist in CloudWatch retention; in that case the rule falls back to CPU.
- The current rule does **not** require continuous evaluation-window GPU datapoint coverage. Any returned
  datapoints on the chosen GPU metric path are treated as sufficient for evaluation; complete
  absence of datapoints causes a safe-default skip instead.
- This is intentionally a loose coverage rule matching current implementation behavior: sparse or
  intermittent GPU datapoints can still drive a decision, which is weaker than requiring dense or
  complete coverage of the evaluation window.
- The current rule defines no minimum datapoint count or density threshold for the GPU path.
- In the current implementation, even a single returned GPU datapoint can drive the GPU-path
  decision.

Canonical threshold:

- emit only when `max_gpu_utilization_pct < gpu_threshold`

Why MAX is required:

- on multi-GPU hosts, averaging across GPU indices can hide a single active accelerator
- if any GPU is materially active, the instance must not be flagged idle

### 6.2 MEDIUM-confidence CPU fallback

If no qualifying GPU metric is discoverable, the rule falls back to:

- namespace: `AWS/EC2`
- metric: `CPUUtilization`

Signal interpretation:

- The rule queries `GetMetricStatistics` with `Statistics=["Maximum"]` and `Period=86400`.
- It then takes the **maximum** daily CPU peak across the evaluation window.
- The current rule does **not** require continuous evaluation-window CPU datapoint coverage. Any returned
  datapoints on the chosen CPU path are treated as sufficient for evaluation; complete absence of
  datapoints causes a safe-default skip instead.
- This is intentionally a loose coverage rule matching current implementation behavior: sparse CPU
  datapoints can still drive a decision, which increases false-positive risk relative to a denser
  or complete-coverage requirement.
- The current rule defines no minimum datapoint count or density threshold for the CPU path.
- In the current implementation, even a very small number of CPU datapoints can drive the CPU-path
  decision.

Canonical threshold:

- emit only when `max_daily_cpu_utilization_pct < cpu_threshold`

Why this is weaker:

- CPU is not a direct accelerator activity metric
- accelerator-heavy workloads can perform real work with low CPU
- absence of the CWAgent GPU metric is not proof of GPU inactivity
- the CPU fallback path therefore has materially higher false-positive risk than the GPU path

Therefore CPU fallback is **MEDIUM confidence only**.

### 6.3 Neuron and non-NVIDIA accelerators

For `trn*`, `inf*`, `dl1`, and `dl2q` families:

- `nvidia_smi_utilization_gpu` is not expected to exist
- CPU fallback is the only supported signal in the current rule
- no EC2-native CloudWatch GPU-equivalent metric exists that this rule can query as a drop-in
  replacement across these families
- finding text must make this limitation explicit

### 6.4 Non-canonical or out-of-contract signals

The following are not used for eligibility:

- `GPUPowerUtilization`
- EC2 network, disk, or status-check metrics
- instance age alone
- purchasing model (`spot`, `scheduled`, `capacity-block`, `on-demand`)
- tags
- CloudWatch Logs or application logs

---

## 7. Confidence, Risk, and Cost

### 7.1 Confidence

- **HIGH** when GPU metric path is used and threshold is met
- **MEDIUM** when CPU fallback path is used and threshold is met

### 7.2 Risk

- `idle_ratio = age_days / effective_idle_days`
- **CRITICAL** when `idle_ratio >= 2.0`
- **HIGH** otherwise

### 7.3 Cost

- `estimated_monthly_cost_usd` is advisory context only
- CleanCloud may use an implementation-defined us-east-1 on-demand monthly cost table
- if the instance type is unknown to that table, a default fallback estimate may be used
- cost must not affect eligibility, confidence, or risk gating

---

## 8. Deterministic Evaluation Order

1. Set `effective_idle_days = max(idle_days, 1)`.
2. Call `DescribeInstances` and fully paginate only `running` instances.
3. For each returned instance:
   - state missing or not `running` -> **SKIP ITEM**
   - `InstanceType` missing or not in allowlist -> **SKIP ITEM**
   - invalid / naive / future `LaunchTime` -> **SKIP ITEM**
   - `age_days < effective_idle_days` -> **SKIP ITEM**
4. Probe GPU metrics with `ListMetrics` for `CWAgent / nvidia_smi_utilization_gpu`.
5. If GPU metrics exist:
   - fetch 1-hour `Maximum` datapoints per metric within `[evaluation_window_start_utc, evaluation_window_end_utc]`
   - if no datapoints or metric retrieval fails -> **SKIP ITEM**
   - compute global max across all GPU metrics
   - if `global_max_gpu >= gpu_threshold` -> **SKIP ITEM**
   - otherwise -> **EMIT HIGH-confidence finding**
6. If no GPU metrics exist:
   - fetch daily `Maximum` datapoints for `AWS/EC2 / CPUUtilization` within `[evaluation_window_start_utc, evaluation_window_end_utc]`
   - if no datapoints or metric retrieval fails -> **SKIP ITEM**
   - compute max daily CPU peak
   - if `max_daily_cpu >= cpu_threshold` -> **SKIP ITEM**
   - otherwise -> **EMIT MEDIUM-confidence finding**

No raw field access after normalization.

---

## 9. Exclusion Rules

1. non-`running` instance state
2. instance type not in the rule allowlist
3. missing `InstanceId`
4. missing `InstanceType`
5. missing, naive, or future `LaunchTime`
6. `age_days < effective_idle_days`
7. GPU metric present but any observed GPU maximum meets or exceeds threshold
8. GPU metric absent and CPU daily peak meets or exceeds threshold
9. missing datapoints on the chosen metric path

---

## 10. Failure Model

**Rule-level failures (FAIL RULE):**

- `DescribeInstances` permission failure (`UnauthorizedOperation`, `AccessDenied`)

**Item-level safe-default skips (SKIP ITEM):**

- malformed identity or timestamps
- unsupported instance family
- too young to classify
- CloudWatch metric retrieval returns no datapoints
- CloudWatch metric retrieval errors on the chosen path

Design principle:

- metric uncertainty must resolve to **not idle**, never to a finding
- CloudWatch errors are treated as safe defaults, not as idle evidence

---

## 11. Output Contract

Each emitted finding must preserve the standard `Finding` contract and include, at minimum:

- `provider = "aws"`
- `rule_id = "aws.ec2.gpu.idle"`
- `resource_type = "aws.ec2.instance"`
- `resource_id = InstanceId`
- `region = evaluated region`
- `risk`
- `confidence`
- `detected_at`
- `estimated_monthly_cost_usd`
- `evidence`
- `details`

### 11.1 Evidence contract

`evidence.signals_used` should include:

- instance running state
- instance type
- purchasing model
- the utilization signal used for eligibility
- age when available

`evidence.signals_not_checked` should include:

- direct accelerator utilization when CPU fallback is used
- scheduled workloads outside the observation window
- planned future use

Additional context should note:

- CPU fallback is heuristic only
- CPU fallback has higher false-positive risk than GPU-based detection
- Neuron families require different telemetry for true accelerator utilization
- missing CWAgent GPU metrics do not prove idleness

### 11.2 Details contract

`details` should include:

- `instance_id`
- `instance_type`
- `name`
- `age_days`
- `idle_days_threshold`
- `idle_ratio`
- `idle_signal`
- `utilization_pct`
- `purchasing_model`
- `gpu_metric_available`
- `gpu_threshold_pct`
- `cpu_threshold_pct`
- `estimated_monthly_cost`
- `cost_basis`
- `tags`

---

## 12. Summary of Intended Semantics

This rule detects **running raw EC2 accelerated instances** that are old enough to evaluate and
appear idle under one of two heuristics:

1. **HIGH confidence** - CloudWatch agent GPU metric proves very low GPU execution activity
2. **MEDIUM confidence** - GPU metric unavailable, and CPU peak remains low over the evaluation window

It is intentionally cost-focused and review-oriented. It does **not** prove that an accelerator
workload is absent; it identifies likely expensive idle compute for human review.
