from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.ec2.gpu.idle",
    "category": "ai",
    "service": "ec2",
    "cost_impact": "high",
}

# GPU/accelerator EC2 instance families (raw EC2, not SageMaker)
_GPU_FAMILIES = (
    "p2.",
    "p3.",
    "p3dn.",
    "p4d.",
    "p4de.",
    "p5.",
    "p5en.",  # H100 + higher network bandwidth than p5
    "p6.",  # NVIDIA B200 (Blackwell)
    "g4dn.",
    "g4ad.",
    "g5.",
    "g5g.",
    "g6.",
    "g6e.",
    "gr6.",
    "trn1.",
    "trn1n.",
    "trn2.",
    "inf1.",
    "inf2.",
    "dl1.",
    "dl2q.",
)

# On-demand monthly cost (us-east-1, 730 h/month)
_MONTHLY_COST = {
    # P2 (NVIDIA K80)
    "p2.xlarge": 657.0,
    "p2.8xlarge": 5_256.0,
    "p2.16xlarge": 10_512.0,
    # P3 (NVIDIA V100)
    "p3.2xlarge": 2_234.0,
    "p3.8xlarge": 8_935.0,
    "p3.16xlarge": 17_870.0,
    "p3dn.24xlarge": 23_882.0,
    # P4 (NVIDIA A100 40GB)
    "p4d.24xlarge": 23_374.0,
    # P4de (NVIDIA A100 80GB)
    "p4de.24xlarge": 32_074.0,
    # P5 (NVIDIA H100)
    "p5.48xlarge": 98_318.0,
    # G4dn (NVIDIA T4)
    "g4dn.xlarge": 379.0,
    "g4dn.2xlarge": 601.0,
    "g4dn.4xlarge": 1_166.0,
    "g4dn.8xlarge": 1_752.0,
    "g4dn.12xlarge": 2_918.0,
    "g4dn.16xlarge": 3_504.0,
    "g4dn.metal": 5_837.0,
    # G4ad (AMD Radeon Pro V520)
    "g4ad.xlarge": 261.0,
    "g4ad.2xlarge": 396.0,
    "g4ad.4xlarge": 698.0,
    "g4ad.8xlarge": 1_295.0,
    "g4ad.16xlarge": 2_474.0,
    # G5 (NVIDIA A10G)
    "g5.xlarge": 604.0,
    "g5.2xlarge": 730.0,
    "g5.4xlarge": 1_168.0,
    "g5.8xlarge": 1_972.0,
    "g5.12xlarge": 2_956.0,
    "g5.16xlarge": 3_358.0,
    "g5.24xlarge": 4_380.0,
    "g5.48xlarge": 8_760.0,
    # G5g (NVIDIA T4g — ARM)
    "g5g.xlarge": 279.0,
    "g5g.2xlarge": 416.0,
    "g5g.4xlarge": 700.0,
    "g5g.8xlarge": 1_209.0,
    "g5g.16xlarge": 2_190.0,
    # G6 (NVIDIA L4)
    "g6.xlarge": 604.0,
    "g6.2xlarge": 730.0,
    "g6.4xlarge": 1_095.0,
    "g6.8xlarge": 1_825.0,
    "g6.12xlarge": 2_738.0,
    "g6.16xlarge": 3_066.0,
    "g6.24xlarge": 4_599.0,
    "g6.48xlarge": 9_198.0,
    # G6e (NVIDIA L40S)
    "g6e.xlarge": 1_460.0,
    "g6e.2xlarge": 1_971.0,
    "g6e.4xlarge": 3_138.0,
    "g6e.8xlarge": 5_256.0,
    "g6e.12xlarge": 7_884.0,
    "g6e.16xlarge": 9_636.0,
    "g6e.24xlarge": 13_140.0,
    "g6e.48xlarge": 18_000.0,
    # Gr6 (NVIDIA L4 — high memory)
    "gr6.4xlarge": 1_095.0,
    "gr6.8xlarge": 1_752.0,
    # Trn1 (AWS Trainium)
    "trn1.2xlarge": 657.0,
    "trn1.32xlarge": 10_512.0,
    "trn1n.32xlarge": 11_753.0,
    # Trn2 (AWS Trainium2)
    "trn2.48xlarge": 110_000.0,
    # Inf1 (AWS Inferentia)
    "inf1.xlarge": 183.0,
    "inf1.2xlarge": 292.0,
    "inf1.6xlarge": 875.0,
    "inf1.24xlarge": 3_503.0,
    # Inf2 (AWS Inferentia2)
    "inf2.xlarge": 438.0,
    "inf2.8xlarge": 3_504.0,
    "inf2.24xlarge": 10_512.0,
    "inf2.48xlarge": 21_024.0,
    # DL1 (Habana Gaudi)
    "dl1.24xlarge": 13_140.0,
    # DL2q (Qualcomm)
    "dl2q.24xlarge": 8_760.0,
}
_DEFAULT_MONTHLY_COST = 600.0

# GPU utilization thresholds
_GPU_UTIL_THRESHOLD_PCT = 5.0  # below this = idle (when GPU metric available)
_CPU_UTIL_THRESHOLD_PCT = 10.0  # below this = idle (CPU fallback)

# Neuron accelerator families — use AWS Neuron SDK, not NVIDIA CUDA.
# nvidia_smi_utilization_gpu is never published for these; CPU fallback is expected.
_NEURON_FAMILIES = ("trn1.", "trn1n.", "trn2.", "inf1.", "inf2.", "dl1.", "dl2q.")

_DAYS_IDLE = 7


def find_idle_gpu_instances(
    session: boto3.Session,
    region: str,
    idle_days: int = _DAYS_IDLE,
    gpu_threshold: float = _GPU_UTIL_THRESHOLD_PCT,
    cpu_threshold: float = _CPU_UTIL_THRESHOLD_PCT,
) -> List[Finding]:
    """
    Find EC2 GPU instances (p2/p3/p4/p5/g4/g5/g6/trn/inf/dl) with low utilization.

    GPU instances (raw EC2, outside SageMaker) incur continuous charges while running
    regardless of whether GPUs are being utilised. A p4d.24xlarge costs ~$23K/month
    whether or not a training job is running. Teams frequently leave GPU instances
    running after a job completes, between experiments, or when a project stalls.

    Detection logic:
    - Instance state is running
    - Instance type is a known GPU/accelerator family
    - Instance is older than idle_days (avoids flagging newly launched instances)
    - GPU utilization < gpu_threshold % over idle_days (HIGH confidence, when the
      nvidia_smi_utilization_gpu metric is discoverable for the instance in CloudWatch)
    - OR CPU utilization < cpu_threshold % over idle_days (MEDIUM confidence fallback,
      used when GPU metrics are not available — CPU alone is a weaker signal)

    GPU metric detection:
    The rule probes CloudWatch ListMetrics for nvidia_smi_utilization_gpu in the CWAgent
    namespace, filtered by InstanceId dimension. This depends on the CloudWatch agent
    being installed and configured to append EC2 instance dimensions (e.g. via
    append_dimensions = {"InstanceId": ...}). AWS does not guarantee the InstanceId
    dimension is present by default; its presence is implementation-dependent. If the
    metric is absent or the agent is misconfigured, the rule falls back to CPU
    utilization. Absence of the metric is NOT proof the GPU is idle.

    Multi-GPU handling:
    For multi-GPU instances (e.g., p4d.24xlarge has 8 A100s), the MAX statistic is
    used across all GPU index dimensions. A single active GPU on an 8-GPU instance
    would be averaged away using AVG, producing a misleadingly low reading.

    Confidence:
    - HIGH: GPU metric discoverable AND max GPU utilization < gpu_threshold over idle_days
    - MEDIUM: GPU metric not discoverable; CPU utilization < cpu_threshold over idle_days

    IAM permissions:
    - ec2:DescribeInstances
    - cloudwatch:GetMetricStatistics
    - cloudwatch:ListMetrics
    """
    idle_days = max(idle_days, 1)

    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        pages = paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])

        for page in pages:
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    # Only running instances incur compute charges
                    if inst.get("State", {}).get("Name") != "running":
                        continue

                    instance_type = inst.get("InstanceType", "")
                    if not _is_gpu_instance(instance_type):
                        continue

                    # Normalize InstanceId — skip if missing or empty (spec section 5)
                    instance_id = (inst.get("InstanceId") or "").strip()
                    if not instance_id:
                        continue

                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    # "spot" | "scheduled" | None (on-demand)
                    instance_lifecycle = inst.get("InstanceLifecycle")
                    purchasing_model = instance_lifecycle if instance_lifecycle else "on-demand"

                    # Normalize LaunchTime — skip if missing, naive, or future (spec section 5, section 8.3)
                    launch_time = inst.get("LaunchTime")
                    if not launch_time:
                        continue  # missing LaunchTime → SKIP ITEM
                    if launch_time.tzinfo is None:
                        continue  # naive timestamp is not tz-aware UTC → SKIP ITEM
                    age_days = (now - launch_time).days
                    if age_days < 0:
                        continue  # future LaunchTime → SKIP ITEM

                    # Skip instances younger than effective_idle_days — too new to classify
                    if age_days < idle_days:
                        continue

                    # Probe for GPU metrics — single ListMetrics call reused for stats
                    gpu_metrics = _list_gpu_metrics(cloudwatch, instance_id)

                    if gpu_metrics:
                        max_gpu_util = _get_max_gpu_utilization(
                            cloudwatch, gpu_metrics, idle_days, now
                        )
                        if max_gpu_util is None or max_gpu_util >= gpu_threshold:
                            continue
                        confidence = ConfidenceLevel.HIGH
                        idle_signal = "gpu_utilization"
                        util_value = max_gpu_util
                        util_label = f"Max GPU utilization: {max_gpu_util:.1f}% (threshold: {gpu_threshold}%)"
                    else:
                        max_cpu = _get_max_daily_cpu_utilization(
                            cloudwatch, instance_id, idle_days, now
                        )
                        if max_cpu is None or max_cpu >= cpu_threshold:
                            continue
                        # CPU fallback is a weak heuristic for GPU workloads:
                        # accelerator utilization is invisible to CPU metrics, so a GPU
                        # instance running a compute-bound model can show near-zero CPU
                        # while doing real work. Confidence is capped at MEDIUM to reflect
                        # this limitation. Absence of the CWAgent GPU metric is NOT proof
                        # that the GPU is idle — the agent may be absent or misconfigured.
                        confidence = ConfidenceLevel.MEDIUM
                        idle_signal = "cpu_utilization_fallback"
                        util_value = max_cpu
                        util_label = (
                            f"Peak daily CPU utilization: {max_cpu:.1f}% "
                            f"(threshold: {cpu_threshold}%) — "
                            f"heuristic only; GPU/accelerator utilization not directly measured"
                        )

                    monthly_cost = _MONTHLY_COST.get(instance_type, _DEFAULT_MONTHLY_COST)
                    idle_ratio = round(age_days / idle_days, 2) if (age_days and idle_days) else 0.0

                    if idle_ratio >= 2.0:
                        risk = RiskLevel.CRITICAL
                    else:
                        risk = RiskLevel.HIGH

                    name_tag = tags.get("Name", instance_id)

                    signals = [
                        "Instance state: running",
                        f"Instance type: {instance_type} (GPU/accelerator family)",
                        f"Purchasing model: {purchasing_model}",
                        util_label,
                        f"Instance age: {age_days} days",
                    ]
                    if not gpu_metrics:
                        if _is_neuron_instance(instance_type):
                            signals.append(
                                "Neuron instance (Trainium/Inferentia) — NVIDIA GPU metric not "
                                "applicable; CPU used as heuristic fallback; confidence MEDIUM. "
                                "Neuron utilization requires AWS Neuron SDK metrics."
                            )
                        else:
                            signals.append(
                                "CWAgent nvidia_smi_utilization_gpu metric not found — "
                                "this may mean the CloudWatch agent is not installed, not that "
                                "the GPU is idle. CPU used as heuristic fallback; confidence MEDIUM."
                            )

                    # signals_not_checked: GPU note only applies on CPU fallback path (spec section 11.1)
                    not_checked = [
                        "Scheduled batch jobs that run outside the observation window",
                        "Planned future use",
                    ]
                    if not gpu_metrics:
                        not_checked.insert(
                            0,
                            "Direct GPU/accelerator utilization — nvidia_smi_utilization_gpu was not "
                            "discoverable in CloudWatch (CWAgent may be absent or not configured with "
                            "InstanceId dimension); absence of the metric does not confirm the GPU is idle",
                        )
                    if purchasing_model == "spot":
                        not_checked.append(
                            "Spot interruption history — Spot instances may appear idle "
                            "between interruption and relaunch"
                        )

                    evidence = Evidence(
                        signals_used=signals,
                        signals_not_checked=not_checked,
                        time_window=f"{idle_days} days",
                    )

                    metric_label = "GPU" if gpu_metrics else "CPU (fallback)"
                    if gpu_metrics:
                        reason = (
                            f"GPU EC2 instance has low GPU utilization "
                            f"({util_value:.1f}%) over {idle_days} days"
                        )
                    else:
                        reason = (
                            f"GPU EC2 instance shows low CPU proxy signal "
                            f"({util_value:.1f}%) over {idle_days} days — "
                            f"GPU activity not directly measured"
                        )
                    findings.append(
                        Finding(
                            provider="aws",
                            rule_id="aws.ec2.gpu.idle",
                            resource_type="aws.ec2.instance",
                            resource_id=instance_id,
                            region=region,
                            estimated_monthly_cost_usd=monthly_cost,
                            title=(
                                f"Idle GPU EC2 Instance ({metric_label} utilization "
                                f"<{gpu_threshold if gpu_metrics else cpu_threshold}% "
                                f"over {idle_days} days)"
                            ),
                            summary=(
                                f"EC2 instance '{name_tag}' ({instance_type}) has had "
                                f"{'GPU' if gpu_metrics else 'CPU'} utilization below "
                                f"{gpu_threshold if gpu_metrics else cpu_threshold}% "
                                f"for {idle_days} days while running, incurring "
                                f"continuous charges (~${monthly_cost:,.0f}/month us-east-1 estimate)."
                            ),
                            reason=reason,
                            risk=risk,
                            confidence=confidence,
                            detected_at=now,
                            evidence=evidence,
                            details={
                                "instance_id": instance_id,
                                "instance_type": instance_type,
                                "name": name_tag,
                                "age_days": age_days,
                                "idle_days_threshold": idle_days,
                                "idle_ratio": idle_ratio,
                                "idle_signal": idle_signal,
                                "utilization_pct": round(util_value, 2),
                                "purchasing_model": purchasing_model,
                                "gpu_metric_available": bool(gpu_metrics),
                                "gpu_metric_note": (
                                    "agent-dependent (CWAgent nvidia_smi_utilization_gpu); "
                                    "absence does not confirm GPU is idle"
                                ),
                                "gpu_threshold_pct": gpu_threshold,
                                "cpu_threshold_pct": cpu_threshold,
                                "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                                "cost_basis": "us-east-1 on-demand (region-dependent estimate)",
                                "tags": tags,
                            },
                        )
                    )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "ec2:DescribeInstances, cloudwatch:GetMetricStatistics, cloudwatch:ListMetrics"
            ) from e
        raise

    return findings


find_idle_gpu_instances.RULE_ID = "aws.ec2.gpu.idle"


def _is_gpu_instance(instance_type: str) -> bool:
    return any(instance_type.startswith(fam) for fam in _GPU_FAMILIES)


def _is_neuron_instance(instance_type: str) -> bool:
    return any(instance_type.startswith(fam) for fam in _NEURON_FAMILIES)


def _list_gpu_metrics(cloudwatch, instance_id: str) -> list:
    """
    Probe CloudWatch ListMetrics for nvidia_smi_utilization_gpu under CWAgent namespace.

    Exhausts pagination via NextToken (spec section 2 key fact 6: ListMetrics returns up to
    500 results per call). Returns all Metrics entries so the caller can reuse them
    for GetMetricStatistics without a second ListMetrics call. Returns [] on any error.
    """
    metrics: list = []
    kwargs: dict = {
        "Namespace": "CWAgent",
        "MetricName": "nvidia_smi_utilization_gpu",
        "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
    }
    try:
        while True:
            resp = cloudwatch.list_metrics(**kwargs)
            metrics.extend(resp.get("Metrics", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token
    except Exception:
        return []
    return metrics


def _get_max_gpu_utilization(
    cloudwatch, gpu_metrics: list, days: int, now: datetime
) -> Optional[float]:
    """
    Return the maximum GPU utilization across all GPU indices over the window.

    Takes the gpu_metrics list already fetched by _list_gpu_metrics — no second
    ListMetrics call. Uses MAX statistic so a single active GPU on a multi-GPU
    instance (e.g., p4d.24xlarge with 8 A100s) is not averaged away.

    Returns None on error — caller treats None as "not idle" (safe default).
    """
    start = now - timedelta(days=days)
    max_util: Optional[float] = None

    for metric in gpu_metrics:
        dimensions = metric.get("Dimensions", [])
        try:
            stats = cloudwatch.get_metric_statistics(
                Namespace="CWAgent",
                MetricName="nvidia_smi_utilization_gpu",
                Dimensions=dimensions,
                StartTime=start,
                EndTime=now,
                Period=3600,
                Statistics=["Maximum"],
            )
            datapoints = stats.get("Datapoints", [])
            if not datapoints:
                continue
            gpu_max = max(dp["Maximum"] for dp in datapoints)
            if max_util is None or gpu_max > max_util:
                max_util = gpu_max
        except Exception:
            continue

    return max_util


def _get_max_daily_cpu_utilization(
    cloudwatch, instance_id: str, days: int, now: datetime
) -> Optional[float]:
    """
    Return the maximum daily CPU peak over the window using AWS/EC2 CPUUtilization.

    Uses Maximum statistic at daily (86400s) period and returns the highest value
    across all returned datapoints (spec section 6.2). This avoids flagging burst workloads
    where a short but significant CPU spike would be averaged away.

    Returns None on error or no datapoints — caller treats None as "not idle" (safe default).
    """
    start = now - timedelta(days=days)
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=now,
            Period=86400,  # 1-day granularity
            Statistics=["Maximum"],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return None
        return max(dp["Maximum"] for dp in datapoints)
    except Exception:
        return None
