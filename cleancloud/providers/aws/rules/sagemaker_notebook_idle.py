from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.sagemaker.notebook.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}

# GPU/accelerator instance families — significantly more expensive than CPU
_GPU_FAMILIES = (
    "ml.g4dn",
    "ml.g5",
    "ml.p2",
    "ml.p3",
    "ml.p4d",
    "ml.p4de",
    "ml.p5",
    "ml.trn1",
    "ml.inf1",
    "ml.inf2",
)

# Approximate monthly cost by instance type (on-demand, us-east-1)
_MONTHLY_COST_BY_INSTANCE = {
    "ml.t2.medium": 40.0,
    "ml.t2.large": 67.0,
    "ml.t2.xlarge": 133.0,
    "ml.t3.medium": 42.0,
    "ml.t3.large": 84.0,
    "ml.t3.xlarge": 168.0,
    "ml.m5.large": 94.0,
    "ml.m5.xlarge": 188.0,
    "ml.m5.2xlarge": 376.0,
    "ml.m5.4xlarge": 752.0,
    "ml.m5.12xlarge": 2_256.0,
    "ml.c5.large": 85.0,
    "ml.c5.xlarge": 171.0,
    "ml.c5.2xlarge": 343.0,
    "ml.c5.4xlarge": 686.0,
    "ml.g4dn.xlarge": 531.0,
    "ml.g4dn.2xlarge": 941.0,
    "ml.g4dn.4xlarge": 1_633.0,
    "ml.g4dn.12xlarge": 2_817.0,
    "ml.g5.xlarge": 600.0,
    "ml.g5.2xlarge": 1_008.0,
    "ml.g5.4xlarge": 1_838.0,
    "ml.g5.12xlarge": 5_443.0,
    "ml.p3.2xlarge": 2_754.0,
    "ml.p3.8xlarge": 11_016.0,
    "ml.p4d.24xlarge": 23_596.0,
    "ml.p4de.24xlarge": 29_908.0,
    "ml.p5.48xlarge": 71_774.0,
    # Trainium (ml.trn1 / ml.trn1n)
    "ml.trn1.2xlarge": 978.0,
    "ml.trn1.32xlarge": 15_695.0,
    "ml.trn1n.32xlarge": 18_089.0,
    # Inferentia (ml.inf1)
    "ml.inf1.xlarge": 166.0,
    "ml.inf1.2xlarge": 264.0,
    "ml.inf1.6xlarge": 793.0,
    "ml.inf1.24xlarge": 3_170.0,
    # Inferentia2 (ml.inf2)
    "ml.inf2.xlarge": 554.0,
    "ml.inf2.8xlarge": 4_427.0,
    "ml.inf2.24xlarge": 13_283.0,
    "ml.inf2.48xlarge": 26_566.0,
}
_DEFAULT_MONTHLY_COST = 150.0


def find_idle_sagemaker_notebooks(
    session: boto3.Session,
    region: str,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find SageMaker Notebook Instances in InService state with no recent activity.

    SageMaker Notebook Instances incur continuous charges while InService, regardless
    of whether they are actively used. GPU-backed notebooks cost $500–$11K+/month.
    Data scientists frequently leave notebook instances running after a sprint ends,
    a project is deprioritised, or when they are granted a new instance and forget
    the old one.

    Detection logic:
    - Notebook is in InService state (only InService instances incur compute charges)
    - LastModifiedTime is older than the idle threshold

    LastModifiedTime is updated by SageMaker when:
    - The notebook configuration is changed (instance type, lifecycle config, tags)
    - The notebook is stopped and restarted
    - A Git repository is synced
    Notebooks with old LastModifiedTime have had no control-plane activity, which is
    the strongest idle signal available without a CloudWatch agent lifecycle config.

    Note: SageMaker Notebook Instances do not publish utilisation metrics to CloudWatch
    by default — unlike endpoints (which publish Invocations) or training jobs. The
    LastModifiedTime approach is the correct and standard signal used by AWS Cost
    Optimisation Hub and third-party FinOps tools for notebook idle detection.

    Confidence:
    - HIGH: LastModifiedTime >= idle_days ago AND age >= idle_days
    - MEDIUM: LastModifiedTime >= 75% of idle_days AND age >= 75% of idle_days

    IAM permissions required:
    - sagemaker:ListNotebookInstances
    """
    # Guard against caller passing 0 — would collapse all thresholds to zero and
    # flag every InService notebook as HIGH confidence regardless of age.
    idle_days = max(idle_days, 1)

    sagemaker = session.client("sagemaker", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = sagemaker.get_paginator("list_notebook_instances")

        for page in paginator.paginate(StatusEquals="InService"):
            for nb in page.get("NotebookInstances", []):
                name = nb["NotebookInstanceName"]

                # Normalize CreationTime — older boto3 may return timezone-naive datetimes
                create_time = nb.get("CreationTime")
                if create_time:
                    if create_time.tzinfo is None:
                        create_time = create_time.replace(tzinfo=timezone.utc)
                    age_days = (now - create_time).days
                else:
                    # CreationTime missing — use idle_days as a neutral default so the
                    # age guard below neither auto-passes nor auto-fails this notebook.
                    age_days = idle_days

                # Skip notebooks younger than half the idle threshold —
                # too new to reliably classify as abandoned
                if age_days < max(idle_days // 2, 7):
                    continue

                # Normalize LastModifiedTime
                last_modified = nb.get("LastModifiedTime")
                if last_modified:
                    if last_modified.tzinfo is None:
                        last_modified = last_modified.replace(tzinfo=timezone.utc)
                    idle_since_days = (now - last_modified).days
                else:
                    # No LastModifiedTime in response — use age as conservative proxy
                    idle_since_days = age_days

                # Confidence thresholds
                threshold_high = idle_days
                threshold_medium = int(idle_days * 0.75)

                if idle_since_days >= threshold_high and age_days >= threshold_high:
                    confidence = ConfidenceLevel.HIGH
                elif idle_since_days >= threshold_medium and age_days >= threshold_medium:
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    continue  # Too borderline for a confident finding

                # Lifecycle config presence: an attached config often indicates the notebook
                # is actively managed (auto-stop, environment setup, etc.), which reduces
                # certainty that it is truly abandoned. Cap HIGH → MEDIUM in this case.
                lifecycle_config = nb.get("NotebookInstanceLifecycleConfigName") or ""
                if lifecycle_config and confidence == ConfidenceLevel.HIGH:
                    confidence = ConfidenceLevel.MEDIUM

                # InstanceType is included in the list_notebook_instances response —
                # no separate describe call needed for cost and GPU classification
                instance_type = nb.get("InstanceType", "")
                is_gpu = bool(
                    instance_type and any(instance_type.startswith(f) for f in _GPU_FAMILIES)
                )
                monthly_cost = _MONTHLY_COST_BY_INSTANCE.get(instance_type, _DEFAULT_MONTHLY_COST)

                # idle_ratio >= 2 means the notebook has been idle for at least twice the
                # threshold (e.g. 28+ days at the default 14-day window). GPU resources at
                # this level are extreme waste — elevate to CRITICAL to surface them first.
                idle_ratio = round(idle_since_days / idle_days, 2) if idle_days > 0 else 0.0
                if is_gpu and idle_ratio >= 2.0:
                    risk = RiskLevel.CRITICAL
                elif is_gpu:
                    risk = RiskLevel.HIGH
                else:
                    risk = RiskLevel.MEDIUM

                signals = [
                    "Notebook state: InService",
                    f"Age: {age_days} days",
                    f"Last control-plane activity: {idle_since_days} days ago (LastModifiedTime)",
                ]
                if instance_type:
                    signals.append(f"Instance type: {instance_type}")
                if is_gpu:
                    signals.append("GPU-backed instance — high hourly cost")
                if lifecycle_config:
                    signals.append(
                        f"Lifecycle config attached: {lifecycle_config} "
                        f"(confidence capped at MEDIUM — notebook may be actively managed)"
                    )

                not_checked = [
                    "Active kernel sessions (requires CloudWatch agent via lifecycle config)",
                    "Scheduled notebook runs (e.g. via EventBridge or Step Functions)",
                    "Planned future use by the assigned user",
                    "Resource tags (e.g. keep_alive=true, environment=dev) — "
                    "use --ignore-tag or cleancloud.yaml exceptions to suppress intentional notebooks",
                ]

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=not_checked,
                    time_window=f"{idle_since_days} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.sagemaker.notebook.idle",
                        resource_type="aws.sagemaker.notebook",
                        resource_id=name,
                        region=region,
                        estimated_monthly_cost_usd=monthly_cost,
                        title=f"Idle SageMaker Notebook (>{idle_days} Days Idle, {idle_since_days} Days Since Activity)",
                        summary=(
                            f"SageMaker Notebook Instance '{name}' has had no control-plane "
                            f"activity for {idle_since_days} days but remains InService, incurring "
                            f"continuous charges (~${monthly_cost:,.0f}/month)."
                        ),
                        reason=f"SageMaker notebook instance has had no control-plane activity for {idle_since_days} days",
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "notebook_name": name,
                            "instance_type": instance_type,
                            "is_gpu": is_gpu,
                            "age_days": age_days,
                            "idle_since_days": idle_since_days,
                            "idle_days_threshold": idle_days,
                            "idle_ratio": idle_ratio,
                            "lifecycle_config": lifecycle_config or None,
                            "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                            "cost_source": f"approximate_{region}",
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "Missing required IAM permissions: sagemaker:ListNotebookInstances"
            ) from e
        raise

    return findings
