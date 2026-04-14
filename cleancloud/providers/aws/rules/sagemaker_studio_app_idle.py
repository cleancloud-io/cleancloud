import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

RULE_METADATA = {
    "id": "aws.sagemaker.studio_app.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}

# GPU/accelerator instance families — significantly more expensive than CPU.
# Sorted so newer families appear alongside related predecessors.
_GPU_FAMILIES = (
    "ml.g4dn",
    "ml.g5",
    "ml.g6",  # NVIDIA L4 (2024)
    "ml.g6e",  # NVIDIA L40S (2024)
    "ml.p2",
    "ml.p3",
    "ml.p4d",
    "ml.p4de",
    "ml.p5",
    "ml.p5en",  # NVIDIA H200 (2024)
    "ml.p6",  # NVIDIA B200 (2025)
    "ml.trn1",
    "ml.trn2",  # Trainium2 (2024)
    "ml.inf1",
    "ml.inf2",
)

# If LastUserActivityTimestamp and LastHealthCheckTimestamp are within this window
# of each other, the "activity" is a health check — not real user interaction.
# SageMaker Studio health checks update LUAT, making idle apps appear recently active.
_HEALTH_CHECK_EPSILON = timedelta(minutes=5)

# App types to include in idle detection
_INCLUDED_APP_TYPES = {"KernelGateway", "JupyterLab", "CodeEditor"}

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
    # NVIDIA L4 (ml.g6) — approximate on-demand us-east-1
    "ml.g6.xlarge": 700.0,
    "ml.g6.2xlarge": 1_097.0,
    "ml.g6.4xlarge": 1_784.0,
    "ml.g6.8xlarge": 3_249.0,
    "ml.g6.12xlarge": 4_874.0,
    "ml.g6.16xlarge": 6_313.0,
    "ml.g6.48xlarge": 16_617.0,
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
_DEFAULT_MONTHLY_COST = 50.0
# GPU instances with unrecognised sizes (e.g. future SKUs) are expensive by nature.
# Use a higher floor so cost estimates don't undervalue GPU findings.
_DEFAULT_MONTHLY_COST_GPU = 200.0

# Minimum app age before it can be flagged, regardless of idle_days.
# Prevents classifying apps as abandoned in their first week of existence.
_MIN_APP_AGE_DAYS = 7


def find_idle_sagemaker_studio_apps(
    session: boto3.Session,
    region: str,
    idle_days: int = 7,
) -> List[Finding]:
    """
    Find SageMaker Studio apps (KernelGateway/JupyterLab/CodeEditor) with no user activity.

    SageMaker Studio apps incur continuous charges while InService. Unlike JupyterServer
    (a low-cost domain-managed infra app), KernelGateway, JupyterLab, and CodeEditor
    apps attach to compute instances and bill at full instance rates. GPU-backed apps
    cost $500–$23K+/month.

    Data scientists frequently leave Studio apps running after finishing a session,
    switching to a new space, or when a project is deprioritised.

    Detection logic:
    - App is InService AND AppType in {KernelGateway, JupyterLab, CodeEditor}
    - LastUserActivityTimestamp (LUAT) from describe_app indicates no recent user interaction.
      Health-check guard: AWS health checks also write to LUAT, so an idle app can appear
      "recently active." We compare LUAT with LastHealthCheckTimestamp (LHCT): if
      |LUAT - LHCT| <= _HEALTH_CHECK_EPSILON (5 minutes), the signal is ambiguous — LUAT
      may be health-check-driven, or the user may have been active moments before the check.
      Either interpretation is possible, so the app is skipped (false negative preferred
      over false positive). A trustworthy LUAT sits well outside the health-check window.
    - Falls back to CreationTime only when LUAT is entirely absent (conservative, MEDIUM)

    Confidence:
    - HIGH: idle_since_days >= idle_days AND age_days >= idle_days,
            using LastUserActivityTimestamp (not a CreationTime fallback)
    - MEDIUM: idle_since_days >= ceil(75% of idle_days) AND age_days >= ceil(75% of idle_days);
              capped at MEDIUM for the CreationTime fallback (LUAT absent), because absence
              of the timestamp is not confirmed zero activity — background kernel execution
              and non-UI interactions may not emit LastUserActivityTimestamp.

    Age guard:
    - Apps younger than max(idle_days // 2, _MIN_APP_AGE_DAYS=7) are always skipped.
      The 7-day floor (_MIN_APP_AGE_DAYS) prevents flagging apps in their first week.

    IAM permissions required:
    - sagemaker:ListApps
    - sagemaker:DescribeApp
    """
    # Guard against caller passing 0 — would collapse all thresholds to zero and
    # flag every InService app as HIGH confidence regardless of age.
    idle_days = max(idle_days, 1)

    sagemaker = session.client("sagemaker", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = sagemaker.get_paginator("list_apps")

        for page in paginator.paginate():
            for app in page.get("Apps", []):
                # Filter: only InService apps of the targeted types
                status = app.get("Status", "")
                app_type = app.get("AppType", "")

                if status != "InService":
                    continue
                if app_type not in _INCLUDED_APP_TYPES:
                    continue

                domain_id = app["DomainId"]
                app_name = app["AppName"]
                space_name = app.get("SpaceName")
                user_profile = app.get("UserProfileName")
                owner = space_name or user_profile or "unknown"

                # Normalize CreationTime — older boto3 may return timezone-naive datetimes
                create_time = app.get("CreationTime")
                if create_time:
                    if create_time.tzinfo is None:
                        create_time = create_time.replace(tzinfo=timezone.utc)
                    age_days = (now - create_time).days
                else:
                    # CreationTime missing — use idle_days as a neutral default
                    age_days = idle_days

                # Skip apps younger than half the idle threshold —
                # too new to reliably classify as abandoned.
                # _MIN_APP_AGE_DAYS (7) is a hard floor — apps in their first week
                # are never flagged regardless of how small idle_days is.
                if age_days < max(idle_days // 2, _MIN_APP_AGE_DAYS):
                    continue

                # Describe app to get instance type and last user activity
                describe_result = _describe_studio_app(
                    sagemaker,
                    domain_id=domain_id,
                    app_type=app_type,
                    app_name=app_name,
                    user_profile_name=user_profile,
                    space_name=space_name,
                )

                # None means a non-auth describe failure — skip unknown state
                if describe_result is None:
                    continue

                instance_type = describe_result.get("instance_type") or ""
                last_activity = describe_result.get("last_activity")
                last_health_check = describe_result.get("last_health_check")

                # Normalize both timestamps to UTC-aware before any comparison.
                if last_activity is not None and last_activity.tzinfo is None:
                    last_activity = last_activity.replace(tzinfo=timezone.utc)
                if last_health_check is not None and last_health_check.tzinfo is None:
                    last_health_check = last_health_check.replace(tzinfo=timezone.utc)

                # If LUAT and LHCT are within _HEALTH_CHECK_EPSILON of each other,
                # the idle signal is unreliable: LUAT may have been written by the
                # health check itself, OR the user was active moments before the check
                # ran.  Either way we cannot infer idleness — skip this app rather than
                # fall back to age, which would falsely flag an actively-used app as
                # "idle since creation."
                if (
                    last_activity is not None
                    and last_health_check is not None
                    and abs((last_health_check - last_activity).total_seconds())
                    <= _HEALTH_CHECK_EPSILON.total_seconds()
                ):
                    continue  # insufficient signal — prefer false negative over false positive

                using_fallback = last_activity is None
                if not using_fallback:
                    idle_since_days = (now - last_activity).days
                    idle_signal_source = "LastUserActivityTimestamp"
                else:
                    # LUAT was never emitted — use app age as a conservative proxy.
                    # This can happen for background kernels or apps that have never
                    # received an interactive session.
                    idle_since_days = age_days
                    idle_signal_source = "CreationTime (no LastUserActivityTimestamp)"

                # Confidence thresholds
                threshold_high = idle_days
                threshold_medium = math.ceil(idle_days * 0.75)

                if idle_since_days >= threshold_high and age_days >= threshold_high:
                    confidence = ConfidenceLevel.HIGH
                elif idle_since_days >= threshold_medium and age_days >= threshold_medium:
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    continue  # Too borderline for a confident finding

                # Cap at MEDIUM when using CreationTime fallback.
                # Absence of LastUserActivityTimestamp ≠ confirmed zero activity —
                # background kernel execution and non-UI interactions may not emit it.
                if using_fallback and confidence == ConfidenceLevel.HIGH:
                    confidence = ConfidenceLevel.MEDIUM

                is_gpu = bool(
                    instance_type and any(instance_type.startswith(f) for f in _GPU_FAMILIES)
                )
                # GPU instances with unrecognised sizes use a higher floor ($200)
                # so cost estimates don't dangerously undervalue GPU findings.
                monthly_cost = _MONTHLY_COST_BY_INSTANCE.get(
                    instance_type,
                    _DEFAULT_MONTHLY_COST_GPU if is_gpu else _DEFAULT_MONTHLY_COST,
                )

                # idle_ratio >= 2 means the app has been idle for at least twice the threshold.
                # GPU resources at this level are extreme waste — escalate to CRITICAL.
                idle_ratio = round(idle_since_days / idle_days, 2) if idle_days > 0 else 0.0
                if is_gpu and idle_ratio >= 2.0:
                    risk = RiskLevel.CRITICAL
                elif is_gpu:
                    risk = RiskLevel.HIGH
                else:
                    risk = RiskLevel.MEDIUM

                resource_id = f"{domain_id}/{owner}/{app_type}/{app_name}"
                owner_type = "space" if space_name else "user_profile"

                signals = [
                    "App state: InService",
                    f"App type: {app_type}",
                    f"Age: {age_days} days",
                    f"Last user activity: {idle_since_days} days ago ({idle_signal_source})",
                ]
                if instance_type:
                    signals.append(f"Instance type: {instance_type}")
                if is_gpu:
                    signals.append("GPU-backed instance — high hourly cost")

                not_checked = [
                    "Active kernel sessions — background execution (papermill, Step Functions) "
                    "may not update LastUserActivityTimestamp; verify no cells are running before deletion",
                    "Scheduled notebook runs (EventBridge, Step Functions)",
                    "Planned future use by the assigned user or space",
                    "Resource tags (e.g. keep_alive=true) — "
                    "use --ignore-tag or cleancloud.yaml exceptions to suppress intentional apps",
                ]

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=not_checked,
                    time_window=f"{idle_since_days} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.sagemaker.studio_app.idle",
                        resource_type="aws.sagemaker.studio_app",
                        resource_id=resource_id,
                        region=region,
                        estimated_monthly_cost_usd=monthly_cost,
                        title=(
                            f"Idle SageMaker Studio App "
                            f"({app_type}, {idle_since_days} Days Since Last Activity)"
                        ),
                        summary=(
                            f"SageMaker Studio {app_type} app '{app_name}' "
                            f"(domain {domain_id}, {owner_type}: {owner}) "
                            f"has had no user activity for {idle_since_days} days but remains "
                            f"InService, incurring continuous charges (~${monthly_cost:,.0f}/month)."
                        ),
                        reason=(
                            f"SageMaker Studio {app_type} app has had no user activity "
                            f"for {idle_since_days} days"
                        ),
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "domain_id": domain_id,
                            "app_name": app_name,
                            "app_type": app_type,
                            "owner": owner,
                            "owner_type": owner_type,
                            "instance_type": instance_type or None,
                            "is_gpu": is_gpu,
                            "age_days": age_days,
                            "idle_since_days": idle_since_days,
                            "idle_signal_source": idle_signal_source,
                            "idle_days_threshold": idle_days,
                            "idle_ratio": idle_ratio,
                            "waste_score": round(monthly_cost * idle_ratio, 2),
                            "estimated_monthly_cost": f"~${monthly_cost:,.0f}/month",
                            "cost_basis": "us-east-1 on-demand estimate",
                            "confidence_note": (
                                "Capped at MEDIUM: LastUserActivityTimestamp absent, "
                                "using CreationTime as fallback — background kernel activity "
                                "may not update this timestamp"
                                if using_fallback
                                else None
                            ),
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError("Missing required IAM permissions: sagemaker:ListApps") from e
        raise

    return findings


def _describe_studio_app(
    sagemaker,
    domain_id: str,
    app_type: str,
    app_name: str,
    user_profile_name: Optional[str],
    space_name: Optional[str],
) -> Optional[Dict]:
    """Describe a SageMaker Studio app and return instance type and last activity.

    Returns a dict with keys:
        - "instance_type": str or None
        - "last_activity": datetime or None  (LastUserActivityTimestamp)
        - "last_health_check": datetime or None  (LastHealthCheckTimestamp)

    Auth errors (AccessDenied/AccessDeniedException/UnauthorizedOperation) are raised
    as PermissionError so the scan framework can surface the missing permission.

    Other ClientErrors (e.g. ResourceNotFound) return None — the caller skips the app
    rather than flagging an unknown state.
    """
    kwargs: Dict = {
        "DomainId": domain_id,
        "AppType": app_type,
        "AppName": app_name,
    }
    # SpaceName and UserProfileName are mutually exclusive in the API
    if space_name:
        kwargs["SpaceName"] = space_name
    elif user_profile_name:
        kwargs["UserProfileName"] = user_profile_name

    try:
        response = sagemaker.describe_app(**kwargs)
        resource_spec = response.get("ResourceSpec") or {}
        instance_type = resource_spec.get("InstanceType") or None
        last_activity = response.get("LastUserActivityTimestamp")
        last_health_check = response.get("LastHealthCheckTimestamp")
        return {
            "instance_type": instance_type,
            "last_activity": last_activity,
            "last_health_check": last_health_check,
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            raise PermissionError("Missing required IAM permissions: sagemaker:DescribeApp") from e
        # Non-auth errors (ResourceNotFound, throttling transient, etc.) — skip this app
        return None
