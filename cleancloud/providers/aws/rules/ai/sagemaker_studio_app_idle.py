"""
Rule: aws.sagemaker.studio_app.idle

    (spec — docs/specs/aws/ai/sagemaker_studio_app_idle.md)

Intent:
    Detect SageMaker Studio applications that are currently InService, belong to
    the supported interactive compute-backed app types, and show no recent best-effort
    activity timestamp for the configured review window, so they can be reviewed as
    possible cleanup candidates.

    This is a CleanCloud-derived review heuristic based on SageMaker Studio app
    metadata, not an AWS-native idle state. It is a read-only review-candidate rule
    — not a delete-safe rule.

Exclusions:
    - domain_id, app_name, or app_type absent (malformed inventory item)
    - list or describe status absent or not "InService"
    - unsupported app_type (only KernelGateway, JupyterLab, CodeEditor are in scope)
    - owner context absent (both space_name and user_profile_name absent)
    - CreationTime absent, naive, or future (timestamp validity only; not a freshness gate)
    - AppArn absent from describe response
    - LastUserActivityTimestamp absent, naive, or future
    - LastUserActivityTimestamp < CreationTime (inconsistent timestamp state)
    - LastUserActivityTimestamp == LastHealthCheckTimestamp (treated as non-user signal)
    - idle_since_days < idle_days_threshold (not idle enough)

Detection:
    - InService KernelGateway, JupyterLab, or CodeEditor app
    - usable_activity_signal = true (LUAT present and not equal to LHCT)
    - idle_since_days >= idle_days_threshold

Key rules:
    - resource_id = AppArn (from DescribeApp)
    - estimated_monthly_cost_usd = None
    - Confidence: HIGH always (missing/unusable activity signal → SKIP, not MEDIUM)
    - Risk: HIGH for accelerator-backed (g*, p*, inf*, trn*); MEDIUM otherwise
    - ListApps failure → FAIL RULE; permission failure → FAIL RULE
    - DescribeApp permission failure → FAIL RULE
    - DescribeApp non-permission failure → SKIP ITEM
    - BotoCoreError on DescribeApp → SKIP ITEM
    - BotoCoreError on ListApps → FAIL RULE
    - Health check check: exact equality only (LUAT == LHCT → SKIP ITEM)
    - CreationTime used for validity/reporting only, not as idle signal fallback

Blind spots:
    - Background kernel execution or non-UI interactions not represented by usable_activity_signal
    - Planned future usage or intentional warm apps
    - Stopped-app / space storage cost
    - Exact region-specific pricing impact

APIs:
    - sagemaker:ListApps
    - sagemaker:DescribeApp
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 7
_ELIGIBLE_STATUS = "InService"
_SUPPORTED_APP_TYPES = frozenset({"KernelGateway", "JupyterLab", "CodeEditor"})

# Accelerator instance type prefixes — used for HIGH risk determination
_ACCELERATOR_PREFIXES = ("ml.g", "ml.p", "ml.inf", "ml.trn")

_FINDING_TITLE = "Idle SageMaker Studio app review candidate"

_SIGNALS_NOT_CHECKED = (
    "Background kernel execution or non-UI interactions not represented by usable_activity_signal",
    "Planned future usage or intentional warm apps",
    "Stopped-app / space storage cost",
    "Exact region-specific pricing impact",
)

RULE_METADATA = {
    "id": "aws.sagemaker.studio_app.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _is_accelerator_backed(instance_type: Optional[str]) -> bool:
    """Return True when the instance type is an accelerator (g*, p*, inf*, trn*)."""
    if not instance_type:
        return False
    return any(instance_type.startswith(prefix) for prefix in _ACCELERATOR_PREFIXES)


def _normalize_list_item(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListApps item to canonical list-level fields.

    Returns None when required fields are absent or invalid — caller must skip item.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity (required; absent → skip) ---
    domain_id = _str(item.get("DomainId"))
    if domain_id is None:
        return None

    app_name = _str(item.get("AppName"))
    if app_name is None:
        return None

    app_type = _str(item.get("AppType"))
    if app_type is None:
        return None

    # --- Status (required; absent → skip) ---
    list_status = _str(item.get("Status"))
    if list_status is None:
        return None

    # --- CreationTime (required; absent, naive, future → skip — timestamp validity only) ---
    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc:
        return None

    age_days = int((now_utc - creation_time_utc).total_seconds() // 86400)

    # --- Owner context (both absent → skip) ---
    space_name = _str(item.get("SpaceName"))
    user_profile_name = _str(item.get("UserProfileName"))

    if space_name is not None:
        owner_type = "space"
        owner_name = space_name
    elif user_profile_name is not None:
        owner_type = "user_profile"
        owner_name = user_profile_name
    else:
        return None  # no owner context → skip

    # --- Optional: instance type from ListApps ResourceSpec ---
    raw_rs = item.get("ResourceSpec")
    resource_spec = raw_rs if isinstance(raw_rs, dict) else {}
    instance_type = _str(resource_spec.get("InstanceType"))

    return {
        "domain_id": domain_id,
        "app_name": app_name,
        "app_type": app_type,
        "list_status": list_status,
        "creation_time_utc": creation_time_utc,
        "age_days": age_days,
        "space_name": space_name,
        "user_profile_name": user_profile_name,
        "owner_type": owner_type,
        "owner_name": owner_name,
        "instance_type": instance_type,
    }


def _normalize_describe(response: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a DescribeApp response to canonical describe-level fields.

    Returns None when required fields are absent or invalid — caller must skip item.
    """
    if not isinstance(response, dict):
        return None

    # --- AppArn → resource_id (required; absent → skip) ---
    app_arn = _str(response.get("AppArn"))
    if app_arn is None:
        return None

    # --- Status (required; absent → skip) ---
    describe_status = _str(response.get("Status"))
    if describe_status is None:
        return None

    # --- LastUserActivityTimestamp (required; absent, naive, future → skip) ---
    raw_luat = response.get("LastUserActivityTimestamp")
    if not isinstance(raw_luat, datetime):
        return None
    if raw_luat.tzinfo is None:
        return None
    last_user_activity_time_utc = raw_luat.astimezone(timezone.utc)
    if last_user_activity_time_utc > now_utc:
        return None

    # --- LastHealthCheckTimestamp (optional; absent/naive → null; future → skip item) ---
    last_health_check_time_utc = None
    raw_lhct = response.get("LastHealthCheckTimestamp")
    if isinstance(raw_lhct, datetime):
        if raw_lhct.tzinfo is None:
            pass  # naive → null
        else:
            lhct = raw_lhct.astimezone(timezone.utc)
            if lhct > now_utc:
                return None  # future → skip item
            last_health_check_time_utc = lhct

    # --- Optional: instance type from DescribeApp ResourceSpec ---
    raw_rs = response.get("ResourceSpec")
    resource_spec = raw_rs if isinstance(raw_rs, dict) else {}
    describe_instance_type = _str(resource_spec.get("InstanceType"))

    return {
        "resource_id": app_arn,
        "app_arn": app_arn,
        "describe_status": describe_status,
        "last_user_activity_time_utc": last_user_activity_time_utc,
        "last_health_check_time_utc": last_health_check_time_utc,
        "describe_instance_type": describe_instance_type,
    }


def find_idle_sagemaker_studio_apps(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)

    try:
        paginator = sagemaker.get_paginator("list_apps")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError("Missing required IAM permission: sagemaker:ListApps") from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    evaluation_window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("Apps", []):
            # --- Step 1: Normalize list item ---
            nl = _normalize_list_item(raw_item, now)
            if nl is None:
                continue

            # --- Step 2: List-level exclusion rules ---
            if nl["list_status"] != _ELIGIBLE_STATUS:
                continue

            if nl["app_type"] not in _SUPPORTED_APP_TYPES:
                continue

            # --- Step 3: DescribeApp ---
            describe_kwargs: Dict = {
                "DomainId": nl["domain_id"],
                "AppType": nl["app_type"],
                "AppName": nl["app_name"],
            }
            # SpaceName and UserProfileName are mutually exclusive in the API
            if nl["space_name"] is not None:
                describe_kwargs["SpaceName"] = nl["space_name"]
            elif nl["user_profile_name"] is not None:
                describe_kwargs["UserProfileName"] = nl["user_profile_name"]

            try:
                raw_describe = sagemaker.describe_app(**describe_kwargs)
            except ClientError as exc:
                if exc.response["Error"]["Code"] in (
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                ):
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeApp"
                    ) from exc
                continue  # non-permission error (e.g. ResourceNotFound) → SKIP ITEM
            except BotoCoreError:
                continue  # transport error → SKIP ITEM

            # --- Step 4: Normalize describe response ---
            nd = _normalize_describe(raw_describe, now)
            if nd is None:
                continue

            # --- Step 5: Re-check describe status ---
            if nd["describe_status"] != _ELIGIBLE_STATUS:
                continue

            # --- Step 6: Timestamp consistency (LUAT < CreationTime → skip) ---
            if nd["last_user_activity_time_utc"] < nl["creation_time_utc"]:
                continue

            # --- Step 7: Health check contamination (exact equality → skip) ---
            if (
                nd["last_health_check_time_utc"] is not None
                and nd["last_user_activity_time_utc"] == nd["last_health_check_time_utc"]
            ):
                continue

            # --- Step 8: Idle threshold ---
            idle_since_days = int(
                (now - nd["last_user_activity_time_utc"]).total_seconds() // 86400
            )
            if idle_since_days < idle_days_threshold:
                continue

            # --- Step 9: Emit ---
            # Prefer describe-level instance type (more authoritative); fall back to list-level
            effective_instance_type = nd["describe_instance_type"] or nl["instance_type"]
            is_gpu_or_accelerator_backed = _is_accelerator_backed(effective_instance_type)
            risk = RiskLevel.HIGH if is_gpu_or_accelerator_backed else RiskLevel.MEDIUM

            signals_used = [
                f"Studio app status is '{_ELIGIBLE_STATUS}'",
                f"Studio app type '{nl['app_type']}' is within the supported scope "
                f"(KernelGateway, JupyterLab, CodeEditor)",
                "usable_activity_signal = true (LastUserActivityTimestamp is present "
                "and not equal to LastHealthCheckTimestamp)",
                f"LastUserActivityTimestamp is {idle_since_days} days old, meeting "
                f"the {idle_days_threshold}-day threshold",
                "Timestamps equal to LastHealthCheckTimestamp are excluded from "
                "activity signal evaluation",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.studio_app.idle",
                    resource_type="aws.sagemaker.studio_app",
                    resource_id=nd["app_arn"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker Studio {nl['app_type']} app '{nl['app_name']}' "
                        f"(domain {nl['domain_id']}, {nl['owner_type']}: {nl['owner_name']}) "
                        f"shows no recent usable activity timestamp for {idle_since_days} days "
                        f"while InService"
                    ),
                    reason=(
                        f"InService SageMaker Studio app shows no recent usable activity "
                        f"timestamp for at least {idle_days_threshold} days"
                    ),
                    risk=risk,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-sagemaker-studio-app-review-candidate",
                        "app_arn": nd["app_arn"],
                        "app_name": nl["app_name"],
                        "app_type": nl["app_type"],
                        "domain_id": nl["domain_id"],
                        "owner_type": nl["owner_type"],
                        "owner_name": nl["owner_name"],
                        "normalized_status": _ELIGIBLE_STATUS,
                        "creation_time": nl["creation_time_utc"].isoformat(),
                        "last_user_activity_time": (nd["last_user_activity_time_utc"].isoformat()),
                        "last_health_check_time": (
                            nd["last_health_check_time_utc"].isoformat()
                            if nd["last_health_check_time_utc"]
                            else None
                        ),
                        "age_days": nl["age_days"],
                        "idle_since_days": idle_since_days,
                        "idle_days_threshold": idle_days_threshold,
                        "evaluation_window_start": evaluation_window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "usable_activity_signal": True,
                        "instance_type": effective_instance_type,
                        "space_name": nl["space_name"],
                        "user_profile_name": nl["user_profile_name"],
                        "is_gpu_or_accelerator_backed": is_gpu_or_accelerator_backed,
                    },
                )
            )

    return findings
