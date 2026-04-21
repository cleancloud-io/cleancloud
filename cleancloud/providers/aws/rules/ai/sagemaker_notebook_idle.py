"""
Rule: aws.sagemaker.notebook.idle

    (spec — docs/specs/aws/ai/sagemaker_notebook_idle.md)

Intent:
    Detect SageMaker notebook instances that are currently InService, old enough
    to evaluate, and show a stale control-plane timestamp state for the configured
    review window, so they can be reviewed as possible cleanup candidates.

    This is a CleanCloud-derived low-fidelity stale-control-plane heuristic, not
    an AWS-native notebook idle state. It is intentionally conservative, and false
    positives are acceptable at this review-candidate stage. It is a read-only
    review-candidate rule — not a delete-safe rule.

Exclusions:
    - NotebookInstanceArn absent (malformed identity)
    - NotebookInstanceName absent (malformed identity)
    - NotebookInstanceStatus absent or not "InService"
    - CreationTime absent, naive, or future
    - LastModifiedTime absent, naive, or future
    - LastModifiedTime < CreationTime (inconsistent timestamp state)
    - age_days < idle_days_threshold (too young)
    - stale_control_plane_days < idle_days_threshold (not stale enough)

Detection:
    - InService notebook instance older than idle_days_threshold
    - LastModifiedTime at least idle_days_threshold days old

Key rules:
    - Signal: stale LastModifiedTime (weak control-plane heuristic only)
    - No DescribeNotebookInstance calls required or permitted
    - estimated_monthly_cost_usd = None
    - Confidence: MEDIUM always (no HIGH — lacks native notebook-session activity signal)
    - Risk: HIGH for accelerator-backed (g*, p*, inf*, trn*); MEDIUM otherwise
    - ListNotebookInstances failure → FAIL RULE
    - Permission failure → FAIL RULE
    - Item normalization failure → SKIP ITEM

Blind spots:
    - Active Jupyter or kernel sessions
    - Presigned URL creation or browser access recency
    - CloudWatch Logs content such as jupyter.log
    - Scheduled notebook runs or external orchestrators
    - SageMaker-managed control-plane actions that can update LastModifiedTime
      without direct user intent
    - Planned future usage or user intent
    - Exact region-specific pricing impact

APIs:
    - sagemaker:ListNotebookInstances
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATUS = "InService"

# Accelerator instance type prefixes — used for HIGH risk determination
# Matches g*, p*, inf*, trn* as specified in the risk model
_ACCELERATOR_PREFIXES = ("ml.g", "ml.p", "ml.inf", "ml.trn")

_FINDING_TITLE = "Idle SageMaker notebook review candidate"

_SIGNALS_NOT_CHECKED = (
    "Active Jupyter or kernel sessions",
    "Presigned URL creation or browser access recency",
    "CloudWatch Logs content such as jupyter.log",
    "Scheduled notebook runs or external orchestrators",
    "SageMaker-managed control-plane actions that can update LastModifiedTime "
    "without direct user intent",
    "Planned future usage or user intent",
    "Exact region-specific pricing impact",
)

RULE_METADATA = {
    "id": "aws.sagemaker.notebook.idle",
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


def _normalize_notebook(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListNotebookInstances item to the canonical field shape.

    Returns None when required identity/status/timestamp fields are absent or
    invalid — the caller must skip the item. All rule logic must operate only
    on the returned normalized dict.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity (required; absent → skip) ---
    notebook_instance_arn = _str(item.get("NotebookInstanceArn"))
    if notebook_instance_arn is None:
        return None

    notebook_instance_name = _str(item.get("NotebookInstanceName"))
    if notebook_instance_name is None:
        return None

    # --- Status (required; absent → skip) ---
    normalized_status = _str(item.get("NotebookInstanceStatus"))
    if normalized_status is None:
        return None

    # --- CreationTime (required; absent, naive, future → skip) ---
    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc:
        return None

    # --- LastModifiedTime (required; absent, naive, future → skip) ---
    raw_lmt = item.get("LastModifiedTime")
    if not isinstance(raw_lmt, datetime):
        return None
    if raw_lmt.tzinfo is None:
        return None
    last_modified_time_utc = raw_lmt.astimezone(timezone.utc)
    if last_modified_time_utc > now_utc:
        return None

    # --- Timestamp consistency (LMT < CT → inconsistent state → skip) ---
    if last_modified_time_utc < creation_time_utc:
        return None

    # --- Derived fields ---
    age_days = int((now_utc - creation_time_utc).total_seconds() // 86400)
    stale_control_plane_days = int((now_utc - last_modified_time_utc).total_seconds() // 86400)

    # --- Optional context fields ---
    instance_type = _str(item.get("InstanceType"))
    lifecycle_config_name = _str(item.get("NotebookInstanceLifecycleConfigName"))
    default_code_repository = _str(item.get("DefaultCodeRepository"))

    raw_repos = item.get("AdditionalCodeRepositories")
    additional_code_repositories = (
        [r for r in raw_repos if isinstance(r, str) and r] if isinstance(raw_repos, list) else []
    )

    return {
        "resource_id": notebook_instance_arn,
        "notebook_instance_arn": notebook_instance_arn,
        "notebook_instance_name": notebook_instance_name,
        "normalized_status": normalized_status,
        "creation_time_utc": creation_time_utc,
        "last_modified_time_utc": last_modified_time_utc,
        "age_days": age_days,
        "stale_control_plane_days": stale_control_plane_days,
        "instance_type": instance_type,
        "lifecycle_config_name": lifecycle_config_name,
        "default_code_repository": default_code_repository,
        "additional_code_repositories": additional_code_repositories,
    }


def find_idle_sagemaker_notebooks(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)

    try:
        paginator = sagemaker.get_paginator("list_notebook_instances")
        pages = list(paginator.paginate(StatusEquals=_ELIGIBLE_STATUS))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "AccessDenied",
            "UnauthorizedOperation",
            "AccessDeniedException",
        ):
            raise PermissionError(
                "Missing required IAM permission: sagemaker:ListNotebookInstances"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    evaluation_window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("NotebookInstances", []):
            # --- Step 1: Normalize ---
            n = _normalize_notebook(raw_item, now)
            if n is None:
                continue

            # --- Step 2: Exclusion rules ---

            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            if n["age_days"] < idle_days_threshold:
                continue

            if n["stale_control_plane_days"] < idle_days_threshold:
                continue

            # --- Step 3: Emit ---
            is_gpu_or_accelerator_backed = _is_accelerator_backed(n["instance_type"])
            risk = RiskLevel.HIGH if is_gpu_or_accelerator_backed else RiskLevel.MEDIUM

            signals_used = [
                f"Notebook instance status is '{_ELIGIBLE_STATUS}'",
                f"Notebook age is {n['age_days']} days, meeting the "
                f"{idle_days_threshold}-day threshold",
                f"LastModifiedTime is {n['stale_control_plane_days']} days old, "
                f"meeting the {idle_days_threshold}-day threshold as a control-plane timestamp",
                "Finding is based on a low-fidelity stale control-plane heuristic, "
                "not a native notebook-session activity metric",
                "LastModifiedTime is not a direct signal of Jupyter usage, kernel "
                "execution, user access, or usage intensity",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.notebook.idle",
                    resource_type="aws.sagemaker.notebook",
                    resource_id=n["notebook_instance_arn"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker notebook instance {n['notebook_instance_name']} "
                        f"shows a stale control-plane timestamp state for "
                        f"{n['stale_control_plane_days']} days while InService"
                    ),
                    reason=(
                        f"InService SageMaker notebook instance shows a stale "
                        f"control-plane timestamp state for at least "
                        f"{idle_days_threshold} days"
                    ),
                    risk=risk,
                    confidence=ConfidenceLevel.MEDIUM,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-sagemaker-notebook-review-candidate",
                        "notebook_instance_arn": n["notebook_instance_arn"],
                        "notebook_instance_name": n["notebook_instance_name"],
                        "normalized_status": n["normalized_status"],
                        "instance_type": n["instance_type"],
                        "creation_time": n["creation_time_utc"].isoformat(),
                        "last_modified_time": n["last_modified_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "stale_control_plane_days": n["stale_control_plane_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "evaluation_window_start": evaluation_window_start.isoformat(),
                        "evaluation_window_end": now.isoformat(),
                        "lifecycle_config_name": n["lifecycle_config_name"],
                        "default_code_repository": n["default_code_repository"],
                        "additional_code_repositories": n["additional_code_repositories"],
                        "is_gpu_or_accelerator_backed": is_gpu_or_accelerator_backed,
                    },
                )
            )

    return findings
